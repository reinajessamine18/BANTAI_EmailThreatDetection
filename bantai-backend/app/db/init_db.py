"""Create / upgrade the SQLite database from the team's SQL files.

`bantai-database/schema.sql` stays the single source of truth for the schema.
This module only *runs* the SQL files; it does not redefine tables.

    fresh database : schema.sql -> seed.sql -> register the deployed model
    existing       : check the schema version, then register the model if not yet done

`schema.sql` declares its version with `PRAGMA user_version = N;`. Existing databases
are upgraded through sequential scripts in `bantai-database/migrations/`; unsupported
version paths are rejected without rebuilding or deleting the database.

A fresh database is built in a temporary file and moved into place only after
everything succeeded, so a failed run never leaves a half-built database behind.

Pure standard library (sqlite3), so it can run before the app is configured.
CLI:  python -m app.db.init_db [--with-sample]
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("bantai.db")

MIN_SQLITE = (3, 31, 0)  # generated columns (scans.scan_code)
BASELINE_VERSION_TAG = "baseline-tfidf-xgb-v1"
_BASELINE_DIR = Path("artifacts") / "baseline"


class DatabaseInitError(RuntimeError):
    """The database could not be created or upgraded."""


@dataclass
class InitResult:
    created: bool = False
    schema_version: int = 0
    model_registered: bool = False


# ---------------------------------------------------------------------------
def _read_sql(path: Path) -> str:
    if not path.is_file():
        raise DatabaseInitError(f"required SQL file not found: {path.name}")
    return path.read_text(encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_VERSION_RE = re.compile(r"PRAGMA\s+user_version\s*=\s*(\d+)", re.IGNORECASE)
_GOOGLE_V9_USER_COLUMNS = {
    "user_id", "full_name", "email", "auth_provider", "sso_subject_id",
    "sso_idp_entity_id", "role", "job_title", "tier_label", "profile_picture",
    "is_active", "last_login_at", "created_at", "updated_at",
}


def _required_schema_version(sql_dir: Path) -> int:
    """The version schema.sql declares for itself."""
    match = _VERSION_RE.search(_read_sql(sql_dir / "schema.sql"))
    if not match:
        raise DatabaseInitError("schema.sql does not declare PRAGMA user_version")
    return int(match.group(1))


def _validate_google_v9_database(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if columns != _GOOGLE_V9_USER_COLUMNS:
        raise DatabaseInitError(
            "schema-9 migration supports the legacy Google SSO users table only; "
            "the existing users table has a different set of columns."
        )
    unsupported_accounts = conn.execute(
        "SELECT COUNT(*) FROM users "
        "WHERE auth_provider <> 'google' OR sso_subject_id IS NULL"
    ).fetchone()[0]
    if unsupported_accounts:
        raise DatabaseInitError(
            "schema-9 migration found non-Google accounts without password hashes; "
            "the database was not changed."
        )
    extra_objects = conn.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE tbl_name = 'users' AND type IN ('index', 'trigger') "
        "AND name NOT LIKE 'sqlite_%' AND name <> 'ux_users_sso'"
    ).fetchone()[0]
    if extra_objects:
        raise DatabaseInitError(
            "schema-9 migration found custom user indexes or triggers; "
            "the database was not changed."
        )


def _check_existing_version(
    conn: sqlite3.Connection, required: int, db_name: str, sql_dir: Path
) -> None:
    found = conn.execute("PRAGMA user_version").fetchone()[0]
    if found > required:
        raise DatabaseInitError(
            f"database schema version is {found} but the code expects {required}. "
            f"Database '{db_name}' is newer than this application."
        )
    while found < required:
        migration = sql_dir / "migrations" / f"{found}_to_{required}.sql"
        if not migration.is_file():
            migration = sql_dir / "migrations" / f"{found}_to_{found + 1}.sql"
        if not migration.is_file():
            raise DatabaseInitError(
                f"database '{db_name}' schema version is {found} but the code expects {required}; "
                f"no migration is available for '{migration.name}'."
            )
        if migration.name == "9_to_10.sql":
            _validate_google_v9_database(conn)
        try:
            conn.executescript(_read_sql(migration))
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise
        migrated = conn.execute("PRAGMA user_version").fetchone()[0]
        expected = int(migration.stem.split("_to_")[-1])
        if migrated != expected:
            raise DatabaseInitError(
                f"migration '{migration.name}' did not set the expected schema version."
            )
        found = migrated


def register_baseline_model(conn: sqlite3.Connection, ml_dir: Path) -> bool:
    """Record the deployed baseline model in `model_versions` and make it the active one.

    Metrics are copied from experiment_config.json and are VALIDATION-set values
    (nothing is invented). Returns False if already registered or if the artifacts
    are not available.
    """
    config_path = Path(ml_dir) / _BASELINE_DIR / "experiment_config.json"
    model_path = Path(ml_dir) / _BASELINE_DIR / "xgboost_model.pkl"
    vectorizer_path = Path(ml_dir) / _BASELINE_DIR / "tfidf_vectorizer.pkl"
    if not (config_path.is_file() and model_path.is_file() and vectorizer_path.is_file()):
        logger.warning("baseline artifacts not found; model_versions left unchanged")
        return False

    if conn.execute(
        "SELECT 1 FROM model_versions WHERE version_tag = ?", (BASELINE_VERSION_TAG,)
    ).fetchone():
        return False

    config = json.loads(config_path.read_text(encoding="utf-8"))
    metrics = config.get("validation_metrics", {})
    notes = (
        "TF-IDF + XGBoost baseline. Metrics are VALIDATION-set values from "
        "experiment_config.json (held-out test results are in "
        "machine-learning/reports/baseline_test_evaluation.md). "
        "scaler_artifact_path holds the fitted TF-IDF vectorizer. "
        f"SHA-256 model={_sha256(model_path)} vectorizer={_sha256(vectorizer_path)}"
    )
    hyperparameters = json.dumps(
        {
            "tfidf_params": config.get("tfidf_params"),
            "xgb_params": config.get("xgb_params"),
            "random_state": config.get("random_state"),
        }
    )
    base = "machine-learning/artifacts/baseline"  # repo-relative; no machine-specific paths

    try:
        conn.execute("UPDATE model_versions SET is_active = 0 WHERE is_active = 1")
        conn.execute(
            "INSERT INTO model_versions (version_tag, algorithm, explainer_type, training_dataset,"
            " n_training_samples, accuracy, precision_score, recall_score, f1_score, roc_auc,"
            " hyperparameters, model_artifact_path, scaler_artifact_path, is_active, deployed_at, notes)"
            " VALUES (?, 'XGBoost', 'shap.TreeExplainer', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                BASELINE_VERSION_TAG,
                "Balanced_Dataset.csv (deduplicated; see dataset_preparation_manifest.json)",
                config.get("train_rows"),
                metrics.get("accuracy"),
                metrics.get("precision"),
                metrics.get("recall"),
                metrics.get("f1_score"),
                metrics.get("roc_auc"),
                hyperparameters,
                f"{base}/xgboost_model.pkl",
                f"{base}/tfidf_vectorizer.pkl",
                _now(),
                notes,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


def _build_fresh(tmp_path: Path, sql_dir: Path, with_sample: bool) -> None:
    conn = sqlite3.connect(tmp_path)
    try:
        conn.executescript(_read_sql(sql_dir / "schema.sql"))
        conn.executescript(_read_sql(sql_dir / "seed.sql"))
        if with_sample:
            conn.executescript(_read_sql(sql_dir / "sample_data.sql"))
        conn.commit()
    finally:
        conn.close()


def init_db(
    db_path: Path,
    sql_dir: Path,
    ml_dir: Optional[Path] = None,
    *,
    with_sample: bool = False,
) -> InitResult:
    """Idempotent. Safe to call on every startup."""
    if sqlite3.sqlite_version_info < MIN_SQLITE:
        raise DatabaseInitError(
            f"SQLite {sqlite3.sqlite_version} is too old; 3.31+ is required"
        )
    db_path, sql_dir = Path(db_path), Path(sql_dir)
    result = InitResult(schema_version=_required_schema_version(sql_dir))
    tmp_path = db_path.with_name(db_path.name + ".building")

    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if not db_path.exists():
            tmp_path.unlink(missing_ok=True)
            _build_fresh(tmp_path, sql_dir, with_sample)
            work_path = tmp_path
            result.created = True
        else:
            work_path = db_path

        conn = sqlite3.connect(work_path)
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            if not result.created:
                _check_existing_version(conn, result.schema_version, db_path.name, sql_dir)
            if ml_dir is not None:
                result.model_registered = register_baseline_model(conn, Path(ml_dir))
        finally:
            conn.close()

        if result.created:
            os.replace(tmp_path, db_path)
    except DatabaseInitError:
        tmp_path.unlink(missing_ok=True)
        raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        tmp_path.unlink(missing_ok=True)
        raise DatabaseInitError(f"database initialization failed ({type(exc).__name__})") from exc

    logger.info(
        "database ready (created=%s, schema_version=%s, model_registered=%s)",
        result.created, result.schema_version, result.model_registered,
    )
    return result


def main() -> None:  # pragma: no cover - thin CLI wrapper
    import argparse

    from app.core.config import get_settings

    parser = argparse.ArgumentParser(description="Create or upgrade the BANTAI database.")
    parser.add_argument("--with-sample", action="store_true",
                        help="load bantai-database/sample_data.sql (demo data) into a NEW database")
    args = parser.parse_args()
    settings = get_settings()
    outcome = init_db(settings.database_path, settings.sql_dir, settings.ml_dir,
                      with_sample=args.with_sample)
    print(outcome)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    main()
