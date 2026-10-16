"""Server-side quota reservations for anonymous email scans."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("bantai.guest_scan_quota")

MAX_GUEST_SCANS = 3
WINDOW = timedelta(hours=24)
PENDING_TIMEOUT = timedelta(minutes=15)


class GuestScanLimitReached(Exception):
    """The client IP has used its guest scan allowance."""


class GuestScanQuotaUnavailable(Exception):
    """The quota cannot be checked safely."""


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def reserve_guest_scan(session, client_ip: str, *, now: datetime | None = None) -> int:
    """Atomically reserve one of three guest scans for this IP."""
    current = now or datetime.now(timezone.utc)
    cutoff = _timestamp(current - WINDOW)
    pending_cutoff = _timestamp(current - PENDING_TIMEOUT)
    created_at = _timestamp(current)

    try:
        session.execute(
            text(
                "DELETE FROM guest_scan_reservations "
                "WHERE (completed_at IS NOT NULL AND completed_at <= :cutoff) "
                "OR (completed_at IS NULL AND created_at <= :pending_cutoff)"
            ),
            {"cutoff": cutoff, "pending_cutoff": pending_cutoff},
        )
        result = session.execute(
            text(
                "INSERT INTO guest_scan_reservations (client_ip, created_at) "
                "VALUES (:client_ip, :created_at)"
            ),
            {"client_ip": client_ip, "created_at": created_at},
        )
        reservation_id = result.lastrowid
        count = session.execute(
            text(
                "SELECT COUNT(*) FROM guest_scan_reservations "
                "WHERE client_ip = :client_ip AND "
                "((completed_at IS NOT NULL AND completed_at > :cutoff) "
                "OR (completed_at IS NULL AND created_at > :pending_cutoff))"
            ),
            {
                "client_ip": client_ip,
                "cutoff": cutoff,
                "pending_cutoff": pending_cutoff,
            },
        ).scalar_one()
        if count > MAX_GUEST_SCANS:
            session.execute(
                text("DELETE FROM guest_scan_reservations WHERE reservation_id = :id"),
                {"id": reservation_id},
            )
            session.commit()
            raise GuestScanLimitReached
        session.commit()
        return reservation_id
    except GuestScanLimitReached:
        raise
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("could not reserve guest scan quota: %s", type(exc).__name__)
        raise GuestScanQuotaUnavailable from None


def complete_guest_scan(session, reservation_id: int) -> None:
    """Mark the reservation successful inside the scan's database transaction."""
    result = session.execute(
        text(
            "UPDATE guest_scan_reservations SET completed_at = :completed_at "
            "WHERE reservation_id = :reservation_id AND completed_at IS NULL"
        ),
        {
            "completed_at": _timestamp(datetime.now(timezone.utc)),
            "reservation_id": reservation_id,
        },
    )
    if result.rowcount != 1:
        raise SQLAlchemyError("guest scan reservation is no longer active")


def release_guest_scan(session, reservation_id: int) -> None:
    """Release a failed request's reservation so it does not consume the allowance."""
    try:
        session.execute(
            text("DELETE FROM guest_scan_reservations WHERE reservation_id = :id"),
            {"id": reservation_id},
        )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.error("could not release guest scan quota: %s", type(exc).__name__)
