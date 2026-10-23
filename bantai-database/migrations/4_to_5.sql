BEGIN IMMEDIATE;

CREATE TABLE guest_scan_reservations (
    reservation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip      TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    completed_at   TEXT
);
CREATE INDEX ix_guest_scan_reservations_ip_created
    ON guest_scan_reservations (client_ip, created_at);
CREATE INDEX ix_guest_scan_reservations_ip_completed
    ON guest_scan_reservations (client_ip, completed_at);

PRAGMA user_version = 5;
COMMIT;
