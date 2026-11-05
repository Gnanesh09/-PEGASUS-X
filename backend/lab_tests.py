"""Fixed, bounded PostgreSQL security checks for an explicitly allowlisted lab only.

No shell execution, network scanning, arbitrary SQL input, data modification,
credential guessing, or destructive database statements are present here.
"""
import ipaddress
import time
from psycopg.conninfo import conninfo_to_dict
from .config import POSTGRES_DSN, POSTGRES_TEST_DSN, ENABLE_LAB_TESTS, LAB_HOST

EXPECTED_DB = "pegasus_lab"
EXPECTED_APP_ROLE = "pegasus_app"
EXPECTED_TEST_ROLE = "pegasus_test"


def _parsed_dsn(dsn: str) -> dict:
    if not dsn:
        raise ValueError("A required PostgreSQL DSN is missing.")
    return conninfo_to_dict(dsn)


def lab_configuration():
    """Validate an exact private-IP allowlist before permitting live test traffic."""
    if not ENABLE_LAB_TESTS:
        return False, "Live lab tests are disabled. Set PEGASUS_ENABLE_LAB_TESTS=true after isolating your VM."
    if not LAB_HOST:
        return False, "Set PEGASUS_LAB_HOST to the exact host-only IPv4 address of your Ubuntu VM."
    try:
        ip = ipaddress.ip_address(LAB_HOST)
    except ValueError:
        return False, "PEGASUS_LAB_HOST must be an IP address, not a hostname."
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local:
        return False, "The allowlisted target must be a private IPv4 host-only VM address."
    try:
        app = _parsed_dsn(POSTGRES_DSN)
        test = _parsed_dsn(POSTGRES_TEST_DSN)
    except Exception as exc:
        return False, f"Could not parse PostgreSQL DSNs: {type(exc).__name__}."
    for label, params, expected_user in (
        ("POSTGRES_DSN", app, EXPECTED_APP_ROLE),
        ("POSTGRES_TEST_DSN", test, EXPECTED_TEST_ROLE),
    ):
        if params.get("host", "").strip() != LAB_HOST:
            return False, f"{label} host must exactly match PEGASUS_LAB_HOST ({LAB_HOST})."
        if params.get("dbname") != EXPECTED_DB:
            return False, f"{label} must point only to database {EXPECTED_DB}."
        if params.get("user") != expected_user:
            return False, f"{label} must use the dedicated {expected_user} role."
    if app.get("port", "5432") != test.get("port", "5432"):
        return False, "Both DSNs must use the same PostgreSQL port."
    return True, "Allowlist passed: private lab IP, dedicated database, and restricted roles."


def _require_psycopg():
    try:
        import psycopg
        return psycopg
    except ImportError as exc:
        raise RuntimeError("Install requirements.txt to enable PostgreSQL lab tests.") from exc


def check_lab_connection():
    ok, message = lab_configuration()
    if not ok:
        return {"connected": False, "enabled": ENABLE_LAB_TESTS, "message": message}
    psycopg = _require_psycopg()
    result = {"connected": False, "enabled": True, "message": "Connection check did not complete."}
    for dsn, expected_role in ((POSTGRES_DSN, EXPECTED_APP_ROLE), (POSTGRES_TEST_DSN, EXPECTED_TEST_ROLE)):
        try:
            with psycopg.connect(dsn, connect_timeout=3) as conn:
                db, role, version = conn.execute(
                    "SELECT current_database(), current_user, version()"
                ).fetchone()
            if db != EXPECTED_DB or role != expected_role:
                return {"connected": False, "enabled": True,
                        "message": f"Safety check failed: expected {EXPECTED_DB}/{expected_role}, got {db}/{role}."}
            result[expected_role] = {"database": db, "user": role, "version": version.split(",")[0]}
        except Exception as exc:
            return {"connected": False, "enabled": True,
                    "message": f"{expected_role} connection failed: {type(exc).__name__}: {str(exc)[:140]}"}
    result.update({"connected": True, "message": "Both restricted lab roles connected successfully."})
    return result


def execute_lab_scenario(scenario_id: str):
    """Perform one predefined, read-only or authentication-only test against the allowlisted DB."""
    ok, message = lab_configuration()
    if not ok:
        return {"execution": "NOT_RUN", "observed": False, "error": message}
    psycopg = _require_psycopg()
    try:
        if scenario_id == "AUTH_BURST":
            # Confirm the dedicated role is valid first, then produce exactly three failed
            # authentication attempts. This is not a password sweep or credential guessing.
            with psycopg.connect(POSTGRES_TEST_DSN, connect_timeout=3) as conn:
                db, role = conn.execute("SELECT current_database(), current_user").fetchone()
            if (db, role) != (EXPECTED_DB, EXPECTED_TEST_ROLE):
                raise RuntimeError("Dedicated test-role identity check failed.")
            params = _parsed_dsn(POSTGRES_TEST_DSN)
            params["password"] = "PEGASUS_INVALID_LAB_TEST_PASSWORD"
            params["connect_timeout"] = "3"
            failures, codes = 0, []
            for _ in range(3):
                try:
                    conn = psycopg.connect(**params)
                    conn.close()
                    codes.append("unexpected_login_success")

                except psycopg.OperationalError as exc:
                    code = getattr(exc, "sqlstate", None)

                    codes.append(code or type(exc).__name__)

                    if code == "28P01":
                        failures += 1

            return {
                "execution": "REAL_LAB_TEST",
                "observed": failures >= 1,
                "scenario_id": "AUTH_BURST",
                "failed_auth_attempts": failures,
                "attempts": 3,
                "sqlstates": codes,
                "database": "pegasus_lab",
                "role": "pegasus_test",
                "note": "Three intentional invalid-password attempts only; no password list used."
            }
        if scenario_id == "PRIVILEGE_CHECK":
            with psycopg.connect(POSTGRES_TEST_DSN, connect_timeout=3) as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                db, role = conn.execute("SELECT current_database(), current_user").fetchone()
                if (db, role) != (EXPECTED_DB, EXPECTED_TEST_ROLE):
                    raise RuntimeError("Dedicated test-role identity check failed.")
                try:
                    conn.execute("SELECT record_id, note FROM public.restricted_demo LIMIT 1").fetchall()
                    denied = False
                except psycopg.errors.InsufficientPrivilege:
                    denied = True
                    conn.rollback()
            return {"execution": "REAL_LAB_TEST", "observed": True,
                    "scenario_id": scenario_id, "permission_denied": denied,
                    "database": db, "role": role,
                    "expected": "permission_denied"}

        if scenario_id == "QUERY_SPIKE":
            started = time.perf_counter()
            with psycopg.connect(POSTGRES_DSN, connect_timeout=3) as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                db, role = conn.execute("SELECT current_database(), current_user").fetchone()
                if (db, role) != (EXPECTED_DB, EXPECTED_APP_ROLE):
                    raise RuntimeError("Dedicated application-role identity check failed.")
                row_counts = []
                # Small fixed burst of 12 SELECTs; no writes, loops controlled by this code.
                for _ in range(12):
                    row_counts.append(conn.execute(
                        "SELECT count(*) FROM public.demo_customers"
                    ).fetchone()[0])
            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            return {"execution": "REAL_LAB_TEST", "observed": True,
                    "scenario_id": scenario_id, "query_count": len(row_counts),
                    "elapsed_ms": elapsed_ms, "queries_per_second": round(len(row_counts) / max(elapsed_ms / 1000, .001), 2),
                    "database": db, "role": role, "read_only": True}

        if scenario_id == "SCHEMA_ENUM":
            with psycopg.connect(POSTGRES_TEST_DSN, connect_timeout=3) as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                db, role = conn.execute("SELECT current_database(), current_user").fetchone()
                if (db, role) != (EXPECTED_DB, EXPECTED_TEST_ROLE):
                    raise RuntimeError("Dedicated test-role identity check failed.")
                tables = conn.execute(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_type = 'BASE TABLE' "
                    "ORDER BY table_name LIMIT 10"
                ).fetchall()
            names = [r[0] for r in tables]
            return {"execution": "REAL_LAB_TEST", "observed": True,
                    "scenario_id": scenario_id, "metadata_objects_seen": len(names),
                    "object_names": names, "database": db, "role": role,
                    "read_only": True}

        return {"execution": "NOT_RUN", "observed": False, "error": "Unknown scenario ID."}
    except Exception as exc:
        return {"execution": "LAB_TEST_ERROR", "observed": False,
                "scenario_id": scenario_id,
                "error": f"{type(exc).__name__}: {str(exc)[:180]}"}
