"""
Black-box API integration tests: real HTTP requests against a real, running
instance of the app (not an embedded Spring context). This is a separate,
second integration layer alongside FullApplicationIntegrationIT
(mvn verify -Pintegration); it doesn't replace it. Where the JUnit suite
runs inside the build with an embedded Spring context, this script talks to
whatever's actually listening on API_BASE_URL, exactly like the real
frontend or a real attacker would.

Modeled on the api_test.py pattern from Dhruv0306/cloudshare-app: a small
TestRunner harness (RUN/PASS/FAIL per case, non-zero exit on any failure),
no pytest, no other test framework, just `requests`.

Usage:
    python3 tests/api_test.py

Environment:
    API_BASE_URL         Base URL of a running instance (default: http://localhost:8080)
    API_TIMEOUT_SECONDS  Per-request timeout in seconds (default: 10)

The target instance must be running with the `dev` profile (or any profile
with ADMIN_USERNAME / ADMIN_PASSWORD set and CORS validation relaxed), since
this script logs in as the seeded admin account for the RBAC checks.
"""

import os
import sys
import uuid

import requests

BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8080")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
API_TIMEOUT_SECONDS = float(os.environ.get("API_TIMEOUT_SECONDS", "10"))

EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class TimeoutSession(requests.Session):
    """requests.Session that applies a default timeout to every call. Plain
    requests.Session calls block forever by default, so a stalled server or
    a hung connection would otherwise stall this script until the CI job's
    own timeout kills it, hiding the real failure."""

    def request(self, method, url, *args, **kwargs):
        kwargs.setdefault("timeout", API_TIMEOUT_SECONDS)
        return super().request(method, url, *args, **kwargs)


def new_session():
    return TimeoutSession()


class TestRunner:
    def __init__(self):
        self.tests_run = 0
        self.tests_failed = 0

    def run_case(self, name, func, *args, **kwargs):
        self.tests_run += 1
        print(f"[RUN] {name} ... ", end="", flush=True)
        try:
            func(*args, **kwargs)
            print("[PASS]")
        except Exception as e:
            self.tests_failed += 1
            print("[FAIL]")
            print(f"   Reason: {e}")

    def summary(self):
        print("\n" + "=" * 50)
        print("API Integration Test Summary")
        print("=" * 50)
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Passed:          {self.tests_run - self.tests_failed}")
        print(f"Failed:          {self.tests_failed}")
        print("=" * 50)
        return self.tests_failed == 0


def generate_random_user():
    suffix = uuid.uuid4().hex[:8]
    return {
        "username": f"api_test_{suffix}",
        "email": f"api_test_{suffix}@example.com",
        "password": f"ApiTestPass_{suffix}!",
    }


def fetch_csrf(session):
    """GET /api/auth/csrf and return (header_name, token). The endpoint is
    unauthenticated on purpose, it's how the frontend bootstraps CSRF before
    any state-changing request."""
    resp = session.get(f"{BASE_URL}/api/auth/csrf")
    assert (
        resp.status_code == 200
    ), f"CSRF bootstrap failed: {resp.status_code} {resp.text}"
    body = resp.json()
    return body["headerName"], body["token"]


def register(session, user):
    header_name, token = fetch_csrf(session)
    return session.post(
        f"{BASE_URL}/api/auth/register",
        json={**user, "confirmPassword": user["password"]},
        headers={header_name: token},
    )


def login(session, username, password):
    header_name, token = fetch_csrf(session)
    return session.post(
        f"{BASE_URL}/api/auth/login",
        data={"username": username, "password": password},
        headers={header_name: token},
    )


# ----------------------------------------------------
# 1. Auth flow
# ----------------------------------------------------
def test_auth_flow():
    session = new_session()
    user = generate_random_user()

    reg_resp = register(session, user)
    assert (
        reg_resp.status_code == 201
    ), f"Expected 201, got {reg_resp.status_code}. Response: {reg_resp.text}"
    assert reg_resp.json().get("success") is True, f"Registration body: {reg_resp.text}"

    login_resp = login(session, user["username"], user["password"])
    assert (
        login_resp.status_code == 200
    ), f"Expected 200, got {login_resp.status_code}. Response: {login_resp.text}"

    me_resp = session.get(f"{BASE_URL}/api/auth/me")
    assert me_resp.status_code == 200, f"Expected 200, got {me_resp.status_code}"
    me_body = me_resp.json()
    assert (
        me_body.get("username") == user["username"]
    ), f"/me returned wrong user: {me_body}"
    assert (
        me_body.get("role") == "USER"
    ), f"Newly registered account should be USER, got: {me_body}"

    header_name, token = fetch_csrf(session)
    logout_resp = session.post(
        f"{BASE_URL}/api/auth/logout", headers={header_name: token}
    )
    assert (
        logout_resp.status_code == 200
    ), f"Expected 200, got {logout_resp.status_code}"

    post_logout_me = session.get(f"{BASE_URL}/api/auth/me")
    assert (
        post_logout_me.status_code == 401
    ), f"Expected 401 after logout, got {post_logout_me.status_code}"


def test_duplicate_registration_is_anti_enumeration():
    session = new_session()
    user = generate_random_user()

    first = register(session, user)
    assert first.status_code == 201, f"First registration should succeed: {first.text}"

    second = register(session, user)
    assert (
        second.status_code == 409
    ), f"Expected 409 for duplicate username, got {second.status_code}"
    message = second.json().get("message", "")
    assert (
        "not available" in message
    ), f"Duplicate registration should return the generic anti-enumeration message, got: {message}"


def test_unauthenticated_requests_are_rejected():
    session = new_session()
    me_resp = session.get(f"{BASE_URL}/api/auth/me")
    assert me_resp.status_code == 401, f"Expected 401, got {me_resp.status_code}"

    history_resp = session.get(f"{BASE_URL}/api/antivirus/history/me")
    assert (
        history_resp.status_code == 401
    ), f"Expected 401, got {history_resp.status_code}"


# ----------------------------------------------------
# 2. Scanning and own history
# ----------------------------------------------------
def test_scan_file_and_read_own_history():
    session = new_session()
    user = generate_random_user()
    register(session, user)
    login(session, user["username"], user["password"])

    header_name, token = fetch_csrf(session)
    files = {
        "file": (
            "api-test.txt",
            b"A harmless API integration test file.\n",
            "text/plain",
        )
    }
    scan_resp = session.post(
        f"{BASE_URL}/api/antivirus/scan/file",
        files=files,
        headers={header_name: token},
    )
    assert (
        scan_resp.status_code == 200
    ), f"Clean file scan should succeed: {scan_resp.status_code} {scan_resp.text}"
    scan_body = scan_resp.json()
    assert (
        scan_body.get("verdict") == "CLEAN"
    ), f"Expected CLEAN verdict, got: {scan_body}"

    history_resp = session.get(f"{BASE_URL}/api/antivirus/history/me?page=0&size=10")
    assert history_resp.status_code == 200
    history_body = history_resp.json()
    assert (
        history_body.get("totalElements", 0) >= 1
    ), f"Own scan history should contain at least the scan just completed: {history_body}"


def test_eicar_file_is_detected():
    session = new_session()
    user = generate_random_user()
    register(session, user)
    login(session, user["username"], user["password"])

    header_name, token = fetch_csrf(session)
    files = {"file": ("eicar.txt", EICAR_STRING, "text/plain")}
    scan_resp = session.post(
        f"{BASE_URL}/api/antivirus/scan/file",
        files=files,
        headers={header_name: token},
    )
    assert (
        scan_resp.status_code == 200
    ), f"EICAR scan request should succeed: {scan_resp.status_code} {scan_resp.text}"
    scan_body = scan_resp.json()
    assert (
        scan_body.get("infected") is True
    ), f"EICAR test file should be flagged infected: {scan_body}"
    assert scan_body.get("verdict") in (
        "SUSPICIOUS",
        "MALICIOUS",
    ), f"EICAR test file should not come back CLEAN: {scan_body}"


# ----------------------------------------------------
# 3. Role-based access control
# ----------------------------------------------------
def test_user_cannot_reach_admin_history():
    session = new_session()
    user = generate_random_user()
    register(session, user)
    login(session, user["username"], user["password"])

    resp = session.get(f"{BASE_URL}/api/antivirus/history?page=0&size=10")
    assert (
        resp.status_code == 403
    ), f"USER role must be denied the admin-only /history endpoint, got {resp.status_code}"


def test_admin_can_reach_admin_history():
    if not ADMIN_PASSWORD:
        raise AssertionError(
            "ADMIN_PASSWORD environment variable is not set; cannot test the seeded admin account. "
            "Set it to whatever ADMIN_PASSWORD the target instance was started with."
        )

    session = new_session()
    login_resp = login(session, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert (
        login_resp.status_code == 200
    ), f"Seeded admin login should succeed: {login_resp.status_code} {login_resp.text}"

    resp = session.get(f"{BASE_URL}/api/antivirus/history?page=0&size=10")
    assert (
        resp.status_code == 200
    ), f"Seeded ADMIN account should reach the global history endpoint: {resp.status_code}"


def test_user_cannot_quarantine_another_users_scan_result():
    """Ownership enforcement is separate from role checks: even though
    /quarantine has no role restriction, a USER shouldn't be able to act on
    another user's scan result just by guessing its ID."""
    owner_session = new_session()
    owner = generate_random_user()
    register(owner_session, owner)
    login(owner_session, owner["username"], owner["password"])

    header_name, token = fetch_csrf(owner_session)
    files = {"file": ("owner-file.txt", b"belongs to the owner\n", "text/plain")}
    scan_resp = owner_session.post(
        f"{BASE_URL}/api/antivirus/scan/file",
        files=files,
        headers={header_name: token},
    )
    assert scan_resp.status_code == 200

    if not ADMIN_PASSWORD:
        raise AssertionError(
            "ADMIN_PASSWORD not set; needed to look up the created scan result's ID."
        )
    admin_session = new_session()
    login(admin_session, ADMIN_USERNAME, ADMIN_PASSWORD)
    admin_history_resp = admin_session.get(
        f"{BASE_URL}/api/antivirus/history?page=0&size=50"
    )
    assert (
        admin_history_resp.status_code == 200
    ), f"Admin history lookup failed: {admin_history_resp.status_code} {admin_history_resp.text}"
    admin_history = admin_history_resp.json()
    matching = [
        r
        for r in admin_history.get("content", [])
        if r.get("fileName") == "owner-file.txt"
    ]
    assert (
        matching
    ), f"Could not find the owner's scan result in admin history: {admin_history}"
    scan_result_id = matching[0]["id"]

    other_session = new_session()
    other = generate_random_user()
    register(other_session, other)
    login(other_session, other["username"], other["password"])

    other_header, other_token = fetch_csrf(other_session)
    quarantine_resp = other_session.post(
        f"{BASE_URL}/api/antivirus/quarantine",
        params={"scanResultId": scan_result_id},
        headers={other_header: other_token},
    )
    assert quarantine_resp.status_code in (403, 404), (
        f"A USER should not be able to quarantine another user's scan result, "
        f"got {quarantine_resp.status_code}: {quarantine_resp.text}"
    )


# ----------------------------------------------------
# Runner
# ----------------------------------------------------
if __name__ == "__main__":
    print(f"Connecting to API at: {BASE_URL}")
    runner = TestRunner()

    runner.run_case("Auth Flow (register, login, me, logout)", test_auth_flow)
    runner.run_case(
        "Duplicate Registration Anti-Enumeration",
        test_duplicate_registration_is_anti_enumeration,
    )
    runner.run_case(
        "Unauthenticated Requests Rejected", test_unauthenticated_requests_are_rejected
    )
    runner.run_case(
        "Scan Clean File and Read Own History", test_scan_file_and_read_own_history
    )
    runner.run_case("EICAR File Is Detected", test_eicar_file_is_detected)
    runner.run_case(
        "USER Cannot Reach Admin History", test_user_cannot_reach_admin_history
    )
    runner.run_case("ADMIN Can Reach Admin History", test_admin_can_reach_admin_history)
    runner.run_case(
        "USER Cannot Quarantine Another User's Scan",
        test_user_cannot_quarantine_another_users_scan_result,
    )

    success = runner.summary()
    sys.exit(0 if success else 1)
