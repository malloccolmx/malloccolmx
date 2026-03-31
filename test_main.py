"""Tests for the WhoAmI API endpoints."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

import main


@pytest.fixture()
def client():
    return TestClient(main.app)


@pytest.fixture()
def fake_active_user():
    return {"_id": ObjectId(), "mail": "user@test.com", "status": "active"}


def _patched_db(find_one_return):
    """Context manager that patches the Motor collection's find_one."""
    mock_coll = MagicMock()
    mock_coll.find_one = AsyncMock(return_value=find_one_return)
    mock_db = MagicMock()
    mock_db.__getitem__ = MagicMock(return_value=mock_coll)
    mock_client = MagicMock()
    mock_client.__getitem__ = MagicMock(return_value=mock_db)
    return patch.object(main, "_mongo_client", mock_client)


# ---------------------------------------------------------------------------
# POST /whoami
# ---------------------------------------------------------------------------


class TestPostWhoAmI:
    def test_returns_jwt_and_iso8601_date_for_active_user(self, client, fake_active_user):
        with _patched_db(fake_active_user):
            r = client.post(
                "/whoami",
                json={"mail": "user@test.com", "access_key": "secret"},
            )
        assert r.status_code == 200
        data = r.json()
        assert "JWT_ACE" in data
        assert "date" in data
        # date must be a valid ISO 8601 UTC datetime (Z suffix)
        date_str = data["date"]
        assert date_str.endswith("Z"), f"Expected Z suffix, got: {date_str}"
        from datetime import datetime
        datetime.fromisoformat(date_str.replace("Z", "+00:00"))  # raises ValueError if invalid

    def test_returns_401_when_user_not_found(self, client):
        with _patched_db(None):
            r = client.post(
                "/whoami",
                json={"mail": "nobody@example.com", "access_key": "bad"},
            )
        assert r.status_code == 401

    def test_returns_422_on_missing_fields(self, client):
        r = client.post("/whoami", json={"mail": "only@mail.com"})
        assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /whoami/{anonmail}
# ---------------------------------------------------------------------------


class TestGetWhoAmI:
    def _get_valid_token(self, client, fake_active_user):
        with _patched_db(fake_active_user):
            r = client.post(
                "/whoami",
                json={"mail": "user@test.com", "access_key": "secret"},
            )
        return r.json()["JWT_ACE"]

    def test_returns_stub_payload_with_valid_token(self, client, fake_active_user):
        token = self._get_valid_token(client, fake_active_user)
        r = client.get(
            "/whoami/admin@anonmail.com",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "testv1-11.14.151241.1a" in data
        assert data["testv1-11.14.151241.1a"]["var"] == "var-1a"
        assert data["testv1-11.14.151241.1a"]["name"] == "name-1a"

    def test_returns_401_without_token(self, client):
        r = client.get("/whoami/admin@anonmail.com")
        assert r.status_code == 401

    def test_returns_401_with_invalid_token(self, client):
        r = client.get(
            "/whoami/admin@anonmail.com",
            headers={"Authorization": "Bearer this.is.not.valid"},
        )
        assert r.status_code == 401
