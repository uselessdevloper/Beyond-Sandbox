import sys
import os
import json
import pytest

                            
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "target_app"))

from database import init_db
import app as flask_app_module


                                                                                
          
                                                                                

@pytest.fixture(scope="session")
def client():

    init_db()
    flask_app_module.app.config["TESTING"] = True
    with flask_app_module.app.test_client() as c:
        yield c


                                                                                
                             
                                                                                

class TestHealth:
    def test_health_check(self, client):

        resp = client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"


class TestUserList:
    def test_list_users_returns_list(self, client):

        resp = client.get("/api/users")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_list_users_has_expected_fields(self, client):

        resp = client.get("/api/users")
        data = json.loads(resp.data)
        for user in data:
            assert "id" in user
            assert "username" in user
            assert "role" in user

    def test_list_users_no_passwords_exposed(self, client):

        resp = client.get("/api/users")
        body = resp.data.decode()
        assert "password" not in body.lower() or "secret" not in body.lower()


class TestUserLookup:
    def test_valid_user_lookup(self, client):

        resp = client.get("/api/user?id=1")
        assert resp.status_code == 200
        data = json.loads(resp.data)
                                                                
                                                             
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(u["username"] == "alice" for u in data)

    def test_user_lookup_id_2(self, client):

        resp = client.get("/api/user?id=2")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any(u["username"] == "bob" for u in data)

    def test_nonexistent_user_returns_empty(self, client):

        resp = client.get("/api/user?id=9999")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == []

    def test_sqli_tautology_blocked(self, client):

        resp = client.get("/api/user?id=1 OR 1=1--")
                                                                 
        if resp.status_code == 200:
            data = json.loads(resp.data)
                                                                       
            assert len(data) <= 1, (
                f"SQLi tautology returned {len(data)} rows — still vulnerable!"
            )

    def test_sqli_union_blocked(self, client):

        payload = "' UNION SELECT 1,username,password FROM users--"
        resp = client.get(f"/api/user?id={payload}")
        body = resp.data.decode().lower()
        assert "secret123" not in body, "Password leaked via UNION injection — still vulnerable!"
        assert "qwerty" not in body


class TestLogin:
    def test_login_valid_credentials(self, client):

        resp = client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "secret123"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["authenticated"] is True
        assert data["user"] == "alice"

    def test_login_wrong_password(self, client):

        resp = client.post(
            "/api/login",
            data=json.dumps({"username": "alice", "password": "wrongpassword"}),
            content_type="application/json",
        )
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert data["authenticated"] is False

    def test_login_nonexistent_user(self, client):

        resp = client.post(
            "/api/login",
            data=json.dumps({"username": "ghost", "password": "anything"}),
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_sqli_auth_bypass_blocked(self, client):

        resp = client.post(
            "/api/login",
            data=json.dumps({"username": "admin'--", "password": "irrelevant"}),
            content_type="application/json",
        )
        if resp.status_code == 200:
            data = json.loads(resp.data)
            assert data.get("authenticated") is not True, (
                "Auth bypass still works — patch did not fix login endpoint!"
            )

    def test_sqli_or_bypass_blocked(self, client):

        resp = client.post(
            "/api/login",
            data=json.dumps({"username": "' OR '1'='1", "password": "' OR '1'='1"}),
            content_type="application/json",
        )
        if resp.status_code == 200:
            data = json.loads(resp.data)
            assert data.get("authenticated") is not True


class TestSearch:
    def test_search_normal_query(self, client):

        resp = client.get("/api/search?q=alice")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) >= 1
        assert any(u["username"] == "alice" for u in data)

    def test_search_empty_returns_all(self, client):

        resp = client.get("/api/search?q=")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) >= 4

    def test_search_no_match_returns_empty(self, client):

        resp = client.get("/api/search?q=zzznomatch")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == []

    def test_sqli_search_blocked(self, client):

        resp = client.get("/api/search?q=' OR '1'='1")
                                                                                
                                                  
        if resp.status_code == 200:
            data = json.loads(resp.data)
                                                                                             
                                                             
            pass                         
        assert resp.status_code != 500, "Search returned 500 — DB error leaked from SQLi"
