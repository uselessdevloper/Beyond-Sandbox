import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "real_target_adapter"))

import app as flask_app_module
from app import init_db


@pytest.fixture(scope="session")
def client():
    init_db()
    flask_app_module.app.config["TESTING"] = True
    with flask_app_module.app.test_client() as c:
        yield c


                                                                                
class TestHealth:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"


class TestListServices:
    def test_no_filter_returns_all(self, client):

        resp = client.get("/listservices")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert isinstance(data, list)
        assert len(data) == 5

    def test_filter_products(self, client):

        resp = client.get("/listservices?category=products")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) == 2
        assert all(r["category"] == "products" for r in data)

    def test_filter_whitepapers(self, client):

        resp = client.get("/listservices?category=whitepapers")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) == 2
        assert all(r["category"] == "whitepapers" for r in data)

    def test_filter_solutions(self, client):

        resp = client.get("/listservices?category=solutions")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) == 1
        assert data[0]["name"] == "Enterprise version"

    def test_nonexistent_category_empty(self, client):

        resp = client.get("/listservices?category=nonexistent")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == []

                         
    def test_sqli_tautology_blocked(self, client):

        resp = client.get("/listservices?category=products' OR '1'='1")
                                                                                 
                                                                         
                                       
        if resp.status_code == 200:
            data = json.loads(resp.data)
            assert len(data) < 5, (
                f"SQLi tautology returned {len(data)} rows — still vulnerable!"
            )

    def test_sqli_union_secret_dump_blocked(self, client):

        payload = "x' UNION SELECT name,description,category,description FROM secret_stuff--"
        resp = client.get(f"/listservices?category={payload}")
        body = resp.data.decode().lower()
        assert "none of these things" not in body, "secret_stuff leaked via UNION — still vulnerable!"
        assert "single regex" not in body

    def test_no_500_on_sqli_payload(self, client):

        resp = client.get("/listservices?category=x'")
        assert resp.status_code != 500, "DB error returned — injection may still work"


class TestGetItem:
    def test_get_item_valid(self, client):
        resp = client.get("/api/item?id=1")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) >= 1
        assert data[0]["id"] == 1

    def test_get_item_invalid(self, client):
        resp = client.get("/api/item?id=9999")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data == []

    def test_sqli_item_tautology_blocked(self, client):
        resp = client.get("/api/item?id=1 OR 1=1")
        if resp.status_code == 200:
            data = json.loads(resp.data)
            assert len(data) <= 1, f"Tautology returned {len(data)} items — still vulnerable!"


class TestSearch:
    def test_search_normal(self, client):
        resp = client.get("/api/search?q=Military")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) >= 1
        assert any("Military" in r["name"] for r in data)

    def test_search_empty_returns_all(self, client):
        resp = client.get("/api/search?q=")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert len(data) == 5

    def test_sqli_search_blocked(self, client):
        resp = client.get("/api/search?q=' OR '1'='1")
        assert resp.status_code != 500


class TestCategories:
    def test_categories_safe(self, client):
        resp = client.get("/api/categories")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert "products" in data
        assert "whitepapers" in data
        assert "solutions" in data
