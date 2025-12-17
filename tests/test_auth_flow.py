def test_register_login_me(client):
    r = client.post(
        "/auth/register",
        json={"email": "u1@example.com", "username": "user1", "password": "Password123!"},
    )
    assert r.status_code == 201, r.text

    r = client.post("/auth/login", json={"username": "user1", "password": "Password123!"})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["username"] == "user1"
