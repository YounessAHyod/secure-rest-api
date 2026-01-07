def test_rate_limit_triggers_429(client):
    # login_target_limiter is configured for 10 req/min per (ip + identifier)
    for i in range(10):
        r = client.post("/auth/login", json={"username": "no_such_user", "password": "wrong"})
        assert r.status_code == 401, (i, r.text)

    r = client.post("/auth/login", json={"username": "no_such_user", "password": "wrong"})
    assert r.status_code == 429, r.text


def test_account_lockout_triggers_423(client):
    client.post(
        "/auth/register",
        json={"email": "lock@example.com", "username": "lock", "password": "Password123!"},
    )

    # lockout triggers on the 6th bad password attempt (>5)
    for i in range(5):
        r = client.post("/auth/login", json={"username": "lock", "password": "WRONG"})
        assert r.status_code == 401, (i, r.text)

    r = client.post("/auth/login", json={"username": "lock", "password": "WRONG"})
    assert r.status_code == 423, r.text
