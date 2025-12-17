from app.models.user import User


def test_admin_users_forbidden_for_normal_user(client, db_session):
    client.post(
        "/auth/register",
        json={
            "email": "u2@example.com",
            "username": "user2",
            "password": "Password123!",
        },
    )

    r = client.post(
        "/auth/login",
        json={"username": "user2", "password": "Password123!"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_admin_users_allowed_for_admin(client, db_session):
    from app.security.auth import hash_password

    admin = User(
        email="admin@example.com",
        username="adminuser",
        hashed_password=hash_password("AdminPass123!"),
        role="admin",
        is_active=True,
    )
    db_session.add(admin)
    db_session.commit()

    r = client.post(
        "/auth/login",
        json={"username": "adminuser", "password": "AdminPass123!"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
