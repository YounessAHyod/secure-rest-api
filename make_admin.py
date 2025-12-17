from app.db.database import SessionLocal
from app.models.user import User

def main():
    db = SessionLocal()
    try:

        target = "user@example.com"

        user = db.query(User).filter(User.email == target).first()
        if not user:
            print("User not found")
            return

        user.role = "admin"
        db.commit()
        print(f"✅ {user.email} is now admin")

    finally:
        db.close()

if __name__ == "__main__":
    main()
