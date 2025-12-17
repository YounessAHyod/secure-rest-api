from fastapi import FastAPI

from app.db.database import engine
from app.models.user import Base
from app.routes import auth, users, admin

app = FastAPI(title="Secure REST API")


@app.on_event("startup")
def on_startup() -> None:
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
