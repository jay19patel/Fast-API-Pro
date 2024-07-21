

from fastapi import FastAPI
from app.database.base import init_db
from contextlib import asynccontextmanager
from app.routes.auth import auth_rout

# Harek Load par aa function execute thase(like.restart par)
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    print("Connection Done ....")
    yield


app = FastAPI(title="Leaning Api building",lifespan=lifespan)


@app.get("/")
async def welcome():
    return "Hello users"

app.include_router(auth_rout,prefix="/auth",tags=["Authetication"])