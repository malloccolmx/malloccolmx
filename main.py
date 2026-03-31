import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from motor.motor_asyncio import AsyncIOMotorClient
from jose import JWTError, jwt
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Configuration  (replace the dummy values before deploying)
# ---------------------------------------------------------------------------

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://dummy_user:dummy_pass@localhost:27017/dummy_db?authSource=admin",
)
MONGO_DB = os.getenv("MONGO_DB", "dummy_db")

# Secret key used to sign JWTs.  Override via environment variable.
# WARNING: if JWT_SECRET is not set, a random key is generated on every startup
# which will invalidate all previously issued tokens on restart.
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
if not os.getenv("JWT_SECRET"):
    import warnings
    warnings.warn(
        "JWT_SECRET env var is not set. A random key will be generated on "
        "every startup, invalidating all previously issued tokens.",
        stacklevel=1,
    )
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 1

# ---------------------------------------------------------------------------
# App + DB setup
# ---------------------------------------------------------------------------

_mongo_client: AsyncIOMotorClient | None = None


def get_db():
    if _mongo_client is None:
        raise RuntimeError("MongoDB client is not initialised")
    return _mongo_client[MONGO_DB]


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _mongo_client
    _mongo_client = AsyncIOMotorClient(MONGO_URI)
    yield
    if _mongo_client is not None:
        _mongo_client.close()


app = FastAPI(title="WhoAmI API", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

bearer_scheme = HTTPBearer()


def create_access_token(subject: str, expires_delta: timedelta) -> tuple[str, datetime]:
    """Return (encoded_jwt, expire_datetime_utc)."""
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {"sub": subject, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expire


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> str:
    """Validate Bearer JWT and return the subject claim."""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        subject: str | None = payload.get("sub")
        if subject is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return subject
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class WhoAmIRequest(BaseModel):
    mail: str
    access_key: str


class WhoAmIResponse(BaseModel):
    JWT_ACE: str
    date: str  # ISO 8601 expiry date


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/whoami", response_model=WhoAmIResponse)
async def post_whoami(body: WhoAmIRequest):
    """
    Authenticate by mail + access_key.

    Looks up the most recent active user document in the ``users`` collection
    (sort _id DESC, project mail / status / _id only).  If found, returns a
    JWT and its ISO 8601 expiry timestamp (+1 hour from now).
    """
    db = get_db()
    user = await db["users"].find_one(
        {"mail": body.mail, "status": "active"},
        sort=[("_id", -1)],
        projection={"_id": 1, "mail": 1, "status": 1},
    )
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # TODO: validate body.access_key against the stored credential for this user.

    token, expire_dt = create_access_token(
        subject=body.mail,
        expires_delta=timedelta(hours=JWT_EXPIRE_HOURS),
    )

    return WhoAmIResponse(
        JWT_ACE=token,
        date=expire_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


@app.get("/whoami/{anonmail}")
async def get_whoami(
    anonmail: str,
    _subject: str = Depends(verify_token),
):
    """
    JWT-protected endpoint.  Returns a stub version/variant map for *anonmail*.
    Logic will be filled in later; for now always returns the fixed test payload.
    """
    return {
        "testv1-11.14.151241.1a": {
            "var": "var-1a",
            "name": "name-1a",
        }
    }
