import os
import time
import hmac
import hashlib
import base64
import sqlite3
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

VERIFY_SECRET = os.getenv("VERIFY_SECRET", "BbVerify_7xP9mK2vR8qL5nW4zT6h").strip()
DB_PATH = os.getenv("VERIFY_DB_PATH", "verification_status.db")

app = FastAPI(title="Bitcoinbb Verification API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)


def db():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS completed_sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            completed_at INTEGER NOT NULL
        )""")


def validate_token(token: str, expected_user_id: Optional[int] = None):
    if not VERIFY_SECRET:
        raise HTTPException(status_code=503, detail="VERIFY_SECRET is not configured on backend")
    try:
        padded = token + ("=" * (-len(token) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode()).decode()
        user_text, expires_text, nonce, signature = decoded.split(":", 3)
        user_id = int(user_text)
        expires = int(expires_text)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verification token")

    payload = f"{user_id}:{expires}:{nonce}"
    expected_signature = hmac.new(VERIFY_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=403, detail="Invalid token signature")
    if expires < int(time.time()):
        raise HTTPException(status_code=410, detail="Verification session expired; reopen the link from the bot")
    if expected_user_id is not None and user_id != int(expected_user_id):
        raise HTTPException(status_code=403, detail="User ID does not match signed session")
    return user_id, expires


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class CompleteRequest(BaseModel):
    user_id: int
    token: str


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def root():
    return {"service": "Bitcoinbb Verification API", "status": "online"}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/api/complete")
def complete(body: CompleteRequest):
    user_id, _ = validate_token(body.token, body.user_id)
    digest = token_hash(body.token)
    with db() as con:
        con.execute(
            "INSERT OR IGNORE INTO completed_sessions(token_hash,user_id,completed_at) VALUES(?,?,?)",
            (digest, user_id, int(time.time())),
        )
    return {"verified": True, "user_id": user_id}


@app.get("/api/status")
def status(token: str = Query(..., min_length=20)):
    user_id, _ = validate_token(token)
    with db() as con:
        row = con.execute("SELECT 1 FROM completed_sessions WHERE token_hash=? AND user_id=?", (token_hash(token), user_id)).fetchone()
    return {"verified": bool(row), "user_id": user_id}
