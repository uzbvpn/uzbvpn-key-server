from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import requests
import secrets
import string
import os

app = FastAPI(title="UzbVpn Key Server")

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_SECRET_KEY") or os.getenv("SUPABASE_KEY")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")


class KeyRequest(BaseModel):
    months: int


def headers():
    return {
        "apikey": SUPABASE_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def generate_key(months):
    chars = string.ascii_uppercase + "23456789"
    a = "".join(secrets.choice(chars) for _ in range(4))
    b = "".join(secrets.choice(chars) for _ in range(4))
    return f"UZB-{months}M-{a}-{b}"


@app.get("/")
def home():
    return {
        "status": "ok",
        "service": "UzbVpn Key Server"
    }


@app.get("/health")
def health():
    if not SUPABASE_URL or not SUPABASE_KEY:
        return {"status": "error", "reason": "Supabase environment variables missing"}
    return {"status": "ok", "supabase": "configured"}


@app.post("/create-key")
def create_key(req: KeyRequest, x_admin_token: str = Header(default="")):
    if not ADMIN_TOKEN or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(403, "Forbidden")

    if req.months not in [1, 3, 6, 12]:
        raise HTTPException(400, "Months must be 1, 3, 6 or 12")

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "Supabase is not configured")

    key = generate_key(req.months)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=req.months * 30)

    data = {
        "key": key,
        "months": req.months,
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "activated": False,
        "device_id": None
    }

    r = requests.post(
        f"{SUPABASE_URL}/rest/v1/keys",
        headers=headers(),
        json=data,
        timeout=15
    )

    if r.status_code >= 400:
        raise HTTPException(500, f"Database error: {r.text}")

    return {
        "key": key,
        "expires_at": expires.isoformat()
    }


@app.post("/check-key")
def check_key(key: str):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(500, "Supabase is not configured")

    r = requests.get(
        f"{SUPABASE_URL}/rest/v1/keys",
        headers=headers(),
        params={
            "key": f"eq.{key}",
            "select": "*"
        },
        timeout=15
    )

    if r.status_code >= 400:
        raise HTTPException(500, f"Database error: {r.text}")

    rows = r.json()

    if not rows:
        raise HTTPException(404, "Key not found")

    item = rows[0]
    expires = datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00"))

    if datetime.now(timezone.utc) >= expires:
        return {
            "valid": False,
            "reason": "expired"
        }

    return {
        "valid": True,
        "months": item["months"],
        "expires_at": item["expires_at"],
        "activated": item.get("activated", False)
    }
