from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
import json
import secrets
import string
import os

app = FastAPI(title="UzbVpn Key Server")

DB = "key-server/keys.json"


class KeyRequest(BaseModel):
    months: int


def load_keys():
    if not os.path.exists(DB) or os.path.getsize(DB) == 0:
        return {}
    with open(DB, "r") as f:
        return json.load(f)


def save_keys(data):
    with open(DB, "w") as f:
        json.dump(data, f, indent=2)


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


@app.post("/create-key")
def create_key(req: KeyRequest):
    if req.months not in [1, 3, 6, 12]:
        raise HTTPException(400, "Months must be 1, 3, 6 or 12")

    keys = load_keys()

    while True:
        key = generate_key(req.months)
        if key not in keys:
            break

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=req.months * 30)

    keys[key] = {
        "months": req.months,
        "created_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "activated": False,
        "device_id": None
    }

    save_keys(keys)

    return {
        "key": key,
        "expires_at": expires.isoformat()
    }


@app.post("/check-key")
def check_key(key: str):
    keys = load_keys()

    if key not in keys:
        raise HTTPException(404, "Key not found")

    item = keys[key]
    expires = datetime.fromisoformat(item["expires_at"])

    if datetime.now(timezone.utc) >= expires:
        return {
            "valid": False,
            "reason": "expired"
        }

    return {
        "valid": True,
        "months": item["months"],
        "expires_at": item["expires_at"],
        "activated": item["activated"]
    }
