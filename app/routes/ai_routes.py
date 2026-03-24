import time
import requests
from fastapi import APIRouter, HTTPException

from app.schemas.ai import RegisterRequest, PredictRequest
from app.services.ai_service import (
    get_ai_url, set_ai_url, get_status,
    forward_predict, check_ai_alive
)
from app.core.config import settings

router = APIRouter()


@router.post("/register-ai")
def register_ai(body: RegisterRequest):
    if body.secret != settings.REGISTER_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    if not body.ai_url.startswith("https://"):
        raise HTTPException(status_code=422, detail="ai_url must be https")

    set_ai_url(body.ai_url)
    return {"status": "registered", "ai_url": body.ai_url}


@router.post("/predict")
def predict(req: PredictRequest):
    ai_url = get_ai_url()

    if not ai_url:
        raise HTTPException(status_code=503, detail="AI not registered")

    try:
        resp = forward_predict(ai_url, req.reactant, req.reagent)
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="AI unreachable")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="AI timeout")

    if resp.status_code == 422:
        raise HTTPException(status_code=422, detail=resp.json().get("detail"))

    if not resp.ok:
        raise HTTPException(status_code=502, detail="AI error")

    return resp.json()


@router.get("/health")
def health():
    ai_url, last_seen = get_status()
    age = round(time.time() - last_seen) if last_seen else None

    return {
        "status": "ok",
        "ai_server_url": ai_url or "not registered",
        "ai_registered": bool(ai_url),
        "ai_last_seen_sec": age,
    }


@router.get("/status")
def status():
    ai_url, last_seen = get_status()

    if not ai_url:
        return {"message": "Waiting for AI server..."}

    alive = check_ai_alive(ai_url)

    return {
        "app_server": "online",
        "ai_server": "online" if alive else "unreachable",
        "ai_url": ai_url,
        "ai_last_seen_sec": round(time.time() - last_seen) if last_seen else None,
    }
