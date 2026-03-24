import threading
import time
import requests

_state_lock = threading.Lock()
_ai_url: str = ""
_ai_last_seen: float = 0

def get_ai_url():
    with _state_lock:
        return _ai_url

def set_ai_url(url: str):
    global _ai_url, _ai_last_seen
    with _state_lock:
        _ai_url = url.rstrip("/")
        _ai_last_seen = time.time()

def get_status():
    return _ai_url, _ai_last_seen


def forward_predict(ai_url, reactant, reagent):
    return requests.post(
        f"{ai_url}/predict",
        json={"reactant": reactant, "reagent": reagent},
        timeout=30,
    )


def check_ai_alive(ai_url):
    try:
        resp = requests.get(f"{ai_url}/health", timeout=5)
        return resp.ok
    except:
        return False
