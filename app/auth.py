import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Cookie, HTTPException, Request, Response
from jose import JWTError, jwt

from .config import get_config

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = timedelta(minutes=15)
REFRESH_TOKEN_EXPIRE = timedelta(days=7)

# Rate limiting: {ip: [(timestamp, ...)] }
_login_attempts: dict[str, list[float]] = defaultdict(list)


def _secret() -> str:
    return get_config()["server"]["secret_key"]


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def create_token(subject: str, token_type: str = "access") -> str:
    expire = ACCESS_TOKEN_EXPIRE if token_type == "access" else REFRESH_TOKEN_EXPIRE
    payload = {
        "sub": subject,
        "type": token_type,
        "exp": datetime.now(timezone.utc) + expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, _secret(), algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _secret(), algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def check_rate_limit(ip: str) -> None:
    cfg = get_config()["auth"]
    limit = cfg.get("rate_limit_attempts", 5)
    window = cfg.get("rate_limit_window", 60)

    now = time.time()
    # Prune old attempts
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < window]
    if len(_login_attempts[ip]) >= limit:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")


def record_attempt(ip: str) -> None:
    _login_attempts[ip].append(time.time())


def check_ip_whitelist(request: Request) -> None:
    whitelist = get_config()["auth"].get("ip_whitelist", [])
    if whitelist:
        client_ip = request.client.host if request.client else "unknown"
        if client_ip not in whitelist:
            raise HTTPException(status_code=403, detail="IP not whitelisted")


def authenticate(request: Request) -> dict:
    """Validate JWT from cookie. Returns decoded payload."""
    check_ip_whitelist(request)
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload
