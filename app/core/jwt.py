from jose import JWTError, jwt
from datetime import datetime, timedelta
from app.core.config import settings
from enum import Enum

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    
    # Convert any Enum values to strings
    for key, value in to_encode.items():
        if isinstance(value, Enum):
            to_encode[key] = value.value

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None
