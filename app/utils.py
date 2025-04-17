from passlib.context import CryptContext
from datetime import timedelta, datetime, timezone
from jose import JWTError, jwt

from fastapi import Request, HTTPException, Depends

from app.dependencies import db_dep
from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
SECRET_KEY = "void@pointer"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 1800


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: float = None):
    """
    Creates a new JWT access token for an authenticated user.
    """
    delta = timedelta(minutes=expires_delta) if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire_time = datetime.now(timezone.utc) + delta
    data.update({"exp": expire_time})

    token = jwt.encode(
        data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )
    return token


def get_current_user(
    request: Request,
    db: db_dep
) -> User:
    auth_header = request.headers.get("Authorization")
    is_bearer = auth_header.startswith("Bearer ") if auth_header else False
    token = auth_header.split(" ")[1] if auth_header else ""

    if not auth_header or not is_bearer:
        raise HTTPException(
            status_code=401,
            detail="You are not authenticated."
        )

    try:
        decoded_jwt = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = decoded_jwt.get("username")
        if not username:
            raise HTTPException(
                status_code=401,
                detail="Token is invalid or missing username."
            )

        db_user = db.query(User).filter(User.username == username).first()
        if not db_user:
            raise HTTPException(
                status_code=404,
                detail="User not found."
            )

        return db_user

    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token."
        )


def get_admin_user(
    user: User = Depends(get_current_user)
):
    if not user.is_staff:
        raise HTTPException(
            status_code=403,
            detail="You do not have admin privileges."
        )

    return user
