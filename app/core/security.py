from fastapi import Request,HTTPException,status
import jwt 
import bcrypt
from datetime import timedelta,datetime,timezone
from app.core.config import setting
import uuid

def generate_hash_password(password :str):
    hash_password = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(hash_password, salt)
    return hashed_password.decode('utf-8')

def check_hash_password(password:str,hashed_password:str):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(payload:dict,expiry:timedelta=None,tokenType:str="Access"):
    payload = payload.copy()
    payload['exp'] = datetime.now(timezone.utc) + expiry
    # payload['iat'] = datetime.now()
    payload['token_type'] = tokenType
    payload['jti']=str(uuid.uuid4())
    token =jwt.encode(payload, setting.SECRET_KEY, algorithm=setting.JWT_ALGORITHM)
    return token

def decode_token(token:str):
    try:
        payload = jwt.decode(token, setting.SECRET_KEY, algorithms=setting.JWT_ALGORITHM)
        return payload  
    except jwt.PyJWTError as e:
        return None


from fastapi.security.http import HTTPBearer,HTTPAuthorizationCredentials

class TokenBearer(HTTPBearer):

    def __init__(self, auto_error=True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials | None:
        creds = await super().__call__(request)

        token = creds.credentials

        token_data = decode_token(token)

        if not self.token_valid(token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail={
                    "error":"This token is invalid or expired",
                    "resolution":"Please get new token"
                }
            )

        if await token_in_blocklist(token_data['jti']):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail={
                    "error":"This token is invalid or has been revoked",
                    "resolution":"Please get new token"
                }
            )

        self.verify_token_data(token_data)


        return token_data

    def token_valid(self, token: str) -> bool:

        token_data = decode_token(token)

        return token_data is not None 

    def verify_token_data(self, token_data):
        raise NotImplementedError("Please Override this method in child classes")


class AccessTokenBearer(TokenBearer):

    def verify_token_data(self, token_data: dict) -> None:
        if token_data and token_data["token_type"] !="Access":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide an access token",
            )
        if datetime.fromtimestamp(token_data["exp"])< datetime.now():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Token expired",

            )


class RefreshTokenBearer(TokenBearer):
    def verify_token_data(self, token_data: dict) -> None:
        if token_data and token_data["token_type"] !="Refresh":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Please provide a refresh token",
            )
        if datetime.fromtimestamp(token_data["exp"])< datetime.now():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Refresh Token expired"
            )



from app.models.user import JWTTokenBlockList
from app.database.base import AsyncSession,get_db
from sqlalchemy.future import select
async def add_jti_to_blocklist(jti: str) -> None:
    async for session in get_db():
        try:
            blocklist = JWTTokenBlockList(jti=jti)
            session.add(blocklist)
            await session.commit()
        finally:
            await session.close()  # Ensure the session is closed properly

async def token_in_blocklist(jti: str) -> bool:
    async for session in get_db():
        try:
            result = await session.execute(select(JWTTokenBlockList).where(JWTTokenBlockList.jti == jti))
            jti_data = result.scalars().first()
        finally:
            await session.close()  # Ensure the session is closed properly
    return jti_data is not None