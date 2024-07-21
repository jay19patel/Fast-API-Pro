from fastapi import APIRouter, Depends, HTTPException, status,FastAPI
from sqlalchemy.exc import IntegrityError
from sqlalchemy.future import select
from app.database.base import AsyncSession, get_db
from app.schemas.auth import RegistrationSchema, LoginSchema
from app.models.user import User
from app.core.security import generate_hash_password, check_hash_password,create_access_token,decode_token,add_jti_to_blocklist
from datetime import datetime ,timedelta
from app.core.config import setting
from typing import Annotated
auth_rout = APIRouter()


@auth_rout.post("/registration",status_code=status.HTTP_201_CREATED)
async def registration(request:RegistrationSchema,db:AsyncSession=Depends(get_db)):
    hashed_password = generate_hash_password(password=request.password)
    try:
        # incoming data no use kari ne object banava mate
        register_user = User(name=request.name,email=request.email,password=hashed_password)
        # User ne db session ma add karva mate
        await db.add(register_user)
        # Changes ne commit karva mate
        await db.commit()  
        return {
            "message":"Registration successful",
            "payload":{"user_id": register_user.id},
        }

    except IntegrityError : 
        await db.rollback()
        raise HTTPException(detail=f"Email alredy exist",status_code=status.HTTP_400_BAD_REQUEST)
    

@auth_rout.post("/login",status_code=status.HTTP_202_ACCEPTED)
async def login(request:LoginSchema,db:AsyncSession=Depends(get_db)):
    user = await db.execute(select(User).where(User.email==request.email))
    user = user.scalars().first()
    if not user:
        raise HTTPException(detail=f"User not found",status_code=status.HTTP_404_NOT_FOUND)
    
    if not check_hash_password(password=request.password,hashed_password=user.password):
        raise HTTPException(detail=f"Invalid password",status_code=status.HTTP_400_BAD_REQUEST)
    
    access_token = create_access_token(payload={"userEmail":user.email,"userId":user.id},expiry=timedelta(minutes=setting.ACCESS_TOKEN_EXPIRY_MINUTES),tokenType="Access")
    refresh_token =create_access_token(payload={"userEmail":user.email,"userId":user.id},expiry=timedelta(days=setting.REFRESH_TOKEN_EXPIRY_DAY),tokenType="Refresh")

    return {"message":"Login successful",
            "payload":{"user_id": user.id,
                       "access_token":access_token,
                       "refresh_token":refresh_token
                       }
            }

@auth_rout.post("/token_decode",status_code=status.HTTP_200_OK)
async def TokenDecode(token:str):
    return decode_token(token=token)


from app.core.security import RefreshTokenBearer,AccessTokenBearer

@auth_rout.get("/refresh_token",status_code=status.HTTP_201_CREATED)
async def create_new_access_token(user_data:dict = Depends(RefreshTokenBearer())):

    if datetime.fromtimestamp(user_data["exp"])> datetime.now():
        access_token = create_access_token(payload={"userEmail":user_data["userEmail"],"userId":user_data["userId"]},expiry=timedelta(minutes=setting.ACCESS_TOKEN_EXPIRY_MINUTES),tokenType="Access") 
        return {"message":"Access token generated",
                "access_token":access_token,
                }
  
@auth_rout.get("/private_page",status_code=status.HTTP_201_CREATED)
async def private_page(user_data:dict = Depends(AccessTokenBearer())):
    return {
        "msg":"Welcome",
        "data":user_data
    }

@auth_rout.get('/logout',status_code=status.HTTP_200_OK)
async def revoke_token(token_details:dict=Depends(AccessTokenBearer())):

    jti = token_details['jti']

    await add_jti_to_blocklist(jti)

    return {
            "message":"Logged Out Successfully"
            }