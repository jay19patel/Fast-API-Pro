from app.database.base import Base
from sqlalchemy import Column,Integer,String,DateTime,func

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True) 
    name = Column(String, index=True)
    email = Column(String, unique=True, index=True,nullable=False) 
    password = Column(String) 
    created_datetime = Column(DateTime(timezone=True), server_default=func.now())
    modified_datetime = Column(DateTime(timezone=True), nullable=True, default=None, onupdate=func.now())

class JWTTokenBlockList(Base):
    __tablename__ ="jwt_token_block_list"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True,nullable=False)
    created_datetime = Column(DateTime(timezone=True), server_default=func.now())

