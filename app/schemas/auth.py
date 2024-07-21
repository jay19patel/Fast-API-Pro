from pydantic import BaseModel,EmailStr

class RegistrationSchema(BaseModel):
    name : str
    email : EmailStr
    password : str  


class LoginSchema(BaseModel):
    email : EmailStr
    password : str

