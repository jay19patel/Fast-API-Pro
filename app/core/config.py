from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL:str
    SECRET_KEY:str
    JWT_ALGORITHM:str
    ACCESS_TOKEN_EXPIRY_MINUTES:int
    REFRESH_TOKEN_EXPIRY_DAY:int
    REDIS_HOST: int
    REDIS_HOST:str
    REDIS_JTI_EXPIRY:int
    
    class Config:
        env_file = ".env"

setting = Settings()
