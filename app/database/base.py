from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.core.config import setting


# Async Engine create kar rahe hain jo PostgreSQL se asynchronous connection establish karega
engine = create_async_engine(setting.DATABASE_URL)

# Declarative Base instance bana rahe hain, jisse hum apne models ko define kar sakte hain
Base = declarative_base()


# Saare tables create karne ke liye function
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # Ye line saare defined models ke liye tables create karti hai

# SessionLocal class create kar rahe hain, jo session manage karega
async_session = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

# Database session ko get karne ke liye function
async def get_db():
    async with async_session() as session:
        yield session  # Ye generator function async session return karta hai



