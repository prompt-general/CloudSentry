import asyncio
from app.database import AsyncSessionLocal
from app.models import Finding

async def test_db():
    async with AsyncSessionLocal() as session:
        result = await session.execute("SELECT version()")
        version = result.scalar()
        print(f"PostgreSQL version: {version}")
        
        # Test finding count
        result = await session.execute("SELECT COUNT(*) FROM findings")
        count = result.scalar()
        print(f"Findings count: {count}")

if __name__ == "__main__":
    asyncio.run(test_db())
