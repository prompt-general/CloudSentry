import asyncio
import asyncpg  # Using asyncpg directly instead of SQLAlchemy

async def test_db():
    try:
        # Connect to PostgreSQL
        conn = await asyncpg.connect(
            host="localhost",
            port=5432,
            user="cloudsentry",
            password="changeme",
            database="cloudsentry"
        )
        
        # Test connection
        version = await conn.fetchval("SELECT version()")
        print(f"PostgreSQL version: {version}")
        
        # Test finding count
        count = await conn.fetchval("SELECT COUNT(*) FROM findings")
        print(f"Findings count: {count}")
        
        # Test rules count
        rules_count = await conn.fetchval("SELECT COUNT(*) FROM rules")
        print(f"Rules count: {rules_count}")
        
        await conn.close()
        print("Database connection test successful!")
        
    except Exception as e:
        print(f"Database connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_db())
