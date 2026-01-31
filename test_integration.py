import asyncio
import sys
sys.path.append('.')  # Add current directory to path

from app.engine.event_ingestor import EventIngestor
from app.engine.rule_engine import RuleEngine

async def test_integration():
    """Test the integrated system"""
    print("Starting CloudSentry integration test...")
    
    # Initialize components
    ingestor = EventIngestor()
    rule_engine = RuleEngine()
    
    # Start with test events
    await ingestor.start('test')
    
    # Wait for processing
    await asyncio.sleep(5)
    
    # Stop
    await ingestor.stop()
    
    print("Integration test completed!")

if __name__ == '__main__':
    asyncio.run(test_integration())
