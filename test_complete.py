import asyncio
import aiohttp
import json
import sys
import time

async def test_complete_system():
    """Test the complete CloudSentry system"""
    
    print("Testing Complete CloudSentry System")
    print("=" * 50)
    
    base_url = "http://localhost:8000"
    api_url = f"{base_url}/api/v1"
    
    async with aiohttp.ClientSession() as session:
        # 1. Test health
        print("\n1. Testing system health...")
        async with session.get(f"{api_url}/health/detailed") as response:
            health = await response.json()
            print(f"   Status: {health.get('status')}")
            print(f"   Database: {health.get('components', {}).get('database')}")
        
        # 2. Trigger test events
        print("\n2. Triggering test events...")
        async with session.post(f"{base_url}/trigger-test") as response:
            if response.status == 200:
                print("   ✓ Test events triggered")
            else:
                print("   ✗ Failed to trigger test events")
        
        # Wait for processing
        print("   Waiting for event processing...")
        await asyncio.sleep(5)
        
        # 3. Check findings
        print("\n3. Checking findings...")
        async with session.get(f"{api_url}/findings?limit=5") as response:
            findings = await response.json()
            print(f"   Found {len(findings)} findings")
            for finding in findings:
                print(f"   - {finding['rule_id']}: {finding['resource_id']} ({finding['severity']})")
        
        # 4. Check rules
        print("\n4. Checking rules...")
        async with session.get(f"{api_url}/rules") as response:
            rules = await response.json()
            print(f"   Found {len(rules)} rules")
        
        # 5. Trigger manual audit
        print("\n5. Triggering manual audit...")
        async with session.post(f"{api_url}/audits/trigger?audit_type=full") as response:
            audit = await response.json()
            print(f"   ✓ Audit triggered: {audit.get('message')}")
            print(f"   Audit ID: {audit.get('audit_id')}")
        
        # 6. Check dashboard
        print("\n6. Checking dashboard...")
        print(f"   Dashboard URL: http://localhost:3000")
        print(f"   API URL: {api_url}")
        print(f"   WebSocket URL: ws://localhost:8000/ws")
        
        print("\n✅ System test completed!")
        print("\nNext steps:")
        print("1. Open http://localhost:3000 in your browser")
        print("2. Check for real-time findings in the dashboard")
        print("3. Review audit history in the API")
        print("4. Test WebSocket connection for real-time updates")

if __name__ == "__main__":
    asyncio.run(test_complete_system())
