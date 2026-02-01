import asyncio
import aiohttp
import json
import sys

async def test_api_endpoints():
    """Test the REST API endpoints"""
    base_url = "http://localhost:8000/api/v1"
    
    async with aiohttp.ClientSession() as session:
        print("Testing CloudSentry API...\n")
        
        # Test 1: Health check
        print("1. Testing health check...")
        async with session.get(f"{base_url}/health/detailed") as response:
            if response.status == 200:
                data = await response.json()
                print(f"   ✓ Health: {data['status']}")
                print(f"   Database: {data['components']['database']}")
                print(f"   Findings count: {data['counts']['findings']}")
            else:
                print(f"   ✗ Health check failed: {response.status}")
        
        # Test 2: Get findings
        print("\n2. Testing findings endpoint...")
        async with session.get(f"{base_url}/findings?limit=5") as response:
            if response.status == 200:
                findings = await response.json()
                print(f"   ✓ Found {len(findings)} findings")
                for finding in findings[:3]:  # Show first 3
                    print(f"   - {finding['rule_id']}: {finding['resource_id']} ({finding['severity']})")
            else:
                print(f"   ✗ Findings endpoint failed: {response.status}")
        
        # Test 3: Get rules
        print("\n3. Testing rules endpoint...")
        async with session.get(f"{base_url}/rules") as response:
            if response.status == 200:
                rules = await response.json()
                print(f"   ✓ Found {len(rules)} rules")
                for rule in rules:
                    print(f"   - {rule['id']}: {rule['description']} ({rule['severity']})")
            else:
                print(f"   ✗ Rules endpoint failed: {response.status}")
        
        # Test 4: Get summary
        print("\n4. Testing summary endpoint...")
        async with session.get(f"{base_url}/findings/stats/summary?time_range=24h") as response:
            if response.status == 200:
                summary = await response.json()
                print(f"   ✓ Summary loaded")
                print(f"   Total findings: {summary['total']}")
                print(f"   By severity: {summary['by_severity']}")
            else:
                print(f"   ✗ Summary endpoint failed: {response.status}")
        
        # Test 5: Trigger audit
        print("\n5. Testing audit trigger...")
        async with session.post(f"{base_url}/audits/trigger?audit_type=full") as response:
            if response.status == 200:
                result = await response.json()
                print(f"   ✓ Audit triggered: {result['message']}")
                print(f"   Audit ID: {result['audit_id']}")
            else:
                print(f"   ✗ Audit trigger failed: {response.status}")
        
        print("\nAll tests completed!")

async def test_websocket():
    """Test WebSocket connection"""
    print("\nTesting WebSocket connection...")
    
    try:
        import websockets
        uri = "ws://localhost:8000/ws"
        
        async with websockets.connect(uri) as websocket:
            print("   ✓ WebSocket connected")
            
            # Send ping
            await websocket.send(json.dumps({"type": "ping"}))
            response = await websocket.recv()
            print(f"   ✓ Ping response: {response}")
            
            # Wait for a few seconds for any real-time messages
            print("   Waiting for real-time findings (10 seconds)...")
            try:
                async for _ in range(10):
                    message = await asyncio.wait_for(websocket.recv(), timeout=1)
                    print(f"   Real-time message: {message}")
            except asyncio.TimeoutError:
                print("   No real-time messages received (expected in test)")
                
    except Exception as e:
        print(f"   ✗ WebSocket test failed: {e}")

if __name__ == "__main__":
    print("CloudSentry API Tests")
    print("=" * 50)
    
    # Run async tests
    asyncio.run(test_api_endpoints())
    asyncio.run(test_websocket())
