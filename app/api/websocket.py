from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import HTMLResponse
import json
import logging
import asyncio
from typing import Dict, List
import aioredis

from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()

class ConnectionManager:
    """Manage WebSocket connections"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.redis = None
        self.settings = get_settings()
    
    async def connect_redis(self):
        """Connect to Redis for pub/sub"""
        if not self.redis:
            self.redis = await aioredis.from_url(
                self.settings.redis_url,
                decode_responses=True
            )
            logger.info("WebSocket manager connected to Redis")
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"New WebSocket connection. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove disconnected WebSocket"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific WebSocket connection"""
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending message to WebSocket: {e}")
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected WebSockets"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    async def subscribe_to_findings(self):
        """Subscribe to Redis channel for new findings"""
        await self.connect_redis()
        
        pubsub = self.redis.pubsub()
        await pubsub.subscribe('cloudsentry:findings')
        
        logger.info("Subscribed to findings channel")
        
        try:
            async for message in pubsub.listen():
                if message['type'] == 'message':
                    finding_data = message['data']
                    await self.broadcast(finding_data)
                    
        except Exception as e:
            logger.error(f"Error in Redis subscription: {e}")
            # Reconnect on error
            await asyncio.sleep(5)
            await self.subscribe_to_findings()


# Global connection manager
manager = ConnectionManager()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time findings
    """
    await manager.connect(websocket)
    
    try:
        # Send welcome message
        welcome_message = {
            "type": "system",
            "message": "Connected to CloudSentry real-time findings",
            "timestamp": "2024-01-15T00:00:00Z"  # TODO: Use actual timestamp
        }
        await manager.send_personal_message(json.dumps(welcome_message), websocket)
        
        # Keep connection alive
        while True:
            # Wait for client message (ping or commands)
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                
                # Handle client commands
                if message.get("type") == "ping":
                    response = {
                        "type": "pong",
                        "timestamp": "2024-01-15T00:00:00Z"
                    }
                    await manager.send_personal_message(json.dumps(response), websocket)
                    
                elif message.get("type") == "subscribe":
                    # Handle subscription requests
                    subscriptions = message.get("subscriptions", [])
                    response = {
                        "type": "subscription_ack",
                        "subscriptions": subscriptions,
                        "timestamp": "2024-01-15T00:00:00Z"
                    }
                    await manager.send_personal_message(json.dumps(response), websocket)
                    
            except json.JSONDecodeError:
                # Not JSON, just echo back
                await manager.send_personal_message(f"Echo: {data}", websocket)
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@router.get("/ws-test")
async def websocket_test_page():
    """
    Test page for WebSocket connections
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CloudSentry WebSocket Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            #messages { 
                border: 1px solid #ccc; 
                padding: 10px; 
                height: 300px; 
                overflow-y: auto;
                margin-bottom: 10px;
            }
            .finding { 
                background: #f0f0f0; 
                padding: 5px; 
                margin: 5px 0; 
                border-radius: 3px;
            }
            .critical { border-left: 4px solid #ff0000; }
            .high { border-left: 4px solid #ff6600; }
            .medium { border-left: 4px solid #ffcc00; }
            .low { border-left: 4px solid #00cc00; }
        </style>
    </head>
    <body>
        <h1>CloudSentry Real-time Findings Test</h1>
        <div id="status">Connecting...</div>
        <div id="messages"></div>
        <button onclick="sendPing()">Send Ping</button>
        <button onclick="clearMessages()">Clear</button>
        
        <script>
            let ws;
            const messagesDiv = document.getElementById('messages');
            const statusDiv = document.getElementById('status');
            
            function connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = `${protocol}//${window.location.host}/ws`;
                
                ws = new WebSocket(wsUrl);
                
                ws.onopen = function() {
                    statusDiv.innerHTML = '<span style="color: green">Connected</span>';
                    logMessage('Connected to CloudSentry WebSocket');
                };
                
                ws.onmessage = function(event) {
                    try {
                        const data = JSON.parse(event.data);
                        handleMessage(data);
                    } catch (e) {
                        logMessage(`Raw: ${event.data}`);
                    }
                };
                
                ws.onerror = function(error) {
                    statusDiv.innerHTML = '<span style="color: red">Connection Error</span>';
                    logMessage(`Error: ${error}`);
                };
                
                ws.onclose = function() {
                    statusDiv.innerHTML = '<span style="color: orange">Disconnected</span>';
                    logMessage('Disconnected from server');
                    // Attempt to reconnect after 5 seconds
                    setTimeout(connectWebSocket, 5000);
                };
            }
            
            function handleMessage(data) {
                if (data.type === 'system') {
                    logMessage(`System: ${data.message}`);
                } else if (data.type === 'pong') {
                    logMessage('Received pong from server');
                } else if (data.type === 'subscription_ack') {
                    logMessage(`Subscribed to: ${data.subscriptions.join(', ')}`);
                } else if (data.rule_id) {
                    // This is a finding
                    const severityClass = data.severity ? data.severity.toLowerCase() : 'unknown';
                    const message = `
                        <div class="finding ${severityClass}">
                            <strong>${data.rule_id}</strong>: ${data.resource_id}<br>
                            Severity: ${data.severity} | Resource: ${data.resource_type}<br>
                            Account: ${data.account_id} | Region: ${data.region}
                        </div>
                    `;
                    messagesDiv.innerHTML = message + messagesDiv.innerHTML;
                } else {
                    logMessage(JSON.stringify(data));
                }
            }
            
            function sendPing() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ type: 'ping' }));
                    logMessage('Sent ping to server');
                }
            }
            
            function sendSubscribe() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ 
                        type: 'subscribe', 
                        subscriptions: ['findings', 'events'] 
                    }));
                    logMessage('Sent subscription request');
                }
            }
            
            function logMessage(message) {
                const timestamp = new Date().toLocaleTimeString();
                messagesDiv.innerHTML += `<div>[${timestamp}] ${message}</div>`;
                messagesDiv.scrollTop = messagesDiv.scrollHeight;
            }
            
            function clearMessages() {
                messagesDiv.innerHTML = '';
            }
            
            // Connect on page load
            connectWebSocket();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)


# Background task for Redis subscription
async def start_websocket_manager():
    """Start the WebSocket manager in the background"""
    try:
        # Start Redis subscription in background
        asyncio.create_task(manager.subscribe_to_findings())
        logger.info("WebSocket manager started")
    except Exception as e:
        logger.error(f"Error starting WebSocket manager: {e}")