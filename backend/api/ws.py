from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
import time
from typing import List
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")

    async def broadcast_telemetry(self, message: dict):
        payload = json.dumps({"type": "telemetry", "data": message})
        await self._broadcast(payload)

    async def broadcast_alert(self, message: dict):
        payload = json.dumps({"type": "alert", "data": message})
        await self._broadcast(payload)

    async def _broadcast(self, message: str):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                dead_connections.append(connection)
        for dead in dead_connections:
            self.disconnect(dead)

manager = ConnectionManager()

@router.websocket("/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Heartbeat handling: Wait for ping, send pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
