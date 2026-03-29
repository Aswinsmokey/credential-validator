from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

ws_router = APIRouter()


class WebSocketManager:
    def __init__(self) -> None:
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, message: dict) -> None:
        dead: list[WebSocket] = []
        for ws in list(self.connections):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


# Single global instance shared across routes and tasks
ws_manager = WebSocketManager()


@ws_router.websocket("/ws/live")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws_manager.connect(ws)
    try:
        while True:
            # Keep alive — client may send abort/pause commands
            data = await ws.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)
    except Exception:
        ws_manager.disconnect(ws)
