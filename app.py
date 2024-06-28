import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sec import PacketSniffer  # Assuming srp.py is in the same directory

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

sniffer = PacketSniffer()

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_data(self, data: str):
        for connection in self.active_connections:
            await connection.send_text(data)

manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(1)
            # Send the flow information to the WebSocket client
            for flow_id, flow_data in sniffer.flows.items():
                await websocket.send_text(json.dumps(flow_data))
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Function to run the packet sniffer in the background
async def run_sniffer():
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, sniffer.capture_packets)

# Run the sniffer as a background task when the application starts
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(run_sniffer())

@app.get("/")
def read_root():
    return {"Hello": "World"}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
