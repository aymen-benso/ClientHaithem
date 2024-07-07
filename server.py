from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import asyncio

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            data = pd.read_csv('./flow.csv').to_dict(orient='records')
            await websocket.send_json(data)
            await asyncio.sleep(1)  # Adjust the interval as needed
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await websocket.close()

@app.get("/")
def read_root():
    data = pd.read_csv('./flow.csv').to_dict(orient='records')
    return data

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
