import asyncio
import uvicorn
from typing import Annotated

from fastapi import FastAPI, Depends

from fastapi_webpush_endpoint import (
    NotificationEndpoint,
    WebPushProtocolResponse,
    WebPushProtocolException,
)

notification_endpoint = NotificationEndpoint(
    "http://127.0.0.1:5000/notification-endpoint/",  # URL of endpoint handling Web Push notifications
)
NotificationProtocolResponseType = Annotated[
    WebPushProtocolResponse | WebPushProtocolException,
    Depends(notification_endpoint)
]

app = FastAPI()


@app.post("/notification-endpoint/")
async def receive_notification(
        message: NotificationProtocolResponseType):
    if isinstance(message, WebPushProtocolResponse):
        print(message)
    return message.as_response()


async def main():
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=5000,
    )
    server = uvicorn.Server(config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
