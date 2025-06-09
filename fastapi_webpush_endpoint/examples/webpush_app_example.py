import asyncio
import uvicorn
from typing import Annotated
from pathlib import Path
import uuid
import json
import os

import httpx
from fastapi import FastAPI, Response, BackgroundTasks, Cookie
from webpush import WebPush, WebPushSubscription

app = FastAPI()
key_directory = os.path.dirname(__file__)
wp = WebPush(
    private_key=Path(os.path.join(key_directory, "private_key.pem")),
    public_key=Path(os.path.join(key_directory, "public_key.pem")),
    subscriber="me@gmail.com",
    ttl=30,
)
# Map session ID to Web Push Subscription
subscriptions: dict[str, WebPushSubscription] = {}


@app.post("/web-app/subscribe", tags=["Web App Backend"])
async def subscribe_user(
        subscription: WebPushSubscription,
        response: Response):
    """
    Register notification service

    Typically, this endpoint would be called by a browser vendor
    notification service (Google, Apple, Mozilla).
    We notify the user by sending messages to this service.
    """
    id = str(uuid.uuid4())
    response.set_cookie(key="session", value=id)
    subscriptions[id] = subscription
    return {"status": "Subscription OK"}


@app.get("/web-app/notify", tags=["Web App Backend"])
async def notify(
        session: Annotated[str, Cookie()],
        background_tasks: BackgroundTasks):
    """
    Notify user
    """
    # Check that user is subscribed
    assert session in subscriptions
    subscription = subscriptions[session]
    # Encrypt message before sending
    message = wp.get(
        message=json.dumps(dict(
            title="Notification Title",
            body="Notification Body",
        )),
        subscription=subscription,
    )
    # Publish message to notification endpoint
    background_tasks.add_task(
        httpx.post,
        url=str(subscription.endpoint),
        content=message.encrypted,
        headers=message.headers,  # type: ignore
    )
    return {"status": "Notification OK"}


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
