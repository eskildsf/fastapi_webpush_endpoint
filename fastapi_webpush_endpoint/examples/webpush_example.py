import asyncio
import uvicorn
from typing import Annotated
from pathlib import Path
import uuid
import json
import os

from fastapi import FastAPI, Response, BackgroundTasks, Cookie, Depends
import httpx
from webpush import WebPush, WebPushSubscription

from fastapi_webpush_endpoint import (
    NotificationEndpoint,
    WebPushProtocolResponse,
    WebPushProtocolException,
    WebPushNotification,
    wait_until_server_ready,
)

# Flag to indicate that notification endpoint received a notification
notification_received = asyncio.Event()

app = FastAPI()

#
# Notification endpoint
#
notification_endpoint = NotificationEndpoint(
    "http://127.0.0.1:5000/notification-endpoint/",  # URL of endpoint handling Web Push notifications
    notification_content_class=WebPushNotification,  # Web Push notification body must adhere to this model
    include_port_in_aud=False,  # webpush omits port number in "aud" claim of JWT
)
NotificationProtocolResponseType = Annotated[
    WebPushProtocolResponse | WebPushProtocolException,
    Depends(notification_endpoint)
]


@app.post("/notification-endpoint/", tags=["Notification Backend"])
async def receive_notification(
        message: NotificationProtocolResponseType):
    """
    Handle messages sent by web apps
    """
    if isinstance(message, WebPushProtocolResponse):
        print(message)
        notification_received.set()
    return message.as_response()

#
# Web app
#
wp = WebPush(
    private_key=Path(os.path.join(os.path.dirname(__file__), "private_key.pem")),
    public_key=Path(os.path.join(os.path.dirname(__file__), "public_key.pem")),
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
    """
    Start FastAPI providing both web app and notification endpoint.
    Under real circumstances these would be separate.

    Create a subscription and trigger a notification at the
    notification endpoint.
    """
    # Run FastAPI in concurrent task
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=5000,
    )
    server = uvicorn.Server(config)
    asyncio.create_task(server.serve())
    await wait_until_server_ready(url="http://127.0.0.1:5000")

    # Subscribe to web app and trigger notification
    async with httpx.AsyncClient() as client:
        # Subscribe to notifications from web app
        await client.post(
            "http://127.0.0.1:5000/web-app/subscribe",
            content=notification_endpoint.subscription,
            headers={"Content-Type": "application/json"},
        )
        # Trigger notification from web app
        await client.get(
            "http://127.0.0.1:5000/web-app/notify",
        )
    await notification_received.wait()
    await server.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
