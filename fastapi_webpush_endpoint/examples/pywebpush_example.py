import asyncio
import uvicorn
from typing import Annotated
import uuid
import json
import os

from fastapi import FastAPI, Response, BackgroundTasks, Cookie, Depends
import aiohttp
from pywebpush import webpush

from fastapi_webpush_endpoint import (
    NotificationEndpoint,
    WebPushProtocolResponse,
    WebPushProtocolException,
    WebPushSubscription,
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
    include_port_in_aud=True,  # pywebpush includes port number in "aud" claim of JWT
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

    # Cast AnyHttpUrl to str
    subscription_dict = subscription.model_dump()
    subscription_dict["endpoint"] = str(subscription_dict["endpoint"])
    # Publish message to notification endpoint
    background_tasks.add_task(
        webpush,
        subscription_info=subscription_dict,
        data=json.dumps(dict(
            title="Notification Title",
            body="Notification Body",
        )),
        vapid_private_key=os.path.join(os.path.dirname(__file__), "private_key.pem"),
        vapid_claims={
            "sub": "mailto:me@gmail.com",
        }
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
    await wait_until_server_ready("http://127.0.0.1:5000")

    # Create unsafe cookie jar because requests are made to ip address
    cookie_jar = aiohttp.CookieJar(unsafe=True)
    # Subscribe to web app and trigger notification
    async with aiohttp.ClientSession(cookie_jar=cookie_jar) as session:
        # Subscribe to notifications from web app
        await session.post(
            "http://127.0.0.1:5000/web-app/subscribe",
            data=notification_endpoint.subscription,
            headers={"Content-Type": "application/json"},
        )
        # Trigger notification from web app
        await session.get(
            "http://127.0.0.1:5000/web-app/notify",
        )
    await notification_received.wait()
    await server.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
