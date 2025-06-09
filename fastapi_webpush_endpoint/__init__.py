"Subscribe to Web Push notifications and receive them in FastAPI."
__version__ = "0.0.1"

import asyncio
from typing import Literal, Annotated, Optional
import re
import base64
import os
from enum import IntEnum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from fastapi import FastAPI, Request, Response, Depends, Header
from pydantic import BaseModel, AnyHttpUrl, NonNegativeInt
import jwt
import http_ece
import uvicorn
import httpx


class WebPushKeys(BaseModel):
    auth: str
    p256dh: str


class WebPushSubscription(BaseModel):
    endpoint: AnyHttpUrl
    keys: WebPushKeys


class NotificationStatusCodes(IntEnum):
    """
    Status codes:
      https://web.dev/articles/push-notifications-web-push-protocol#response_from_push_service
      https://developer.apple.com/documentation/usernotifications/sending-web-push-notifications-in-web-apps-and-browsers#Review-responses-for-push-notification-errors
    """
    CREATED = 201
    TOO_MANY_REQUESTS = 429
    INVALID_REQUEST = 400
    AUTHENTICATION_ERROR = 403
    NOT_FOUND = 404
    INVALID_METHOD = 405
    GONE = 410
    PAYLOAD_SIZE_TOO_LARGE = 413


class WebPushProtocolException(Exception):
    """
    Class to hold exception which may arise when decoding and decrypting WebPush message.
    """
    def __init__(self, message: str, status_code: NotificationStatusCodes):
        self.message = message
        self.status_code = status_code

    def as_response(self) -> Response:
        return Response(content=self.message, status_code=self.status_code)


class WebPushNotificationAction(BaseModel):
    """
    https://notifications.spec.whatwg.org/#dom-notification-actions
    """
    action: str
    title: str
    icon: AnyHttpUrl


class WebPushNotification(BaseModel):
    """
    https://notifications.spec.whatwg.org/#object-members
    """
    actions: Optional[list[WebPushNotificationAction]] = None
    badge: Optional[AnyHttpUrl] = None
    body: Optional[str] = None
    data: Optional[dict[str, str]] = None
    dir: Optional[Literal["auto", "ltr", "rtl"]] = None
    icon: Optional[AnyHttpUrl] = None
    image: Optional[AnyHttpUrl] = None
    lang: Optional[str] = None
    renotify: Optional[bool] = None
    requireInteraction: Optional[bool] = None
    silent: Optional[bool] = None
    tag: Optional[str] = None
    timestamp: Optional[NonNegativeInt] = None
    title: Optional[str] = None
    vibrate: Optional[list[NonNegativeInt]] = None

    def model_dump(self, *args, **kwargs):
        kwargs.pop('exclude_none', None)
        return super().model_dump(*args, exclude_none=True, **kwargs)


class WebPushProtocolResponse(BaseModel):
    """
    https://web.dev/articles/push-notifications-web-push-protocol#more_headers
    """
    ttl: NonNegativeInt
    topic: Optional[str]
    urgency: Optional[Literal["very-low", "low", "normal", "high"]]
    notification: BaseModel | str

    def as_response(self):
        return Response("Created", status_code=NotificationStatusCodes.CREATED)


class NotificationEndpoint:
    def __init__(
            self,
            endpoint_url: AnyHttpUrl | str,
            auth_secret: Optional[bytes] = None,
            max_message_size: int = 4096,
            notification_content_class: Optional[type[BaseModel]] = None,
            include_port_in_aud: bool = True):
        """
        Web Push Endpoint which can receive Web Push messages.

        > notification_endpoint = NotificationEndpoint(
        >     "http://127.0.0.1:5000/notification-endpoint/"
        > )
        > NotificationProtocolResponseType = Annotated[
        >     WebPushProtocolResponse | WebPushProtocolException,
        >     Depends(notification_endpoint)
        > ]
        >
        > app = FastAPI()
        > @app.post("/notification-endpoint/")
        > async def receive_notification(message: NotificationProtocolResponseType):
        >     # Handle 'message'
        >     return message.as_response()
        """
        # Check init parameters
        if max_message_size < 4096:
            raise ValueError(
                "A notification endpoint must support a message size of at least 4096 bytes."
                "https://datatracker.ietf.org/doc/html/draft-ietf-webpush-protocol-10#section-7.2"
            )
        self.max_message_size = max_message_size
        self.endpoint_url = endpoint_url if isinstance(endpoint_url, AnyHttpUrl) else AnyHttpUrl(endpoint_url)
        if not self.endpoint_url.scheme:
            raise ValueError("endpoint must include url scheme.")
        self.aud = f"{self.endpoint_url.scheme}://{self.endpoint_url.host}:{self.endpoint_url.port}" \
                   if include_port_in_aud else \
                   f"{self.endpoint_url.scheme}://{self.endpoint_url.host}"
        if auth_secret is not None and len(auth_secret) != 16:
            raise ValueError("auth_secret must be 16 bytes long.")
        self.auth_secret = auth_secret or os.urandom(16)  # Secret bytes
        self.notification_content_class = notification_content_class

        # Create private key
        self.receive_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    def decode_public_key_from_vapid(self, key: str) -> ec.EllipticCurvePublicKey:
        if (rem := len(key) % 4) != 0:
            key += "=" * (4 - rem)
        public_key_bytes = base64.urlsafe_b64decode(key)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            public_key_bytes
        )
        return public_key

    def check_method(self, request: Request):
        if request.method.lower() != "post":
            raise WebPushProtocolException(
                message=f"Method '{request.method}' isn't POST.",
                status_code=NotificationStatusCodes.INVALID_METHOD,
            )

    def check_message_size(self, encrypted_msg):
        if len(encrypted_msg) > self.max_message_size:
            raise WebPushProtocolException(
                message=f"Payload size too large ({len(encrypted_msg)}>{self.max_message_size}).",
                status_code=NotificationStatusCodes.PAYLOAD_SIZE_TOO_LARGE,
            )

    def check_authorization(self, authorization):
        # Check authorization header
        m = re.match(r"vapid t=(?P<token>.*),\s*k=(?P<public_key>.*)", authorization)
        if not m:
            raise WebPushProtocolException(
                message="Invalid 'Authorization' header. "
                        "Expected format 'vapid t=(token), k=(public_key)'.",
                status_code=NotificationStatusCodes.INVALID_REQUEST,
            )

        # Decode vapid token
        try:
            public_key = self.decode_public_key_from_vapid(m["public_key"])
        except Exception:
            raise WebPushProtocolException(
                message="VAPID token error. Public key cannot be decoded.",
                status_code=NotificationStatusCodes.AUTHENTICATION_ERROR,
            )
        try:
            jwt.decode(
                m["token"].encode("utf-8"),
                key=public_key,
                algorithms=["ES256"],
                audience=self.aud,
            )
        except jwt.PyJWTError as ex:
            raise WebPushProtocolException(
                message="VAPID token error: "+", ".join(ex.args),
                status_code=NotificationStatusCodes.AUTHENTICATION_ERROR,
            )

    def decrypt_message(
            self,
            encrypted_msg: bytes) -> str:
        # Decrypt message
        try:
            return http_ece.decrypt(
                encrypted_msg,
                private_key=self.receive_key,
                auth_secret=self.auth_secret
            ).decode("utf-8")
        except Exception:
            raise WebPushProtocolException(
                message="Unable to decrypt message.",
                status_code=NotificationStatusCodes.INVALID_REQUEST,
            )

    async def __call__(
            self,
            request: Request,
            authorization: Annotated[str, Header()],
            ttl: Annotated[int, Header(gte=0)],
            content_encoding: Annotated[Optional[Literal["aes128gcm"]], Header()] = None,
            topic: Annotated[Optional[str], Header(max_length=32)] = None,
            urgency: Annotated[Optional[Literal["very-low", "low", "normal", "high"]], Header()] = None,):
        """
        Callable dependency for FastAPI endpoint.

        > notification_endpoint = NotificationEndpoint(
        >     "http://127.0.0.1:5000/notification-endpoint/"
        > )
        > NotificationProtocolResponseType = Annotated[
        >     WebPushProtocolResponse | WebPushProtocolException,
        >     Depends(notification_endpoint)
        > ]
        >
        > app = FastAPI()
        > @app.post("/notification-endpoint/")
        > async def receive_notification(message: NotificationProtocolResponseType):
        >     if isinstance(message, WebPushProtocolResponse):
        >         print(message)
        >     return message.as_response()
        """
        encrypted_message = await request.body()
        try:
            self.check_method(request)
            self.check_message_size(encrypted_message)
            self.check_authorization(authorization)
            content = self.decrypt_message(encrypted_message)
            # Attempt to validate model if one is present
            # Otherwise, the decrypted message will be passed
            # on as a string.
            if self.notification_content_class:
                content = self.notification_content_class.model_validate_json(content)
            result = WebPushProtocolResponse(
                ttl=ttl,
                topic=topic,
                urgency=urgency,
                notification=content,
            )
            return result
        except WebPushProtocolException as ex:
            return ex

    @property
    def subscription(self):
        """
        Creates JSON to send to service which will submit messages
        to the NotificationEndpoint.

        > notification_service = NotificationService(
        >     "http://127.0.0.1:8000/notification-service/"
        > )
        > httpx.post(
        >     "http://127.0.0.1:8000/web-app/subscribe",
        >     content=notification_service.listener,
        >     headers={"Content-Type": "application/json"}
        > )
        """
        dh = self.receive_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # Create subscription object
        return WebPushSubscription(
            endpoint=self.endpoint_url,
            keys=WebPushKeys(
                auth=base64.urlsafe_b64encode(self.auth_secret).decode("utf-8"),
                p256dh=base64.urlsafe_b64encode(dh).decode("utf-8"),
            )
        ).model_dump_json()


async def wait_until_server_ready(
        url: Optional[AnyHttpUrl | str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: float = 2.0):
    """
    Convenience function to wait until 'port' on 'host' is
    available to service connections.
    """
    if url is not None:
        assert host is None and port is None, ValueError("'host' and 'port' cannot be provided when 'url' is providede.")
        if isinstance(url, str):
            url = AnyHttpUrl(url)
        assert url.host, ValueError("'url' does not contain a host")
        host = url.host
        port = url.port
    else:
        assert host is not None and port is not None, ValueError("'host' and 'port' must be provided when 'url' is not providede.")

    async def wait_forever_until_server_ready():
        while True:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        host,
                        port,
                    ),
                    timeout=0.1,
                )
                writer.close()
                await writer.wait_closed()
                return
            except (ConnectionError, asyncio.TimeoutError):
                pass
    await asyncio.wait_for(wait_forever_until_server_ready(), timeout=timeout)


class CaptureNotFinished(Exception):
    """
    Exception raised upon access to CaptureNotifications.captured_notifications
    while context manager is not finalized.
    """
    pass


class CapturedNotifications:
    """
    Object to hold response to subscription request
    and list of Web Push notifications received by the
    NotificationEndpoint.

    The list of notifications is incomplete until finalization
    of the NotificationEndpoint server is finished.
    """
    def __init__(self):
        self._subscription_response = None
        self._notifications = None
        self._context_manager_exited = False

    def set_notifications(self, notifications: list[WebPushProtocolResponse | WebPushProtocolException]):
        assert self._notifications is None, ValueError("CaptureNotifications appears to have been reused.")
        self._context_manager_exited = True
        self._notifications = notifications

    def set_subscription_response(self, subscription_response: httpx.Response):
        assert self._subscription_response is None, ValueError("CaptureNotifications appears to have been reused.")
        self._subscription_response = subscription_response

    @property
    def notifications(self) -> list[WebPushProtocolResponse | WebPushProtocolException]:
        if not self._context_manager_exited:
            raise CaptureNotFinished("Notifications cannot be accessed inside the scope of 'async with'")
        assert self._notifications is not None
        return self._notifications

    @property
    def subscription_response(self) -> httpx.Response:
        assert self._subscription_response is not None
        return self._subscription_response


class CaptureNotifications:
    """
    Context manager capturing Web Push notifications
    emitted from web app which receives Web Push
    subscription at 'subscription_url'.

    Arguments to NotificationEndpoint can be supplied:
    'auth_secret', 'notification_content_class' and
    'include_port_in_aud'.

    If a FastAPI object is supplied via 'fastapi_app'
    then it is launched by the context manager. Otherwise
    it is assumed to have been launched elsewhere.

    Potential key word arguments to the httpx.request
    call to the 'subscription_url' can also be supplied.
    """
    def __init__(self,
                 subscription_url: str | AnyHttpUrl,
                 auth_secret: Optional[bytes] = None,
                 max_message_size: int = 4096,
                 notification_content_class: Optional[type[BaseModel]] = None,
                 include_port_in_aud: bool = False,
                 fastapi_app: Optional[FastAPI] = None,
                 **httpx_subscription_parameters):

        # Create instance variables
        self.notifications: list[WebPushProtocolResponse | WebPushProtocolException] = []
        self.app_server: Optional[uvicorn.Server] = None
        self.httpx_subscription_parameters = httpx_subscription_parameters
        self.captured_notifications = CapturedNotifications()

        # Subscription url must specify host and port
        if isinstance(subscription_url, str):
            subscription_url = AnyHttpUrl(subscription_url)
        assert subscription_url.host is not None
        assert subscription_url.port is not None
        assert subscription_url.scheme.lower() == "http"

        # httpx_subscription_parameters cannot specify url or content
        if any(key.lower() == "url" for key in httpx_subscription_parameters.keys()):
            raise ValueError("Url should be specified via 'subscription_url' parameter.")
        if any(key.lower() == "content" for key in httpx_subscription_parameters.keys()):
            raise ValueError("Content cannot be specified. It is provided by the notification endpoint.")

        # Initialize fastapi_app server if fastapi_app is provided
        if fastapi_app is not None:
            self.app_server = self.setup_uvicorn(
                fastapi_app,
                host=subscription_url.host,
                port=subscription_url.port,
            )

        # Set up endpoint on a different port to avoid
        # url collisions
        endpoint_url = AnyHttpUrl.build(
            scheme=subscription_url.scheme,
            host=subscription_url.host,
            port=subscription_url.port+1,
            path="/notification-endpoint/",
        )

        self.notification_endpoint = NotificationEndpoint(
            str(endpoint_url),
            auth_secret=auth_secret,
            max_message_size=max_message_size,
            notification_content_class=notification_content_class,
            include_port_in_aud=include_port_in_aud,
        )

        # Set up webpush app and server
        webpush_app = self.setup_webpush_endpoint_fastapi(endpoint_url)
        self.webpush_server = self.setup_uvicorn(
            webpush_app,
            host=endpoint_url.host,
            port=endpoint_url.port
        )

        # Save urls for later
        self.subscription_url = subscription_url
        self.webpush_endpoint_url = endpoint_url

    def setup_webpush_endpoint_fastapi(self, endpoint_url: AnyHttpUrl):
        assert endpoint_url.path
        # Set up notification endpoint
        app = FastAPI()
        NotificationProtocolResponseType = Annotated[
            WebPushProtocolResponse | WebPushProtocolException,
            Depends(self.notification_endpoint)
        ]

        @app.post(endpoint_url.path)
        async def receive_notification(
                message: NotificationProtocolResponseType):  # type: ignore
            self.notifications.append(message)
            return message.as_response()

        return app

    def setup_uvicorn(self, app, host, port):
        config = uvicorn.Config(
            app,
            host=host,
            port=port,
        )
        return uvicorn.Server(config)

    async def __aenter__(self):
        # Start Uvicorn servers
        self._endpoint_task = asyncio.create_task(self.webpush_server.serve())
        await wait_until_server_ready(url=self.webpush_endpoint_url)
        if self.app_server:
            self._app_task = asyncio.create_task(self.app_server.serve())
            await wait_until_server_ready(url=self.subscription_url)

        # Subscribe to notifications from web app via provided subscription_url
        async with httpx.AsyncClient() as client:
            method = self.httpx_subscription_parameters.pop("method", "POST")
            response = await client.request(
                method=method,
                url=str(self.subscription_url),
                content=self.notification_endpoint.subscription,
                **self.httpx_subscription_parameters,
            )
            self.captured_notifications.set_subscription_response(response)
        return self.captured_notifications

    async def __aexit__(self, exception, value, traceback):
        # Stop Uvicorn servers
        if self.app_server:
            await self.app_server.shutdown()
        await self.webpush_server.shutdown()
        # Finalize captured_notifications
        self.captured_notifications.set_notifications(self.notifications)
