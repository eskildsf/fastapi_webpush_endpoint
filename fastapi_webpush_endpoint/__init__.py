"Subscribe to Web Push notifications and receive them in FastAPI."
__version__ = "0.0.1"

from typing import Literal, Annotated, Optional
import re
import base64
import os
from enum import IntEnum
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from pydantic import BaseModel, AnyHttpUrl
from fastapi import Request, Response, Header
import jwt
import http_ece


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
    Class to hold error which may arise when decoding and decrypting message.
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
    timestamp: Optional[int] = None
    title: Optional[str] = None
    vibrate: Optional[list[int]] = None

    def model_dump(self, *args, **kwargs):
        kwargs.pop('exclude_none', None)
        return super().model_dump(*args, exclude_none=True, **kwargs)


class WebPushProtocolResponse(BaseModel):
    """
    https://web.dev/articles/push-notifications-web-push-protocol#more_headers
    """
    ttl: int
    topic: Optional[str]
    urgency: Optional[Literal["very-low", "low", "normal", "high"]]
    notification: BaseModel | str

    def as_response(self):
        return Response("Created", status_code=NotificationStatusCodes.CREATED)


class NotificationEndpoint:
    def __init__(
            self,
            endpoint: AnyHttpUrl | str,
            auth_secret: Optional[bytes] = None,
            max_message_size: int = 4096,
            notification_content_class: Optional[type[BaseModel]] = None,
            include_port_in_aud: bool = True):
        # Check init parameters
        if max_message_size < 4096:
            raise ValueError(
                "A notification service must support a message size of at least 4096 bytes."
                "https://datatracker.ietf.org/doc/html/draft-ietf-webpush-protocol-10#section-7.2"
            )
        self.max_message_size = max_message_size
        self.endpoint = endpoint if isinstance(endpoint, AnyHttpUrl) else AnyHttpUrl(endpoint)
        if not self.endpoint.scheme:
            raise ValueError("endpoint must include url scheme.")
        self.aud = f"{self.endpoint.scheme}://{self.endpoint.host}:{self.endpoint.port}" \
                   if include_port_in_aud else \
                   f"{self.endpoint.scheme}://{self.endpoint.host}"
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
            endpoint=self.endpoint,
            keys=WebPushKeys(
                auth=base64.urlsafe_b64encode(self.auth_secret).decode("utf-8"),
                p256dh=base64.urlsafe_b64encode(dh).decode("utf-8"),
            )
        ).model_dump_json()
