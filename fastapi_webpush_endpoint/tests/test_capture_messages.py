import unittest
import asyncio
import uvicorn

import httpx

from fastapi_webpush_endpoint import CaptureNotifications, wait_until_server_ready
from fastapi_webpush_endpoint.examples.webpush_app_example import app as webpush_app


class TestUnittestIntegration(unittest.IsolatedAsyncioTestCase):
    """
    Test cases that demonstrate how CaptureNotifications
    can be used as a tool in tests.
    """
    async def asyncSetUp(self) -> None:
        asyncio.get_running_loop().slow_callback_duration = 0.5

    async def test_capture_messages_start_uvicorn(self):
        """
        Capture messages sent by web app started
        outside of CaptureNotifications context manager.
        """
        # Run FastAPI in concurrent task
        config = uvicorn.Config(
            webpush_app,
            host="127.0.0.1",
            port=5000,
        )
        self.server = uvicorn.Server(config)
        self._server_task = asyncio.create_task(self.server.serve())
        await wait_until_server_ready(host="127.0.0.1", port=5000)

        async with CaptureNotifications(
                subscription_url="http://127.0.0.1:5000/web-app/subscribe") as captured:
            async with httpx.AsyncClient(cookies=captured.subscription_response.cookies) as client:
                # Trigger notification from web app
                await client.get("http://127.0.0.1:5000/web-app/notify")
            await self.server.shutdown()
        self.assertEqual(len(captured.notifications), 1)

    async def test_capture_messages_pass_fastapi_instance(self):
        """
        Capture messages sent by web app started
        by CaptureNotifications context manager.
        """
        async with CaptureNotifications(
                subscription_url="http://127.0.0.1:5000/web-app/subscribe",
                fastapi_app=webpush_app) as captured:
            async with httpx.AsyncClient(cookies=captured.subscription_response.cookies) as client:
                # Trigger notification from web app
                await client.get("http://127.0.0.1:5000/web-app/notify")
        self.assertEqual(len(captured.notifications), 1)

    async def test_capture_multiple_messages(self):
        """
        Capture lots ofmessages sent by web app started
        by CaptureNotifications context manager.
        """
        async with CaptureNotifications(
                subscription_url="http://127.0.0.1:5000/web-app/subscribe",
                fastapi_app=webpush_app) as captured:
            async with httpx.AsyncClient(cookies=captured.subscription_response.cookies) as client:
                # Trigger notifications from web app
                gets = [client.get("http://127.0.0.1:5000/web-app/notify") for _ in range(10)]
                await asyncio.gather(*gets)
        self.assertEqual(len(captured.notifications), 10)


if __name__ == "__main__":
    unittest.main()
