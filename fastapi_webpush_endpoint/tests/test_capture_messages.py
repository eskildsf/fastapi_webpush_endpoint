import unittest
import asyncio
import uvicorn

import httpx

from fastapi_webpush_endpoint import CaptureNotifications
from fastapi_webpush_endpoint.examples.webpush_app_example import app as web_app


class TestUnittestIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_capture_messages_start_uvicorn(self):
        # Run FastAPI in concurrent task
        config = uvicorn.Config(
            web_app,
            host="127.0.0.1",
            port=5000,
        )
        self.server = uvicorn.Server(config)
        self._server_task = asyncio.create_task(self.server.serve())

        async with CaptureNotifications(
                subscription_url="http://127.0.0.1:5000/web-app/subscribe") as captured:
            async with httpx.AsyncClient(cookies=captured.subscription_response.cookies) as client:
                # Trigger notification from web app
                await client.get("http://127.0.0.1:5000/web-app/notify")
            await self.server.shutdown()
        self.assertEqual(len(captured.notifications), 1)

    async def test_capture_messages_pass_fastapi(self):
        async with CaptureNotifications(
                subscription_url="http://127.0.0.1:5000/web-app/subscribe",
                fastapi_app=web_app) as captured:
            async with httpx.AsyncClient(cookies=captured.subscription_response.cookies) as client:
                # Trigger notification from web app
                await client.get("http://127.0.0.1:5000/web-app/notify")
        self.assertEqual(len(captured.notifications), 1)


if __name__ == "__main__":
    unittest.main()
