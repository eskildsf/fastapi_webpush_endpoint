import unittest
import asyncio

from fastapi_webpush_endpoint.examples import (
    webpush_example,
    pywebpush_example,
)


class TestExamples(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        asyncio.get_running_loop().slow_callback_duration = 0.5

    async def test_webpush(self):
        with self.assertLogs("httpx", level="INFO") as logger:
            await webpush_example.main()
            self.assertIn('POST http://127.0.0.1:5000/notification-endpoint/ "HTTP/1.1 201 Created"', logger.records[-1].message)


class TestPyWebpush(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        asyncio.get_running_loop().slow_callback_duration = 0.5

    async def test_pywebpush(self):
        with self.assertLogs("urllib3", level="DEBUG") as logger:
            await pywebpush_example.main()
            self.assertIn('"POST /notification-endpoint/ HTTP/1.1" 201', logger.records[-1].message)


if __name__ == "__main__":
    unittest.main()
