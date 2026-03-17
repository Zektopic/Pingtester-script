import unittest
import asyncio
from unittest.mock import patch, AsyncMock
from testping1 import is_reachable

class TestIsReachable(unittest.IsolatedAsyncioTestCase):

    @patch('testping1.asyncio.create_subprocess_exec')
    async def test_is_reachable_success(self, mock_exec):
        """Test is_reachable returns True for a successful ping."""
        # Simulate a successful ping response by returning 0
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        ip, is_success = await is_reachable('127.0.0.1')
        self.assertTrue(is_success)
        self.assertEqual(ip, '127.0.0.1')

    @patch('testping1.asyncio.create_subprocess_exec')
    async def test_is_reachable_failure(self, mock_exec):
        """Test is_reachable returns False for a failed ping."""
        # Simulate a failed ping response by returning a non-zero exit code
        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_exec.return_value = mock_proc

        ip, is_success = await is_reachable('10.0.0.1')
        self.assertFalse(is_success)
        self.assertEqual(ip, '10.0.0.1')

    @patch('testping1.asyncio.create_subprocess_exec')
    async def test_is_reachable_invalid_ip_format(self, mock_exec):
        """Test is_reachable returns False and does not call subprocess for invalid IP."""
        ip, is_success = await is_reachable('invalid_ip')
        self.assertFalse(is_success)
        self.assertEqual(ip, 'invalid_ip')
        mock_exec.assert_not_called()

    @patch('testping1.asyncio.create_subprocess_exec')
    async def test_is_reachable_argument_injection(self, mock_exec):
        """Test is_reachable prevents argument injection by rejecting invalid IPs."""
        ip, is_success = await is_reachable('-h')
        self.assertFalse(is_success)
        mock_exec.assert_not_called()

        ip, is_success = await is_reachable('192.168.1.1; rm -rf /')
        self.assertFalse(is_success)
        mock_exec.assert_not_called()

    @patch('testping1.asyncio.create_subprocess_exec')
    async def test_is_reachable_calls_ping_correctly(self, mock_exec):
        """Test is_reachable calls the ping command with correct arguments."""
        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_exec.return_value = mock_proc

        await is_reachable('192.168.1.1', timeout=5)
        # Verify that asyncio.create_subprocess_exec was called with the correct arguments, including the timeout
        mock_exec.assert_called_once_with(
            'ping', '-c', '1', '-W', '5', '192.168.1.1',
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )

if __name__ == '__main__':
    unittest.main()
