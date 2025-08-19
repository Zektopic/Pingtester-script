import unittest
import subprocess
from unittest.mock import patch, MagicMock
from testping1 import is_reachable

class TestIsReachable(unittest.TestCase):

    @patch('testping1.subprocess.Popen')
    def test_is_reachable_success(self, mock_popen):
        """Test is_reachable returns True for a successful ping."""
        mock_process = MagicMock()
        # Simulate a successful ping response containing "bytes from"
        mock_process.communicate.return_value = (b'64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.063 ms', b'')
        mock_popen.return_value = mock_process

        self.assertTrue(is_reachable('127.0.0.1'))

    @patch('testping1.subprocess.Popen')
    def test_is_reachable_failure(self, mock_popen):
        """Test is_reachable returns False for a failed ping."""
        mock_process = MagicMock()
        # Simulate a failed ping response
        mock_process.communicate.return_value = (b'Request timed out.', b'')
        mock_popen.return_value = mock_process

        self.assertFalse(is_reachable('10.0.0.1'))

    @patch('testping1.subprocess.Popen')
    def test_is_reachable_calls_ping_correctly(self, mock_popen):
        """Test is_reachable calls the ping command with correct arguments."""
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'', b'')
        mock_popen.return_value = mock_process

        is_reachable('192.168.1.1', timeout=5)
        # Verify that subprocess.Popen was called with the correct arguments, including the timeout
        mock_popen.assert_called_once_with(
            ['ping', '-c', '1', '-W', '5', '192.168.1.1'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

if __name__ == '__main__':
    unittest.main()
