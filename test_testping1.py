import unittest
import subprocess
from unittest.mock import patch, MagicMock
from testping1 import is_reachable

class TestIsReachable(unittest.TestCase):

    @patch('testping1.subprocess.call')
    def test_is_reachable_success(self, mock_call):
        """Test is_reachable returns True for a successful ping."""
        # Simulate a successful ping response by returning 0
        mock_call.return_value = 0

        self.assertTrue(is_reachable('127.0.0.1'))

    @patch('testping1.subprocess.call')
    def test_is_reachable_failure(self, mock_call):
        """Test is_reachable returns False for a failed ping."""
        # Simulate a failed ping response by returning a non-zero exit code
        mock_call.return_value = 1

        self.assertFalse(is_reachable('10.0.0.1'))

    @patch('testping1.subprocess.call')
    def test_is_reachable_invalid_ip_format(self, mock_call):
        """Test is_reachable returns False and does not call subprocess for invalid IP."""
        self.assertFalse(is_reachable('invalid_ip'))
        mock_call.assert_not_called()

    @patch('testping1.subprocess.call')
    def test_is_reachable_ip_length_limit(self, mock_call):
        """Test is_reachable enforces length limit on IP addresses."""
        long_ip = "1" * 101
        self.assertFalse(is_reachable(long_ip))
        mock_call.assert_not_called()

    @patch('testping1.subprocess.call')
    def test_is_reachable_argument_injection(self, mock_call):
        """Test is_reachable prevents argument injection by rejecting invalid IPs."""
        self.assertFalse(is_reachable('-h'))
        mock_call.assert_not_called()
        self.assertFalse(is_reachable('192.168.1.1; rm -rf /'))
        mock_call.assert_not_called()

    @patch('testping1.subprocess.call')
    def test_is_reachable_invalid_timeout(self, mock_call):
        """Test is_reachable rejects invalid timeout values."""
        self.assertFalse(is_reachable('192.168.1.1', timeout='-h'))
        mock_call.assert_not_called()
        self.assertFalse(is_reachable('192.168.1.1', timeout='1; ls'))
        mock_call.assert_not_called()
        self.assertFalse(is_reachable('192.168.1.1', timeout=-1))
        mock_call.assert_not_called()
        self.assertFalse(is_reachable('192.168.1.1', timeout=0))
        mock_call.assert_not_called()
        self.assertFalse(is_reachable('192.168.1.1', timeout=None))
        mock_call.assert_not_called()
        # 🛡️ Sentinel: Test resource exhaustion prevention
        self.assertFalse(is_reachable('192.168.1.1', timeout=101))
        mock_call.assert_not_called()

    @patch('testping1.subprocess.call')
    def test_is_reachable_secure_error_handling(self, mock_call):
        """Test is_reachable handles OSError securely without leaking exceptions."""
        mock_call.side_effect = FileNotFoundError("No such file or directory: 'ping'")
        with self.assertLogs(level='ERROR') as log:
            self.assertFalse(is_reachable('127.0.0.1'))
            self.assertIn("Failed to execute ping command safely.", log.output[0])
            self.assertNotIn("FileNotFoundError", log.output[0])

    @patch('testping1.subprocess.call')
    def test_is_reachable_prevents_log_injection(self, mock_call):
        """Test is_reachable escapes user input to prevent log injection (CRLF)."""
        malicious_ip = "127.0.0.1\nERROR:root:System Compromised"

        with self.assertLogs(level='ERROR') as log:
            self.assertFalse(is_reachable(malicious_ip))
            # Verify the newline character is escaped using repr() instead of evaluated
            self.assertIn(r"Invalid IP address format: '127.0.0.1\nERROR:root:System Compromised'", log.output[0])
            self.assertNotIn("\nERROR:root:System Compromised", log.output[0])

        malicious_timeout = "1\nERROR:root:System Compromised"
        with self.assertLogs(level='ERROR') as log:
            self.assertFalse(is_reachable('192.168.1.1', timeout=malicious_timeout))
            self.assertIn(r"Invalid timeout value: '1\nERROR:root:System Compromised'", log.output[0])
            self.assertNotIn("\nERROR:root:System Compromised", log.output[0])

    @patch('testping1.subprocess.call')
    def test_is_reachable_subprocess_timeout(self, mock_call):
        """Test is_reachable handles subprocess.TimeoutExpired securely."""
        mock_call.side_effect = subprocess.TimeoutExpired(cmd='ping', timeout=7)
        with self.assertLogs(level='ERROR') as log:
            self.assertFalse(is_reachable('127.0.0.1', timeout=5))
            self.assertIn("Ping command timed out unexpectedly.", log.output[0])
            self.assertNotIn("TimeoutExpired", log.output[0])

    @patch('testping1.subprocess.call')
    def test_is_reachable_calls_ping_correctly(self, mock_call):
        """Test is_reachable calls the ping command with correct arguments."""
        mock_call.return_value = 0

        is_reachable('192.168.1.1', timeout=5)
        # Verify that subprocess.call was called with the correct arguments, including the timeout
        mock_call.assert_called_once_with(
            ['ping', '-c', '1', '-W', '5', '192.168.1.1'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=7
        )

if __name__ == '__main__':
    unittest.main()
