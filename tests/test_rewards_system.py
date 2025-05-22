import asyncio
import json
import unittest
from unittest.mock import patch, MagicMock, mock_open
import os # For setUp and tearDown
from datetime import datetime, timezone # Needed for checking log content if timestamp is dynamic

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature # Should be caught by handler

# Assuming 'Server' can be imported (adjust path if necessary)
# For the purpose of this task, we assume petals.server.server.Server is the correct path
from petals.server.server import Server 
from aiohttp import web # For crafting mock requests

# The logger is defined in petals.server.server, so we patch it there.
# from hivemind.utils.logging import get_logger 

# Helper Utilities
def generate_test_key_pair():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_key_pem

def sign_payload(private_key, payload_dict):
    message_bytes = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

class TestCryptoRewards(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Create a mock Server instance. We don't want to instantiate a real Server.
        # We will attach the methods we want to test to this mock.
        self.server_mock = MagicMock(spec=Server) 
        
        # Configure attributes that the methods might use
        self.server_mock.rewards_log_path = "test_rewards_log.jsonl" 

        # Bind the Server methods to the mock instance.
        # This allows testing the methods as if they were part of a Server instance.
        # The methods are taken directly from the Server class definition.
        self.server_mock._validate_contribution = Server._validate_contribution.__get__(self.server_mock, Server)
        self.server_mock.handle_crypto_reward = Server.handle_crypto_reward.__get__(self.server_mock, Server)
        # handle_hello is not strictly needed if not called, but good for completeness if it were.
        self.server_mock.handle_hello = Server.handle_hello.__get__(self.server_mock, Server)

        self.test_private_key, self.test_public_key_pem = generate_test_key_pair()

        # Clean up log file before each test if it exists
        if os.path.exists(self.server_mock.rewards_log_path):
            os.remove(self.server_mock.rewards_log_path)

    def tearDown(self):
        # Clean up log file after each test
        if os.path.exists(self.server_mock.rewards_log_path):
            os.remove(self.server_mock.rewards_log_path)

    # Tests for _validate_contribution
    @patch('petals.server.server.logger') 
    def test_validate_contribution_valid(self, mock_logger_validate):
        payload = {"gpu_power": 100.5, "block_height": 10}
        pub_key_str = "test_pub_key_pem_str_valid"
        self.assertTrue(self.server_mock._validate_contribution(payload, pub_key_str))
        mock_logger_validate.info.assert_any_call(f"Validating contribution: {payload} for contributor {pub_key_str[:30]}...")
        mock_logger_validate.info.assert_any_call(f"Contribution validated successfully for {pub_key_str[:30]}")

    @patch('petals.server.server.logger')
    def test_validate_contribution_missing_fields(self, mock_logger_validate):
        payload_missing_gpu = {"block_height": 10}
        self.assertFalse(self.server_mock._validate_contribution(payload_missing_gpu, "test_pub_key"))
        mock_logger_validate.warning.assert_called_with("Validation failed: gpu_power or block_height missing from payload.")

        payload_missing_block = {"gpu_power": 100}
        self.assertFalse(self.server_mock._validate_contribution(payload_missing_block, "test_pub_key"))
        mock_logger_validate.warning.assert_called_with("Validation failed: gpu_power or block_height missing from payload.")

    @patch('petals.server.server.logger')
    def test_validate_contribution_invalid_gpu_power(self, mock_logger_validate):
        payload_zero_gpu = {"gpu_power": 0, "block_height": 10}
        self.assertFalse(self.server_mock._validate_contribution(payload_zero_gpu, "test_pub_key"))
        mock_logger_validate.warning.assert_called_with(f"Validation failed: Invalid gpu_power: 0")

        payload_str_gpu = {"gpu_power": "high", "block_height": 10}
        self.assertFalse(self.server_mock._validate_contribution(payload_str_gpu, "test_pub_key"))
        mock_logger_validate.warning.assert_called_with(f"Validation failed: Invalid gpu_power: high")

    @patch('petals.server.server.logger')
    def test_validate_contribution_invalid_block_height(self, mock_logger_validate):
        payload_neg_block = {"gpu_power": 100, "block_height": -1}
        self.assertFalse(self.server_mock._validate_contribution(payload_neg_block, "test_pub_key"))
        mock_logger_validate.warning.assert_called_with(f"Validation failed: Invalid block_height: -1")

        payload_float_block = {"gpu_power": 100, "block_height": 10.5}
        self.assertFalse(self.server_mock._validate_contribution(payload_float_block, "test_pub_key"))
        mock_logger_validate.warning.assert_called_with(f"Validation failed: Invalid block_height: 10.5")

    # Tests for handle_crypto_reward
    @patch('petals.server.server.logger') 
    @patch('builtins.open', new_callable=mock_open)
    async def test_handle_crypto_reward_valid_request(self, mock_file_open, mock_logger_handler):
        payload_data = {"block_height": 10, "gpu_power": 100.0, "other_data": "test"}
        signature_hex = sign_payload(self.test_private_key, payload_data)
        request_data = {
            "payload": payload_data,
            "contributor_public_key_pem_str": self.test_public_key_pem,
            "signature_hex": signature_hex
        }

        mock_request = MagicMock(spec=web.Request)
        # mock_request.json.return_value = asyncio.Future() # Old way
        # mock_request.json.return_value.set_result(request_data) # Old way
        async def mock_json_method(): # New way for async def
            return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)


        # For this specific test, we assume _validate_contribution passes.
        # We are not re-testing _validate_contribution's internal logic here.
        self.server_mock._validate_contribution = MagicMock(return_value=True) 
            
        response = await self.server_mock.handle_crypto_reward(mock_request)

        self.assertEqual(response.status, 200)
        self.assertEqual(response.text, "Reward request received, signature and contribution validated")
        
        # Check file logging
        mock_file_open.assert_called_once_with(self.server_mock.rewards_log_path, 'a')
        handle = mock_file_open() # Get the mock file handle
        
        # Construct expected log entry (timestamp is dynamic, so we can't match exactly)
        # We check that json.dumps was called with the correct structure
        args_list = handle.write.call_args_list
        self.assertTrue(len(args_list) > 0)
        written_content_json = args_list[0][0][0].strip() # Get the first arg of the first call to write()
        written_data = json.loads(written_content_json)
        
        self.assertEqual(written_data["contributor_id"], self.test_public_key_pem)
        self.assertEqual(written_data["reward_payload"], payload_data)
        self.assertEqual(written_data["status"], "pending_payment")
        self.assertTrue("timestamp" in written_data)

        mock_logger_handler.info.assert_any_call(f"Received and validated crypto reward request: {payload_data} from {self.test_public_key_pem[:30]}...")
        self.server_mock._validate_contribution.assert_called_once_with(payload_data, self.test_public_key_pem)


    @patch('petals.server.server.logger')
    async def test_handle_crypto_reward_invalid_json_body(self, mock_logger_handler):
        mock_request = MagicMock(spec=web.Request)
        mock_request.json = MagicMock(side_effect=json.JSONDecodeError("mock error", "doc", 0))
        
        response = await self.server_mock.handle_crypto_reward(mock_request)
        self.assertEqual(response.status, 400)
        self.assertTrue("Invalid JSON" in response.text)
        mock_logger_handler.warning.assert_called_once_with("Failed to decode JSON body: mock error: line 1 column 1 (char 0)")

    @patch('petals.server.server.logger')
    async def test_handle_crypto_reward_missing_payload_field(self, mock_logger_handler):
        request_data = {
            # "payload": {"block_height": 10, "gpu_power": 100}, # Missing
            "contributor_public_key_pem_str": self.test_public_key_pem,
            "signature_hex": "dummy_sig"
        }
        mock_request = MagicMock(spec=web.Request)
        async def mock_json_method(): return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)

        response = await self.server_mock.handle_crypto_reward(mock_request)
        self.assertEqual(response.status, 400)
        self.assertTrue("Missing required fields: payload" in response.text)

    @patch('petals.server.server.logger')
    async def test_handle_crypto_reward_missing_pubkey_field(self, mock_logger_handler):
        request_data = {
            "payload": {"block_height": 10, "gpu_power": 100},
            # "contributor_public_key_pem_str": self.test_public_key_pem, # Missing
            "signature_hex": "dummy_sig"
        }
        mock_request = MagicMock(spec=web.Request)
        async def mock_json_method(): return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)
        response = await self.server_mock.handle_crypto_reward(mock_request)
        self.assertEqual(response.status, 400)
        self.assertTrue("Missing required fields: contributor_public_key_pem_str" in response.text)

    @patch('petals.server.server.logger')
    async def test_handle_crypto_reward_missing_signature_field(self, mock_logger_handler):
        request_data = {
            "payload": {"block_height": 10, "gpu_power": 100},
            "contributor_public_key_pem_str": self.test_public_key_pem,
            # "signature_hex": "dummy_sig" # Missing
        }
        mock_request = MagicMock(spec=web.Request)
        async def mock_json_method(): return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)
        response = await self.server_mock.handle_crypto_reward(mock_request)
        self.assertEqual(response.status, 400)
        self.assertTrue("Missing required fields: signature_hex" in response.text)

    @patch('petals.server.server.logger')
    async def test_handle_crypto_reward_bad_public_key_format(self, mock_logger_handler):
        payload_data = {"block_height": 10, "gpu_power": 100}
        signature_hex = sign_payload(self.test_private_key, payload_data)
        request_data = {
            "payload": payload_data,
            "contributor_public_key_pem_str": "THIS IS NOT A VALID PEM KEY",
            "signature_hex": signature_hex 
        }
        mock_request = MagicMock(spec=web.Request)
        async def mock_json_method(): return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)
        response = await self.server_mock.handle_crypto_reward(mock_request)
        self.assertEqual(response.status, 400)
        self.assertTrue("Invalid public key format" in response.text)

    @patch('petals.server.server.logger')
    async def test_handle_crypto_reward_invalid_signature(self, mock_logger_handler):
        payload_data = {"block_height": 10, "gpu_power": 100}
        # Sign with one key
        signature_hex = sign_payload(self.test_private_key, payload_data)
        
        # But present a different public key (or a tampered signature)
        other_private_key, other_public_key_pem = generate_test_key_pair()

        request_data = {
            "payload": payload_data,
            "contributor_public_key_pem_str": other_public_key_pem, # Key mismatch
            "signature_hex": signature_hex 
        }
        mock_request = MagicMock(spec=web.Request)
        async def mock_json_method(): return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)
        response = await self.server_mock.handle_crypto_reward(mock_request)
        self.assertEqual(response.status, 401)
        self.assertEqual(response.text, "Invalid signature")
    
    @patch('petals.server.server.logger')
    @patch('builtins.open', new_callable=mock_open) # Mock open as it might be called before validation fail
    async def test_handle_crypto_reward_contribution_validation_fails(self, mock_file_open, mock_logger_handler):
        payload_data = {"block_height": -5, "gpu_power": 0} # Invalid payload for _validate_contribution
        signature_hex = sign_payload(self.test_private_key, payload_data)
        request_data = {
            "payload": payload_data,
            "contributor_public_key_pem_str": self.test_public_key_pem,
            "signature_hex": signature_hex
        }

        mock_request = MagicMock(spec=web.Request)
        async def mock_json_method(): return request_data
        mock_request.json = MagicMock(side_effect=mock_json_method)

        # Ensure _validate_contribution is called with the real logic for this test
        # by re-assigning the original method that was bound in setUp
        # or by mocking its return value to False.
        self.server_mock._validate_contribution = MagicMock(return_value=False)
            
        response = await self.server_mock.handle_crypto_reward(mock_request)

        self.assertEqual(response.status, 403)
        self.assertEqual(response.text, "Contribution validation failed")
        mock_file_open.assert_not_called() # Log file should not be written to
        self.server_mock._validate_contribution.assert_called_once_with(payload_data, self.test_public_key_pem)

if __name__ == '__main__':
    unittest.main()
```
