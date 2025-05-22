# Crypto Reward System

## 1. Overview

The Petals Crypto Reward System is designed to enable contributors to be recognized and eventually rewarded for providing their computing power to the network. In its current phase, the system focuses on securely logging validated contributions. These logs serve as a basis for future payment distribution, which is handled externally to the server's direct operation at this stage.

The core of the system is an HTTP endpoint where contributors can submit proof of their work, signed cryptographically to ensure authenticity.

## 2. Enabling the Reward System

By default, the crypto reward system and its associated HTTP endpoint are disabled. To enable it, use the following command-line flag when starting the Petals server:

*   `--enable-rewards`

Alternatively, you can set the environment variable:

*   `PETALS_ENABLE_REWARDS=true`

If this flag is not set, the HTTP server for rewards will not start, and the `/crypto_rewards` endpoint will not be available.

## 3. Configuration Parameters

The reward system can be configured using the following parameters:

*   **HTTP Server Port:**
    *   CLI: `--http-port <port_number>`
    *   Env: `PETALS_HTTP_PORT=<port_number>`
    *   Default: `8081`
    *   Description: Specifies the port on which the HTTP server for the reward system will listen. Ensure this port is accessible to contributors who need to submit reward requests.

*   **Rewards Log Path:**
    *   CLI: `--rewards-log-path <path_to_file>`
    *   Env: `PETALS_REWARDS_LOG_PATH=<path_to_file>`
    *   Default: `rewards_log.jsonl`
    *   Description: The file path where validated reward requests will be logged in JSON Lines format. The server process must have write permissions to this path.

## 4. Sending Reward Requests (Client-Side Guide)

Contributors need to send an HTTP POST request to the server to submit their contribution details.

*   **Endpoint:** `POST /crypto_rewards`
*   **Headers:**
    *   `Content-Type: application/json`

*   **Request Body (JSON Structure):**
    The body of the POST request must be a JSON object with the following structure:

    ```json
    {
      "payload": {
        "block_height": 123,
        "gpu_power": 100.5,
        // ... any other relevant metrics defining the contribution ...
        "timestamp_utc": "2023-10-27T10:30:00.123456Z", // Example: Client-generated UTC timestamp
        "nonce": "unique_string_or_number_for_this_request" // Example: Client-generated unique identifier
      },
      "contributor_public_key_pem_str": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE...\n-----END PUBLIC KEY-----",
      "signature_hex": "3045022100..."
    }
    ```
    *   **`payload` (object):** Contains the actual data defining the contribution.
        *   `block_height` (integer, example): The block number or a similar identifier related to the work done.
        *   `gpu_power` (number, example): A measure of GPU power contributed (e.g., TFLOPs, tasks completed).
        *   **Note:** The `payload` should also include fields to prevent replay attacks, such as a client-generated UTC timestamp (`timestamp_utc`) and a unique nonce (`nonce`). The server may enforce checks on these.
    *   **`contributor_public_key_pem_str` (string):** The contributor's ECDSA public key (using the SECP256K1 curve), encoded in PEM format. This key will be used to verify the signature.
    *   **`signature_hex` (string):** The hex-encoded ECDSA signature of the canonical JSON representation of the `payload` object.

*   **Signature Generation:**
    1.  **Key Pair:** The contributor must have an ECDSA key pair. The **SECP256K1** curve is expected.
    2.  **Message Construction (Canonical JSON):** The message to be signed is the `payload` object serialized into a JSON string. **Crucially, the keys within the `payload` object must be sorted alphabetically before serialization.** This ensures a consistent byte string for signature generation and verification.
        *   Example in Python: `json.dumps(payload, sort_keys=True).encode('utf-8')`
    3.  **Signing:** The UTF-8 encoded byte string of the canonical JSON payload is then signed using the contributor's private key. The hashing algorithm used for the signature must be **SHA256**.
    4.  **Encoding:** The resulting signature should be encoded into a hexadecimal string.

## 5. Server Response

*   **`200 OK`:** If the request is valid, the signature is verified, and the contribution data passes basic validation, the server responds with a 200 OK status and a text message like `"Reward request received, signature and contribution validated"`. The contribution is then logged.
*   **`400 Bad Request`:** Returned for issues like:
    *   Invalid JSON in the request body.
    *   Missing required fields (`payload`, `contributor_public_key_pem_str`, `signature_hex`).
    *   Malformed public key PEM string.
    *   Malformed hex signature.
*   **`401 Unauthorized`:** Returned if the signature verification fails (i.e., the signature does not match the payload and public key).
*   **`403 Forbidden`:** Returned if the signature is valid, but the content of the `payload` fails server-side contribution validation rules (e.g., invalid `gpu_power` or `block_height`).
*   **`500 Internal Server Error`:** Returned for unexpected errors on the server side.

## 6. Rewards Log (`rewards_log.jsonl`)

When a reward request is successfully validated (both signature and contribution data), an entry is appended to the rewards log file specified by `--rewards-log-path` (default: `rewards_log.jsonl`).

The file is in **JSON Lines (JSONL)** format, meaning each line is a valid JSON object.

*   **Log Entry Structure:**
    ```json
    {"timestamp": "YYYY-MM-DDTHH:MM:SS.ffffffZ", "contributor_id": "PEM_PUBLIC_KEY_STRING", "reward_payload": {"block_height": ..., "gpu_power": ..., ...}, "status": "pending_payment"}
    ```
    *   `timestamp`: An ISO 8601 UTC timestamp indicating when the server processed and logged the record.
    *   `contributor_id`: The PEM-encoded public key string of the contributor, taken from the request.
    *   `reward_payload`: The exact `payload` dictionary submitted by the contributor.
    *   `status`: Currently always `"pending_payment"`, indicating that this record is awaiting external processing for actual reward distribution.

## 7. Security

Security is paramount for a system handling rewards. Please refer to **`SECURITY_CRYPTO_REWARDS.md`** (or the main `SECURITY.md` if integrated there) for detailed information on:
*   Contributor authentication and identity.
*   Contribution validation processes.
*   API endpoint protection.
*   Private key management best practices (though the server doesn't handle payout keys directly).
*   Rewards log integrity.
*   Preventing replay attacks.

It is crucial to understand these aspects before deploying or interacting with the reward system.

## 8. Example Client Code Snippet (Python)

The following Python snippet demonstrates how a client might construct and send a reward request. This is a conceptual example and requires the `requests` and `cryptography` libraries.

```python
import json
import requests # type: ignore
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# --- Configuration (Client-Side) ---
PETALS_SERVER_URL = "http://localhost:8081" # Replace with the actual server URL

# **Important: Securely load or generate your private key.**
# This is just a placeholder for key loading.
# Ensure your key is an ECDSA key using the SECP256K1 curve.
try:
    # Example: Load from a PEM file (replace with your actual key loading)
    with open("contributor_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # Or your password if the key is encrypted
            backend=default_backend()
        )
except FileNotFoundError:
    print("Error: Private key file not found. Please generate or specify the correct path.")
    exit()
except Exception as e:
    print(f"Error loading private key: {e}")
    exit()

# Derive the public key in PEM format
public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# --- Constructing the Request ---
reward_payload = {
    "block_height": 42,
    "gpu_power": 150.75,
    "task_type": "inference_tokens",
    "num_tokens": 10240,
    "timestamp_utc": datetime.now(timezone.utc).isoformat(), # Important for replay prevention
    "nonce": os.urandom(16).hex() # Important for replay prevention
}

# 1. Create the canonical JSON string from the payload
message_to_sign_bytes = json.dumps(reward_payload, sort_keys=True).encode('utf-8')

# 2. Sign the message (SHA256 is used by default with ECDSA in many high-level APIs,
#    but explicitly defining it is good practice with cryptography library)
signature = private_key.sign(
    message_to_sign_bytes,
    ec.ECDSA(hashes.SHA256())
)

# 3. Convert signature to hex
signature_hex = signature.hex()

# 4. Prepare the full request body
request_body = {
    "payload": reward_payload,
    "contributor_public_key_pem_str": public_key_pem,
    "signature_hex": signature_hex
}

# --- Sending the Request ---
print(f"Sending request to: {PETALS_SERVER_URL}/crypto_rewards")
print(f"Request body: {json.dumps(request_body, indent=2)}")

try:
    response = requests.post(
        f"{PETALS_SERVER_URL}/crypto_rewards",
        json=request_body, # requests library handles JSON serialization and Content-Type header
        headers={"Content-Type": "application/json"} # Explicitly set, though `json=` often suffices
    )
    print(f"\n--- Response ---")
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"Error sending request: {e}")

```
**Note on Example Client:** The Python example includes placeholders for loading a private key and demonstrates adding `timestamp_utc` and `nonce` to the payload, which are good practices for preventing replay attacks. Real-world client implementations should ensure robust key management and error handling.
```
