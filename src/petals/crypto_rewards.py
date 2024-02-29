import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from petals.utils import hf_auth

# The following environment variables must be set before using this module:
#
# PETALS_CRYPTO_REWARDS_PUBLIC_KEY: The public key used to verify cryptocurrency reward signatures.
# PETALS_CRYPTO_REWARDS_PRIVATE_KEY: The private key used to sign cryptocurrency reward requests.

# Generate a new ECDSA key pair.
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
public_key = private_key.public_key()

# Serialize the public key to a PEM-encoded file.
with open("public_key.pem", "wb") as f:
    f.write(public_key.export_key(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

# Serialize the private key to a PEM-encoded file.
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Load the public key used to verify cryptocurrency reward signatures.
try:
    with open(os.environ["PETALS_CRYPTO_REWARDS_PUBLIC_KEY"], "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), default_backend())
except FileNotFoundError:
    print("Error loading public key from environment variable.")
    exit(1)

# Load the private key used to sign cryptocurrency reward requests.
try:
    with open(os.environ["PETALS_CRYPTO_REWARDS_PRIVATE_KEY"], "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
except FileNotFoundError:
    print("Error loading private key from environment variable.")
    exit(1)

# Create a new HFAuth object.
hf_auth = hf_auth.HFAuth()

# Get the current block height.
block_height = hf_auth.get_block_height()

# Create a new cryptocurrency reward request.
crypto_rewards_request = {
    "block_height": block_height,
    "gpu_power": 100,  # This is just an example. The actual GPU power will need to be measured.
}

# Sign the request.
crypto_rewards_signature = private_key.sign(
    hashes.Hash(hashes.SHA256(), backend=default_backend()).update(json.dumps(crypto_rewards_request).encode("utf-8")),
    ec.ECDSA(ec.SECP256K1()))

# Send the request to the Petals server.
response = hf_auth.send_request(
    "POST",
    "/crypto_rewards",
    json=crypto_rewards_request,
    headers={"Signature": crypto_rewards_signature.hex()}
)

# Check the response.
if response.status_code == 200:
    print("Cryptocurrency reward request sent successfully.")
else:
    print("Error sending cryptocurrency reward request.")
