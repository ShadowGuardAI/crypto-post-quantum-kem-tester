import argparse
import logging
import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import kem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- KEM Implementation (Example: Kyber768) ---
try:
    from cryptography.hazmat.primitives.asymmetric import x25519
except ImportError:
    logging.error("x25519 not available, ensure your cryptography library is up-to-date (>=41.0.0 for OQS KEM support).")
    raise

# Dummy KEM implementation (replace with actual post-quantum KEMs when available)
class DummyKEM:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def encapsulate(self):
        # Generate a random shared secret and ciphertext
        shared_secret = os.urandom(32) # 32 bytes is a common key size
        ciphertext = os.urandom(64) # Simulate an encapsulated ciphertext
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext):
        # Generate a random shared secret (since we don't have a real KEM)
        shared_secret = os.urandom(32)
        return shared_secret
# --- End KEM Implementation ---

def setup_argparse():
    """
    Sets up the command-line argument parser.
    """
    parser = argparse.ArgumentParser(description="Tests the integration and performance of post-quantum KEMs.")
    parser.add_argument("--iterations", type=int, default=10, help="Number of KEM iterations to perform.")
    parser.add_argument("--test_encryption", action="store_true", help="Test encryption/decryption with KEM-derived key.")
    parser.add_argument("--message_size", type=int, default=1024, help="Size of the message to encrypt (bytes), used with --test_encryption.")
    parser.add_argument("--kem_type", type=str, default="DummyKEM", help="Type of KEM to use (e.g., DummyKEM). Replace with actual KEM names when available.")
    parser.add_argument("--cipher", type=str, default="AES256", help="Cipher algorithm for encryption test.")
    parser.add_argument("--public_key_file", type=str, help="File containing the recipient's public key (for offline testing).")
    parser.add_argument("--private_key_file", type=str, help="File containing the recipient's private key (for offline testing).")
    parser.add_argument("--generate_keys", action="store_true", help="Generate a public/private key pair for the specified KEM.")
    return parser.parse_args()


def test_kem_performance(iterations, kem_type):
    """
    Tests the performance of a given KEM through multiple encapsulation/decapsulation cycles.
    """
    try:
        if kem_type == "DummyKEM":
            kem_instance = DummyKEM()  # Instantiate the dummy KEM
        else:
            raise ValueError(f"Unsupported KEM type: {kem_type}")

        start_time = time.time()
        for i in range(iterations):
            ciphertext, shared_secret_encap = kem_instance.encapsulate()
            shared_secret_decap = kem_instance.decapsulate(ciphertext)

            if shared_secret_encap != shared_secret_decap:
                logging.error("Shared secrets do not match after decapsulation!")
                return False

        end_time = time.time()
        duration = end_time - start_time
        logging.info(f"KEM performance test completed in {duration:.4f} seconds for {iterations} iterations.")
        logging.info(f"Average time per iteration: {duration/iterations:.6f} seconds.")
        return True

    except Exception as e:
        logging.error(f"Error during KEM performance test: {e}")
        return False


def derive_key(shared_secret, key_size=32):
    """
    Derives a key from a shared secret using HKDF.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=None,  # Recommended to use a salt
        info=b'KEM-derived key',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


def encrypt_message(message, key):
    """
    Encrypts a message using AES-256-CBC with a KEM-derived key.
    """
    try:
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Prepend IV to the ciphertext
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return None


def decrypt_message(ciphertext, key):
    """
    Decrypts a message encrypted with AES-256-CBC.
    """
    try:
        iv = ciphertext[:16]  # Extract IV from the beginning of the ciphertext
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        return unpadded_data
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return None


def test_encryption_decryption(kem_type, message_size, cipher_type):
    """
    Tests KEM integration with encryption/decryption using a derived key.
    """
    try:
        if kem_type == "DummyKEM":
            kem_instance = DummyKEM()
        else:
            raise ValueError(f"Unsupported KEM type: {kem_type}")

        ciphertext_kem, shared_secret = kem_instance.encapsulate()
        derived_key = derive_key(shared_secret)

        message = os.urandom(message_size)
        encrypted_message = encrypt_message(message, derived_key)

        if encrypted_message is None:
            logging.error("Encryption failed.")
            return False

        shared_secret_decapsulated = kem_instance.decapsulate(ciphertext_kem)
        derived_key_decapsulated = derive_key(shared_secret_decapsulated)

        decrypted_message = decrypt_message(encrypted_message, derived_key_decapsulated)

        if decrypted_message is None:
            logging.error("Decryption failed.")
            return False

        if message != decrypted_message:
            logging.error("Decrypted message does not match original message!")
            return False

        logging.info("Encryption/Decryption test successful.")
        return True

    except Exception as e:
        logging.error(f"Error during encryption/decryption test: {e}")
        return False

def generate_key_pair(kem_type, public_key_file, private_key_file):
    """
    Generates a public/private key pair for the specified KEM.
    """
    try:
        if kem_type == "DummyKEM":
            kem_instance = DummyKEM()
            public_key = kem_instance.public_key
            private_key = kem_instance.private_key

            # Serialize the keys.  Note: For real KEMs, use the appropriate serialization format.
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )


        else:
            raise ValueError(f"Unsupported KEM type: {kem_type}")
        
        with open(public_key_file, "wb") as f:
            f.write(public_key_pem)

        with open(private_key_file, "wb") as f:
            f.write(private_key_pem)

        logging.info(f"Key pair generated successfully.")
        logging.info(f"Public key saved to: {public_key_file}")
        logging.info(f"Private key saved to: {private_key_file}")

    except Exception as e:
        logging.error(f"Error generating key pair: {e}")


def main():
    """
    Main function to execute the KEM tester.
    """
    args = setup_argparse()

    if args.generate_keys:
        if not args.public_key_file or not args.private_key_file:
            logging.error("--public_key_file and --private_key_file must be specified with --generate_keys.")
            return
        generate_key_pair(args.kem_type, args.public_key_file, args.private_key_file)
        return


    if args.iterations > 0:
        if not test_kem_performance(args.iterations, args.kem_type):
            logging.error("KEM performance test failed.")

    if args.test_encryption:
        if not test_encryption_decryption(args.kem_type, args.message_size, args.cipher):
            logging.error("Encryption/Decryption test failed.")

if __name__ == "__main__":
    main()