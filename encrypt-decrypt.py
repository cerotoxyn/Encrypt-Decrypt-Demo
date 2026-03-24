import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# PASSWORD / AUTHENTICATION
def hash_password(password: str) -> str:
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# IN MEMORY USER DATABASE
users = {
    "admin1": {
        "password_hash": hash_password("AdminPass123"),
        "role": "admin"
    },
    "user1": {
        "password_hash": hash_password("UserPass123"),
        "role": "user"
    }
}

def login(username: str, password: str):
    """Check username and password and return user info if valid."""
    user = users.get(username)
    if not user:
        return None

    if user["password_hash"] == hash_password(password):
        return {"username": username, "role": user["role"]}
    return None

# ROLE BASED ACCESS CONTROL
def requires_role(user, allowed_roles):
    """Check whether the logged-in user has permission."""
    if user["role"] not in allowed_roles:
        raise PermissionError(
            f"Access denied. '{user['role']}' role is not allowed for this action."
        )

# SYMMETRIC ENCRYPTION
def generate_symmetric_key():
    """Generate a Fernet symmetric key."""
    return Fernet.generate_key()


def symmetric_encrypt(message: str, key: bytes) -> bytes:
    """Encrypt a message with a symmetric key."""
    cipher = Fernet(key)
    return cipher.encrypt(message.encode())


def symmetric_decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt a message with a symmetric key."""
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext).decode()

# ASYMMETRIC ENCRYPTION
def generate_rsa_keys():
    """Generate RSA private/public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def asymmetric_encrypt(message: str, public_key) -> bytes:
    """Encrypt a message with the RSA public key."""
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def asymmetric_decrypt(ciphertext: bytes, private_key) -> str:
    """Decrypt a message with the RSA private key."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()


def export_public_key(public_key) -> str:
    """Convert public key to PEM format for display/storage."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()


def export_private_key(private_key) -> str:
    """Convert private key to PEM format for display/storage."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

# APPLICATION LOGIC
def main():
    print("=" * 60)
    print("Secure Messaging Demo")
    print("Symmetric + Asymmetric Encryption with Login and RBAC")
    print("=" * 60)

    username = input("Username: ").strip()
    password = input("Password: ").strip()

    current_user = login(username, password)

    if not current_user:
        print("\nLogin failed. Invalid username or password.")
        return

    print(f"\nLogin successful. Welcome, {current_user['username']}!")
    print(f"Your role is: {current_user['role']}")

    # Sample message
    message = input("\nEnter a short message to encrypt: ").strip()

    if not message:
        print("No message entered. Exiting.")
        return

    # Generate keys
    symmetric_key = generate_symmetric_key()
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # Encrypt using both methods
    symmetric_ciphertext = symmetric_encrypt(message, symmetric_key)
    asymmetric_ciphertext = asymmetric_encrypt(message, rsa_public_key)

    print("\n--- Encryption Results ---")
    print("Original Message:", message)
    print("Symmetric Key (base64):", symmetric_key.decode())
    print("Symmetric Ciphertext:", symmetric_ciphertext.decode())
    print("RSA Public Key:\n", export_public_key(rsa_public_key))
    print("RSA Ciphertext (base64):", base64.b64encode(asymmetric_ciphertext).decode())

    print("\n--- Access-Controlled Decryption Menu ---")
    print("1. Decrypt symmetric message")
    print("2. Decrypt asymmetric message")
    choice = input("Choose an option: ").strip()

    try:
        if choice == "1":
            # both admin and user can decrypt symmetric messages
            requires_role(current_user, ["admin", "user"])
            decrypted_message = symmetric_decrypt(symmetric_ciphertext, symmetric_key)
            print("\nSymmetric decryption successful.")
            print("Decrypted Message:", decrypted_message)

        elif choice == "2":
            # only admin can decrypt with private RSA key in this demo
            requires_role(current_user, ["admin"])
            decrypted_message = asymmetric_decrypt(asymmetric_ciphertext, rsa_private_key)
            print("\nAsymmetric decryption successful.")
            print("Decrypted Message:", decrypted_message)
            print("\nRSA Private Key:\n", export_private_key(rsa_private_key))

        else:
            print("Invalid option selected.")

    except PermissionError as e:
        print(f"\n{e}")

    print("\nProgram finished.")


if __name__ == "__main__":
    main()