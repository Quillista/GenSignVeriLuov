from Crypto.Hash import SHA256  # Correct import
import numpy as np
from Crypto.Random import get_random_bytes


# Helper functions for LUOV

def generate_random_matrix(rows, cols):
    """ Generate a random binary matrix of shape (rows, cols). """
    return np.random.randint(2, size=(rows, cols), dtype=np.uint8)


def generate_polynomial(degree):
    """ Generate a random polynomial of a given degree. """
    return np.random.randint(2, size=(degree + 1,), dtype=np.uint8)  # Random binary polynomial


def hash_function(data):
    """ Hash function (SHA-256) to hash data. """
    h = SHA256.new()
    h.update(data)
    return h.digest()


def xor_bytes(a, b):
    """ XOR two byte arrays. """
    return bytes(x ^ y for x, y in zip(a, b))


# LUOV Signature Generation

def generate_key_LUOV(n, k, m):
    """ Generates the LUOV public and private keys. """
    # Secret key
    E = generate_random_matrix(n, k)  # Random matrix E (n x k)
    f = generate_polynomial(k)  # Random polynomial f
    
    # Public key
    A = generate_random_matrix(n, m)  # Random matrix A (n x m)
    
    # Public key consists of A and E
    public_key = (A, E)
    
    # Secret key consists of E and f
    secret_key = (E, f)
    
    return public_key, secret_key


def sign_message(secret_key, message):
    """ Sign a message using the secret key. """
    E, f = secret_key
    
    # Step 1: Hash the message
    message_bytes = message.encode()  # Convert message to bytes
    salt = get_random_bytes(16)  # Random salt for message
    hash_input = message_bytes + salt
    hash_value = hash_function(hash_input)  # Hash the message
    
    # Step 2: Flatten E for simplified signature generation
    E_flat = E.flatten()
    
    # Step 3: Generate signature
    signature = xor_bytes(hash_value, E_flat[:len(hash_value)])  # XOR hash value with flattened E
    
    return signature, salt


# LUOV Signature Verification

def verify_signature(public_key, signature, message, salt):
    """ Verify the LUOV signature for a given message. """
    A, E = public_key
    
    # Step 1: Hash the message
    message_bytes = message.encode()
    hash_input = message_bytes + salt
    hash_value = hash_function(hash_input)  # Hash the message
    
    # Step 2: Flatten E for verification
    E_flat = E.flatten()
    
    # Step 3: Recalculate the signature
    expected_signature = xor_bytes(hash_value, E_flat[:len(hash_value)])
    
    # Step 4: Verify the signature matches
    return signature == expected_signature


# Main function to demonstrate signing and verification

def main():
    # Parameters for the LUOV system
    n, k, m = 7, 57, 197  # Example parameters (n, k, m)

    # Generate keys
    public_key, secret_key = generate_key_LUOV(n, k, m)
    
    # Example message to sign
    message = "This is a test message."

    # Sign the message
    signature, salt = sign_message(secret_key, message)
    print(f"Signature: {signature.hex()}")
    print(f"Salt: {salt.hex()}")
    
    # Verify the signature
    is_valid = verify_signature(public_key, signature, message, salt)
    
    # Output result
    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")


if __name__ == "__main__":
    main()
