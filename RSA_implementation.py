from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

KEY_SIZE = 2048

# This function generates the RSA private key object.
# It automatically finds two large primes p and q,
# calculates the modulus n = p*q, and finds the private exponent d.
private_key = rsa.generate_private_key(
    public_exponent=65537,  #presentation example for e, efficient and secure
    key_size=KEY_SIZE
)

public_key = private_key.public_key()
print("--- RSA Keys Generated ---")
print(f"Key Size: {KEY_SIZE} bits (Modulus n)")

