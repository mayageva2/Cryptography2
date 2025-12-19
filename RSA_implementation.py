from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

KEY_SIZE = 2048

# Key creation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=KEY_SIZE
)

public_key = private_key.public_key()
print("--- RSA Keys Generated ---")
print(f"Key Size: {KEY_SIZE} bits (Modulus n)")

# Encryption
message = b"I love Potatoes"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Ciphertext (hex): {ciphertext.hex()[:50]}...")

# Decryption
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Decrypted Message: {plaintext.decode()}")

'''
במימוש ה-RSA שלי בחרתי להשתמש ב-Key Size של 2048 ביט.
גודל המפתח מציין את האורך (בביטים) של המספר n, שהוא המכפלה של שני מספרים ראשוניים גדולים (p וq).
ככל שהמספר n גדול יותר, כך קשה יותר לגלות את p וq, אבל אם נבחר מפתח גדול מידי ההצפנה והפענוח יהיו איטיים מאוד.
2048 ביט נחשב כיום לתקן המינימלי המומלץ בתעשייה,משום שהוא מספק איזון בין אבטחה חזקה לבין מהירות עבודה של המחשב.
'''