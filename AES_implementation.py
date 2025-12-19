import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Key creation
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)

# Generate a Nonce
nonce = os.urandom(12)

print("--- AES Keys Generated ---")
print(f"Key (hex): {key.hex()[:20]}...")
print(f"Nonce (hex): {nonce.hex()}")

# Encryption
message = b"I also love chocolate"
ciphertext = aesgcm.encrypt(nonce, message, None)

print(f"Ciphertext (hex): {ciphertext.hex()}")

# Decryption
try:
    decrypted_message = aesgcm.decrypt(nonce, ciphertext, None)
    print(f"Decrypted Message: {decrypted_message.decode()}")
except Exception as e:
    print(f"Decryption failed! The data might have been tampered with. Error: {e}")

'''
במימוש ה-AES שלי השתמשתי ב-Nonce בגודל של 96 ביטים (12 בתים).
Nonce הוא ערך אקראי שנועד להצטרף למפתח ההצפנה בכל פעם שמבצעים פעולה חדשה, זה מבטיח שכל הצפנה תהיה ייחודית לחלוטין.
גודל זה מאפשר לאלגוריתם לעבוד בצורה היעילה ביותר ללא צורך בפעולות הכנה נוספות: פה יתווסף מונה שישלים ל128 ביטים,
בגדלים אחרים ייתכן והיינו צריכים לבצע Hash נוסף ובכך מאיטים את התהליך.
בנוסף, גודל זה מספקים מרחב עצום של אפשרויות אקראיות. זה מבטיח שהסיכוי שיווצר אותו Nonce פעמיים בטעות הוא אפסי.
'''