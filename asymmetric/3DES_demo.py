from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import base64

def pad(data):
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def triple_des_encrypt(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def triple_des_decrypt(ciphertext_b64, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted).decode()

if __name__ == "__main__":
    # 必须是 16 或 24 字节的合法 DES3 密钥
    while True:
        key = get_random_bytes(24)
        try:
            DES3.adjust_key_parity(key)
            break
        except ValueError:
            continue

    message = "Hello, 3DES Encryption!"
    encrypted = triple_des_encrypt(message, key)
    decrypted = triple_des_decrypt(encrypted, key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
