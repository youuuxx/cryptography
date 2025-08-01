from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# --- Padding ---
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# --- AES ECB 模式 ---
def aes_encrypt_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def aes_decrypt_ecb(ciphertext_b64, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded).decode()

# --- 测试 ---
if __name__ == "__main__":
    key = b'ThisIsA16ByteKey'  # 必须是16字节（128位）
    message = "Hello, AES Encryption!"

    encrypted = aes_encrypt_ecb(message, key)
    decrypted = aes_decrypt_ecb(encrypted, key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
