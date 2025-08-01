from Crypto.Cipher import DES
import base64

# DES 块大小固定为 8 字节
def pad(data):
    pad_len = 8 - len(data) % 8
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def des_decrypt(ciphertext_b64, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted).decode()

if __name__ == "__main__":
    key = b'8bytekey'  # DES 密钥必须是 8 字节
    message = "Hello, DES!"

    encrypted = des_encrypt(message, key)
    decrypted = des_decrypt(encrypted, key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
