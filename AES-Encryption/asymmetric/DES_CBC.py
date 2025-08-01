from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64

BLOCK_SIZE = 8  # DES块大小

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def des_encrypt_cbc(plaintext, key):
    iv = get_random_bytes(BLOCK_SIZE)  # 生成随机IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    # 返回Base64编码的IV和密文，使用冒号分隔
    return base64.b64encode(iv).decode() + ':' + base64.b64encode(ciphertext).decode()

def des_decrypt_cbc(iv_ciphertext_b64, key):
    iv_b64, ciphertext_b64 = iv_ciphertext_b64.split(':')
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext).decode('utf-8')

if __name__ == "__main__":
    key = b'8bytekey'
    message = "Hello, DES in CBC mode!"

    encrypted = des_encrypt_cbc(message, key)
    decrypted = des_decrypt_cbc(encrypted, key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
