from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# --- 手写PKCS7填充 ---
def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# --- AES CBC模式加密 ---
def aes_encrypt_cbc(plaintext, key):
    # 生成随机IV(初始化向量)，长度16字节。
    # IV保证相同明文每次加密结果不同，增强安全性。
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    # 返回Base64编码的IV和密文，方便存储和传输
    return base64.b64encode(iv).decode() + ':' + base64.b64encode(ciphertext).decode()

# --- AES CBC模式解密 ---
def aes_decrypt_cbc(iv_ciphertext_b64, key):
    #以冒号 : 拼接IV和密文，方便一起传输或存储
    #这个格式是自定义的，解密时通过冒号分割提取IV和密文
    iv_b64, ciphertext_b64 = iv_ciphertext_b64.split(':')
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext).decode('utf-8')

# --- 测试 ---
if __name__ == "__main__":
    key = b'ThisIsA16ByteKey'  # 必须是16字节（128位）
    message = "Hello, AES Encryption with CBC!"

    encrypted = aes_encrypt_cbc(message, key)
    decrypted = aes_decrypt_cbc(encrypted, key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
