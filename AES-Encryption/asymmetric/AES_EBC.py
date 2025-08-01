from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
# 用于把二进制密文转换为可打印的ASCII字符串（方便存储和运输）
import base64

# --- Padding ---
def pad(data):
    # 计算要填充多少个字节，这样填充符合PKCS7标准
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    # 取最后一个字节的值（即填充长度）
    pad_len = data[-1]
    # 去掉对应数量的填充字节，恢复原始明文
    return data[:-pad_len]

# --- AES ECB 模式 ---
def aes_encrypt_ecb(plaintext, key):
    # 创建AES加密器，使用指定密钥和ECB模式
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext.encode('utf-8'))
    ciphertext = cipher.encrypt(padded)
    return base64.b64encode(ciphertext).decode()

def aes_decrypt_ecb(ciphertext_b64, key):
   # 使用同样的密钥和ECB模式创建 解密器
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext_padded = cipher.decrypt(ciphertext)
    return unpad(plaintext_padded).decode()

# --- 测试 ---
if __name__ == "__main__":
    key = b'ThisIsA16cellKey'  # 必须是16字节（128位）
    message = "Hello, AES Encryption!"

    encrypted = aes_encrypt_ecb(message, key)
    decrypted = aes_decrypt_ecb(encrypted, key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
