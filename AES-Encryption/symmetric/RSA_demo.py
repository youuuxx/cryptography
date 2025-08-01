from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# 生成 RSA 密钥对
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 加密函数
def rsa_encrypt(plaintext, public_key_bytes):
    #先用RSA.import_key把传入的公钥字节转成密钥对象
    public_key = RSA.import_key(public_key_bytes)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode()

# 解密函数
def rsa_decrypt(ciphertext_b64, private_key_bytes):
    private_key = RSA.import_key(private_key_bytes)
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(ciphertext_b64)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

if __name__ == "__main__":
    private_key, public_key = generate_keys()

    message = "Hello, RSA!"
    encrypted = rsa_encrypt(message, public_key)
    decrypted = rsa_decrypt(encrypted, private_key)

    print("Original:", message)
    print("Encrypted (Base64):", encrypted)
    print("Decrypted:", decrypted)
