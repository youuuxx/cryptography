import socket
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
DH_G = 2

class DiffieHellman:
    def __init__(self):
        self.private_key = int.from_bytes(get_random_bytes(32), 'big') % DH_P
        self.public_key = pow(DH_G, self.private_key, DH_P)

    def generate_shared_key(self, other_public_key):
        shared_secret = pow(other_public_key, self.private_key, DH_P)
        shared_key = hashlib.sha256(shared_secret.to_bytes(256, 'big')).digest()
        return shared_key

class SecureChannel:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
        return base64.b64encode(iv + ciphertext).decode()

    def hmac(self, message):
        return hmac.new(self.key, message.encode(), hashlib.sha256).hexdigest()

def load_private_key(path):
    with open(path, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

def load_public_key(path):
    with open(path, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

def main():
    HOST = '127.0.0.1'
    PORT = 65432

    client_private_key = load_private_key("keys/client_private.pem")
    server_rsa_pub = load_public_key("keys/server_public.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        dh = DiffieHellman()

        server_pub = int(s.recv(4096).decode().strip())
        print(f"Received server public key: {server_pub}")

        # 客户端对自己DH公钥签名，证明身份
        h = SHA256.new(str(dh.public_key).encode())
        signature = pkcs1_15.new(client_private_key).sign(h)

        s.sendall(str(dh.public_key).encode() + b'\n')
        s.sendall(base64.b64encode(signature) + b'\n')

        server_sig_b64 = s.recv(4096).decode().strip()
        server_sig = base64.b64decode(server_sig_b64)
        h_server = SHA256.new(str(server_pub).encode())

        # 验证服务器签名，确认服务器身份
        try:
            pkcs1_15.new(server_rsa_pub).verify(h_server, server_sig)
            print("Server identity verified successfully!")
        except (ValueError, TypeError):
            print("Server signature verification failed!")
            s.close()
            return

        shared_key = dh.generate_shared_key(server_pub)
        channel = SecureChannel(shared_key)
        print("Shared key established.")

        plaintext = "Hello, identity authenticated and encrypted message!"
        ciphertext = channel.encrypt(plaintext)
        mac = channel.hmac(ciphertext)

        s.sendall(ciphertext.encode())
        s.sendall(mac.encode())

        response = s.recv(4096).decode()
        print("Server response:", response)

if __name__ == "__main__":
    main()
