import socket
import threading
import base64
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
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

    def decrypt(self, b64_ciphertext):
        data = base64.b64decode(b64_ciphertext)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()

    def verify_hmac(self, message, hmac_to_verify):
        calc_hmac = hmac.new(self.key, message.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(calc_hmac, hmac_to_verify)

def load_public_key(path):
    with open(path, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

def load_private_key(path):
    with open(path, "rb") as f:
        key_data = f.read()
    return RSA.import_key(key_data)

def handle_client(conn, addr, server_rsa_key, client_rsa_pub):
    print(f"Connected by {addr}")

    dh = DiffieHellman()
    conn.sendall(str(dh.public_key).encode() + b'\n')

    client_pub = int(conn.recv(4096).decode().strip())
    print(f"Received client public key: {client_pub}")

    client_sig_b64 = conn.recv(4096).decode().strip()
    client_sig = base64.b64decode(client_sig_b64)

    # 验证客户端签名
    h = SHA256.new(str(client_pub).encode())
    try:
        pkcs1_15.new(client_rsa_pub).verify(h, client_sig)
        print("Client identity verified successfully!")
    except (ValueError, TypeError):
        print("Client signature verification failed!")
        conn.sendall(b"Client signature verification failed.\n")
        conn.close()
        return

    h_server = SHA256.new(str(dh.public_key).encode())
    server_sig = pkcs1_15.new(server_rsa_key).sign(h_server)
    conn.sendall(base64.b64encode(server_sig) + b'\n')

    shared_key = dh.generate_shared_key(client_pub)
    channel = SecureChannel(shared_key)
    print("Shared key established.")

    ciphertext = conn.recv(4096).decode()
    mac = conn.recv(4096).decode()

    if not channel.verify_hmac(ciphertext, mac):
        print("HMAC verification failed! Message tampered.")
        conn.sendall(b"HMAC verification failed.\n")
        conn.close()
        return

    print("HMAC verified successfully.")
    plaintext = channel.decrypt(ciphertext)
    print(f"Decrypted message: {plaintext}")

    conn.sendall(b"Message received and verified.\n")
    conn.close()

def main():
    HOST = '127.0.0.1'
    PORT = 65432

    server_rsa_key = load_private_key("keys/server_private.pem")
    client_rsa_pub = load_public_key("keys/client_public.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr, server_rsa_key, client_rsa_pub)).start()

if __name__ == "__main__":
    main()
