import os
from Crypto.PublicKey import RSA

def generate_and_save_keys(private_path, public_path):
    key = RSA.generate(2048)
    with open(private_path, "wb") as f:
        f.write(key.export_key())
    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key())
    print(f"Keys saved to {private_path} and {public_path}")

if __name__ == "__main__":
    os.makedirs("keys", exist_ok=True)
    generate_and_save_keys("keys/client_private.pem", "keys/client_public.pem")
    generate_and_save_keys("keys/server_private.pem", "keys/server_public.pem")
