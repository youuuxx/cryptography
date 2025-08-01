from Crypto.Hash import SHA256

def hash_sha256(data: str) -> str:
    h = SHA256.new()
    h.update(data.encode('utf-8'))
    return h.hexdigest()

if __name__ == "__main__":
    message = "Hello, Hash!"
    print("Original:", message)
    print("SHA256 Hash:", hash_sha256(message))
