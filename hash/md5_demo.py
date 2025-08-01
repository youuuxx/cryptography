from Crypto.Hash import MD5

def hash_md5(data: str) -> str:
    h = MD5.new()
    h.update(data.encode('utf-8'))
    return h.hexdigest()

if __name__ == "__main__":
    message = "Hello, Hash!"
    print("Original:", message)
    print("MD5 Hash:", hash_md5(message))
