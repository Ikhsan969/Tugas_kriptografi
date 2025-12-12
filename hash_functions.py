
from Crypto.Hash import MD5, SHA256, SHA512

def compute_hash(data, algorithm="sha256"):
    if algorithm == "md5":
        h = MD5.new()
    elif algorithm == "sha512":
        h = SHA512.new()
    else:
        h = SHA256.new()
    h.update(data.encode())
    return h.hexdigest()

if __name__ == "__main__":
    print("MD5:", compute_hash("Data contoh", "md5"))
    print("SHA256:", compute_hash("Data contoh", "sha256"))
    print("SHA512:", compute_hash("Data contoh", "sha512"))
