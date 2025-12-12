
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.publickey(), key

def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(ciphertext_b64, private_key):
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

if __name__ == "__main__":
    pub, priv = generate_rsa_keys()
    ct = rsa_encrypt("Pesan RSA", pub)
    print("Ciphertext:", ct)
    print("Dekripsi:", rsa_decrypt(ct, priv))
