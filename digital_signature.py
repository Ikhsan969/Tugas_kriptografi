
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def generate_keys():
    key = RSA.generate(2048)
    return key.publickey(), key

def sign_message(message, private_key):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(message, signature_b64, public_key):
    h = SHA256.new(message.encode())
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except:
        return False

if __name__ == "__main__":
    pub, priv = generate_keys()
    msg = "Dokumen penting"
    sig = sign_message(msg, priv)
    print("Signature:", sig)
    print("Valid:", verify_signature(msg, sig, pub))
    print("Valid setelah modifikasi:", verify_signature(msg + "X", sig, pub))
