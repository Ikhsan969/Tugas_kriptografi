import numpy as np

# ----------------------
# 1) CAESAR
# ----------------------
def caesar_encrypt(plaintext, shift):
    ciphertext = ''
    for c in plaintext.upper():
        if c.isalpha():
            ciphertext += chr((ord(c) - 65 + shift) % 26 + 65)
        else:
            ciphertext += c
    return ciphertext

# ----------------------
# 2) VIGENERE
# ----------------------
def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.upper()
    key = key.upper()
    ciphertext = ""
    j = 0
    for c in plaintext:
        if c.isalpha():
            k = ord(key[j % len(key)]) - 65
            ciphertext += chr((ord(c) - 65 + k) % 26 + 65)
            j += 1
        else:
            ciphertext += c
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""
    j = 0
    for c in ciphertext:
        if c.isalpha():
            k = ord(key[j % len(key)]) - 65
            plaintext += chr((ord(c) - 65 - k) % 26 + 65)
            j += 1
        else:
            plaintext += c
    return plaintext

# ----------------------
# 3) AFFINE
# ----------------------
def affine_encrypt(plaintext, a, b):
    ciphertext = ""
    for c in plaintext.upper():
        if c.isalpha():
            x = ord(c) - 65
            ciphertext += chr(((a * x + b) % 26) + 65)
        else:
            ciphertext += c
    return ciphertext

def affine_decrypt(ciphertext, a, b):
    def mod_inverse(a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError("Tidak ada invers modular untuk a (tidak invertible mod 26)")
    plaintext = ""
    for c in ciphertext.upper():
        if c.isalpha():
            y = ord(c) - 65
            plaintext += chr(((a_inv * (y - b)) % 26) + 65)
        else:
            plaintext += c
    return plaintext

# ----------------------
# 4) PLAYFAIR
# ----------------------
def generate_playfair_matrix(key):
    key = "".join(dict.fromkeys(key.upper().replace("J", "I")))  # hapus duplikat & J->I
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for c in key:
        alphabet = alphabet.replace(c, "")
    matrix = key + alphabet
    return [list(matrix[i:i+5]) for i in range(0, 25, 5)]

def find_position(matrix, letter):
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == letter:
                return i, j
    return None

def playfair_prepare_text(text):
    text = text.upper().replace("J", "I")
    text = "".join(c for c in text if c.isalpha())
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i+1 < len(text):
            b = text[i+1]
            if a == b:
                pairs.append(a + 'X')
                i += 1
            else:
                pairs.append(a + b)
                i += 2
        else:
            pairs.append(a + 'X')
            i += 1
    return pairs

def playfair_encrypt(plaintext, key):
    matrix = generate_playfair_matrix(key)
    pairs = playfair_prepare_text(plaintext)
    ciphertext = ""
    for pair in pairs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            ciphertext += matrix[row1][(col1+1)%5] + matrix[row2][(col2+1)%5]
        elif col1 == col2:
            ciphertext += matrix[(row1+1)%5][col1] + matrix[(row2+1)%5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = generate_playfair_matrix(key)
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    plaintext = ""
    for pair in pairs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)
        if row1 == row2:
            plaintext += matrix[row1][(col1-1)%5] + matrix[row2][(col2-1)%5]
        elif col1 == col2:
            plaintext += matrix[(row1-1)%5][col1] + matrix[(row2-1)%5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    return plaintext

# ----------------------
# 5) HILL (2x2)
# ----------------------
def text_to_numbers(text):
    return [ord(c) - ord('A') for c in text.upper() if c.isalpha()]

def numbers_to_text(nums):
    return ''.join(chr(int(n) + ord('A')) for n in nums)

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def matrix_mod_inverse(matrix, modulus):
    det = int(round(np.linalg.det(matrix))) % modulus
    det_inv = mod_inverse(det, modulus)
    if det_inv is None:
        raise ValueError("Matrix tidak invertible mod {}".format(modulus))
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    return (det_inv * adjugate) % modulus

def hill_encrypt(plaintext, key_matrix):
    nums = text_to_numbers(plaintext)
    n = key_matrix.shape[0]
    while len(nums) % n != 0:
        nums.append(ord('X') - ord('A'))  # padding dengan 'X'
    ciphertext = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        result = np.dot(key_matrix, block) % 26
        ciphertext.extend(result)
    return numbers_to_text(ciphertext)

def hill_decrypt(ciphertext, key_matrix):
    inv_matrix = matrix_mod_inverse(key_matrix, 26)
    nums = text_to_numbers(ciphertext)
    n = key_matrix.shape[0]
    plaintext = []
    for i in range(0, len(nums), n):
        block = np.array(nums[i:i+n])
        result = np.dot(inv_matrix, block) % 26
        plaintext.extend(result)
    return numbers_to_text(plaintext)

# ----------------------
# Jalankan semua dengan plaintext "HELLO"
# ----------------------
plaintext = "HELLO"

# Caesar
caesar_ct = caesar_encrypt(plaintext, 3)
caesar_dec = caesar_encrypt(caesar_ct, -3)

# Vigenere (pakai key "LEMON")
vigenere_ct = vigenere_encrypt(plaintext, "LEMON")
vigenere_dec = vigenere_decrypt(vigenere_ct, "LEMON")

# Affine (a=5,b=8)
affine_ct = affine_encrypt(plaintext, 5, 8)
affine_dec = affine_decrypt(affine_ct, 5, 8)

# Playfair (key "MONARCHY")
playfair_ct = playfair_encrypt(plaintext, "MONARCHY")
playfair_dec = playfair_decrypt(playfair_ct, "MONARCHY")

# Hill (2x2 key)
hill_key = np.array([[3,3],[2,5]])
hill_ct = hill_encrypt(plaintext, hill_key)
hill_dec = hill_decrypt(hill_ct, hill_key)

# Cetak hasil
print("Plaintext :", plaintext)
print()
print("=== Caesar ===")
print("Ciphertext:", caesar_ct)
print("Decrypt   :", caesar_dec)
print()
print("=== Vigenere (key=LEMON) ===")
print("Ciphertext:", vigenere_ct)
print("Decrypt   :", vigenere_dec)
print()
print("=== Affine (a=5,b=8) ===")
print("Ciphertext:", affine_ct)
print("Decrypt   :", affine_dec)
print()
print("=== Playfair (key=MONARCHY) ===")
print("Prepared pairs (for info) :", playfair_prepare_text(plaintext))
print("Ciphertext:", playfair_ct)
print("Decrypt   :", playfair_dec)
print("Note      : 'X' may appear from padding or doubling letters.")
print()
print("=== Hill (2x2 key=[[3,3],[2,5]]) ===")
print("Ciphertext:", hill_ct)
print("Decrypt   :", hill_dec)
print("Note      : Hill adds 'X' as padding if needed (so decryption can show trailing X).")