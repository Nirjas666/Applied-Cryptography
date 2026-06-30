import random
from math import gcd

# -----------------------------
# Check if number is prime
# -----------------------------
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


# -----------------------------
# Generate random prime
# -----------------------------
def generate_prime(start=100, end=300):
    while True:
        num = random.randint(start, end)
        if is_prime(num):
            return num


# -----------------------------
# Modular Inverse
# -----------------------------
def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if b == 0:
            return (a, 1, 0)

        gcd_val, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (gcd_val, x, y)

    _, x, _ = extended_gcd(e, phi)
    return x % phi


# -----------------------------
# RSA Key Generation
# -----------------------------
def generate_keys():

    p = generate_prime()
    q = generate_prime()

    while p == q:
        q = generate_prime()

    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randint(2, phi - 1)

    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    d = mod_inverse(e, phi)

    return (e, n), (d, n), p, q


# -----------------------------
# Encryption
# -----------------------------
def encrypt(public_key, plaintext):

    e, n = public_key

    cipher = [pow(ord(char), e, n) for char in plaintext]

    return cipher


# -----------------------------
# Decryption
# -----------------------------
def decrypt(private_key, ciphertext):

    d, n = private_key

    plain = ''.join(chr(pow(char, d, n)) for char in ciphertext)

    return plain


# -----------------------------
# Main
# -----------------------------
def main():

    public_key, private_key, p, q = generate_keys()

    print("=" * 50)
    print("RSA Key Generation")
    print("=" * 50)
    print(f"Prime p : {p}")
    print(f"Prime q : {q}")
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")

    message = input("\nEnter message: ")

    encrypted = encrypt(public_key, message)
    print("\nEncrypted Message:")
    print(encrypted)

    decrypted = decrypt(private_key, encrypted)
    print("\nDecrypted Message:")
    print(decrypted)


if __name__ == "__main__":
    main()