import hmac
import hashlib


# -----------------------------
# Generate HMAC
# -----------------------------
def generate_hmac(key, message):
    hmac_obj = hmac.new(
        key.encode(),
        message.encode(),
        hashlib.sha256
    )
    return hmac_obj.hexdigest()


# -----------------------------
# Verify HMAC
# -----------------------------
def verify_hmac(key, message, received_hmac):
    calculated_hmac = generate_hmac(key, message)

    # Secure comparison to prevent timing attacks
    return hmac.compare_digest(calculated_hmac, received_hmac)


# -----------------------------
# Main
# -----------------------------
def main():

    print("=" * 50)
    print("HMAC (SHA-256) Implementation")
    print("=" * 50)

    key = input("Enter Secret Key: ")
    message = input("Enter Message: ")

    generated_hmac = generate_hmac(key, message)

    print("\nGenerated HMAC:")
    print(generated_hmac)

    print("\nVerifying HMAC...")

    if verify_hmac(key, message, generated_hmac):
        print("HMAC Verification Successful.")
        print("Message Integrity Verified.")
    else:
        print("HMAC Verification Failed.")
        print("Message Has Been Modified.")


if __name__ == "__main__":
    main()