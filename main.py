# ==========================================
#     BASIC ENCRYPTION & DECRYPTION
#          Caesar Cipher - Python
# ==========================================

def encrypt(text, shift):
    encrypted_text = ""

    for char in text:

        # Uppercase letters
        if char.isupper():
            encrypted_text += chr(
                (ord(char) - ord('A') + shift) % 26 + ord('A')
            )

        # Lowercase letters
        elif char.islower():
            encrypted_text += chr(
                (ord(char) - ord('a') + shift) % 26 + ord('a')
            )

        # Keep spaces, numbers and special characters unchanged
        else:
            encrypted_text += char

    return encrypted_text


def decrypt(text, shift):
    decrypted_text = ""

    for char in text:

        # Uppercase letters
        if char.isupper():
            decrypted_text += chr(
                (ord(char) - ord('A') - shift) % 26 + ord('A')
            )

        # Lowercase letters
        elif char.islower():
            decrypted_text += chr(
                (ord(char) - ord('a') - shift) % 26 + ord('a')
            )

        # Keep spaces, numbers and special characters unchanged
        else:
            decrypted_text += char

    return decrypted_text


# ==========================================
#              MAIN PROGRAM
# ==========================================

print("==========================================")
print("       BASIC ENCRYPTION & DECRYPTION")
print("            CAESAR CIPHER")
print("==========================================")

# Take input from user
text = input("Enter your text: ")

# Take shift key
while True:
    try:
        shift = int(input("Enter shift key (1-25): "))

        if 1 <= shift <= 25:
            break
        else:
            print("Please enter a number between 1 and 25.")

    except ValueError:
        print("Invalid input! Please enter a number.")


# Encrypt the text
encrypted_text = encrypt(text, shift)

# Decrypt the encrypted text
decrypted_text = decrypt(encrypted_text, shift)


# ==========================================
#              DISPLAY RESULTS
# ==========================================

print("\n------------- RESULTS -------------")

print("Original Text   :", text)
print("Shift Key       :", shift)
print("Encrypted Text  :", encrypted_text)
print("Decrypted Text  :", decrypted_text)

print("-----------------------------------")
print("Encryption and Decryption completed!")