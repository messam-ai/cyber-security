# Password Strength Checker
# DecodeLabs - Cyber Security Project 1

import string

print("===================================")
print("      PASSWORD STRENGTH CHECKER")
print("===================================")

password = input("Enter your password: ")

score = 0

# 1. Check password length
if len(password) >= 8:
    score += 1

# 2. Check uppercase letter
if any(char.isupper() for char in password):
    score += 1

# 3. Check number
if any(char.isdigit() for char in password):
    score += 1

# 4. Check symbol
if any(char in string.punctuation for char in password):
    score += 1

# 5. Determine password strength
if score <= 1:
    strength = "WEAK"
elif score <= 3:
    strength = "MEDIUM"
else:
    strength = "STRONG"

# Display result
print("\n-----------------------------------")
print("Password Strength:", strength)
print("-----------------------------------")

# Display suggestions
if strength == "WEAK":
    print("Suggestion:")
    print("- Use at least 8 characters")
    print("- Add uppercase letters")
    print("- Add numbers")
    print("- Add symbols")

elif strength == "MEDIUM":
    print("Your password is fairly good.")
    print("Try adding more character variety.")

else:
    print("Excellent! Your password is strong.")

print("===================================")
