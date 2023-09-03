import os
from cryptography.fernet import Fernet

# Generate a random encryption key
def generate_key():
    return Fernet.generate_key()

# Initialize the encryption key
def initialize_key():
    key_file = "encryption_key.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as key_file:
            key = key_file.read()
    else:
        key = generate_key()
        with open(key_file, "wb") as key_file:
            key_file.write(key)
    return key

# Encrypt a password
def encrypt_password(key, password):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt a password
def decrypt_password(key, encrypted_password):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Main menu
def main():
    key = initialize_key()

    while True:
        print("\nPassword Manager Menu:")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            website = input("Enter website name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            encrypted_password = encrypt_password(key, password)

            with open("passwords.txt", "a") as password_file:
                password_file.write(f"{website} | {username} | {encrypted_password.hex()}\n")
            print("Password stored successfully!")

        elif choice == "2":
            website = input("Enter website name: ")
            username = input("Enter username: ")

            with open("passwords.txt", "r") as password_file:
                for line in password_file:
                    parts = line.split(" | ")
                    if len(parts) == 3 and parts[0] == website and parts[1] == username:
                        encrypted_password = bytes.fromhex(parts[2])
                        decrypted_password = decrypt_password(key, encrypted_password)
                        print(f"Password: {decrypted_password}")
                        break
                else:
                    print("Password not found!")

        elif choice == "3":
            print("Exiting Password Manager.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
