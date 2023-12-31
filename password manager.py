import os
from password_handling import check_main_password
from cryptography.fernet import Fernet

# List all stored passwords
def list_passwords(key):
    with open("passwords.txt", "r") as password_file:
        print("\nStored Passwords:")
        for line in password_file:
            parts = line.split(" | ")
            if len(parts) == 3:
                website = parts[0]
                username = parts[1]
                encrypted_password = bytes.fromhex(parts[2])
                decrypted_password = decrypt_password(key, encrypted_password)
                print(f"Title: {website}\n Username: {username}\n Password: {decrypted_password}\n")

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
    key = check_main_password(input('Enter your password\n'))

    while True:
        print("\nPassword Manager Menu:")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. List all passwords")
        print("4. Exit")
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

        elif choice=="3":
            list_passwords(key)

        elif choice == "4":
            print("Exiting Password Manager.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
