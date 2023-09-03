import os
from password_handling import create_main_password
from cryptography.fernet import Fernet

def encrypt_password(key, password):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

if __name__=='__main__':
    key = create_main_password(input('Enter main password\n'))
    with open('passwords_tmp.txt','r') as openfile:
        data = openfile.read()
    entries = data.split('\n\n')
    entry_dict = {}
    for entry in entries:
        title, username, password = entry.split('\n')
        username = username[username.find(': ')+2:]
        password = password[password.find(': ')+2:]

        entry_dict[title] = {
            'Username':username,
            'Password':password
        }
    for title, _dict in entry_dict.items():
        encrypted_password = encrypt_password(key,_dict['Password'])
        username = _dict['Username']
        with open("passwords.txt", "a") as password_file:
            password_file.write(f"{title} | {username} | {encrypted_password.hex()}\n")
        print("Password stored successfully!")