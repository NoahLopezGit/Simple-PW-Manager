import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#create password configuration
def create_main_password(password):
    password = password.encode()
    salt = os.urandom(16)
    with open('salt_config.txt','wb') as openfile:
        openfile.write(salt)
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    with open("encryption_key.key", "wb") as key_file:
        key_file.write(key)
    return key

#get encrypt/decrypt key from password
def check_main_password(password):
    password = password.encode()
    with open('salt_config.txt','rb') as openfile:
        salt = openfile.read()
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key