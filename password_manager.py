import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

def write_key(master_pwd):
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)
    # Store an encrypted test string using the new master password
    derived_key = derive_key(master_pwd, b'some_salt_')
    fer = Fernet(derived_key)
    test_string = "test"
    encrypted_test_string = fer.encrypt(test_string.encode())
    with open('test_string.enc', 'wb') as test_file:
        test_file.write(encrypted_test_string)

def load_key():
    with open('key.key', 'rb') as key_file:
        key = key_file.read()
    return key

def derive_key(master_pwd: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))

def validate_master_password(master_pwd: str) -> bool:
    try:
        derived_key = derive_key(master_pwd, b'some_salt_')
        fer = Fernet(derived_key)
        # Attempt to decrypt the stored test string
        with open('test_string.enc', 'rb') as test_file:
            encrypted_test_string = test_file.read()
            decrypted_test_string = fer.decrypt(encrypted_test_string).decode()
        return decrypted_test_string == "test"
    except Exception:
        return False

# Check if the key and test string files exist
if not os.path.exists('key.key') or not os.path.exists('test_string.enc'):
    master_pwd = input('Create a new master password: \n-> ')
    write_key(master_pwd)
    print("Master password has been set. Please run the script again.")
    exit()

# Prompt for the master password and validate it
master_pwd = input('What is the master password? \n-> ')
if not validate_master_password(master_pwd):
    print("Invalid master password. Exiting...")
    exit()

# If the master password is correct, derive the key and proceed
derived_key = derive_key(master_pwd, b'some_salt_')
fer = Fernet(derived_key)

def view():
    try:
        with open('passwords.txt', 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                user, passw = data.split('|')
                print(f'User: {user} | Password: {fer.decrypt(passw.encode()).decode()}')
    except cryptography.fernet.InvalidToken:
        print("Invalid password. Decryption failed.")
    except FileNotFoundError:
        print("The passwords.txt file does not exist.")

def add():
    name = input("Account Name: \n-> ")
    pwd = input("Password: \n-> ")

    with open('passwords.txt', 'a') as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + '\n')

while True:
    mode = input('Would you like to add a new password or view existing ones? (view, add), Q to Quit\n-> ').lower()
    
    if mode == 'q':
        break

    if mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print('Invalid mode')
        continue
