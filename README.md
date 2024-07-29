# Simple Password Manager

This is a simple password manager implemented in Python. It securely stores and retrieves passwords using a master password.

## Features

- Encrypt and store passwords.
- View stored passwords.
- Validate master password before access.

## Requirements

- Python 3.x
- `cryptography` library

## Installation

1. Clone the repository or download the code files.
2. Install dependencies:
    ```bash
    pip install cryptography
    ```

## Usage

1. **First Run**:
    - Run the script and create a new master password when prompted.
    - The script will set up and then prompt you to run it again.

2. **Subsequent Runs**:
    - Enter the master password to access stored passwords or add new ones.
    - Use options to view (`view`) or add (`add`) passwords, or quit (`q`).

```bash
python password_manager.py
```


## Security
- Master password is validated by decrypting a stored test string.
- Passwords are encrypted using Fernet symmetric encryption.
- Ensure to remember your master password, as it is essential for decryption.

## Note
- The master password is required for every run to ensure security.
- In a real-world application, use a unique salt for each user and store it securely.