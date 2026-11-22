# fbpassmanager by Finboex

A lightweight, offline desktop password manager written in Python with a Tkinter interface. It stores credentials locally in encrypted vault files so your passwords stay on your own machine without relying on cloud services. Made in visual studio with the help of gemini "auto" model.

## Features
- **Encrypted Local Storage:** Uses PBKDF2-HMAC-SHA256 key derivation (480,000 iterations) and Fernet encryption to protect saved credentials.
- **Multi-Vault Support:** Create, rename, and manage multiple separate vaults—each unlocked automatically by its own master password.
- **Built-In Password Generator:** Generate customizable random passwords (8–128 characters) with uppercase, lowercase, digits, and symbols.
- **Privacy & Security Safeguards:**
  - Automatically clears copied passwords from the clipboard after 15 seconds.
  - Locks the vault and closes the application after 60 seconds of window inactivity.
- **Organized Local Storage:** Vault files are saved locally in `%APPDATA%\fbpassmanager\vaults`.

## Usage
- **Windows Executable:** Download `PasswordManager.exe` from the **Releases** page and run it directly.
- **From Source:**
  1. Install the dependency:
     ```bash
     pip install cryptography
     ```
  2. Run the application:
     ```bash
     python app.py
     ```
