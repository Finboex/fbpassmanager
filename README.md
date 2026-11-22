# fbpassmanager by Finboex

A lightweight, offline desktop password manager written in Python with a Tkinter interface. It stores credentials locally in encrypted vault files so your passwords stay on your own machine without relying on cloud services. Made in visual studio with gemini "auto" model.

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

## Screenshots of program

- **Interface before making any vaults**
<img width="885" height="555" alt="image" src="https://github.com/user-attachments/assets/d746b326-0a94-48d7-bfc1-81c16f52cbe6" />


- **Interface after having atleast 1 vault made**
<img width="884" height="547" alt="image" src="https://github.com/user-attachments/assets/94642b2a-d436-4921-904f-33e7c15e9f95" />

- **UI after logged into your vault**
<img width="950" height="577" alt="image" src="https://github.com/user-attachments/assets/2881efc9-c29a-4557-9f72-23e2c9ed9729" />

- **Usage of the app**

<iframe width="560" height="315" src="https://www.youtube.com/embed/hlmwbalWs9o?si=aLJvfuvXcaLd22md" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

