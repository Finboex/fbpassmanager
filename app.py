import base64
import hashlib
import json
import os
import platform
import re
import secrets
import string
import subprocess
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Password Generator ---
SYMBOLS = "!@#$%^&*()-_=+[]{}?"
ALPHABET = string.ascii_letters + string.digits + SYMBOLS
INACTIVITY_TIMEOUT_MS = 60_000  # 1 minute


def generate_password(length: int) -> str:
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(SYMBOLS),
    ]

    remaining = [secrets.choice(ALPHABET) for _ in range(length - len(required))]

    password_chars = required + remaining
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


# --- Vault Storage & Encryption ---
def get_vault_dir() -> str:
    appdata = os.environ.get("APPDATA")
    if appdata:
        base_dir = os.path.join(appdata, "fbpassmanager")
    else:
        base_dir = os.path.join(os.path.expanduser("~"), ".fbpassmanager")
    vault_dir = os.path.join(base_dir, "vaults")
    os.makedirs(vault_dir, exist_ok=True)
    return vault_dir


VAULT_DIR = get_vault_dir()
DEFAULT_VAULT = "vault.dat"
ITERATIONS = 480_000


def is_vault_filename(fname: str) -> bool:
    return fname == DEFAULT_VAULT or (fname.startswith("vault_") and fname.endswith(".dat"))


def list_vault_files(directory: str = VAULT_DIR) -> list[str]:
    """Finds existing vault files in the vaults directory."""
    os.makedirs(directory, exist_ok=True)
    files = []
    for fname in sorted(os.listdir(directory)):
        full_path = os.path.join(directory, fname)
        if is_vault_filename(fname) and os.path.isfile(full_path):
            files.append(fname)
    return files


def normalize_vault_filename(raw_name: str) -> str:
    """Converts a user input like 'Work', 'vault_work', or 'vault_work.dat' into a valid vault filename."""
    cleaned = raw_name.strip()
    if not cleaned:
        raise ValueError("Vault name cannot be empty.")
    if cleaned.lower().endswith(".dat"):
        cleaned = cleaned[:-4]
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", cleaned).strip("_").lower()
    if not cleaned or cleaned == "vault":
        return DEFAULT_VAULT
    if not cleaned.startswith("vault_"):
        cleaned = f"vault_{cleaned}"
    return f"{cleaned}.dat"


def make_new_vault_path(master_password: str, directory: str = VAULT_DIR) -> str:
    """Returns 'vault.dat' in the vaults folder for the first vault, or a unique filename for extra vaults."""
    os.makedirs(directory, exist_ok=True)
    first = os.path.join(directory, DEFAULT_VAULT)
    if not os.path.exists(first):
        return first
    digest = hashlib.sha256(
        f"{master_password}:{os.urandom(8).hex()}".encode("utf-8")
    ).hexdigest()[:10]
    return os.path.join(directory, f"vault_{digest}.dat")


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def save_vault(entries: list[dict], master_password: str, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    plaintext = json.dumps(entries).encode("utf-8")
    token = fernet.encrypt(plaintext)

    payload = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "token": token.decode("ascii"),
    }
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp_path, path)


def try_load_vault(master_password: str, path: str) -> tuple[bool, list[dict]]:
    """Attempts to decrypt a vault file. Returns (True, entries) on success, (False, []) on wrong password."""
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    salt = base64.b64decode(payload["salt"])
    token = payload["token"].encode("ascii")

    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        plaintext = fernet.decrypt(token)
    except InvalidToken:
        return False, []

    return True, json.loads(plaintext.decode("utf-8"))


def unlock_matching_vault(
    master_password: str, directory: str = VAULT_DIR
) -> tuple[str, list[dict]] | None:
    """Checks all existing vault files and returns (path, entries) for the first match."""
    for fname in list_vault_files(directory):
        path = os.path.join(directory, fname)
        try:
            ok, entries = try_load_vault(master_password, path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            continue
        if ok:
            return path, entries
    return None


# --- Formatting Helpers ---
def format_service_label(service: str) -> str:
    """Normalizes a service name like 'Google' into 'google password'."""
    cleaned = (service or "account").strip().lower()
    if not cleaned.endswith("password"):
        cleaned = f"{cleaned} password"
    return cleaned


def format_service_password_string(service: str, password: str) -> str:
    """Formats a string like 'google password: <secret>'."""
    return f"{format_service_label(service)}: {password}"


# --- Tkinter UI ---
class PasswordManagerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Local Password Manager")
        self.root.geometry("820x450")

        self.vault_path: str = os.path.join(VAULT_DIR, DEFAULT_VAULT)
        self.master_password: str = ""
        self.entries: list[dict] = []
        self._inactivity_timer: str | None = None

        self._bind_activity_events()
        self.reset_inactivity_timer()
        self.show_unlock_screen()

    def _bind_activity_events(self) -> None:
        self.root.bind_all("<Any-KeyPress>", self._on_user_activity, add="+")
        self.root.bind_all("<Any-Button>", self._on_user_activity, add="+")
        self.root.bind_all("<Motion>", self._on_user_activity, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.lock_and_exit)

    def _on_user_activity(self, _event=None) -> None:
        self.reset_inactivity_timer()

    def reset_inactivity_timer(self) -> None:
        if self._inactivity_timer is not None:
            try:
                self.root.after_cancel(self._inactivity_timer)
            except tk.TclError:
                pass
            self._inactivity_timer = None
        try:
            self._inactivity_timer = self.root.after(INACTIVITY_TIMEOUT_MS, self.lock_and_exit)
        except tk.TclError:
            pass

    def lock_and_exit(self) -> None:
        if self._inactivity_timer is not None:
            try:
                self.root.after_cancel(self._inactivity_timer)
            except tk.TclError:
                pass
            self._inactivity_timer = None

        self.master_password = ""
        self.entries = []
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass

        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def clear_root(self) -> None:
        for widget in self.root.winfo_children():
            widget.destroy()

    def enable_paste(self, entry: ttk.Entry) -> None:
        def do_paste(_event=None):
            entry.focus_set()
            self.root.update_idletasks()
            try:
                text = self.root.clipboard_get()
            except tk.TclError:
                entry.event_generate("<<Paste>>")
                return "break"

            if text:
                clean_text = text.replace("\r\n", "").replace("\n", "").replace("\r", "")
                if entry.selection_present():
                    entry.delete("sel.first", "sel.last")
                entry.insert("insert", clean_text)
            return "break"

        def do_clear():
            entry.focus_set()
            entry.delete(0, "end")

        entry.bind("<Control-v>", do_paste)
        entry.bind("<Control-V>", do_paste)
        entry.bind("<<Paste>>", do_paste)

        menu = tk.Menu(entry, tearoff=0)
        menu.add_command(label="Paste", command=do_paste)
        menu.add_command(label="Clear", command=do_clear)

        def show_menu(event):
            entry.focus_set()
            menu.tk_popup(event.x_root, event.y_root)

        entry.bind("<Button-3>", show_menu)

    def open_vaults_folder(self) -> None:
        os.makedirs(VAULT_DIR, exist_ok=True)
        system = platform.system()
        try:
            if system == "Windows":
                os.startfile(VAULT_DIR)  # type: ignore[attr-defined]
            elif system == "Darwin":
                subprocess.Popen(["open", VAULT_DIR])
            else:
                subprocess.Popen(["xdg-open", VAULT_DIR])
        except OSError as err:
            messagebox.showerror("Folder Error", f"Could not open vaults folder:\n{err}")

    def show_unlock_screen(self) -> None:
        self.clear_root()
        has_any_vault = len(list_vault_files()) > 0

        frame = ttk.Frame(self.root, padding=24)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        heading = "Unlock Vault" if has_any_vault else "Create Initial Vault"
        ttk.Label(frame, text=heading, font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 12)
        )

        ttk.Label(frame, text="Master Password:").grid(row=1, column=0, sticky="e", padx=(0, 8))
        pw_entry = ttk.Entry(frame, show="*", width=28)
        pw_entry.grid(row=1, column=1, pady=4)
        self.enable_paste(pw_entry)
        pw_entry.focus_set()
        self.root.after(50, pw_entry.focus_set)

        confirm_entry = None
        if not has_any_vault:
            ttk.Label(frame, text="Confirm Password:").grid(row=2, column=0, sticky="e", padx=(0, 8))
            confirm_entry = ttk.Entry(frame, show="*", width=28)
            confirm_entry.grid(row=2, column=1, pady=4)
            self.enable_paste(confirm_entry)

        def submit(_event=None):
            pw = pw_entry.get()
            if not pw:
                messagebox.showerror("Error", "Master password cannot be empty.")
                return

            if not has_any_vault:
                if confirm_entry and pw != confirm_entry.get():
                    messagebox.showerror("Error", "Passwords do not match.")
                    return
                if len(pw) < 10:
                    messagebox.showwarning("Weak Password", "Consider using at least 10+ characters.")
                new_path = make_new_vault_path(pw)
                self.vault_path = new_path
                self.master_password = pw
                self.entries = []
                save_vault(self.entries, self.master_password, self.vault_path)
                self.show_vault_screen()
                return

            matched = unlock_matching_vault(pw)
            if matched is None:
                messagebox.showerror("Unlock Failed", "Invalid master password.")
                return

            self.vault_path, self.entries = matched
            self.master_password = pw
            self.show_vault_screen()

        btn_text = "Unlock" if has_any_vault else "Create Vault"
        submit_row = 3 if confirm_entry else 2
        ttk.Button(frame, text=btn_text, command=submit).grid(
            row=submit_row, column=0, columnspan=2, pady=(14, 0)
        )
        pw_entry.bind("<Return>", submit)
        if confirm_entry:
            confirm_entry.bind("<Return>", submit)

    def open_new_vault_dialog(self) -> None:
        """Allows creating a new vault only after an existing vault is already unlocked."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New Vault")
        dialog.geometry("360x180")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="New Master Password:").grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
        new_pw_entry = ttk.Entry(frame, show="*", width=22)
        new_pw_entry.grid(row=0, column=1, pady=4)
        self.enable_paste(new_pw_entry)
        dialog.after(50, new_pw_entry.focus_set)

        ttk.Label(frame, text="Confirm Password:").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
        confirm_pw_entry = ttk.Entry(frame, show="*", width=22)
        confirm_pw_entry.grid(row=1, column=1, pady=4)
        self.enable_paste(confirm_pw_entry)

        def create_vault(_event=None):
            new_pw = new_pw_entry.get()
            confirm_pw = confirm_pw_entry.get()
            if not new_pw:
                messagebox.showerror("Error", "Master password cannot be empty.", parent=dialog)
                return
            if new_pw != confirm_pw:
                messagebox.showerror("Error", "Passwords do not match.", parent=dialog)
                return
            if unlock_matching_vault(new_pw) is not None:
                messagebox.showerror(
                    "Duplicate Password",
                    "That master password already unlocks an existing vault.",
                    parent=dialog,
                )
                return
            if len(new_pw) < 10:
                messagebox.showwarning(
                    "Weak Password", "Consider using at least 10+ characters.", parent=dialog
                )

            new_path = make_new_vault_path(new_pw)
            save_vault([], new_pw, new_path)
            self.vault_path = new_path
            self.master_password = new_pw
            self.entries = []
            dialog.destroy()
            self.show_vault_screen()

        btns = ttk.Frame(frame)
        btns.grid(row=2, column=0, columnspan=2, pady=(14, 0))
        ttk.Button(btns, text="Create", command=create_vault).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Cancel", command=dialog.destroy).pack(side="left")

        new_pw_entry.bind("<Return>", create_vault)
        confirm_pw_entry.bind("<Return>", create_vault)

    def open_rename_vault_dialog(self) -> None:
        """Allows renaming the currently unlocked vault file inside VAULT_DIR."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Rename Current Vault")
        dialog.geometry("380x170")
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill="both", expand=True)

        current_name = os.path.basename(self.vault_path)
        ttk.Label(frame, text=f"Current: {current_name}").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )

        ttk.Label(frame, text="New Vault Name:").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
        name_var = tk.StringVar()
        name_entry = ttk.Entry(frame, textvariable=name_var, width=24)
        name_entry.grid(row=1, column=1, pady=4)
        self.enable_paste(name_entry)
        dialog.after(50, name_entry.focus_set)

        hint_var = tk.StringVar(value="Saved as: vault_<name>.dat")
        ttk.Label(frame, textvariable=hint_var, foreground="gray").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(2, 0)
        )

        def update_hint(*_args):
            try:
                hint_var.set(f"Saved as: {normalize_vault_filename(name_var.get())}")
            except ValueError:
                hint_var.set("Enter a non-empty vault name")

        name_var.trace_add("write", update_hint)

        def do_rename(_event=None):
            try:
                new_filename = normalize_vault_filename(name_var.get())
            except ValueError as err:
                messagebox.showerror("Invalid Name", str(err), parent=dialog)
                return

            new_path = os.path.join(VAULT_DIR, new_filename)
            if os.path.abspath(new_path) == os.path.abspath(self.vault_path):
                dialog.destroy()
                return

            if os.path.exists(new_path):
                messagebox.showerror(
                    "Name Taken",
                    f"A vault named '{new_filename}' already exists.",
                    parent=dialog,
                )
                return

            try:
                os.replace(self.vault_path, new_path)
            except OSError as err:
                messagebox.showerror("Rename Failed", f"Could not rename vault:\n{err}", parent=dialog)
                return

            self.vault_path = new_path
            dialog.destroy()
            self.show_vault_screen()

        btns = ttk.Frame(frame)
        btns.grid(row=3, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(btns, text="Rename", command=do_rename).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Cancel", command=dialog.destroy).pack(side="left")

        name_entry.bind("<Return>", do_rename)

    def show_vault_screen(self) -> None:
        self.clear_root()

        top_bar = ttk.Frame(self.root, padding=(12, 10))
        top_bar.pack(fill="x")

        vault_name = os.path.basename(self.vault_path)
        ttk.Label(
            top_bar,
            text=f"Saved Credentials ({vault_name})",
            font=("TkDefaultFont", 13, "bold"),
        ).pack(side="left")
        ttk.Button(top_bar, text="Lock Vault", command=self.lock_vault).pack(side="right")
        ttk.Button(top_bar, text="Rename Vault", command=self.open_rename_vault_dialog).pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(top_bar, text="New Vault", command=self.open_new_vault_dialog).pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(top_bar, text="Open Vaults Folder", command=self.open_vaults_folder).pack(
            side="right", padx=(0, 8)
        )

        # Entry form
        form = ttk.LabelFrame(self.root, text="Add Credential", padding=10)
        form.pack(fill="x", padx=12, pady=(0, 8))

        ttk.Label(form, text="Service:").grid(row=0, column=0, sticky="w")
        service_var = tk.StringVar()
        service_entry = ttk.Entry(form, textvariable=service_var, width=18)
        service_entry.grid(row=0, column=1, padx=(4, 10))
        self.enable_paste(service_entry)

        ttk.Label(form, text="Username:").grid(row=0, column=2, sticky="w")
        user_var = tk.StringVar()
        user_entry = ttk.Entry(form, textvariable=user_var, width=18)
        user_entry.grid(row=0, column=3, padx=(4, 10))
        self.enable_paste(user_entry)

        ttk.Label(form, text="Length:").grid(row=0, column=4, sticky="w")
        length_var = tk.IntVar(value=20)
        ttk.Spinbox(form, from_=8, to=128, textvariable=length_var, width=6).grid(
            row=0, column=5, padx=(4, 10)
        )

        ttk.Label(form, text="Password:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        pw_var = tk.StringVar()
        pw_field = ttk.Entry(form, textvariable=pw_var, show="*", width=18)
        pw_field.grid(row=1, column=1, padx=(4, 10), pady=(8, 0))
        self.enable_paste(pw_field)

        def on_generate():
            try:
                length = int(length_var.get())
                pw = generate_password(length)
            except (ValueError, tk.TclError) as err:
                messagebox.showerror("Invalid Length", str(err))
                return

            pw_var.set(pw)

        ttk.Button(form, text="Generate", command=on_generate).grid(
            row=1, column=2, padx=(0, 6), pady=(8, 0)
        )

        def add_entry():
            service = service_var.get().strip()
            username = user_var.get().strip()
            password = pw_var.get()

            if not service or not password:
                messagebox.showerror("Missing Fields", "Service and password are required.")
                return

            label = format_service_label(service)
            labeled_password = format_service_password_string(service, password)
            self.entries.append(
                {
                    "service": service,
                    "service_label": label,
                    "labeled_password": labeled_password,
                    "username": username,
                    "password": password,
                }
            )
            save_vault(self.entries, self.master_password, self.vault_path)

            service_var.set("")
            user_var.set("")
            pw_var.set("")
            refresh_tree()

        ttk.Button(form, text="Save", command=add_entry).grid(
            row=1, column=3, sticky="w", pady=(8, 0)
        )

        # Table of entries
        columns = ("service", "username", "password")
        tree = ttk.Treeview(self.root, columns=columns, show="headings", height=11)
        tree.heading("service", text="Service")
        tree.heading("username", text="Username")
        tree.heading("password", text="Password")
        tree.column("service", width=180)
        tree.column("username", width=200)
        tree.column("password", width=360)
        tree.pack(fill="both", expand=True, padx=12)

        revealed_row: str | None = None

        def masked_password(item: dict) -> str:
            label = item.get("service_label") or format_service_label(item["service"])
            return f"{label}: ••••••••"

        def revealed_password(item: dict) -> str:
            return item.get("labeled_password") or format_service_password_string(
                item["service"], item["password"]
            )

        def refresh_tree():
            nonlocal revealed_row
            revealed_row = None
            for row in tree.get_children():
                tree.delete(row)
            for idx, item in enumerate(self.entries):
                tree.insert(
                    "",
                    "end",
                    iid=str(idx),
                    values=(item["service"], item["username"], masked_password(item)),
                )

        def get_selected_index() -> int | None:
            sel = tree.selection()
            if not sel:
                messagebox.showinfo("Select Row", "Select a credential row first.")
                return None
            return int(sel[0])

        def toggle_reveal():
            nonlocal revealed_row
            idx = get_selected_index()
            if idx is None:
                return
            iid = str(idx)
            item = self.entries[idx]
            if revealed_row == iid:
                tree.item(
                    iid,
                    values=(item["service"], item["username"], masked_password(item)),
                )
                revealed_row = None
            else:
                if revealed_row is not None and tree.exists(revealed_row):
                    prev = self.entries[int(revealed_row)]
                    tree.item(
                        revealed_row,
                        values=(prev["service"], prev["username"], masked_password(prev)),
                    )
                tree.item(
                    iid,
                    values=(item["service"], item["username"], revealed_password(item)),
                )
                revealed_row = iid

        def copy_to_clipboard(text: str, label: str) -> None:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.after(15_000, lambda: self.clear_clipboard_if_matches(text))
            messagebox.showinfo("Copied", f"{label} copied to clipboard (clears in 15s).")

        def copy_password():
            idx = get_selected_index()
            if idx is None:
                return
            copy_to_clipboard(self.entries[idx]["password"], "Password")

        def copy_labeled_password():
            idx = get_selected_index()
            if idx is None:
                return
            copy_to_clipboard(revealed_password(self.entries[idx]), "Labeled password")

        def delete_entry():
            idx = get_selected_index()
            if idx is None:
                return
            del self.entries[idx]
            save_vault(self.entries, self.master_password, self.vault_path)
            refresh_tree()

        actions = ttk.Frame(self.root, padding=12)
        actions.pack(fill="x")
        ttk.Button(actions, text="Show / Hide Password", command=toggle_reveal).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Copy Password", command=copy_password).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Copy With Label", command=copy_labeled_password).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Delete", command=delete_entry).pack(side="left")

        refresh_tree()

    def clear_clipboard_if_matches(self, secret: str) -> None:
        try:
            if self.root.clipboard_get() == secret:
                self.root.clipboard_clear()
        except tk.TclError:
            pass

    def lock_vault(self) -> None:
        self.master_password = ""
        self.entries = []
        self.lock_and_exit()


if __name__ == "__main__":
    root = tk.Tk()
    PasswordManagerApp(root)
    root.mainloop()
