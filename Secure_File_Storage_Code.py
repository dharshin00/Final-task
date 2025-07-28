import os
from cryptography.fernet import Fernet
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

key_file = "filekey.key"

def generate_key():
    key = Fernet.generate_key()
    with open(key_file, "wb") as filekey:
        filekey.write(key)

def load_key():
    if not os.path.exists(key_file):
        generate_key()
    return open(key_file, "rb").read()

def encrypt_file(filename):
    key = load_key()
    fernet = Fernet(key)
    with open(filename, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(filename + ".enc", "wb") as enc_file:
        enc_file.write(encrypted)
    return hashlib.sha256(original).hexdigest()

def decrypt_file(enc_filename):
    key = load_key()
    fernet = Fernet(key)
    with open(enc_filename, "rb") as enc_file:
        encrypted = enc_file.read()
    decrypted = fernet.decrypt(encrypted)
    new_filename = enc_filename.replace(".enc", ".dec")
    with open(new_filename, "wb") as dec_file:
        dec_file.write(decrypted)
    return hashlib.sha256(decrypted).hexdigest()

def select_encrypt():
    filename = filedialog.askopenfilename()
    if filename:
        hash_val = encrypt_file(filename)
        messagebox.showinfo("Encrypted", f"File encrypted.
SHA256: {hash_val}")

def select_decrypt():
    filename = filedialog.askopenfilename()
    if filename:
        hash_val = decrypt_file(filename)
        messagebox.showinfo("Decrypted", f"File decrypted.
SHA256: {hash_val}")

def main_gui():
    window = tk.Tk()
    window.title("Secure File Storage with AES")
    window.geometry("300x150")

    tk.Button(window, text="Encrypt File", command=select_encrypt, width=25).pack(pady=10)
    tk.Button(window, text="Decrypt File", command=select_decrypt, width=25).pack(pady=10)

    window.mainloop()

if __name__ == "__main__":
    main_gui()