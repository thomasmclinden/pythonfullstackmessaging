from cryptography.hazmat.primitives import hashes
import tkinter as tk
from tkinter import messagebox, scrolledtext
import json
import base64
import requests
import os
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER = "http://localhost:8080"

class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        root.title("Secure Messaging Client")

        self.session_id = None
        self.aes_key = None

        # --- UI ---
        tk.Label(root, text="Student ID").grid(row=0, column=0)
        tk.Label(root, text="Name").grid(row=1, column=0)
        tk.Label(root, text="GPA").grid(row=2, column=0)

        self.id_entry = tk.Entry(root)
        self.name_entry = tk.Entry(root)
        self.gpa_entry = tk.Entry(root)

        self.id_entry.grid(row=0, column=1)
        self.name_entry.grid(row=1, column=1)
        self.gpa_entry.grid(row=2, column=1)

        tk.Button(root, text="Send Secure Message", command=self.send_message)\
            .grid(row=3, column=0, columnspan=2, pady=10)

        self.output = scrolledtext.ScrolledText(root, width=50, height=12)
        self.output.grid(row=4, column=0, columnspan=2)

        self.initialize_session()

    # --- CRYPTO / NETWORK ---

    def initialize_session(self):
        self.output.insert(tk.END, "Fetching server public key...\n")
        pubkey = self.fetch_public_key()

        self.aes_key = os.urandom(32)  # AES-256

        encrypted_key = pubkey.encrypt(
            self.aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        resp = requests.post(
            SERVER + "/session",
            json={"encryptedKey": base64.b64encode(encrypted_key).decode()}
        )

        self.session_id = resp.json()["sessionID"]
        self.output.insert(tk.END, f"Session established: {self.session_id}\n\n")

    def fetch_public_key(self):
        resp = requests.get(SERVER + "/publicKey")
        data = resp.json()["publicKey"]
        key_bytes = base64.b64decode(data)
        return serialization.load_der_public_key(key_bytes)

    def send_message(self):
        try:
            student = {
                "id": int(self.id_entry.get()),
                "name": self.name_entry.get(),
                "gpa": float(self.gpa_entry.get())
            }
        except ValueError:
            messagebox.showerror("Error", "Invalid input")
            return

        plaintext = json.dumps(student).encode()

        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        mac = hmac.new(
            self.aes_key,
            ciphertext,
            hashlib.sha256
        ).digest()

        payload = {
            "sessionID": self.session_id,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "hmac": base64.b64encode(mac).decode()
        }

        resp = requests.post(SERVER + "/message", json=payload)
        result = resp.json()

        self.output.insert(tk.END, json.dumps(result, indent=2) + "\n\n")


# --- Run GUI ---
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureClientGUI(root)
    root.mainloop()