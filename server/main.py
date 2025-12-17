# This is a Python conversion of your Go server
# It uses Flask for HTTP endpoints and Tkinter for a simple GUI
# Requirements: flask, cryptography

import base64
import json
import os
import threading
import hmac
import hashlib
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

# ------------------ Crypto Setup ------------------

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

sessions = {}

# ------------------ Flask Server ------------------

app = Flask(__name__)

@app.route('/publicKey', methods=['GET'])
def public_key_endpoint():
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jsonify({"publicKey": base64.b64encode(der).decode()})

@app.route('/session', methods=['POST'])
def session_endpoint():
    data = request.get_json()
    encrypted_key = base64.b64decode(data['encryptedKey'])

    symm_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    session_id = os.urandom(16).hex()
    sessions[session_id] = symm_key
    log(f"New session created: {session_id}")

    return jsonify({"sessionID": session_id})

@app.route('/message', methods=['POST'])
def message_endpoint():
    data = request.get_json()
    session_id = data['sessionID']

    if session_id not in sessions:
        return jsonify({"validHMAC": False, "message": "Unknown session"})

    key = sessions[session_id]
    ciphertext = base64.b64decode(data['ciphertext'])
    nonce = base64.b64decode(data['nonce'])
    recv_hmac = base64.b64decode(data['hmac'])

    expected = hmac.new(key, ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(expected, recv_hmac):
        return jsonify({"validHMAC": False, "message": "HMAC verification failed"})

    try:
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        student = json.loads(plaintext.decode())
        log(f"Received student: {student}")
        return jsonify({
            "validHMAC": True,
            "message": "Decrypted successfully",
            "student": student
        })
    except Exception as e:
        return jsonify({"validHMAC": True, "message": str(e)})

# ------------------ GUI ------------------

root = tk.Tk()
root.title("Secure Server Monitor")
root.geometry("600x400")

log_box = ScrolledText(root)
log_box.pack(expand=True, fill='both')


def log(msg):
    log_box.insert(tk.END, msg + "\n")
    log_box.see(tk.END)

# ------------------ Threading ------------------

def run_server():
    app.run(port=8080, debug=False, use_reloader=False)

threading.Thread(target=run_server, daemon=True).start()
log("Server running on http://localhost:8080")

root.mainloop()
