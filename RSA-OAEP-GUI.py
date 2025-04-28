#Kelompok   : 1
#Kelas      : CIS 2025
#Anggota 1  : Muhammad Fahreza Azka Arafat - 2106752331
#Anggota 2  : Arditio Reihansyah Putra Pradana - 2106751972


from sympy import randprime
from random import randint
import hashlib
import os

def randomprimegenerator(bits):
    #Lower bound if 2048 2^2047
    lower_bound = 2**(bits - 1)
    #Upper bound if 2048 2^2048 - 1
    upper_bound = 2**bits - 1
    prime = randprime(lower_bound, upper_bound)
    return prime

#Sourced from slide 4 CIS 2025 page 36
def extendedeuclidean(a, b):
    if b == 0:
        return a, 1, 0
    else:
        x2, x1, y2, y1 = 1, 0, 0, 1
        r = 0
        while b > 0:
            q = a // b
            r = a - q * b
            x = x2 - q * x1
            y = y2 - q * y1
            a, b = b, r
            x2, x1 = x1, x
            y2, y1 = y1, y
        return a, x2, y2

#Adapted from slide 9 CIS 2025 page 18
def encryptionkeygenerator(phi):
    while True:
        # 1 < e < phi also gcd(e, phi) = 1
        e = randint(2, phi - 1)
        gcd = extendedeuclidean(e, phi)[0]
        if gcd == 1:
            break
    return e

#Adapted from slide 9 CIS 2025 page 18
def keygenerator():
    p = randomprimegenerator(1024)
    q = randomprimegenerator(1024)

    n = p * q
    phi = (p - 1) * (q - 1)
    e = encryptionkeygenerator(phi)
    d = extendedeuclidean(e, phi)[1] % phi

    return (e, n), (d, n)

def encrypt(message, public_key):
    # OAEP encode
    n_bytes = (public_key[1].bit_length() + 7) // 8
    message_bytes = message.encode()
    em = oaep_encode(message_bytes, n_bytes)
    m_int = int.from_bytes(em, "big")
    if m_int > public_key[1]:
        raise ValueError("Message too long for this key size")
    cyphertext = pow(m_int, public_key[0], public_key[1])
    return cyphertext

def decrypt(ciphertext, private_key):
    n_bytes = (private_key[1].bit_length() + 7) // 8
    m_int = pow(ciphertext, private_key[0], private_key[1])
    em = m_int.to_bytes(n_bytes, "big")
    message_bytes = oaep_decode(em, n_bytes)
    return message_bytes.decode("utf-8")

def mgf1(seed, length, hash_func=hashlib.sha256):
    counter = 0
    output = b""
    while len(output) < length:
        C = counter.to_bytes(4, byteorder="big")
        output += hash_func(seed + C).digest()
        counter += 1
    return output[:length]

def oaep_encode(message, k, label=b"", hash_func=hashlib.sha256):
    # k: length of modulus in bytes
    mLen = len(message)
    hLen = hash_func().digest_size
    lHash = hash_func(label).digest()
    ps = b"\x00" * (k - mLen - 2 * hLen - 2)
    db = lHash + ps + b"\x01" + message
    seed = os.urandom(hLen)
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    maskedDB = bytes([db[i] ^ dbMask[i] for i in range(len(db))])
    seedMask = mgf1(maskedDB, hLen, hash_func)
    maskedSeed = bytes([seed[i] ^ seedMask[i] for i in range(hLen)])
    return b"\x00" + maskedSeed + maskedDB

def oaep_decode(em, k, label=b"", hash_func=hashlib.sha256):
    hLen = hash_func().digest_size
    lHash = hash_func(label).digest()
    if len(em) != k or em[0] != 0:
        raise ValueError("Decryption error")
    maskedSeed = em[1:hLen+1]
    maskedDB = em[hLen+1:]
    seedMask = mgf1(maskedDB, hLen, hash_func)
    seed = bytes([maskedSeed[i] ^ seedMask[i] for i in range(hLen)])
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    db = bytes([maskedDB[i] ^ dbMask[i] for i in range(len(maskedDB))])
    lHash_ = db[:hLen]
    if lHash_ != lHash:
        raise ValueError("Decryption error")
    # Find the 0x01 separator
    i = hLen
    while i < len(db):
        if db[i] == 1:
            break
        elif db[i] != 0:
            raise ValueError("Decryption error")
        i += 1
    return db[i+1:]

import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog

class RSAGUI:
    def __init__(self, master):
        self.master = master
        master.title("RSA Encryption/Decryption GUI")

        self.public_key = None
        self.private_key = None

        # Key Generation
        self.key_frame = tk.LabelFrame(master, text="Key Generation")
        self.key_frame.pack(padx=10, pady=5, fill="x")

        self.gen_key_btn = tk.Button(self.key_frame, text="Generate Keys", command=self.generate_keys)
        self.gen_key_btn.pack(pady=5)

        self.pub_key_label = tk.Label(self.key_frame, text="Public Key: None")
        self.pub_key_label.pack()
        self.priv_key_label = tk.Label(self.key_frame, text="Private Key: None")
        self.priv_key_label.pack()

        # Encryption
        self.encrypt_frame = tk.LabelFrame(master, text="Encryption")
        self.encrypt_frame.pack(padx=10, pady=5, fill="x")

        self.msg_entry = tk.Entry(self.encrypt_frame, width=50)
        self.msg_entry.pack(pady=5)
        self.encrypt_btn = tk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt_message)
        self.encrypt_btn.pack(pady=5)
        self.encrypted_text = scrolledtext.ScrolledText(self.encrypt_frame, height=3, width=60)
        self.encrypted_text.pack()

        # File Encryption
        self.file_encrypt_btn = tk.Button(self.encrypt_frame, text="Encrypt File", command=self.encrypt_file)
        self.file_encrypt_btn.pack(pady=5)
        self.file_label = tk.Label(self.encrypt_frame, text="No file selected")
        self.file_label.pack()

        # Decryption
        self.decrypt_frame = tk.LabelFrame(master, text="Decryption")
        self.decrypt_frame.pack(padx=10, pady=5, fill="x")

        self.decrypt_entry = tk.Entry(self.decrypt_frame, width=50)
        self.decrypt_entry.pack(pady=5)
        self.decrypt_btn = tk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt_message)
        self.decrypt_btn.pack(pady=5)
        self.decrypted_text = tk.Label(self.decrypt_frame, text="Decrypted Message: ")
        self.decrypted_text.pack()

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                self.file_label.config(text=f"Loaded: {file_path}")
                # Placeholder: actual encryption not implemented yet
                messagebox.showinfo("File Loaded", f"File '{file_path}' loaded successfully.\n(Size: {len(file_data)} bytes)")
            except Exception as e:
                messagebox.showerror("File Error", f"Failed to load file: {e}")
        else:
            self.file_label.config(text="No file selected")

    def generate_keys(self):
        self.public_key, self.private_key = keygenerator()
        self.pub_key_label.config(text=f"Public Key: {self.public_key}")
        self.priv_key_label.config(text=f"Private Key: {self.private_key}")

    def encrypt_message(self):
        if not self.public_key:
            messagebox.showerror("Error", "Please generate keys first.")
            return
        msg = self.msg_entry.get()
        try:
            encrypted = encrypt(msg, self.public_key)
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert(tk.END, str(encrypted))
            self.decrypt_entry.delete(0, tk.END)
            self.decrypt_entry.insert(0, str(encrypted))
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))

    def decrypt_message(self):
        if not self.private_key:
            messagebox.showerror("Error", "Please generate keys first.")
            return
        try:
            encrypted = int(self.decrypt_entry.get())
            decrypted = decrypt(encrypted, self.private_key)
            self.decrypted_text.config(text=f"Decrypted Message: {decrypted}")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = RSAGUI(root)
    root.mainloop()