#Kelompok   : 1
#Kelas      : CIS 2025
#Anggota 1  : Muhammad Fahreza Azka Arafat - 2106752331
#Anggota 2  : Arditio Reihansyah Putra Pradana - 2106751972


from sympy import randprime
from random import randint
import hashlib
import os
import tkinter as tk
from tkinter import messagebox, filedialog

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
    #Calculate the length of the modulus in bytes
    n_bytes = (public_key[1].bit_length() + 7) // 8
    #Convert the plaintext to bytes
    message_bytes = message.encode()
    #Apply OAEP padding to the message
    em = oaep_encode(message_bytes, n_bytes)
    #Convert the padded message to an integer for RSA encryption
    m_int = int.from_bytes(em, "big")
    #Check if the integer representation is too large for the modulus
    if m_int > public_key[1]:
        raise ValueError("Message too long for this key size")
    #Perform RSA encryption using the public key: ciphertext = m_int^e mod n
    cyphertext = pow(m_int, public_key[0], public_key[1])
    #Return the ciphertext as an integer
    return cyphertext

def decrypt(ciphertext, private_key):
    #Calculate the number of bytes needed to represent the modulus n
    n_bytes = (private_key[1].bit_length() + 7) // 8
    #Perform RSA decryption using the private key: m_int = ciphertext^d mod n
    m_int = pow(ciphertext, private_key[0], private_key[1])
    #Convert the decrypted integer back to bytes to obtain OAEP encoded message
    em = m_int.to_bytes(n_bytes, "big")
    #Remove OAEP padding from the decrypted message to obtain the original message
    message_bytes = oaep_decode(em, n_bytes)
    #Decrypt the bytes to a UTF-8 string
    return message_bytes.decode("utf-8")

def mgf1(seed, length, hash_func=hashlib.sha256):
    #Init counter and output = b""
    counter = 0
    output = b""
    #Generate the mask until the output length is met
    while len(output) < length:
        #Convert counter to 4 byte big endian
        C = counter.to_bytes(4, byteorder="big")
        #Hash the seed concatenated with the counter
        output += hash_func(seed + C).digest()
        counter += 1
    return output[:length]

def oaep_encode(message, k, label=b"", hash_func=hashlib.sha256):
    # k: length of modulus in bytes
    mLen = len(message) #Message length in bytes
    hLen = hash_func().digest_size #Hash output length
    #1. Hash the label
    lHash = hash_func(label).digest()
    #2. Initialize the padding string of zero bytes
    ps = b"\x00" * (k - mLen - 2 * hLen - 2)
    #3. Concatenate the label hash, padding string, 0x01 byte, and the message to obtain the data block
    db = lHash + ps + b"\x01" + message
    #4. Genarate a random seed of hLen bytes
    seed = os.urandom(hLen)
    #5. Generate the dbMask using MGF1 with the seed
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    #6. XOR the data block with dbMask to obtain the masked data block
    maskedDB = bytes([db[i] ^ dbMask[i] for i in range(len(db))])
    #7. Generate the seedMask using MGF1 with the masked data block
    seedMask = mgf1(maskedDB, hLen, hash_func)
    #8. XOR the seed with seedMask to obtain the masked seed
    maskedSeed = bytes([seed[i] ^ seedMask[i] for i in range(hLen)])
    #9. Concatenate 0x00, maskedSeed, and maskedDB to get the encoded message (EM)
    return b"\x00" + maskedSeed + maskedDB

def oaep_decode(em, k, label=b"", hash_func=hashlib.sha256):
    #hLen: length of the hash output
    hLen = hash_func().digest_size
    #1. Hash the label
    lHash = hash_func(label).digest()
    #2. Check encoded message length and the leading byte
    if len(em) != k or em[0] != 0:
        raise ValueError("Decryption error")
    #3. Split the encoded message into masked seed and masked data block
    maskedSeed = em[1:hLen+1]
    maskedDB = em[hLen+1:]
    #4. Unmask the seed using MGF1 and masked data block
    seedMask = mgf1(maskedDB, hLen, hash_func)
    seed = bytes([maskedSeed[i] ^ seedMask[i] for i in range(hLen)])
    #5. Unmask the data block using MGF1 and the obtained seed
    dbMask = mgf1(seed, k - hLen - 1, hash_func)
    db = bytes([maskedDB[i] ^ dbMask[i] for i in range(len(maskedDB))])
    #6. Check if the label hash matches
    lHash_ = db[:hLen]
    if lHash_ != lHash:
        raise ValueError("Decryption error")
    #7. Find the 0x01 separator to know the start of the message
    i = hLen
    while i < len(db):
        if db[i] == 1:
            break
        elif db[i] != 0:
            raise ValueError("Decryption error")
        i += 1
    #8. Return original message (bytes after the 0x01 separator)
    return db[i+1:]

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

        self.save_pub_btn = tk.Button(self.key_frame, text="Save Public Key", command=self.save_public_key)
        self.save_pub_btn.pack(pady=2)
        self.save_priv_btn = tk.Button(self.key_frame, text="Save Private Key", command=self.save_private_key)
        self.save_priv_btn.pack(pady=2)

        self.load_pub_btn = tk.Button(self.key_frame, text="Load Public Key", command=self.load_public_key)
        self.load_pub_btn.pack(pady=2)
        self.load_priv_btn = tk.Button(self.key_frame, text="Load Private Key", command=self.load_private_key)
        self.load_priv_btn.pack(pady=2)

        self.pub_key_label = tk.Label(self.key_frame, text="Public Key: None")
        self.pub_key_label.pack()
        self.priv_key_label = tk.Label(self.key_frame, text="Private Key: None")
        self.priv_key_label.pack()

        # Encryption/Decryption
        self.encrypt_frame = tk.LabelFrame(master, text="Encryption/Decryption")
        self.encrypt_frame.pack(padx=10, pady=5, fill="x")

        # File Encryption
        self.file_encrypt_btn = tk.Button(self.encrypt_frame, text="Encrypt File", command=self.encrypt_file)
        self.file_encrypt_btn.pack(pady=5)
        self.file_label = tk.Label(self.encrypt_frame, text="No file selected")
        self.file_label.pack()

        # Decryption
        self.decrypt_frame = tk.LabelFrame(master, text="Decryption")
        self.decrypt_frame.pack(padx=10, pady=5, fill="x")

        self.file_decrypt_btn = tk.Button(self.encrypt_frame, text="Decrypt File", command=self.decrypt_file)
        self.file_decrypt_btn.pack(pady=5)

    def generate_keys(self):
        self.public_key, self.private_key = keygenerator()
        def truncate_num(num, maxlen=10):
            num_str = str(num)
            if len(num_str) > maxlen * 2:
                return num_str[:maxlen] + "..." + num_str[-maxlen:]
            return num_str
        def truncate_key(key):
            e_or_d, n = key
            return f"({truncate_num(e_or_d)}, {truncate_num(n)})"
        self.pub_key_label.config(text=f"Public Key: {truncate_key(self.public_key)}")
        self.priv_key_label.config(text=f"Private Key: {truncate_key(self.private_key)}")

    #Key Save/Load
    def save_public_key(self):
        if not self.public_key:
            messagebox.showerror("Error", "No public key to save.")
            return
        #Save as .pub (decimal)
        file_path = filedialog.asksaveasfilename(defaultextension=".pub", filetypes=[("Public Key", "*.pub"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(f"{self.public_key[0]}\n{self.public_key[1]}")
            messagebox.showinfo("Saved", "Public key saved.")
        #Save as .txt (hexadecimal)
        hex_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt"), ("All Files", "*.*")], title="Save Public Key as Hexadecimal")
        if hex_path:
            with open(hex_path, "w") as f:
                f.write(f"{hex(self.public_key[0])[2:]}\n{hex(self.public_key[1])[2:]}")
            messagebox.showinfo("Saved", "Public key (hex) saved.")

    def save_private_key(self):
        if not self.private_key:
            messagebox.showerror("Error", "No private key to save.")
            return
        #Save as .pri (decimal)
        file_path = filedialog.asksaveasfilename(defaultextension=".pri", filetypes=[("Private Key", "*.pri"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "w") as f:
                f.write(f"{self.private_key[0]}\n{self.private_key[1]}")
            messagebox.showinfo("Saved", "Private key saved.")
        #Save as .txt (hexadecimal)
        hex_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt"), ("All Files", "*.*")], title="Save Private Key as Hexadecimal")
        if hex_path:
            with open(hex_path, "w") as f:
                f.write(f"{hex(self.private_key[0])[2:]}\n{hex(self.private_key[1])[2:]}")
            messagebox.showinfo("Saved", "Private key (hex) saved.")

    def load_public_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Public Key", "*.pub"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as f:
                lines = f.read().splitlines()
                self.public_key = (int(lines[0]), int(lines[1]))
            self.pub_key_label.config(text=f"Public Key loaded from file.")

    def load_private_key(self):
        file_path = filedialog.askopenfilename(filetypes=[("Private Key", "*.pri"), ("All Files", "*.*")])
        if file_path:
            with open(file_path, "r") as f:
                lines = f.read().splitlines()
                self.private_key = (int(lines[0]), int(lines[1]))
            self.priv_key_label.config(text=f"Private Key loaded from file.")
    
    #File Encryption
    def encrypt_file(self):
        if not self.public_key:
            messagebox.showerror("Error", "Please load a public key first.")
            return
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                self.file_label.config(text=f"Loaded: {file_path}")

                #RSA can only encrypt data up to a certain size (for 2048-bit keys, much less than 256 bytes after OAEP padding).
                #This piece of code calculates the maximum plaintext size per block that can be safely OAEP-padded and encrypted with RSA.
                n_bytes = (self.public_key[1].bit_length() + 7) // 8
                hLen = hashlib.sha256().digest_size
                max_block = n_bytes - 2 * hLen - 2

                encrypted_blocks = []
                #Read the file in binary and split it into chunks of max_block bytes.
                #Each chunk is OAEP-padded and encrypted separately
                for i in range(0, len(file_data), max_block):
                    chunk = file_data[i:i+max_block]
                    em = oaep_encode(chunk, n_bytes)
                    m_int = int.from_bytes(em, "big")
                    if m_int > self.public_key[1]:
                        raise ValueError("Block too large for key size")
                    c = pow(m_int, self.public_key[0], self.public_key[1])
                    encrypted_blocks.append(c.to_bytes(n_bytes, "big"))

                #Store extension as 10 bytes to preserve the extension
                ext = os.path.splitext(file_path)[1][:9]  #max 9 chars + null
                ext_bytes = ext.encode().ljust(10, b' ')

                out_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Encrypted Bin", "*.bin"), ("All Files", "*.*")])
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(ext_bytes)
                        for block in encrypted_blocks:
                            f.write(block)
                    messagebox.showinfo("Success", f"File encrypted and saved as {out_path}")
            except Exception as e:
                messagebox.showerror("File Error", f"Failed to encrypt file: {e}")
        else:
            self.file_label.config(text="No file selected")

    #File Decryption
    #Mirrors the encryption process, reading the file in blocks of n_bytes, decrypting each block and concatenating the results.
    def decrypt_file(self):
        if not self.private_key:
            messagebox.showerror("Error", "Please load a private key first.")
            return
        file_path = filedialog.askopenfilename(title="Select file to decrypt", filetypes=[("Encrypted Bin", "*.bin"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    ext_bytes = f.read(10)
                    encrypted_data = f.read()
                ext = ext_bytes.decode().strip() or ".bin"
                n_bytes = (self.private_key[1].bit_length() + 7) // 8
                hLen = hashlib.sha256().digest_size

                decrypted_bytes = b""
                for i in range(0, len(encrypted_data), n_bytes):
                    block = encrypted_data[i:i+n_bytes]
                    c = int.from_bytes(block, "big")
                    m_int = pow(c, self.private_key[0], self.private_key[1])
                    em = m_int.to_bytes(n_bytes, "big")
                    chunk = oaep_decode(em, n_bytes)
                    decrypted_bytes += chunk

                #Save with original extension
                out_path = filedialog.asksaveasfilename(
                    title="Save decrypted file as",
                    defaultextension=ext,
                    filetypes=[("Original File", f"*{ext}"), ("All Files", "*.*")]
                )
                if out_path:
                    with open(out_path, "wb") as f:
                        f.write(decrypted_bytes)
                    messagebox.showinfo("Success", f"File decrypted and saved as {out_path}")
            except Exception as e:
                messagebox.showerror("File Error", f"Failed to decrypt file: {e}")
        

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("727x727")
    root.resizable(False, False)
    app = RSAGUI(root)
    root.mainloop()