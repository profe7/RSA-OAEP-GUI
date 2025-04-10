#Kelompok   : 1
#Kelas      : CIS 2025
#Anggota 1  : Muhammad Fahreza Azka Arafat - 2106752331
#Anggota 2  : Arditio Reihansyah Putra Pradana - 2106751972


from sympy import randprime
from random import randint

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

#Adapted from slide 9 CIS 2025 page 19
def encrypt(message, public_key):
    # Convert message to bytes and then to an integer
    message = int.from_bytes(message.encode(), "big")

    if message > public_key[1]:
        raise ValueError("Messsage exceeds the key size")
    
    # RSA encryption formula: c = m^e mod n
    cyphertext = (message ** public_key[0]) % public_key[1]
    return cyphertext

#Adapted from slide 9 CIS 2025 page 19
def decrypt(message, private_key):
    # RSA decryption formula: m = c^d mod n
    message = (message ** private_key[0]) % private_key[1]

    #Bytes to integer conversion, then to bytes, +7 to approximate the nearest byte size that can accomodate the message
    byte_len = (message.bit_length() + 7) // 8

    #Decode back to string
    message_bytes = message.to_bytes(byte_len, byteorder="big")

    return message_bytes.decode("utf-8")
    
#Debug
if __name__ == "__main__":
    public_key, private_key = keygenerator()
    print("Public Key:", public_key)
    print("Private Key:", private_key)
    print("e:", public_key[0])
    print("d:", private_key[0])

    input_message = input("Enter a message to encrypt: ")
    print("Original message:", input_message)
    encrypted_message = encrypt(input_message, public_key)
    print("Encrypted message:", encrypted_message)
    decrypted_message = decrypt(encrypted_message, private_key)
    print("Decrypted message:", decrypted_message)

