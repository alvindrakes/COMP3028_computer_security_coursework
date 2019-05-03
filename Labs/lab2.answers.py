import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# This is our fictitious server - feel free to look at its code for tips
from servers import EncryptionServer
server = EncryptionServer()

### Electronic Code Book ###
key = b'\xb4\xdd$4\xbb\xa4\xf4\x8d\x9c\x17\xfb\x1b\xd4Q?\xf8'
message = b"this is a 32 byte secret message"

cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
print(server.decrypt_aes_ecb(key, ciphertext))

### Counter Mode ###
# A new 128-bit key for AES
key = b'>SMNs^\xc0\xed\xc1\xc0SS\x9d\x8f&\x02'
message = b"This secret message is an arbitrary length, as CTR mode operates as a stream cipher."
nonce = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
print(server.decrypt_aes_ctr(key, nonce + ciphertext))


### Key Exchange ###
# Get server parameters (g,n)
parameters = server.get_parameters()

# Generate our private key (a)
private_key = parameters.generate_private_key()

# Generate a public key using our private key (g^a mod n)
public_key = private_key.public_key()

# Get server public key (g^b mod n)
server_public_key = server.get_public_key()

# Exchange for pre-master-secret (g^ab mod n)
shared_secret = private_key.exchange(server_public_key)

# Send our public key to the server so it can do the same
server.submit_public_key(public_key)


### Key Derivation ###
# Use HKDF to derive a symmetric key (256-bytes)
hkdf = HKDF(algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'g53sec',
                backend=default_backend())
aes_key = hkdf.derive(shared_secret)

# Get a message from the server encrypted using the new shared symmetric key
server_message = server.get_encrypted_message()
nonce = server_message[0:16]
ciphertext = server_message[16:]

# Use AES-CTR to decrypt the message
cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=backend)
encryptor = cipher.decryptor()
plaintext = encryptor.update(ciphertext) + encryptor.finalize()
print (plaintext)


### Authenticated Encryption ###
# Generate a random key and nonce pair
aead_key = os.urandom(32)
aead_nonce = os.urandom(12)

# The fictitious database record
record = {
    "ID": "0054",
    "Surname": "Smith",
    "FirstName": "John",
    "JoinDate": "2016-03-12",
    "LastLogin": "2017-05-19",
    "Address": "5 Mornington Crescent, London, WN1 1DA",
    "Nationality": "UK",
    "DOB": "1963-09-14",
    "NI": "JC123456C",
    "Phone": "01224103232",
    "Data": None,
    "Nonce": None,
}

# Encrypt record function
def encrypt_record(record, key, nonce):
    # Remove pass and provide implementation
    plaintext = '\x1f'.join(
        [v for k, v in record.items() if k in ['Address', 'Nationality', 'DOB', 'NI', 'Phone']]
    ).encode("UTF-8")

    ad = '\x1f'.join([v for k, v in record.items() if
                   k in ['ID', 'Surname', 'FirstName', 'JoinDate', 'LastLogin']]
    ).encode("UTF-8")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad)

    record.update({
        "Address": None,
        "Nationality": None,
        "DOB": None,
        "NI": None,
        "Phone": None,
        "Data": ciphertext,
        "Nonce": nonce,
    })

def decrypt_record(record, key):
    # Remove pass and provide implementation
    ad = '\x1f'.join([v for k, v in record.items() if
                      k in ['ID', 'Surname', 'FirstName', 'JoinDate', 'LastLogin']]).encode("UTF-8")

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(record["Nonce"], record["Data"], ad).decode("UTF-8").split('\x1f')

    record.update({
        "Address": plaintext[0],
        "Nationality": plaintext[1],
        "DOB": plaintext[2],
        "NI": plaintext[3],
        "Phone": plaintext[4],
        "Data": None,
        "Nonce": None,
    })

# Helper function, you dont need to change it
def print_record(record):
    print("{")
    for k, v in record.items():
        print(" ", k, ":", v)
    print("}")

# Encrypt the record and print it. All confidential fields should be "None" at this point
encrypt_record(record, aead_key, aead_nonce)
print_record(record)

# Decrypt the record and print it. All confidential fields should be restored
decrypt_record(record, aead_key)
print_record(record)