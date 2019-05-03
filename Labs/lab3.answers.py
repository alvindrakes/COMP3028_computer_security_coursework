import os
import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from base64 import b16encode
backend = default_backend()

# This is our fictitious server - feel free to look at its code for tips
from servers import EncryptionServer
server = EncryptionServer()

### Hashing ###
# Hash the following messages using SHA256
message_one = b'This is a message we\'d like to hash. It includes a number #0112933.'
message_two = b'This is a message we\'d like to hash. It includes a number #0112934.'

hash_fn = hashes.Hash(hashes.SHA256(), backend=default_backend())
hash_fn.update(message_one)
message_one_hash = hash_fn.finalize()
print (b16encode(message_one_hash))

hash_fn = hashes.Hash(hashes.SHA256(), backend=default_backend())
hash_fn.update(message_two)
message_two_hash = hash_fn.finalize()
print (b16encode(message_two_hash))

# Load the entire works of Shakespeare into a bytes object
with open('./data/shakespeare.txt', 'rb') as f:
    data = f.read()

# Use the SHA-256 hash function to hash the entire works of Shakespeare
hash_fn = hashes.Hash(hashes.SHA256(), backend=default_backend())
hash_fn.update(data)
shakespeare_hash = hash_fn.finalize()
print (b16encode(shakespeare_hash))


### Asymmetric Cryptography ###
# Load server public key.
with open('./data/rsa_public.pem', 'r') as f:
    pem_data = f.read().encode("UTF-8")
    server_rsa_public_key = load_pem_public_key(data=pem_data,
                                                backend=backend)

# Create a challenge token
message = os.urandom(64)

# Have the server sign it
signed_message = server.sign_document(message)

# Verify the signature
try:
    # Verify the signed message using public_key.verify()
    server_rsa_public_key.verify(
        signed_message,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print ("The server successfully signed the message.")
except InvalidSignature:
    print("The server failed our signature verification.")



### Digital Certificates ###
# Load certificate chain
def get_bytes(str):
    with open(str, 'rb') as f:
        data = f.read()
    return data

certificate = load_pem_x509_certificate(get_bytes('./data/certs/nottingham.pem'),backend)
inter = load_pem_x509_certificate(get_bytes('./data/certs/intermediate.pem'),backend)
root = load_pem_x509_certificate(get_bytes('./data/certs/root.ca.pem'),backend)

inter_public_key = inter.public_key()
root_public_key = root.public_key()

# Validate signatures x3
try:
    inter_public_key.verify(certificate.signature,
                            certificate.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            certificate.signature_hash_algorithm)
    print("Server certificate signature is valid")
except InvalidSignature:
    print("Server certificate signature is invalid")

try:
    root_public_key.verify(inter.signature,
                           inter.tbs_certificate_bytes,
                           padding.PKCS1v15(),
                           inter.signature_hash_algorithm)
    print("Intermediate certificate signature is valid")
except InvalidSignature:
    print("The intermediate certificate failed our signature verification!")

try:
    root_public_key.verify(root.signature,
                           root.tbs_certificate_bytes,
                           padding.PKCS1v15(),
                           root.signature_hash_algorithm)
    print("Root certificate signature is valid")
except InvalidSignature:
    print("The root certificate failed our signature verification!")

# Validate certificate valid periods x3
current_time = datetime.datetime.utcnow()
if certificate.not_valid_before <= current_time <= certificate.not_valid_after:
    print ("Server certificate period is valid.")
else:
    print ("Server certificate period not valid")

if inter.not_valid_before <= current_time <= inter.not_valid_after:
    print ("Intermediate certificate period is valid.")
else:
    print ("Intermediate certificate period not valid")

if root.not_valid_before <= current_time <= root.not_valid_after:
    print ("Root certificate period is valid.")
else:
    print ("Root certificate period not valid")

# Optional: verify KeyUsage x3
from cryptography import x509

cert_keyusage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
inter_keyusage = inter.extensions.get_extension_for_class(x509.KeyUsage).value
root_keyusage = root.extensions.get_extension_for_class(x509.KeyUsage).value

if cert_keyusage.key_encipherment and cert_keyusage.digital_signature:
	print ("Server KeyUsage is valid.")
else:
	print ("Server KeyUsage is not valid.")

if inter_keyusage.key_cert_sign:
	print ("Inter KeyUsage is valid.")
else:
	print ("Inter KeyUsage is not valid.")

if root_keyusage.key_cert_sign:
	print ("Root KeyUsage is valid.")
else:
	print ("Root KeyUsage is not valid.")