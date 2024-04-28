from Crypto.Cipher import ChaCha20
from Crypto.Hash import BLAKE2s
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES3
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import time

def timed_function(func, *args, **kwargs):
    start_time = time.perf_counter()
    result = func(*args, **kwargs)
    end_time = time.perf_counter()
    return result, end_time - start_time

# Cha cha encryption
def encrypt_message_cha_cha(plaintext, key):
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_message_cha_cha(enc_info, key):
    enc_info = base64.b64decode(enc_info)
    nonce = enc_info[:8]
    ciphertext = enc_info[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# Salsa encryption
def encrypt_message_salsa20(plaintext, key):
    cipher = Salsa20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_message_salsa20(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    nonce = encrypted_message[:8]
    ciphertext = encrypted_message[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# AES_CTR encryption
def encrypt_message_aes_ctr(plaintext, key):
    cipher = AES.new(key, AES.MODE_CTR, nonce=get_random_bytes(8))
    ciphertext = cipher.encrypt(plaintext)
    nonce = cipher.nonce
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_message_aes_ctr(enc_info, key):
    enc_info = base64.b64decode(enc_info)
    nonce = enc_info[:8]  # Extract the nonce, which should be 8 bytes long
    ciphertext = enc_info[8:]
    # Use the same nonce for decryption
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# RSA Encryption and Decryption
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message_rsa(plaintext, public_key):
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(plaintext)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_rsa(encrypted_message, private_key):
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')

# Blowfish Encryption and Decryption
def encrypt_message_blowfish(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_plaintext = pad(plaintext, Blowfish.block_size)
    encrypted_message = cipher.encrypt(padded_plaintext)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_blowfish(encrypted_message, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(base64.b64decode(encrypted_message))
    decrypted_message = unpad(decrypted_padded_message, Blowfish.block_size)
    return decrypted_message.decode('utf-8')

# 3DES Encryption and Decryption
def encrypt_message_3des(plaintext, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_text = pad(plaintext, DES3.block_size)
    encrypted_message = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message_3des(encrypted_message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(base64.b64decode(encrypted_message))
    decrypted_message = unpad(decrypted_padded_message, DES3.block_size)
    return decrypted_message.decode('utf-8')

# Custom encryption
def generate_key(passphrase):
    """ Generate a secure key from a passphrase. """
    return hashlib.sha256(passphrase.encode('utf-8')).digest()

def simple_pseudo_random_stream(key, length):
    stream = b''
    counter = 0
    while len(stream) < length:
        counter_bytes = counter.to_bytes(8, 'little')
        hash_obj = hashlib.sha256(key + counter_bytes)
        stream += hash_obj.digest()
        counter += 1
    return stream[:length]

def encrypt_custom(plaintext, key):
    """ Encrypt the plaintext using a pseudo-random stream derived from the key. """
    key = hashlib.sha256(key).digest()
    pseudo_random_stream = simple_pseudo_random_stream(key, len(plaintext))
    ciphertext = bytes([p ^ s for p, s in zip(plaintext, pseudo_random_stream)])
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_custom(ciphertext, key):
    """ Decrypt the ciphertext using a pseudo-random stream derived from the key. """
    ciphertext = base64.b64decode(ciphertext)
    key = hashlib.sha256(key).digest()
    pseudo_random_stream = simple_pseudo_random_stream(key, len(ciphertext))
    plaintext = bytes([c ^ s for c, s in zip(ciphertext, pseudo_random_stream)])
    return plaintext.decode('utf-8')

def generate_blake_hash(data):
    hash_obj = BLAKE2s.new(digest_bits=256)
    hash_obj.update(data)
    return hash_obj.hexdigest()

# Generate keys
private_key_rsa, public_key_rsa = generate_rsa_keys()
key_3des = DES3.adjust_key_parity(get_random_bytes(24))
key_32_bytes = get_random_bytes(32)
key_aes = get_random_bytes(16)  # AES key needs to be 16 bytes for AES-128
key_custom = generate_key("secure_passphrase")

original_text = 'Hello IoT World!'
# Encrypt and time
encrypted_salsa, time_salsa = timed_function(encrypt_message_salsa20, original_text.encode('utf-8'), key_32_bytes)
encrypted_chacha, time_chacha = timed_function(encrypt_message_cha_cha, original_text.encode('utf-8'), key_32_bytes)
encrypted_aes, time_aes = timed_function(encrypt_message_aes_ctr, original_text.encode('utf-8'), key_aes)
encrypted_rsa, time_rsa = timed_function(encrypt_message_rsa, original_text.encode('utf-8'), public_key_rsa)
encrypted_3des, time_3des = timed_function(encrypt_message_3des, original_text.encode('utf-8'), key_3des)
encrypted_blowfish, time_blowfish = timed_function(encrypt_message_blowfish, original_text.encode('utf-8'), key_32_bytes)
encrypted_custom, time_enc_custom = timed_function(encrypt_custom, original_text.encode('utf-8'), key_custom)



# Decrypt and time
decrypted_salsa, time_dec_salsa = timed_function(decrypt_message_salsa20, encrypted_salsa, key_32_bytes)
decrypted_chacha, time_dec_chacha = timed_function(decrypt_message_cha_cha, encrypted_chacha, key_32_bytes)
decrypted_aes, time_dec_aes = timed_function(decrypt_message_aes_ctr, encrypted_aes, key_aes)
decrypted_rsa, time_dec_rsa = timed_function(decrypt_message_rsa, encrypted_rsa, private_key_rsa)
decrypted_3des, time_dec_3des = timed_function(decrypt_message_3des, encrypted_3des, key_3des)
decrypted_blowfish, time_dec_blowfish = timed_function(decrypt_message_blowfish, encrypted_blowfish, key_32_bytes)
decrypted_custom, time_dec_custom = timed_function(decrypt_custom, encrypted_custom, key_custom)

# Hash and time
hash_blake, time_blake = timed_function(generate_blake_hash, original_text.encode('utf-8'))

# Output results
print(f"salsa Encryption Time: {time_salsa:.6f}s, Decryption Time: {time_dec_salsa:.6f}s")
print(f"ChaCha20 Encryption Time: {time_chacha:.6f}s, Decryption Time: {time_dec_chacha:.6f}s")
print(f"AES-CTR Encryption Time: {time_aes:.6f}s, Decryption Time: {time_dec_aes:.6f}s")
print(f"RSA Encryption Time: {time_rsa:.6f}s, Decryption Time: {time_dec_rsa:.6f}s")
print(f"3DES Encryption Time: {time_3des:.6f}s, Decryption Time: {time_dec_3des:.6f}s")
print(f"Blowfish Encryption Time: {time_blowfish:.6f}s, Decryption Time: {time_dec_blowfish:.6f}s")
print(f"Custom Encryption Time: {time_enc_custom:.6f}s, Decryption Time: {time_dec_custom:.6f}s")



print(f"BLAKE2s Hashing Time: {time_blake:.6f}s")