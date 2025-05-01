"""
DEMO-AKA cipher functions: Using AESGCM to encrypt/decrypt.
"""
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def AEAD_encrypt(key,nonce,data,aad) -> bytes:
    aesgcm = AESGCM(key)   
    ciphertext = aesgcm.encrypt(nonce, data, aad)    
    return ciphertext


def AEAD_decrypt(key,nonce,ciphertext,aad) -> bytes:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce,ciphertext, aad)
    return plaintext