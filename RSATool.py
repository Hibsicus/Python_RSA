# -*- coding: utf-8 -*-
"""
Created on Thu Oct 19 22:20:51 2017

@author: lhibi
"""

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes

def CreateRSAKeys():
    code = 'testname'
    
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=code, pkcs=8, protection="scryptAndAES128-CBC")
    
    with open('rsa_key.bin', 'wb') as f:
        f.write(encrypted_key)
        
    with open('rsa_public.pem', 'wb') as f:
        f.write(key.publickey().exportKey())
    
def Encrypt(filename):
    data = ''
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    with open(filename, 'wb') as out_file:
        #收件人秘鑰
        recipient_key = RSA.importKey(open('rsa_public.pem').read())
        session_key = get_random_bytes(16)
        
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text, tag = cipher_aes.encrypt_and_digest(data)
        
        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(cipher_text)
       
def Descrypt(filename):
    code = 'testname'
    with open(filename, 'rb') as fobj:
        private_key = RSA.import_key(open('rsa_key.bin').read(), passphrase=code)
        
        enc_session_key, nonce, tag, cipher_text = [fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        
        data = cipher_aes.decrypt_and_verify(cipher_text, tag)
        
    with open(filename, 'wb') as wobj:
        wobj.write(data)


if __name__ == "__main__":    
#    CreateRSAKeys()
#    Encrypt('test_rsa.txt')
    Descrypt('test_rsa.txt')
    
