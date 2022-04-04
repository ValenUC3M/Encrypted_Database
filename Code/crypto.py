import base64
import os
import sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class Cryptinaitor:
    def __init__(self, admin_key):
        # admin key defined for the super mega encrypt-hash of user
        self.admin_key = admin_key
        # this is the user in the db storage equivalent
        self.user_crypt_hashed = None
        # user key needed to encrypt users data in storage
        self.user_key = None
        self.password = None

    # key generator with salt and password given
    def pbkdf2(self, pwd, salt):
        # we change user from str to binary type data
        binary_data = pwd.encode("latin-1")
        # generation of b64 url safe type data from the binary_data
        b64url_binary_data = base64.urlsafe_b64encode(binary_data)
        # use of hash algorithm with length = 16 and salt given as parameter in byte type data
        # we first create the kdf with all the data needed for derivation
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000, )
        # derivation process stored in key var
        key = kdf.derive(b64url_binary_data)
        # return of the key in binary data type for storage in self.user_key
        return key

    # function to swap from binary data type to url safe b64 type
    def decodec_binary(self, binary_data):
        # we create de b64 equivalent
        binary_64_data = base64.urlsafe_b64encode(binary_data)
        # we transform it to str type for storage purposes only
        # return of the str b64 url safe transformation
        return binary_64_data.decode("ascii")

    # function to swap from url safe b64 str type data to original binary data
    def encodec_binary(self, binary_64_data_str):
        # change from str b64 to binary b64 type data for decoding
        binary_64_data = binary_64_data_str.encode("ascii")
        # we decode the b64 type data to the original binary type data
        # return of the original binary type data
        return base64.urlsafe_b64decode(binary_64_data)

    # hash method for password derivation for storage authentication
    def scrypt(self, text, salt):
        # calc of the kdf data for the derivation
        # salt is binary data type and text is str type
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, )
        # we need to transform into binary de text var
        binary_data = text.encode("latin-1")
        # derivation using binary text and the kdf
        key = kdf.derive(binary_data)
        # we return the b64 url safe str value for storage purposes
        return self.decodec_binary(key)

    # encryption using AES for general data tuples from db
    def AES_GCM_encrypt(self, data, nonce):
        # since we authenticate using sql methods we don't need aad
        aad = None
        # transform data into binary type data
        data = data.encode("ascii")
        # we take user key as the key for the encryption
        aesgcm = AESGCM(self.user_key)
        # data encrypt using given nonce and with aesgcm key
        encrypted_text = aesgcm.encrypt(nonce, data, aad)
        # we swap the encrypt to b64 str for storage purposes using decode
        return self.decodec_binary(encrypted_text)

    # decryption using AES for general data tuples from db
    def AES_GCM_decrypt(self, data, nonce):
        # since we authenticate using sql methods we don't need aad
        aad = None
        # take salt and nonce from data base tuple and transform back to binary
        data = self.encodec_binary(data)
        nonce = self.encodec_binary(nonce)
        # we take user key as the key for the encryption
        aesgcm = AESGCM(self.user_key)
        # decrypt using the nonce and the aesgcm given
        decrypted_text = aesgcm.decrypt(nonce, data, aad)
        # the original data needs to be decoded first
        return decrypted_text.decode("ascii")

    # kinda cool method but pretty useless actually xd
    # encryption with super hash for extra security and coolness
    def encrypt_user(self, data):
        # since we authenticate using sql methods we don't need aad
        aad = None
        # transform data into binary type data
        text = data[0].encode("ascii")
        # take salt and nonce from data base tuple and transform back to binary
        nonce = self.encodec_binary(data[3])
        salt = self.encodec_binary(data[2])
        # use the admin key (binary data) to encrypt
        aesgcm = AESGCM(self.admin_key)
        # encrypt using aesgcm and nonce given
        encrypted_text = aesgcm.encrypt(nonce, text, aad)
        # transform the binary data to b64 binary data
        b64url_binary_data = base64.urlsafe_b64encode(encrypted_text)
        # load the hash algorithm with salt given
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000, )
        # derivation of the b64 data with the kdf created
        key = kdf.derive(b64url_binary_data)
        # transform the binary data to str b64 data for storage purposes
        return self.decodec_binary(key)

    # tuple decrypt for big amounts of data from storage db
    def decrypt_list(self, data):
        # to make modifications we need to transform first to list type
        for i in range(len(data)):
            # from tuple type to list type
            data[i] = list(data[i])
        # for every index available in tuple
        for i in range(len(data)):
            # position 1 is for the object name so use the position 4 to decrypt it
            data[i][1] = self.AES_GCM_decrypt(data[i][1], data[i][4])
            # position 2 is for the object name so use the position 5 to decrypt it
            data[i][2] = self.AES_GCM_decrypt(data[i][2], data[i][5])
            # position 3 is for the object name so use the position 6 to decrypt it
            data[i][3] = self.AES_GCM_decrypt(data[i][3], data[i][6])
        # return the modified tuple of lists
        return data

    # does nothing yet, and probably forever
    def encrypt_list(self, data):
        # to make modifications we need to transform first to list type
        for i in range(len(data)):
            # from tuple type to list type
            data[i] = list(data[i])
        # for every index available in tuple
        for i in range(len(data)):
            data[i][4] = self.decodec_binary(os.urandom(12))
            data[i][5] = self.decodec_binary(os.urandom(12))
            data[i][6] = self.decodec_binary(os.urandom(12))
            data[i][1] = self.AES_GCM_encrypt(data[i][1], self.encodec_binary(data[i][4]))
            data[i][2] = self.AES_GCM_encrypt(data[i][2], self.encodec_binary(data[i][5]))
            data[i][3] = self.AES_GCM_encrypt(data[i][3], self.encodec_binary(data[i][6]))
        return data

    def RSA_create_key(self, password):
        # with password given first generate a private key object
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # aux array for key storage
        key_array = [None, None]
        # we need to now serialize both the public and the private keys for storage
        # first store the encrypted version of the private key using the private bytes method and the password
        key_array[0] = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("latin-1"))
        )
        # store the not encrypted version of the public key using public key method
        public_key = private_key.public_key()
        key_array[1] = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # return the array with both data serialized
        return key_array

    def undo_serialization(self, data, password=None):
        # when password not given, means its public key undo
        # first decode back to bytes the given key for proper use
        binary_data = self.encodec_binary(data)
        if password is None:
            # undo serialization with method given and binary data
            public_key = serialization.load_pem_public_key(
                binary_data,
            )
            # return of the public key object
            return public_key
        else:
            # undo serialization with method given, binary data and password in binary type
            private_key = serialization.load_pem_private_key(
                binary_data,
                password=self.password,
            )
            # return of the private key object
            return private_key

    def RSA_encrypt(self, message, public_key):
        # encrypt message using the method given with the message
        # message needs to be encoded first to bytes
        ciphertext = public_key.encrypt(
            message.encode("latin-1"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # return of str b64 version of ciphertext
        return self.decodec_binary(ciphertext)

    def RSA_decrypt(self, ciphertext, private_key):
        # decrypt message using the method given with the ciphertext
        # message needs to be decoded first to original bytes
        plaintext = private_key.decrypt(
            self.encodec_binary(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # return the decoded version of the original text
        return plaintext.decode("latin-1")

    def RSA_sign(self, private_key, message):
        signature = private_key.sign(
            message.encode("latin-1"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return self.decodec_binary(signature)

    def RSA_check_sign(self, public_key, message, signature):
        try:
            public_key.verify(
                self.encodec_binary(signature),
                message.encode("latin-1"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            # when invalid sign detected, return False
            print("warning: invalid sign detected")
            return 0
    # estatico
    def create_certificate(self, file_desc):
        # data del certificado
        data = file_desc.read()
        # crea un objeto certificado
        cert = x509.load_pem_x509_certificate(data)
        return cert

    def check_certificate(self, certificate_main, certificate_check):
        try:
            # public key del certificado
            var = certificate_check.public_key()
            var.verify(
                certificate_main.signature,
                certificate_main.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate_main.signature_hash_algorithm,
            )
            return True

        except:
            # when invalid sign detected, return False
            print("warning: invalid signature detected")
            return False


aux = Cryptinaitor(b'j7\x85\x1a9\xa0\x1b%\xe6\x08\x19\xeb:\xc3\xd2a')
# for test purposes
