import base64
import binascii

from flask import jsonify
from flask_restful import reqparse, abort, Api, Resource

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from . import api

allowed_key_size_choices = [1024, 2048, 3072]
rsa_key_parser = reqparse.RequestParser()
rsa_key_parser.add_argument(
    "key_size",
    required=True,
    type=int,
    choices=allowed_key_size_choices,
    help=f"Available key size choices are {', '.join([str(x) for x in allowed_key_size_choices])}",
)


class RSAKey(Resource):
    def post(self):
        args = rsa_key_parser.parse_args()
        key_size = args["key_size"]

        key_pair = RSA.generate(key_size)
        public_key = key_pair.publickey().exportKey("PEM")
        private_key = key_pair.exportKey("PEM")

        public_key_str = public_key.decode("ascii")
        private_key_str = private_key.decode("ascii")
        data = dict(public_key=public_key_str, private_key=private_key_str)

        return jsonify(data)


rsa_encrypt_parser = reqparse.RequestParser()
rsa_encrypt_parser.add_argument("public_key", required=True)
rsa_encrypt_parser.add_argument("message", required=True)


class RSAEncrypt(Resource):
    def post(self):
        args = rsa_encrypt_parser.parse_args()
        public_key = RSA.importKey(args["public_key"])
        message = args["message"]

        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = encryptor.encrypt(str.encode(message))

        # we return a base64 representation
        data = dict(encrypted_message=base64.b64encode(encrypted).decode("ascii"))

        return jsonify(data)


rsa_decrypt_parser = reqparse.RequestParser()
rsa_decrypt_parser.add_argument("private_key", required=True)
rsa_decrypt_parser.add_argument("encrypted_message", required=True)


class RSADecrypt(Resource):
    def post(self):
        args = rsa_decrypt_parser.parse_args()
        private_key = RSA.import_key(args["private_key"])
        # decrypt the base64 representation to get the encrypted bytes
        encrypted_message = base64.b64decode(args["encrypted_message"])

        decryptor = PKCS1_OAEP.new(private_key)
        decrypted = decryptor.decrypt(encrypted_message)

        data = dict(decrypted_message=decrypted.decode())

        return jsonify(data)


api.add_resource(RSAKey, "/rsa/key")
api.add_resource(RSAEncrypt, "/rsa/encrypt")
api.add_resource(RSADecrypt, "/rsa/decrypt")
