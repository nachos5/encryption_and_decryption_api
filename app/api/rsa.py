import base64
import binascii

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from . import api

rsa_encrypt_parser = reqparse.RequestParser()
rsa_encrypt_parser.add_argument("public_key", required=True, type=str)
rsa_encrypt_parser.add_argument("message", required=True, type=str)


class RSAEncrypt(Resource):
    @api.expect(rsa_encrypt_parser)
    @api.doc(responses={200: "Success", 400: "Validation Error"})
    def get(self):
        args = rsa_encrypt_parser.parse_args()
        try:
            public_key_str = args["public_key"].replace(
                "\\n", "\n"
            )  # for sending through URL
            public_key = RSA.import_key(public_key_str)
        except Exception as e:
            print(e)
            abort(400, "Invalid public key format.")
        message = args["message"]

        encryptor = PKCS1_OAEP.new(public_key)
        encrypted = encryptor.encrypt(str.encode(message))

        # we return a base64 representation
        data = {"encrypted_message": base64.b64encode(encrypted).decode("ascii")}

        return jsonify(data)


rsa_decrypt_parser = reqparse.RequestParser()
rsa_decrypt_parser.add_argument("private_key", required=True, type=str)
rsa_decrypt_parser.add_argument(
    "encrypted_message",
    required=True,
    type=str,
    help="Encrypted message in base64 format.",
)


class RSADecrypt(Resource):
    @api.expect(rsa_decrypt_parser)
    @api.doc(responses={200: "Success", 400: "Validation Error"})
    def get(self):
        args = rsa_decrypt_parser.parse_args()
        try:
            private_key_str = args["private_key"].replace(
                "\\n", "\n"
            )  # for sending through URL
            private_key = RSA.importKey(private_key_str)
        except Exception as e:
            print(e)
            abort(400, "Invalid private key format.")
        # decrypt the base64 representation to get the encrypted bytes
        encrypted_message = base64.b64decode(args["encrypted_message"])

        decryptor = PKCS1_OAEP.new(private_key)
        decrypted = decryptor.decrypt(encrypted_message)

        data = dict(decrypted_message=decrypted.decode())

        return jsonify(data)


ns = api.namespace("rsa", description="RSA operations")
ns.add_resource(RSAEncrypt, "/encrypt")
ns.add_resource(RSADecrypt, "/decrypt")
