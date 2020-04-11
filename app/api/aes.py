import base64

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from . import api

aes_encrypt_parser = reqparse.RequestParser()
aes_encrypt_parser.add_argument(
    "key", required=True, type=str, help="the key has to be base64 encoded."
)
aes_encrypt_parser.add_argument("message", required=True, type=str)
modes = ["ECB", "CBC", "CTR"]
aes_encrypt_parser.add_argument(
    "mode",
    type=str,
    required=True,
    choices=modes,
    help=f"Invalid mode, must be {modes}.",
)


class AESEncrypt(Resource):
    @api.expect(aes_encrypt_parser)
    @api.doc(responses={200: "Success", 400: "Validation Error", 500: "Internal Error"})
    def post(self):
        args = aes_encrypt_parser.parse_args()
        key_bytes = base64.b64decode(args["key"])
        encoded_message = args["message"].encode("utf-8")
        padding = pad(encoded_message, AES.block_size)
        mode = args["mode"]

        try:
            if mode == "ECB":
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                encrypted_message = cipher.encrypt(padding)
            elif mode == "CBC":
                cipher = AES.new(key_bytes, AES.MODE_CBC)
                encrypted_message = cipher.iv + cipher.encrypt(padding)
            elif mode == "CTR":
                salt = base64.b64encode(get_random_bytes(512))
                cipher = AES.new(
                    key_bytes, AES.MODE_CTR, nonce=salt[: AES.block_size - 1]
                )
                encrypted_message = cipher.nonce + cipher.encrypt(encoded_message)
        except Exception as e:
            print(e)
            abort(500, "Internal Error")

        return base64.b64encode(encrypted_message).decode("ascii")


aes_decrypt_parser = reqparse.RequestParser()
aes_decrypt_parser.add_argument(
    "key", required=True, type=str, help="the key has to be base64 encoded."
)
aes_decrypt_parser.add_argument(
    "encrypted_message",
    required=True,
    type=str,
    help="Encrypted message in base64 format.",
)
aes_decrypt_parser.add_argument(
    "mode",
    type=str,
    required=True,
    choices=modes,
    help=f"Invalid mode, must be {modes}.",
)


class AESDecrypt(Resource):
    @api.expect(aes_decrypt_parser)
    @api.doc(responses={200: "Success", 400: "Validation Error", 500: "Internal Error"})
    def post(self):
        args = aes_decrypt_parser.parse_args()
        key_bytes = base64.b64decode(args["key"])
        encrypted_message_bytes = base64.b64decode(args["encrypted_message"])
        mode = args["mode"]

        try:
            if mode == "ECB":
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                final_bytes = unpad(
                    cipher.decrypt(encrypted_message_bytes), AES.block_size
                )
            elif mode == "CBC":
                cipher = AES.new(
                    key_bytes, AES.MODE_CBC, encrypted_message_bytes[: AES.block_size]
                )
                final_bytes = unpad(
                    cipher.decrypt(encrypted_message_bytes[AES.block_size :]),
                    AES.block_size,
                )
            elif mode == "CTR":
                cipher = AES.new(
                    key_bytes,
                    AES.MODE_CTR,
                    nonce=encrypted_message_bytes[: AES.block_size - 1],
                )
                final_bytes = cipher.decrypt(
                    encrypted_message_bytes[AES.block_size - 1 :]
                )
        except Exception as e:
            print(e)
            abort(500, "Internal Error")

        return final_bytes.decode("utf-8")


ns = api.namespace("aes", description="AES operations")
ns.add_resource(AESEncrypt, "/encrypt")
ns.add_resource(AESDecrypt, "/decrypt")
