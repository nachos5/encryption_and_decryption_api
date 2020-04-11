import binascii
from base64 import b64encode, b64decode

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

from . import api

# Triple DES
# 192 bit (24 bytes or 24 ASCII charactes) keys

# https://pycryptodome.readthedocs.io/en/latest/src/cipher/des3.html

# Option 1: key_1 != key_2 != key_3
# Option 2: key_1 == key_3 != key_2
# Option 3: key_1 == key_2 == key_3 -> Triple DES degrades to Single DES (not allowed)

allowed_modes = ["ECB", "CBC", "CFB", "OFB"]
allowed_iv_modes = ["base64", "utf-8"]

des3_encrypt_parser = reqparse.RequestParser()
des3_encrypt_parser.add_argument("key_1", required=True, type=str)
des3_encrypt_parser.add_argument("key_2", required=True, type=str)
des3_encrypt_parser.add_argument("key_3", required=True, type=str)
des3_encrypt_parser.add_argument(
    "mode",
    required=True,
    type=str,
    choices=allowed_modes,
    help=f"Invalid mode, must be {allowed_modes}.",
)
des3_encrypt_parser.add_argument("iv", type=str, help="initialization vector.")
des3_encrypt_parser.add_argument("message", required=True, type=str)


class DES3Encrypt(Resource):
    @api.expect(des3_encrypt_parser)
    @api.doc(response={200: "Success", 400: "Validation Error"})
    def post(self):
        args = des3_encrypt_parser.parse_args()
        key_1 = args["key_1"]
        key_2 = args["key_2"]
        key_3 = args["key_3"]
        mode = args["mode"].upper()
        iv = args["iv"]
        message = args["message"]

        try:
            key = DES3.adjust_key_parity(
                str.encode(key_1) + str.encode(key_2) + str.encode(key_3)
            )
        except Exception as e:
            print(e)
            abort(
                400,
                "Invalid key format, each key must be of length 8. The three keys must be different from each other or key_1 == key_3 != key_2",
            )

        if iv:
            if mode == "ECB":
                abort(400, "Mode 'ECB' doesn't use an Initialization vector")
            elif len(iv.encode("utf-8")) != 8:
                abort(400, "Initialization vector must be of length 8")
            else:
                iv = str.encode(iv)

        message = str.encode(message)

        try:
            # Electronic Code Book
            if mode == "ECB":
                cipher = DES3.new(key, DES3.MODE_ECB)
                encrypted = cipher.encrypt(pad(message, DES3.block_size))
                cipher_iv = ""
            # Cipher-Block Chaining
            elif mode == "CBC":
                cipher = DES3.new(key, DES3.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(message, DES3.block_size))
                cipher_iv = b64encode(cipher.iv).decode("utf-8")
            # Cipher FeedBack
            elif mode == "CFB":
                cipher = DES3.new(key, DES3.MODE_CFB, iv)
                encrypted = cipher.encrypt(message)
                cipher_iv = b64encode(cipher.iv).decode("utf-8")
            # Output FeedBack
            elif mode == "OFB":
                cipher = DES3.new(key, DES3.MODE_OFB, iv)
                encrypted = cipher.encrypt(message)
                cipher_iv = b64encode(cipher.iv).decode("utf-8")
        except Exception as e:
            print(e)
            abort(500, "Unknown error")

        # Return base64
        data = {
            "iv": cipher_iv,
            "encrypted_message": b64encode(encrypted).decode("utf-8"),
        }

        return jsonify(data)


des3_decrypt_parser = reqparse.RequestParser()
des3_decrypt_parser.add_argument("key_1", required=True, type=str)
des3_decrypt_parser.add_argument("key_2", required=True, type=str)
des3_decrypt_parser.add_argument("key_3", required=True, type=str)
des3_decrypt_parser.add_argument(
    "mode",
    required=True,
    type=str,
    choices=allowed_modes,
    help=f"Invalid mode, must be {allowed_modes}.",
)
des3_decrypt_parser.add_argument(
    "iv_mode",
    type=str,
    choices=allowed_iv_modes,
    help=f"Invalid mode, must be {allowed_iv_modes}.",
)
des3_decrypt_parser.add_argument("iv", type=str, help="initialization vector.")
des3_decrypt_parser.add_argument(
    "encrypted_message",
    required=True,
    type=str,
    help="Encrypted message in base64 format.",
)


class DES3Decrypt(Resource):
    @api.expect(des3_decrypt_parser)
    @api.doc(response={200: "Success", 400: "Validation Error"})
    def post(self):
        args = des3_decrypt_parser.parse_args()
        key_1 = args["key_1"]
        key_2 = args["key_2"]
        key_3 = args["key_3"]
        mode = args["mode"].upper()
        iv_mode = args["iv_mode"]
        iv = args["iv"]
        encrypted_message = args["encrypted_message"]

        # Error handling
        try:
            key = DES3.adjust_key_parity(
                str.encode(key_1) + str.encode(key_2) + str.encode(key_3)
            )
        except Exception as e:
            print(e)
            abort(
                400,
                "Invalid key format, each key must be of length 8. The three keys must be different from each other or key_1 == key_3 != key_2",
            )

        if iv:
            if mode == "ECB":
                abort(400, "Mode 'ECB' doesn't use an Initialization vector")

            # Accept both utf-8 and base64
            if iv_mode == "base64":
                try:
                    iv = b64decode(iv)
                except Exception as e:
                    print(e)
                    abort(400, "Invalid base64 string")
            elif len(iv.encode("utf-8")) != 8:
                abort(400, "Initialization vector must be of length 8")
            else:
                iv = str.encode(iv)

        try:
            encrypted_message = b64decode(encrypted_message)
        except binascii.Error as e:
            print(e)
            abort(400, "Message has to be encoded in base64")

        try:
            # Electronic Code Book
            if mode == "ECB":
                cipher = DES3.new(key, DES3.MODE_ECB)
                decrypted = unpad(cipher.decrypt(encrypted_message), DES3.block_size)
            # Cipher-Block Chaining
            elif mode == "CBC":
                cipher = DES3.new(key, DES3.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(encrypted_message), DES3.block_size)
            # Cipher FeedBack
            elif mode == "CFB":
                cipher = DES3.new(key, DES3.MODE_CFB, iv)
                decrypted = cipher.decrypt(encrypted_message)
            # Output FeedBack
            elif mode == "OFB":
                cipher = DES3.new(key, DES3.MODE_OFB, iv)
                decrypted = cipher.decrypt(encrypted_message)
        except Exception as e:
            print(e)
            abort(500, "Unknown error")

        # Return base64
        data = {"decrypted_message": decrypted.decode()}

        return jsonify(data)


ns = api.namespace("des3", description="DES3 operations")
ns.add_resource(DES3Encrypt, "/encrypt")
ns.add_resource(DES3Decrypt, "/decrypt")
