import base64
import binascii

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

des3_encrypt_parser = reqparse.RequestParser()
des3_encrypt_parser.add_argument("key_1", required=True, type=str)
des3_encrypt_parser.add_argument("key_2", required=True, type=str)
des3_encrypt_parser.add_argument("key_3", required=True, type=str)
des3_encrypt_parser.add_argument("message", required=True, type=str)

class DES3Encrypt(Resource):
  @api.expect(des3_encrypt_parser)
  @api.doc(response={200: "Success", 400: "Validation Error"})
  def post(self):
    args = des3_encrypt_parser.parse_args()
    try:
      key_1 = str.encode(args["key_1"])
      key_2 = str.encode(args["key_2"])
      key_3 = str.encode(args["key_3"])
      key = DES3.adjust_key_parity(key_1 + key_2 + key_3)
    except Exception as e:
      print(e)
      abort(400, "Invalid public key format.")
    message = args["message"]

    encryptor = DES3.new(key, DES3.MODE_ECB)
    encrypted = encryptor.encrypt(pad(str.encode(message), 16))

    # we return a base64 representation
    data = {
      'encrypted_message': base64.b64encode(encrypted)#.decode("ascii")
    }

    return jsonify(data)


des3_decrypt_parser = reqparse.RequestParser()
des3_decrypt_parser.add_argument("key_1", required=True, type=str)
des3_decrypt_parser.add_argument("key_2", required=True, type=str)
des3_decrypt_parser.add_argument("key_3", required=True, type=str)
des3_decrypt_parser.add_argument("encrypted_message", required=True, type=str, help="Encrypted message in base64 format.")

class DES3Decrypt(Resource):
  @api.expect(des3_decrypt_parser)
  @api.doc(response={200: "Success", 400: "Validation Error"})
  def post(self):
    args = des3_decrypt_parser.parse_args()
    try:
      key_1 = str.encode(args["key_1"])
      key_2 = str.encode(args["key_2"])
      key_3 = str.encode(args["key_3"])
      key = DES3.adjust_key_parity(key_1 + key_2 + key_3)
    except Exception as e:
      print(e)
      abort(400, "Invalid public key format.")
    encrypted_message = base64.b64decode(args["encrypted_message"])

    decryptor = DES3.new(key, DES3.MODE_ECB)
    decrypted = unpad(decryptor.decrypt(encrypted_message), 16)

    # we return a base64 representation
    data = {
      'decrypted_message': decrypted.decode()
    }

    return jsonify(data)

ns = api.namespace("des3", description="DES3 operations")
ns.add_resource(DES3Encrypt, "/encrypt")
ns.add_resource(DES3Decrypt, "/decrypt")


