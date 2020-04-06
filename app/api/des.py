import base64
import binascii

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

from . import api

# Single DES
# 64 bit (8 bytes or 8 ASCII charactes) key

des_encrypt_parser = reqparse.RequestParser()
des_encrypt_parser.add_argument("key", required=True, type=str)
des_encrypt_parser.add_argument("message", required=True, type=str)

class DESEncrypt(Resource):
  @api.expect(des_encrypt_parser)
  @api.doc(response={200: "Success", 400: "Validation Error"})
  def post(self):
    args = des_encrypt_parser.parse_args()
    try:
      key = str.encode(args["key"])
    except Exception as e:
      print(e)
      abort(400, "Invalid public key format.")
    message = args["message"]

    encryptor = DES.new(key, DES.MODE_ECB)
    encrypted = encryptor.encrypt(pad(str.encode(message), 16))

    # we return a base64 representation
    data = {
      'encrypted_message': base64.b64encode(encrypted)#.decode("ascii")
    }

    return jsonify(data)


des_decrypt_parser = reqparse.RequestParser()
des_decrypt_parser.add_argument("key", required=True, type=str)
des_decrypt_parser.add_argument("encrypted_message", required=True, type=str, help="Encrypted message in base64 format.")

class DESDecrypt(Resource):
  @api.expect(des_encrypt_parser)
  @api.doc(response={200: "Success", 400: "Validation Error"})
  def post(self):
    args = des_encrypt_parser.parse_args()
    try:
      key = str.encode(args["key"])
    except Exception as e:
      print(e)
      abort(400, "Invalid public key format.")
    encrypted_message = base64.b64decode(args["encrypted_message"])

    decryptor = DES.new(key, DES.MODE_ECB)
    decrypted = unpad(decryptor.decrypt(encrypted_message), 16)

    # we return a base64 representation
    data = {
      'decrypted_message': decrypted.decode()
    }

    return jsonify(data)

ns = api.namespace("des", description="DES operations")
ns.add_resource(DESEncrypt, "/encrypt")
ns.add_resource(DESDecrypt, "/decrypt")


