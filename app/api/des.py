import binascii
from base64 import b64encode, b64decode

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

from . import api

# Single DES
# 64 bit (8 bytes or 8 ASCII charactes) key

allowed_modes = ['ECB', 'CBC', 'CFB', 'OFB']
allowed_iv_modes = ['base64', 'utf-8']

des_encrypt_parser = reqparse.RequestParser()
des_encrypt_parser.add_argument("key", required=True, type=str)
des_encrypt_parser.add_argument("mode", required=True, type=str, choices=allowed_modes)
des_encrypt_parser.add_argument("iv", type=str)
des_encrypt_parser.add_argument("message", required=True, type=str)

class DESEncrypt(Resource):
  @api.expect(des_encrypt_parser)
  @api.doc(response={200: "Success", 400: "Validation Error"})
  def get(self):
    args = des_encrypt_parser.parse_args()
    key = args["key"]
    mode = args["mode"].upper()
    message = args["message"]
    iv = args["iv"]

    # Error handling
    if len(key.encode("utf-8")) != DES.block_size:
      abort(400, "Invalid key, must be of length 8")
    else:
      key = str.encode(key)
    if mode not in allowed_modes:
      abort(400, f'Invalid mode, must be {allowed_modes}')
    if iv is not None:
      if mode == 'ECB':
        abort(400, "Mode 'ECB' doesn't use an Initialization vector")
      elif len(iv.encode("utf-8")) != 8:
        abort(400, "Initialization vector must be of length 8")
      else:
        iv = str.encode(iv)
    if message is None:
      abort(400, "No message to encrypt")
    else:
      message = str.encode(message)

    try:
    # Electronic Code Book
      if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(message, DES.block_size))
        cipher_iv = ''
      # Cipher-Block Chaining
      elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message, DES.block_size))
        cipher_iv = b64encode(cipher.iv).decode("utf-8")
      # Cipher FeedBack
      elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv)
        encrypted = cipher.encrypt(message)
        cipher_iv = b64encode(cipher.iv).decode("utf-8")
      # Output FeedBack
      elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv)
        encrypted = cipher.encrypt(message)
        cipher_iv = b64encode(cipher.iv).decode("utf-8")
    except Exception as e:
      print(e)
      abort(500, "Unknown error")

    # Return base64
    data = {
      'iv': cipher_iv,
      'encrypted_message': b64encode(encrypted).decode("utf-8")
    }

    return jsonify(data)


des_decrypt_parser = reqparse.RequestParser()
des_decrypt_parser.add_argument("key", required=True, type=str)
des_decrypt_parser.add_argument("mode", required=True, type=str, choices=allowed_modes)
des_decrypt_parser.add_argument("iv_mode", type=str, choices=allowed_iv_modes)
des_decrypt_parser.add_argument("iv", type=str)
des_decrypt_parser.add_argument("encrypted_message", required=True, type=str, help="Encrypted message in base64 format.")

class DESDecrypt(Resource):
  @api.expect(des_decrypt_parser)
  @api.doc(response={200: "Success", 400: "Validation Error"})
  def get(self):
    args = des_decrypt_parser.parse_args()
    key = args["key"]
    mode = args["mode"].upper()
    encrypted_message = args["encrypted_message"]
    iv_mode = args["iv_mode"]
    iv = args["iv"]

    # Error handling
    if len(key.encode("utf-8")) != DES.block_size:
      abort(400, "Invalid key, must be of length 8")
    else:
      key = str.encode(key)
    if mode not in allowed_modes:
      abort(400, f'Invalid mode, must be {allowed_modes}')
    if iv is not None:
      if mode == 'ECB':
        abort(400, "Mode 'ECB' doesn't use an Initialization vector")

      if iv_mode not in allowed_iv_modes:
        abort(400, f'Invalid mode, must be {allowed_iv_modes}')
      
      # Accept both utf-8 and base64
      if iv_mode == 'base64':
        try:
          iv = b64decode(iv)
        except Exception as e:
          print(e)
          abort(400, "Invalid base64 string")
      elif len(iv.encode("utf-8")) != 8:
        abort(400, "Initialization vector must be of length 8")
      else:
        iv = str.encode(iv)

    if encrypted_message is not None:
      try:
        encrypted_message = b64decode(encrypted_message)
      except binascii.Error as e:
        print(e)
        abort(400, "Message has to be encoded in base64")
    else:
      abort(400, "No message to decrypt")

    try:
      # Electronic Code Book
      if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_message), DES.block_size)
      # Cipher-Block Chaining
      elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_message), DES.block_size)
      # Cipher FeedBack
      elif mode == 'CFB':
        cipher = DES.new(key, DES.MODE_CFB, iv)
        decrypted = cipher.decrypt(encrypted_message)
      # Output FeedBack
      elif mode == 'OFB':
        cipher = DES.new(key, DES.MODE_OFB, iv)
        decrypted = cipher.decrypt(encrypted_message)
    except Exception as e:
      print(e)
      abort(500, "Unknown error")

    # Return base64
    data = {
      'decrypted_message': decrypted.decode()
    }

    return jsonify(data)

ns = api.namespace("des", description="DES operations")
ns.add_resource(DESEncrypt, "/encrypt")
ns.add_resource(DESDecrypt, "/decrypt")


