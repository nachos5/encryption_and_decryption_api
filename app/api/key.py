from flask import jsonify
from flask_restx import reqparse, Resource
from Crypto.PublicKey import RSA, DSA, ECC

from . import api

rsa_key_parser = reqparse.RequestParser()
rsa_key_parser.add_argument(
  "key_size",
  required=True,
  type=int,
  choices=[1024, 2048, 3072],
  help="Key size in bits.",
)

class RSAKey(Resource):
  @api.expect(rsa_key_parser)
  @api.doc(responses={200: "Success", 400: "Validation Error"})
  def get(self):
    args = rsa_key_parser.parse_args()
    key_size = args["key_size"]

    key_pair = RSA.generate(key_size)
    public_key = key_pair.publickey().exportKey("PEM")
    private_key = key_pair.exportKey("PEM")

    data = {
      'public_key': public_key.decode("ascii"),
      'private_key': private_key.decode("ascii"),
    }

    return jsonify(data)

dsa_key_parser = reqparse.RequestParser()
dsa_key_parser.add_argument(
  "key_size",
  required=True,
  type=int,
  choices=[1024, 2048, 3072],
  help="Key size in bits.",
)

class DSAKey(Resource):
  @api.expect(dsa_key_parser)
  @api.doc(responses={200: "Success", 400: "Validation Error"})
  def get(self):
    args = dsa_key_parser.parse_args()
    key_size = args["key_size"]

    key_pair = DSA.generate(key_size)
    public_key = key_pair.publickey().exportKey("PEM")
    private_key = key_pair.exportKey("PEM")

    data = {
      'public_key': public_key.decode("ascii"),
      'private_key': private_key.decode("ascii"),
    }

    return jsonify(data)

ecc_key_parser = reqparse.RequestParser()
ecc_key_parser.add_argument(
  "curve",
  required=True,
  type=str,
  choices=['P-256', 'P-384', 'P-521'],
  help="Elliptic curve",
)

class ECCKey(Resource):
  @api.expect(ecc_key_parser)
  @api.doc(responses={200: "Success", 400: "Validation Error"})
  def get(self):
    args = ecc_key_parser.parse_args()
    curve = args["curve"]

    key_pair = ECC.generate(curve=curve)
    public_key = key_pair.public_key().export_key(format="PEM")
    private_key = key_pair.export_key(format="PEM")

    data = {
      'public_key': public_key,
      'private_key': private_key,
    }

    return jsonify(data)


ns = api.namespace("key", description="Key pair")
ns.add_resource(RSAKey, "/rsa")
ns.add_resource(DSAKey, "/dsa")
ns.add_resource(ECCKey, "/ecc")