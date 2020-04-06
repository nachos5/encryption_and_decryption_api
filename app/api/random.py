import base64
import string

from flask import jsonify
from flask_restx import reqparse, Resource

from Crypto.Random import get_random_bytes
from Crypto.Random.random import shuffle

from . import api

random_strings_parser = reqparse.RequestParser()
random_strings_parser.add_argument("length", required=True)

class RandomString(Resource):
  @api.expect(random_strings_parser)
  @api.doc(responses={200: "Success", 400: "Validation Error"})
  def post(self):
    args = random_strings_parser.parse_args()
    n = int(args["length"])

    rand_string = [s for s in string.printable]
    shuffle(rand_string)

    data = {
      'random': ''.join([str(x) for x in rand_string[:n]])
    }

    return jsonify(data)

ns = api.namespace("random", description="Random data")
ns.add_resource(RandomString, "/string")