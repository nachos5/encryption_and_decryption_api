import os
import json

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from . import api

json_path = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "..", "descriptions.json"
)


def read_json(algorithm):
    with open(json_path, "r") as json_file:
        data = json.load(json_file)
        return data[algorithm]


parser = reqparse.RequestParser()
algs = ["aes", "des", "des3", "rsa"]
parser.add_argument(
    "algorithm", required=True, choices=algs,
)


class Description(Resource):
    @api.expect(parser)
    def get(self):
        args = parser.parse_args()
        alg = args["algorithm"]
        return jsonify(read_json(alg))


ns = api.namespace("description", description="Descriptions for the algorithms")
ns.add_resource(Description, "")
