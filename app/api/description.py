import os
import json

from flask import jsonify
from flask_restx import reqparse, abort, Api, Resource

from . import api

json_path = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), "..", "descriptions.json"
)


def read_json(subject):
    with open(json_path, "r") as json_file:
        data = json.load(json_file)
        return data[subject]


parser = reqparse.RequestParser()
subjects = ["aes", "des", "desImplementation", "des3", "des3Implementation", "rsa", "mode", "iv", "ecb", "cbc", "cfb", "ofb", "ctr"]
parser.add_argument(
    "subject", required=True, choices=subjects,
)

class Description(Resource):
    @api.expect(parser)
    def get(self):
        args = parser.parse_args()
        subject = args["subject"]
        return jsonify(read_json(subject))


ns = api.namespace("description", description="Descriptions for the algorithms")
ns.add_resource(Description, "")
