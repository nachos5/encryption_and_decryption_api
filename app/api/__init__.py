from flask_restx import Api

from app import app

api = Api(app, version="0.0", title="Encryption & Decryption API")

from . import aes, des, des3, key, random, rsa, description
