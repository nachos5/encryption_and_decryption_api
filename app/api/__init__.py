from flask_restx import Api

from app import app

api = Api(app, version="0.0", title="Encryption & Decryption API")

from . import rsa
from . import des
from . import des3
from . import key
from . import random
