import os

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

from app import api

if os.environ.get("IS_PRODUCTION"):
    app.config.from_object("config.ProductionConfig")
else:
    app.config.from_object("config.DevelopmentConfig")
