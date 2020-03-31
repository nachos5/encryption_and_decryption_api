import os

from flask import Flask

app = Flask(__name__)

from app import api

if os.environ.get("IS_PRODUCTION"):
    print("PRODUCTION")
    app.config.from_object("config.ProductionConfig")
else:
    app.config.from_object("config.DevelopmentConfig")

print(app.config["SECRET_KEY"])
