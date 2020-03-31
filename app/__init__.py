from flask import Flask

app = Flask(__name__)

from app import api

try:
    app.config.from_envvar("CONFIG_OBJECT")
except Exception as e:
    print(e)
    app.config.from_object("config.DevelopmentConfig")

print(app.config["SECRET_KEY"])
