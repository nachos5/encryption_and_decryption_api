from flask import Flask
from flask_api import FlaskAPI

app = FlaskAPI(__name__)

from app import api

try:
    app.config.from_envvar("CONFIG_OBJECT")
except:
    app.config.from_object("config.DevelopmentConfig")
