from flask import render_template
from flask_restful import Api

from app import app

api = Api(app)

from . import errors, rsa


@app.route("/", methods=["GET"])
def info():
    return render_template("info.html")
