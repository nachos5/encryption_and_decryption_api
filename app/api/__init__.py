from flask import render_template

from app import app

from . import errors, rsa


@app.route("/", methods=["GET"])
def info():
    return render_template("info.html")
