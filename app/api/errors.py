from flask import jsonify

from app import app


def error_dict(e):
    return dict(code=e.code, description=e.description)


@app.errorhandler(400)
def bad_request(e):
    print(dir(e))
    return jsonify(error=error_dict(e)), 400


@app.errorhandler(403)
def forbidden(e):
    return jsonify(error=error_dict(e)), 403


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error=error_dict(e)), 404
