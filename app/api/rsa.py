import ast
import base64
import binascii

from flask import abort, jsonify, request

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from app import app

from app.utils.validators import check_required_fields


@app.route("/rsa/generate_key", methods=["POST"])
@check_required_fields(["key_size"])
def rsa_generate_key_pair():
    post_data = request.json
    key_size = post_data["key_size"]
    # allowed key sizes in bits
    allowed_key_sizes = ["1024", "2048", "3072"]

    if str(key_size) not in allowed_key_sizes:
        abort(403, description=f"Allowed key sizes are {' '.join(allowed_key_sizes)}")

    key_pair = RSA.generate(key_size)
    public_key = key_pair.publickey().exportKey("PEM")
    private_key = key_pair.exportKey("PEM")

    public_key_str = public_key.decode("ascii")
    private_key_str = private_key.decode("ascii")
    data = dict(public_key=public_key_str, private_key=private_key_str)

    return jsonify(data)


@app.route("/rsa/encrypt", methods=["POST"])
@check_required_fields(["public_key", "message"])
def rsa_encrypt():
    post_data = request.json
    public_key = RSA.importKey(post_data["public_key"])
    message = post_data["message"]

    encryptor = PKCS1_OAEP.new(public_key)
    encrypted = encryptor.encrypt(str.encode(message))

    # we return a base64 representation
    data = dict(encrypted_message=base64.b64encode(encrypted).decode("ascii"))

    return jsonify(data)


@app.route("/rsa/decrypt", methods=["POST"])
@check_required_fields(["private_key", "encrypted_message"])
def rsa_decrypt():
    post_data = request.json
    private_key = RSA.import_key(post_data["private_key"])
    # decrypt the base64 representation to get the encrypted bytes
    encrypted_message = base64.b64decode(post_data["encrypted_message"])

    decryptor = PKCS1_OAEP.new(private_key)
    decrypted = decryptor.decrypt(encrypted_message)

    data = dict(decrypted_message=decrypted.decode())

    return jsonify(data)
