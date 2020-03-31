import os
import json

info_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "info"))


def get_info(algorithm, class_name):
    filepath = os.path.join(info_dir, f"{algorithm}.json")
    with open(filepath) as json_file:
        text = json_file.read()
        d = json.loads(text)
    return d[class_name]

