from functools import wraps

from flask import abort, request


def field_errors(fields, messages):
    d = dict()
    for f, m in zip(fields, messages):
        d[f] = m
    return d


def check_required_fields(required_fields=[]):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.json
            if not data:
                missing_fields = required_fields
            else:
                missing_fields = [x for x in required_fields if x not in data.keys()]
            if missing_fields:
                abort(
                    400,
                    description=field_errors(
                        missing_fields, ["This field is required"] * len(missing_fields)
                    ),
                )
            return f(*args, **kwargs)
        return decorated_function

    return decorator

