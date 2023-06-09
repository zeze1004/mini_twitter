import jwt
from api import *
from functools import wraps
from flask import request, Response, current_app, g


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.headers.get('Authorization')
        _str = ""
        if access_token is not None:
            try:
                payload = jwt.decode(access_token, current_app.config['JWT_SECRET_KEY'], 'HS256')
            except jwt.InvalidTokenError as e:
                _str += str(e)
                payload = None

            if payload is None:
                return Response(status=401, response=_str)

            user_id = payload['user_id']
            g.user_id = user_id
            g.user = get_user(user_id) if user_id else None
        else:
            return Response(status=401, response=_str)
        return f(*args, **kwargs)

    return decorated_function
