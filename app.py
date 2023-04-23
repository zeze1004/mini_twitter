from datetime import timedelta, datetime

import bcrypt as bcrypt
import g as g
import jwt as jwt
from flask import Flask, jsonify, request
from sqlalchemy import create_engine

from decorate import login_required
from util import *
from api import *


def create_app(test_config=None):
    app = Flask(__name__)

    if not test_config:
        app.config.from_pyfile("config.py")
    else:
        app.config.update(test_config)

    database = create_engine(app.config["DB_URL"], max_overflow=0)  # 데이터베이스와 연결
    app.database = database  # Flask instance의 attribute로 가리킴
    app.config["JWT_SECRET_KEY"] = "base"

    @app.route('/', methods=['GET'])
    def index():
        return "Hello Flask"

    @app.route('/ping', methods=['GET'])
    def ping():
        return "pong"

    @app.route("/sign-up", methods=['POST'])
    def sign_up():
        new_user = request.json
        new_user["password"] = bcrypt.hashpw(password=new_user["password"].encode("utf-8"),
                                             salt=bcrypt.gensalt())
        new_user_id = insert_user(new_user)
        new_user = get_user(new_user_id)
        return jsonify(new_user)

    @app.route("/login", methods=["POST"])
    def login():
        credential = request.json
        email = credential["email"]
        password = credential["password"]
        user_credential = get_user_id_and_password(email)

        if user_credential and bcrypt.checkpw(password=password.encode("utf-8"),
                                              hashed_password=user_credential["hashed_password"].encode("utf-8")):
            user_id = user_credential["id"]
            payload = {
                "user_id": user_id,
                "exp": datetime.utcnow() + timedelta(seconds=60 * 60 * 24)
            }
            token = jwt.encode(payload=payload,
                               key=app.config["JWT_SECRET_KEY"],
                               algorithm="HS256")
            return jsonify({
                # "access_token": token.decode()
                "access_token": token
            })
        else:
            return "", 401


    @app.route('/tweet', methods=['POST'])
    @login_required
    def tweet():
        user_tweet = request.json
        user_tweet['id'] = g.user_id
        tweet = user_tweet['tweet']

        if len(tweet) > 300:
            return '300자를 초과했습니다.', 400

        insert_tweet(user_tweet)

        return '', 200

    @app.route('/follow', methods=['POST'])
    @login_required
    def follow():
        payload = request.json
        payload['id'] = g.user_id

        insert_follow(payload)

        return '', 200

    @app.route('/unfollow', methods=['POST'])
    @login_required
    def unfollow():
        payload = request.json
        payload['id'] = g.user_id

        insert_unfollow(payload)

        return '', 200

    @app.route('/timeline/<int:user_id>', methods=['GET'])
    def timeline(user_id):
        return jsonify({
            'user_id': user_id,
            'timeline': get_timeline(user_id)
        })

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
