from flask import Blueprint, current_app
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext import restful
from flask.ext.socketio import SocketIO
from flask.ext.redis import FlaskRedis

import config


app = Blueprint('v1', __name__)
db = SQLAlchemy()
api = restful.Api(prefix='/v1')
socketio = SocketIO()
redis = FlaskRedis()


_before1req = []
def before_first_request(func):
    """ decorator to launch func before 1st request """
    _before1req.append(func)

def init_app(flask_app):
    db.init_app(flask_app)
    api.init_app(flask_app)
    init_admin(flask_app)
    # FIXME! Socketio requires resource name to match on client and on server
    # so Nginx rewriting breaks it
    socketio.init_app(flask_app, resource='{}/v1/socket.io'.format(
        '/test' if config.TEST else ''
    ))
    redis.init_app(flask_app)
    flask_app.register_blueprint(app, url_prefix='/v1')
    flask_app.before_first_request_funcs.extend(_before1req)


# now apply routes
from . import routes
from . import cas
from .admin import init as init_admin
