from flask import Blueprint
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext import restful
from flask.ext.socketio import SocketIO

app = Blueprint('v1', __name__)
db = SQLAlchemy()
api = restful.Api(prefix='/v1')
socketio = SocketIO()

_before1req = []
def before_first_request(func):
    """ decorator to launch func before 1st request """
    _before1req.append(func)
def init_app(flask_app):
    db.init_app(flask_app)
    api.init_app(flask_app)
    socketio.init_app(flask_app)
    flask_app.register_blueprint(app, url_prefix='/v1')
    flask_app.before_first_request_funcs.extend(_before1req)


# now apply routes
from . import routes
from . import cas
