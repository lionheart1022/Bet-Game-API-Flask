#!/usr/bin/env python3

# Observer daemon:
# listens on some port/path,
# may have some children configured,
# knows how many streams can it handle.
# Also each host accepts connections only from its known siblings.
#
# Messaging flow:
#
# Client -> Master: Please watch the stream with URL ... for game ...
# Master: checks if this stream is already watched
# Master -> Slave1: Can you watch one more stream? (details)
# Slave1 -> Master: no
# Master -> Slave2: Can you watch one more stream? (details)
# Slave2 -> Master: yes
# (or if none agreed - tries to watch itself)
# ...
# Slave2 -> Master: stream X finished, result is Xres
# Master -> Poller: stream X done

# API:
# PUT /streams/id - watch the stream (client->master->slave)
# GET /streams/id - check stream status (master->slave)

from flask import Flask, jsonify
from flask.ext import restful
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful.utils import http_status_message
from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import BadRequest, MethodNotAllowed, Forbidden, NotImplemented, NotFound

import logging

import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.DB_URL
app.config['ERROR_404_HELP'] = False # disable this flask_restful feature
db = SQLAlchemy(app)
api = restful.Api(app)

# Fix request context's remote_addr property to respect X-Real-IP header
from flask import Request
from werkzeug.utils import cached_property
class MyRequest(Request):
    @cached_property
    def remote_addr(self):
        """The remote address of the client, with respect to X-Real-IP header"""
        return self.headers.get('X-Real-IP') or super().remote_addr
app.request_class = MyRequest


# JSONful error handling
def make_json_error(ex):
    code = getattr(ex, 'code', 500)
    if hasattr(ex, 'data'):
        response = jsonify(**ex.data)
    else:
        response = jsonify(error_code = code, error = http_status_message(code))
    response.status_code = code
    return response
for code in default_exceptions.keys():
    app.error_handler_spec[None][code] = make_json_error


def init_app(logfile=None):
    app.logger.setLevel(logging.DEBUG)

    logger = logging.FileHandler(logfile) if logfile else logging.StreamHandler()
    logger.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'))
    logger.setLevel(logging.DEBUG)
    app.logger.addHandler(logger)

    return app


# declare model
class Stream(db.Model):
    id = db.Column(db.Integer, primary_key=True)

# now define our endpoints
@api.resource(
    '/streams',
    '/streams/',
    '/streams/<id>',
)
class StreamResource(restful.Resource):
    def get(self, id=None):
        pass

    def put(self, id=None):
        if not id:
            raise MethodNotAllowed
        pass

    def delete(self, id=None):
        if not id:
            raise MethodNotAllowed
        pass

if __name__ == '__main__':
    init_app()
    app.run(port=8021, debug=True)
