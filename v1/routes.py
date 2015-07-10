from flask import request, url_for, jsonify, current_app, g
from flask.ext import restful
from flask.ext.restful import fields, marshal, marshal_with, marshal_with_field

from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import BadRequest, MethodNotAllowed, Forbidden, NotImplemented, NotFound

import requests
import eventlet
from datetime import datetime, timedelta
import math
from functools import reduce
import itertools

import config
from .models import *
from .helpers import *
from .helpers import MyRequestParser as RequestParser # instead of system one
from .main import app, db, api, before_first_request

# Players
@api.resource(
    '/players',
    '/players/',
    '/players/<int:id>',
)
class PlayerResource(api.Resource):
    @classproperty
    def parser(cls):
        parser = RequestParser()
        for name, type, required in [
            ('player_nick', None, True),
            ('email', email, True),
            ('password', password, True),
            ('facebook_token', None, False),
        ]:
            parser.add_argument(
                name,
                required = required,
                type=string_field(
                    getattr(Player, name),
                    ftype=type))
        return parser

    def get(self, id=None):
        pass
        # TODO

    def post(self, id=None):
        if id:
            raise MethodNotAllowed
        # TODO

    def patch(self, id=None):
        if not id:
            raise MethodNotAllowed
        # TODO
@app.route('/players/login', ['POST'])
def player_login():
    pass


# Balance
@app.route('/balance', ['GET'])
def balance_get():
    pass
@app.route('/balance/append', ['POST'])
def balance_append():
    pass
@app.route('/balance/withdraw', ['POST'])
def balance_withdraw():
    pass


# Games
@api.resource(
    '/games',
    '/games/',
    '/games/<int:id>',
)
class GameResource(api.Resource):
    def get(self, id=None):
        pass

    def post(self, id=None):
        if id:
            raise MethodNotAllowed
        # TODO

    def patch(self, id=None):
        if not id:
            raise MethodNotAllowed
        # TODO
