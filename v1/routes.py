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
    @classproperty
    def fields_self(cls):
        return dict(
            id = fields.Integer,
            player_nick = fields.String,
            email = fields.String,
            facebook_connected = fields.Boolean(attribute='facebook_token'),
            balance = fields.Float,
            devices = fields.List(fields.Nested(dict(
                id = fields.Integer,
                last_login = fields.DateTime,
            ))),
            # TODO: some stats
        )
    @classproperty
    def fields_public(cls):
        copy = cls.fields_self.copy()
        del copy['balance']
        del copy['devices']
        return copy

    @classmethod
    def login_do(cls, player):
        # TODO create device if applicable

        return dict(
            player = marshal(player, self.fields_self),
            token = makeToken(player),
        )

    @require_auth
    def get(self, user, id=None):
        if not id:
            raise NotImplemented
        player = Player.query.get(id)
        if not player:
            raise NotFound
        return marshal(player,
                       self.fields_self
                       if player == user else
                       self.fields_public)

    def post(self, id=None):
        if id:
            raise MethodNotAllowed
        args = self.parser.parse_args()
        player = Player()
        for key, val in args.items():
            if hasattr(player, key):
                setattr(player, key)
        # TODO: validate fb token
        db.session.add(player)
        db.session.commit()

        # TODO send greeting

        return self.login_do(player)

    def patch(self, id=None):
        if not id:
            raise MethodNotAllowed
        # TODO

    @classmethod
    @app.route('/players/login', ['POST'])
    def player_login(cls):
        parser = RequestParser()
        parser.add_argument('email', required=False)
        parser.add_argument('player_nick', required=False)
        parser.add_argument('password', required=True)
        args = parser.parse_args()
        if args.email:
            player = Player.query.filter_by(email=args.email).one()
            if not player:
                abort('Unknown email', 404)
        elif args.player_nick:
            player = Player.query.filter_by(player_nick=args.player_nick).one()
            if not player:
                abort('Unknown player nick', 404)
        else:
            abort('Please provide either email or player_nick')

        if not check_password(args.password, player.password):
            abort('Password incorrect', 403)

        return cls.login_do(player)


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
