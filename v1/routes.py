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
    '/players/<id>',
)
class PlayerResource(restful.Resource):
    @classproperty
    def parser(cls):
        parser = RequestParser()
        partial = parser.partial = RequestParser()
        login = parser.login = RequestParser()
        for name, type, required in [
            ('player_nick', None, True),
            ('email', email, True),
            ('password', encrypt_password, True),
            ('facebook_token', federatedRenewFacebook, False), # should be last to avoid extra queries
        ]:
            parser.add_argument(
                name,
                required = required,
                type=string_field(
                    getattr(Player, name),
                    ftype=type))
            partial.add_argument(
                name,
                required = False,
                type=string_field(
                    getattr(Player, name),
                    ftype=type))
        login.add_argument('push_token', type=string_field(Device.push_token),
                           required=True)
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
    def login_do(cls, player, args=None):
        if not args:
            args = cls.parser.login.parse_args()
        dev = Device.query.filter_by(player = player,
                                     push_token = args.push_token
                                     ).first()
        if not dev:
            dev = Device()
            dev.player = player
            dev.push_token = args.push_token
            db.session.add(dev)
        dev.last_login = datetime.utcnow()

        db.session.commit() # to create device id

        return dict(
            player = marshal(player, cls.fields_self),
            token = makeToken(player),
        )

    @require_auth
    def get(self, user, id=None):
        if not id:
            # TODO?
            raise NotImplemented

        player = Player.find(id)
        if not player:
            raise NotFound

        return marshal(player,
                       self.fields_self
                       if player == user else
                       self.fields_public)

    def post(self, id=None):
        if id:
            raise MethodNotAllowed
        args_login = self.parser.login.parse_args() # check before others
        args = self.parser.parse_args()

        player = Player()
        for key, val in args.items():
            if hasattr(player, key):
                setattr(player, key, val)
        # TODO: validate fb token
        db.session.add(player)
        db.session.commit()

        # TODO send greeting

        return self.login_do(player, args_login)

    @require_auth
    def patch(self, user, id=None):
        if not id:
            raise MethodNotAllowed

        if id.lower() not in ('me', str(user.id), user.player_nick.lower()):
            abort('You cannot edit other player\'s info', 403)

        args = self.parser.partial.parse_args()

        for key, val in args.items():
            if hasattr(user, key):
                setattr(user, key, val)

        db.session.commit()

        return marshal(user, self.fields_self)

    @classmethod
    @app.route('/players/login', methods=['POST'])
    def player_login(cls):
        parser = RequestParser()
        parser.add_argument('email', required=False)
        parser.add_argument('player_nick', required=False)
        parser.add_argument('password', required=True)
        args = parser.parse_args()
        if args.email:
            player = Player.query.filter_by(email=args.email).first()
            if not player:
                abort('Unknown email', 404)
        elif args.player_nick:
            player = Player.query.filter_by(player_nick=args.player_nick).first()
            if not player:
                abort('Unknown player nick', 404)
        else:
            abort('Please provide either email or player_nick')

        if not check_password(args.password, player.password):
            abort('Password incorrect', 403)

        return cls.login_do(player)


# Balance
@app.route('/balance', methods=['GET'])
@require_auth
def balance_get(user):
    return jsonify(
        balance = user.balance
    )
@app.route('/balance/append', methods=['POST'])
def balance_append():
    pass
@app.route('/balance/withdraw', methods=['POST'])
def balance_withdraw():
    pass


# Games
@api.resource(
    '/games',
    '/games/',
    '/games/<int:id>',
)
class GameResource(restful.Resource):
    @classproperty
    def fields(cls):
        return {
            'id': fields.Integer,
            'creator': fields.Nested(PlayerResource.fields_public),
            'opponent': fields.Nested(PlayerResource.fields_public),
            'gamemode': fields.String,
            'gametype': fields.String,
            'bet': fields.Float,
            'create_date': fields.DateTime,
            'state': fields.String,
            'accept_date': fields.DateTime,
            'winner': fields.String,
            'finish_date': fields.DateTime,
        }
    @require_auth
    def get(self, user, id=None):
        if id:
            game = Game.query.get(id)
            if not game:
                raise NotFound

            # TODO: allow?
            if user not in [game.creator, game.opponent]:
                raise Forbidden

            return marshal(game, self.fields)

        query = user.games
        # TODO: filters

        return jsonify(games = marshal(
            query,
            fields.List(fields.Nested(self.fields))))

    @require_auth
    def post(self, user, id=None):
        if id:
            raise MethodNotAllowed

        parser = RequestParser()
        parser.add_argument('opponent_id', type=str, required=True)
        parser.add_argument('gamemode', options=Game.GAMEMODES, required=True)
        parser.add_argument('gametype', options=Game.GAMETYPES, required=True)
        parser.add_argument('bet', type=float, required=True)
        args = parser.parse_args()

        opponent = Player.find(args.opponent_id)
        if not opponent:
            abort('[opponent_id]: no such player')
        if opponent == user:
            abort('You cannot compete with yourself')

        if args.bet < 0.99:
            abort('[bet]: too low amount')
        if args.bet > user.balance:
            abort('[bet]: not enough coins')

        game = Game()
        game.creator = user
        game.opponent = opponent
        game.bet = args.bet
        game.gamemode = args.gamemode
        game.gametype = args.gametype
        db.session.add(game)
        db.session.commit()

        return marshal(game, self.fields), 201

    def patch(self, id=None):
        if not id:
            raise MethodNotAllowed

        parser = RequestParser()
        parser.add_argument('state', options=[
            'accepted', 'declined'
        ])
        args = parser.parse_args()

        game = Game.get(id)
        if not game:
            raise NotFound

        user = check_auth(Game.creator_id)

        if game.state != 'new':
            abort('This game is already {}'.format(game.state))

        game.state = args.state
        game.accept_date = datetime.utcnow()

        db.session.commit()

        return marshal(game, self.fields)
