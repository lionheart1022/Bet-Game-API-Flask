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
            balance = fields.Raw, # because it is already JSON
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
    def login_do(cls, player, args=None, created=False):
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

        ret = jsonify(
            player = marshal(player, cls.fields_self),
            token = makeToken(player),
        )
        if created:
            ret.status_code = 201
        return ret

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
        # TODO: validate fb token and nick
        db.session.add(player)
        db.session.commit()

        # TODO send greeting

        return self.login_do(player, args_login, created=True)

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

    @app.route('/players/<id>/login', methods=['POST'])
    def player_login(id):
        parser = RequestParser()
        parser.add_argument('password', required=True)
        args = parser.parse_args()

        player = Player.query.filter_by(player_nick=id).first()
        if not player:
            player = Player.query.filter_by(email=id).first()
        if not player:
            abort('Unknown player nick or email', 404)

        if not check_password(args.password, player.password):
            abort('Password incorrect', 403)

        return PlayerResource.login_do(player)


# Balance
@app.route('/balance', methods=['GET'])
@require_auth
def balance_get(user):
    return jsonify(
        balance = user.balance_obj,
    )
@app.route('/balance/append', methods=['POST'])
@require_auth
def balance_append(user):
    parser = RequestParser()
    parser.add_argument('payment_id', required=True)
    parser.add_argument('total', type=float, required=True)
    parser.add_argument('currency', required=True)
    parser.add_argument('dry_run', type=boolean_field, default=False)
    args = parser.parse_args()

    log.info('Payment received: '+' '.join(
        ['{}: {}'.format(k,v) for k,v in args.items()]))

    coins = args.total # TODO

    if not args.dry_run:
        # verify payment...
        ret = PayPal.call('GET', 'payments/payment/'+args.payment_id)
        if ret.get('state') != 'approved':
            abort('Payment not approved', success=False)

        transaction = None
        for tr in ret.get('transactions', []):
            if tr.get('amount') == dict(
                total = args.total,
                currency = args.currency,
            ):
                transaction = tr
                break
        else:
            abort('No corresponding transaction found', success=False)

        for sale in transaction.get('related_resources', []):
            if sale.get('state') == 'completed':
                break
        else:
            abort('Sale is not completed', success=False)

        # now payment should be verified
        log.info('Payment approved, adding coins')

        user.balance += coins
    return jsonify(
        success=True,
        dry_run=args.dry_run,
        added=coins,
        balance=user.balance_obj,
    )

@app.route('/balance/withdraw', methods=['POST'])
@require_auth
def balance_withdraw(user):
    parser = RequestParser()
    parser.add_argument('coins', type=float, required=True)
    parser.add_argument('currency', default='USD')
    parser.add_argument('paypal_email', type=email, required=True)
    parser.add_argument('dry_run', type=boolean_field, default=False)
    args = parser.parse_args()

    if args.coins < config.WITHDRAW_MINIMUM:
        abort('Too small amount, minimum withdraw amount is {} coins'
              .format(config.WITHDRAW_MINIMUM))

    try:
        amount = dict(
            value = args.coins * Fixer.latest('USD', args.currency),
            currency = args.currency,
        )
    except ValueError:
        abort('Unknown currency provided')

    if user.available < args.coins:
        abort('Not enough coins')

    if args.dry_run:
        return jsonify(
            success = True,
            paid = amount,
            dry_run = True,
            balance = user.balance_obj,
        )

    # first withdraw coins...
    user.balance -= args.coins
    db.session.commit()

    # ... and only then do actual transaction;
    # will return balance if failure happens

    try:
        ret = PayPal.call('POST', 'payments/payouts', dict(
            sync_mode = True,
        ), dict(
            sender_batch_header = dict(
#                sender_batch_id = None,
                email_subject = 'You have a payout',
                recipient_type = 'EMAIL',
            ),
            items = [
                dict(
                    recipient_type = 'EMAIL',
                    amount = amount,
                    receiver = args.paypal_email,
                ),
            ],
        ))
        try:
            trinfo = ret['items'][0]
        except IndexError:
            trinfo = None
        stat = trinfo.get('transaction_status')
        if stat == 'SUCCESS':
            log.info('Payout succeeded to {}, {} coins'.format(
                args.paypal_email, args.coins))
            return jsonify(success=True,
                           dry_run=False,
                           paid = amount,
                           transaction_id=trinfo.get('payout_item_id'),
                           balance = user.balance_obj,
                           )
        log.debug(str(ret))
        log.warning('Payout failed to {}, {} coins, stat {}'.format(
            args.paypal_email, args.coins, stat))
        if stat in ['PENDING', 'PROCESSING']:
            # TODO: wait and retry
            pass

        abort('Couldn\'t complete payout: '+
              trinfo.get('errors',{}).get('message', 'Unknown error'),
              500,
              status=stat,
              transaction_id=trinfo.get('payout_item_id'),
              paypal_code=ret.get('_code'),
              success=False,
              dry_run=False,
              )
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        # restore balance
        user.balance += args.coins
        db.session.commit()

        log.error('Exception while performing payout', exc_info=True)

        abort('Couldn\'t complete payout', 500,
              success=False, dry_run=False)


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
            abort('[bet]: too low amount', problem='bet')
        if args.bet > user.available:
            abort('[bet]: not enough coins', problem='coins')

        game = Game()
        game.creator = user
        game.opponent = opponent
        game.bet = args.bet
        game.gamemode = args.gamemode
        game.gametype = args.gametype
        db.session.add(game)

        user.locked += game.bet

        db.session.commit()

        notify_users(game)

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

        if args.state == 'accepted' and game.bet > user.available:
            abort('Not enough coins', problem='coins')

        game.state = args.state
        game.accept_date = datetime.utcnow()

        user.locked += game.bet

        db.session.commit()

        notify_users(game)

        return marshal(game, self.fields)
