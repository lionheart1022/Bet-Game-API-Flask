from flask import request, url_for, jsonify, current_app, g, send_file
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
from PIL import Image
from io import BytesIO

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
            ('_force', gamertag_force_field, False),
            ('nickname', None, True),
            ('email', email, True),
            ('password', encrypt_password, True),
            ('facebook_token', federatedRenewFacebook, False), # should be last to avoid extra queries
            ('ea_gamertag', gamertag_field, False),
        ]:
            if hasattr(Player, name):
                type = string_field(getattr(Player, name), ftype=type)
            parser.add_argument(
                name,
                required = required,
                type=type,
            )
            partial.add_argument(
                name,
                required = False,
                type=type,
            )
        login.add_argument('push_token',
                           type=string_field(Device.push_token,
                                             # 64 hex digits = 32 bytes
                                             ftype=hex_field(64)),
                           required=False)
        partial.add_argument('old_password', required=False)
        return parser
    @classproperty
    def fields_self(cls):
        return dict(
            id = fields.Integer,
            nickname = fields.String,
            email = fields.String,
            facebook_connected = fields.Boolean(attribute='facebook_token'),
            balance = fields.Raw, # because it is already JSON
            devices = fields.List(fields.Nested(dict(
                id = fields.Integer,
                last_login = fields.DateTime,
            ))),
            ea_gamertag = fields.String,
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
            token = makeToken(player, device=dev),
            created = created,
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

        mailsend(player, 'greeting')
        # we don't check result as it is not critical if this email is not sent

        return self.login_do(player, args_login, created=True)

    @require_auth(allow_nonfilled=True)
    def patch(self, user, id=None):
        if not id:
            raise MethodNotAllowed

        if Player.find(id) != user:
            abort('You cannot edit other player\'s info', 403)

        args = self.parser.partial.parse_args()

        if args.password:
            if not request.is_secure and not current_app.debug:
                abort('Please use secure connection', 406)
            # if only hash available then we have no password yet
            # and will not check old password field
            if len(user.password) > 16:
                if not args.old_password:
                    abort('Please specify old password if you want to change it',
                        problem='old_password')
                if not check_password(args.old_password, user.password):
                    abort('Old password doesn\'t match')

        for key, val in args.items():
            if val and hasattr(user, key):
                setattr(user, key, val)

        db.session.commit()

        return marshal(user, self.fields_self)

    @app.route('/players/<id>/login', methods=['POST'])
    def player_login(id):
        parser = RequestParser()
        parser.add_argument('password', required=True)
        args = parser.parse_args()

        player = Player.find(id)
        if not player:
            abort('Unknown nickname, gamertag or email', 404)

        if not check_password(args.password, player.password):
            abort('Password incorrect', 403)

        return PlayerResource.login_do(player)

    @app.route('/federated_login', methods=['POST'])
    @secure_only
    def federated():
        parser = RequestParser()
        parser.add_argument('token', type=federatedRenewFacebook, required=True)
        args = parser.parse_args()

        ret = requests.get(
            'https://graph.facebook.com/v2.3/me',
            params = dict(
                access_token = args.token,
                fields = 'id,email,name',
            ),
        )
        jret = ret.json()
        if 'error' in jret:
            err = jret['error']
            abort('Error fetching email from Facebook: {} {} ({})'.format(
                err.get('code', ret.status_code),
                err.get('type', ret.reason),
                err.get('message', 'no details'),
            ))
        if 'email' in jret:
            identity = jret['email']
        elif 'id' in jret:
            identity = jret['id']
        else:
            abort('Facebook didn\'t return email nor user id')

        name = jret.get('name')
        if name:
            n=1
            while Player.query.filter_by(nickname=name).count():
                name = '{} {}'.format(jret['name'], n)
                n+=1

        player = Player.query.filter_by(email=identity).first()
        created = False
        if not player:
            created = True
            player = Player()
            player.email = identity
            player.password = encrypt_password(None) # random salt
            player.nickname = name
            db.session.add(player)
        player.facebook_token = args.token
        return PlayerResource.login_do(player, created=created)

    @app.route('/players/<id>/reset_password', methods=['POST'])
    def reset_password(id):
        player = Player.find(id)
        if not player:
            abort('Unknown nickname, gamertag or email', 404)

        # send password recovery link
        ret = mailsend(player, 'recover',
                 link='https://betgame.co.uk/password.html'
                 '#userid={}&token={}'.format(
                     player.id,
                     makeToken(player)
                 ))
        if not ret:
            return jsonify(success=False, message='Couldn\'t send mail')

        return jsonify(
            success=True,
            message='Password recovery link sent to your email address',
        )

    @app.route('/players/<id>/pushtoken', methods=['POST'])
    @require_auth
    def pushtoken(user, id):
        if Player.find(id) != user:
            raise Forbidden

        if not g.device_id:
            abort('No device id in auth token, please auth again', problem='token')

        parser = RequestParser()
        parser.add_argument('push_token',
                            type=hex_field(64), # = 32 bytes
                            required=True)
        args = parser.parse_args()

        # first try find device which already uses this token
        dev = Device.query.filter_by(player = user,
                                     push_token = args.push_token
                                     ).first()
        # if we found it, then we will actually just update its last login date
        if not dev:
            # if not found - get current one (which most likely has no token)
            dev = Device.query.get(g.device_id)
            if dev.push_token:
                abort('This device already have push token specified')

        dev.push_token = args.push_token
        # update last login as it may be another device object
        # than one that was used for actual login
        dev.last_login = datetime.utcnow()
        db.session.commit()
        return jsonify(success=True)

# Balance
@app.route('/balance', methods=['GET'])
@require_auth
def balance_get(user):
    return jsonify(
        balance = user.balance_obj,
    )
@app.route('/balance/deposit', methods=['POST'])
@require_auth
def balance_deposit(user):
    parser = RequestParser()
    parser.add_argument('payment_id', required=False)
    parser.add_argument('total', type=float, required=True)
    parser.add_argument('currency', required=True)
    parser.add_argument('dry_run', type=boolean_field, default=False)
    args = parser.parse_args()

    log.info('Payment received: '+' '.join(
        ['{}: {}'.format(k,v) for k,v in args.items()]))

    rate = Fixer.latest(args.currency, 'USD')
    if not rate:
        abort('[currency]: Unknown currency {}'.format(args.currency),
              problem='currency')
    coins = args.total * rate

    if not args.dry_run:
        if not args.payment_id:
            abort('[payment_id]: required unless dry_run is true')
        # verify payment...
        ret = PayPal.call('GET', 'payments/payment/'+args.payment_id)
        if ret.get('state') != 'approved':
            abort('Payment not approved: {} - {}'.format(
                ret.get('name', '(no error code)'),
                ret.get('message', '(no error message)'),
            ), success=False)

        transaction = None
        for tr in ret.get('transactions', []):
            amount = tr.get('amount')
            if (
                (float(amount['total']), amount['currency']) ==
                (args.total, args.currency)
            ):
                transaction = tr
                break
        else:
            abort('No corresponding transaction found', success=False)

        for res in transaction.get('related_resources', []):
            sale = res.get('sale')
            if not sale:
                continue
            if sale.get('state') == 'completed':
                break
        else:
            abort('Sale is not completed', success=False)

        # now payment should be verified
        log.info('Payment approved, adding coins')

        user.balance += coins
        db.session.commit()
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
    parser.add_argument('paypal_email', type=email, required=False)
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
    except (TypeError, ValueError):
        # for bad currencies, Fixer will return None
        # and coins*None results in TypeError
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
    if not args.paypal_email:
        abort('[paypal_email] should be specified unless you are running dry-run')

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


# Game types
@app.route('/gametypes', methods=['GET'])
def gametypes():
    parser = RequestParser()
    parser.add_argument('full', type=boolean_field, default=False)
    args = parser.parse_args()
    if args.full:
        return jsonify(gametypes = Game.GAMETYPES)
    else:
        return jsonify(gametypes = list(Game.GAMETYPES))

@app.route('/gametypes/<id>/image', methods=['GET'])
def gametype_image(id):
    if id not in Game.GAMETYPES:
        raise NotFound

    parser = RequestParser()
    parser.add_argument('w', type=int, required=False)
    parser.add_argument('h', type=int, required=False)
    args = parser.parse_args()

    img = Image.open('images/{}.png'.format(id))
    ow, oh = img.size
    if args.w or args.h:
        if not args.h or (args.w and args.h and (args.w/args.h) > (ow/oh)):
            dw = args.w
            dh = round(oh / ow * dw)
        else:
            dh = args.h
            dw = round(ow / oh * dh)

        # resize
        img = img.resize((dw, dh), Image.ANTIALIAS)

        # crop if needed
        if args.w and args.h:
            if args.w != dw:
                # crop horizontally
                cw = (dw-args.w)/2
                cl, cr = math.floor(cw), math.ceil(cw)
                img = img.crop(box=(cl, 0, img.width-cr, img.height))
            elif args.h != dh:
                # crop vertically
                ch = (dh-args.h)/2
                cu, cd = math.floor(ch), math.ceil(ch)
                img = img.crop(box=(0, cu, img.width, img.height-cd))

    img_file = BytesIO()
    img.save(img_file, 'png')
    img_file.seek(0)
    return send_file(img_file, mimetype='image/png')


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
            'gamertag_created': fields.String,
            'gamertag_opponent': fields.String,
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

        parser = RequestParser()
        parser.add_argument('page', type=int, default=1)
        parser.add_argument('results_per_page', type=int, default=10)
        args = parser.parse_args()
        # cap
        if args.results_per_page > 50:
            abort('[results_per_page]: max is 50')

        query = user.games
        # TODO: filters
        total_count = query.count()
        query = query.paginate(args.page, args.results_per_page,
                               error_out = False).items

        return jsonify(
            games = fields.List(fields.Nested(self.fields)).format(query),
            num_results = total_count,
            total_pages = math.ceil(total_count/args.results_per_page),
            page = args.page,
        )

    @require_auth
    def post(self, user, id=None):
        if id:
            raise MethodNotAllowed

        parser = RequestParser()
        parser.add_argument('opponent_id', type=lambda k: Player.find_or_fail(k),
                            required=True, dest='opponent')
        parser.add_argument('gamertag_creator', required=False)
        parser.add_argument('gamertag_opponent', required=False)
        parser.add_argument('gametype', choices=Game.GAMETYPES.keys(),
                            required=True)
        parser.add_argument('gamemode', choices=Game.GAMEMODES, required=True)
        parser.add_argument('bet', type=float, required=True)
        args = parser.parse_args()

        if args.opponent == user:
            abort('You cannot compete with yourself')

        if not Game.GAMETYPES[args.gametype]['supported']:
            abort('Game type {} is not supported yet'.format(args.gametype))

        gamertag_field = Game.GAMETYPES[args.gametype]['identity']

        args.creator = user # to simplify checking
        def check_gamertag(who, msgf):
            if not args['gamertag_'+who]:
                if gamertag_field:
                    args['gamertag_'+who] = getattr(args[who], gamertag_field)
                if not args['gamertag_'+who]:
                    abort('You didn\'t specify {} gamertag, and '
                          '{}don\'t have default one configured.'.format(*msgf))
        check_gamertag('creator', ('your', ''))
        check_gamertag('opponent', ('opponent\'s', 'they '))

        if args.bet < 0.99:
            abort('[bet]: too low amount', problem='bet')
        if args.bet > user.available:
            abort('[bet]: not enough coins', problem='coins')

        game = Game()
        game.creator = user
        game.opponent = args.opponent
        game.gamertag_creator = args.gamertag_creator
        game.gamertag_opponent = args.gamertag_opponent
        game.gamemode = args.gamemode
        game.gametype = args.gametype
        game.bet = args.bet
        db.session.add(game)

        user.locked += game.bet

        db.session.commit()

        notify_users(game)

        return marshal(game, self.fields), 201

    def patch(self, id=None):
        if not id:
            raise MethodNotAllowed

        parser = RequestParser()
        parser.add_argument('state', choices=[
            'accepted', 'declined', 'cancelled'
        ])
        args = parser.parse_args()

        game = Game.query.get(id)
        if not game:
            raise NotFound

        user = check_auth()
        if user == game.creator:
            if args.state not in ['cancelled']:
                abort('Game invitation creator can only cancel it')
        elif user == game.opponent:
            if args.state not in ['accepted', 'declined']:
                abort('Game invitation opponent cannot cancel it')
        else:
            abort('You cannot change this invitation', 403)

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


# Beta testers
@api.resource(
    '/betatesters'
)
class BetaResource(restful.Resource):
    def post(self):
        def nonempty(val):
            if not val:
                raise ValueError('Should not be empty')
            return val
        parser = RequestParser()
        parser.add_argument('email', type=email, required=True)
        parser.add_argument('name', type=nonempty, required=True)
        parser.add_argument('games',
                            default='')
        parser.add_argument('platforms',
                            type=multival_field(Beta.PLATFORMS, True),
                            default='')
        parser.add_argument('console', default='')
        args = parser.parse_args()

        beta = Beta()
        beta.email = args.email
        beta.name = args.name
        beta.gametypes = args.games
        beta.platforms = ','.join(args.platforms)
        beta.console = args.console
        db.session.add(beta)
        db.session.commit()
        return jsonify(success = True)
