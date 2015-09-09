from flask import request, jsonify, current_app, g, send_file
from flask.ext import restful
from flask.ext.restful import fields, marshal
from sqlalchemy.sql.expression import func

from werkzeug.exceptions import HTTPException
from werkzeug.exceptions import BadRequest, MethodNotAllowed, Forbidden, NotImplemented, NotFound

import os
from io import BytesIO
from datetime import datetime, timedelta
import math
from functools import reduce
import itertools
import requests
from PIL import Image

import config
from .models import *
from .helpers import *
from .apis import *
from .polling import *
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
        fieldlist = [
            ('_force', gamertag_force_field, False),
            ('nickname', None, True),
            ('email', email, True),
            ('password', encrypt_password, True),
            ('facebook_token', federatedRenewFacebook, False), # should be last to avoid extra queries
            ('bio', None, False),
        ]
        identities = set()
        for poller in Poller.allPollers():
            if poller.identity:
                identities.add((poller.identity, poller.identity_check, False))
        fieldlist.extend(identities)
        for name, type, required in fieldlist:
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
            bio = fields.String,
            has_userpic = fields.Boolean,
            devices = fields.List(fields.Nested(dict(
                id = fields.Integer,
                last_login = fields.DateTime,
            ))),

            ea_gamertag = fields.String,
            riot_summonerName = fields.String,
            steam_id = fields.String,
            starcraft_uid = fields.String,

            # some stats
            gamecount = fields.Integer, # FIXME: optimize query somehow?
            winrate = fields.Float,
            #popularity = fields.Integer,
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
            # Leaderboard mode

            parser = RequestParser()
            parser.add_argument('filter')
            parser.add_argument('filt_op',
                                choices=['startswith', 'contains'],
                                default='startswith',
                                )
            parser.add_argument(
                'order',
                choices=sum(
                    [[s, '-'+s]
                     for s in
                     ('lastbet',
                      'popularity',
                      'winrate',
                      )], []),
                required=False,
            )
            #parser.add_argument('names_only', type=boolean_field)
            parser.add_argument('page', type=int, default=1)
            parser.add_argument('results_per_page', type=int, default=10)
            args = parser.parse_args()
            # cap
            if args.results_per_page > 50:
                abort('[results_per_page]: max is 50')

            if args.filter:
                query = Player.search(args.filter, args.filt_op)
            else:
                query = Player.query

            if args.order:
                if args.order.startswith('-'):
                    order = getattr(Player, args.order[1:]).desc()
                else:
                    order = getattr(Player, args.order).asc()
                query = query.order_by(order)
            # TODO: sort by win rate desc if requested

            if query:
                total_count = query.count()
                query = query.paginate(args.page, args.results_per_page,
                                    error_out = False).items

            return jsonify(
                players = fields.List(
                    fields.Nested(
                        self.fields_public
                    )
                ).format(query),
                num_results = total_count,
                total_pages = math.ceil(total_count/args.results_per_page),
                page = args.page,
            )

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

        log.debug('NEW USER: '+repr(request.get_data()))

        args_login = self.parser.login.parse_args() # check before others
        args = self.parser.parse_args()

        player = Player()
        for key, val in args.items():
            if hasattr(player, key):
                setattr(player, key, val)
        if 'userpic' in request.files:
            UserpicResource.upload(request.files['userpic'], player)
        # TODO: validate fb token?
        db.session.add(player)
        db.session.commit()

        self.greet(player)

        return self.login_do(player, args_login, created=True)

    def greet(self, user):
        mailsend(user, 'greeting')
        # we don't check result as it is not critical if this email is not sent
        mailsend(user, 'greet_personal',
                 sender='Doug from BetGame <doug@betgame.co.uk>',
                 delayed = timedelta(days=1),
                 )

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
                # if old password not specified, don't check it -
                # it is not secure, but allows password recovery.
                # TODO: use special token for password recovery?..
                if args.old_password:
                    if not check_password(args.old_password, user.password):
                        abort('Old password doesn\'t match')

        hadmail = bool(user.email)

        for key, val in args.items():
            if val and hasattr(user, key):
                setattr(user, key, val)
                if not hadmail and key == 'email':
                    self.greet(user)
        if 'userpic' in request.files:
            UserpicResource.upload(request.files['userpic'], user)

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

    @app.route('/players/<id>/recent_opponents')
    @require_auth
    def recent_opponents(user, id):
        if Player.find(id) != user:
            raise Forbidden

        return jsonify(opponents = fields.List(fields.Nested(
            PlayerResource.fields_public
        )).format(user.recent_opponents))

# Userpic
@api.resource('/players/<id>/userpic')
class UserpicResource(restful.Resource):
    PICDIR = os.path.dirname(__file__)+'/../userpics/'
    @classmethod
    def file_for(cls, player):
        return os.path.join(cls.PICDIR, str(player.id)+'.png')

    @require_auth
    def get(self, user, id):
        player = Player.find(id)
        if not player:
            raise NotFound

        f = self.file_for(player)
        if not os.path.exists(f):
            return (None, 204) # HTTP code 204 NO CONTENT
        return send_file(f)

    @classmethod
    def upload(cls, f, player):
        if not f.filename.lower().endswith('.png'):
            abort('[userpic]: only PNG files allowed')

        # FIXME: limit size!

        f.save(cls.file_for(player))

    @require_auth(allow_nonfilled=True)
    def put(self, id, user):
        player = Player.find(id)
        if not player:
            raise NotFound
        if player != user:
            raise Forbidden

        f = request.files.get('userpic')
        if not f:
            abort('[userpic]: please provide file!')

        self.upload(f, player)

        return dict(success=True)

    def post(self, *args, **kwargs):
        return self.put(*args, **kwargs)

# Balance
@app.route('/balance', methods=['GET'])
@require_auth
def balance_get(user):
    return jsonify(
        balance = user.balance_obj,
    )
@app.route('/balance/history', methods=['GET'])
@require_auth
def balance_history(user):
    parser = RequestParser()
    parser.add_argument('page', type=int, default=1)
    parser.add_argument('results_per_page', type=int, default=10)
    args = parser.parse_args()

    if args.results_per_page > 50:
        abort('[results_per_page]: max is 50')

    query = user.transactions
    total_count = query.count()
    query = query.paginate(args.page, args.results_per_page,
                           error_out=False).items

    return jsonify(
        transactions = fields.List(fields.Nested(dict(
            id = fields.Integer,
            date = fields.DateTime,
            type = fields.String,
            sum = fields.Float,
            balance = fields.Float,
            game_id = fields.Integer,
            comment = fields.String,
        ))).format(query),
        num_results = total_count,
        total_pages = math.ceil(total_count/args.results_per_page),
        page = args.page,
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
        db.session.add(Transaction(
            player = user,
            type = 'deposit',
            sum = coins,
            balance = user.balance,
            comment = 'Converted from {} {}'.format(args.total, args.currency),
        ))
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
    db.session.add(Transaction(
        player = user,
        type = 'withdraw',
        sum = -coins,
        balance = user.balance,
        comment = 'Converted to {} {}'.format(
            amount,
            args.currency,
        ),
    ))
    db.session.commit()

    # ... and only then do actual transaction;
    # will return balance if failure happens

    try:
        ret = PayPal.call('POST', 'payments/payouts', dict(
            sync_mode = True,
        ), dict(
            sender_batch_header = dict(
#                sender_batch_id = None,
                email_subject = 'Payout from BetGame',
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
        # TODO: add transaction id to our Transaction object
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
        # restore balance
        user.balance += args.coins
        db.session.add(Transaction(
            player = user,
            type = 'withdraw',
            sum = coins,
            balance = user.balance,
            comment = 'Withdraw operation aborted due to error',
        ))
        db.session.commit()

        log.error('Exception while performing payout', exc_info=True)

        if isinstance(e, HTTPException):
            raise

        abort('Couldn\'t complete payout', 500,
              success=False, dry_run=False)


# Game types
@app.route('/gametypes', methods=['GET'])
def gametypes():
    parser = RequestParser()
    parser.add_argument('betcount', type=boolean_field, default=False)
    parser.add_argument('latest', type=boolean_field, default=False)
    args = parser.parse_args()

    counts = {}
    if args.betcount:
        bca = (db.session.query(Game.gametype,
                                func.count(Game.gametype),
                                func.max(Game.create_date),
                                )
               .group_by(Game.gametype).all())
        counts = {k: (c, d) for k,c,d in bca}
    times = []
    if args.latest:
        bta = (Game.query
               .with_entities(Game.gametype, func.max(Game.create_date))
               .group_by(Game.gametype)
               .order_by(Game.create_date.desc())
               .all())
        times = bta # in proper order

    gamedata = []
    identities = {}
    for poller in Poller.allPollers():
        for gametype, gametype_name in poller.gametypes.items():
            if poller.identity:
                data = dict(
                    id = gametype,
                    name = gametype_name,
                    supported = True,
                    gamemodes = poller.gamemodes,
                    identity = poller.identity,
                    identity_name = poller.identity_name,
                    twitch = poller.twitch,
                )
                if args.betcount:
                    data['betcount'], data['lastbet'] = \
                        counts.get(gametype, (0, None))
                if isinstance(poller.description, dict):
                    data['description'] = poller.description[gametype]
                else:
                    data['description'] = poller.description
                if data['description']:
                    # strip enclosing whites,
                    # then replace single \n's with spaces
                    # and double \n's with single \n's
                    data['description'] = '\n'.join(map(
                        lambda para: ' '.join(map(
                            lambda line: line.strip(),
                            para.split('\n')
                        )),
                        data['description'].strip().split('\n\n')
                    ))
                gamedata.append(data)
                identities[poller.identity] = poller.identity_name
            else: # DummyPoller
                gamedata.append(dict(
                    id = gametype,
                    name = gametype_name,
                    supported = False,
                ))
    ret = dict(
        gametypes = gamedata,
        identities = identities,
    )
    if args.latest:
        ret['latest'] = [
            dict(
                gametype = gametype,
                date = date,
            ) for gametype, date in times
        ]
    return jsonify(**ret)

@app.route('/gametypes/<id>/image')
@app.route('/gametypes/<id>/background')
def gametype_image(id):
    if id not in Poller.all_gametypes:
        raise NotFound

    parser = RequestParser()
    parser.add_argument('w', type=int, required=False)
    parser.add_argument('h', type=int, required=False)
    args = parser.parse_args()

    filename = 'images/{}{}.png'.format(
        'bg/' if request.path.endswith('/background') else '',
        id,
    )
    try:
        img = Image.open(filename)
    except FileNotFoundError:
        raise NotFound # 404
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
            'gamertag_creator': fields.String,
            'gamertag_opponent': fields.String,
            'twitch_handle': fields.String,
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
        parser.add_argument(
            'order',
            choices=sum(
                [[s, '-'+s]
                 for s in
                 ('create_date',
                  'accept_date',
                  'gametype',
                  'creator_id',
                  'opponent_id',
                  )], []),
            required=False,
        )
        args = parser.parse_args()
        # cap
        if args.results_per_page > 50:
            abort('[results_per_page]: max is 50')

        query = user.games

        # TODO: filters
        if args.order:
            if args.order.startswith('-'):
                order = getattr(Game, args.order[1:]).desc()
            else:
                order = getattr(Game, args.order).asc()
            query = query.order_by(order)


        total_count = query.count()
        query = query.paginate(args.page, args.results_per_page,
                               error_out = False).items

        return jsonify(
            games = fields.List(fields.Nested(self.fields)).format(query),
            num_results = total_count,
            total_pages = math.ceil(total_count/args.results_per_page),
            page = args.page,
        )

    @classproperty
    def postparser(cls):
        parser = RequestParser()
        parser.add_argument('opponent_id', type=Player.find_or_fail,
                            required=True, dest='opponent')
        parser.add_argument('gamertag_creator', required=False)
        parser.add_argument('gamertag_opponent', required=False)
        parser.add_argument('twitch_handle',
                            type=Twitch.check_handle,
                            required=False)
        parser.add_argument('gametype', choices=Poller.all_gametypes,
                            required=True)
        parser.add_argument('bet', type=float, required=True)
        return parser
    @require_auth
    def post(self, user, id=None):
        if id:
            raise MethodNotAllowed

        args = self.postparser.parse_args()
        args.gamemode = None

        poller = Poller.findPoller(args.gametype)
        if not poller or poller == DummyPoller:
            abort('Game type {} is not supported yet'.format(args.gametype))

        if poller.gamemodes:
            gmparser = RequestParser()
            gmparser.add_argument('gamemode', choices=poller.gamemodes,
                                required=True)
            gmargs = gmparser.parse_args()
            args.gamemode = gmargs.gamemode

        if args.opponent == user:
            abort('You cannot compete with yourself')

        gamertag_field = poller.identity

        args.creator = user # to simplify checking
        def check_gamertag(who, msgf):
            if args['gamertag_'+who]:
                # Checking method might convert data somehow,
                # so it is mandatory to call it.
                checker = poller.identity_check
                if isinstance(checker, str): # resolve it here
                    checker = globals()[checker]
                try:
                    args['gamertag_'+who] = checker(args['gamertag_'+who])
                except ValueError as e:
                    abort('[gamertag_{}]: {}'.format(who, e))
            else:
                if gamertag_field:
                    args['gamertag_'+who] = getattr(args[who], gamertag_field)
                if not args['gamertag_'+who]:
                    abort('You didn\'t specify {} gamertag, and '
                          '{}don\'t have default one configured.'.format(*msgf))
        check_gamertag('creator', ('your', ''))
        check_gamertag('opponent', ('opponent\'s', 'they '))

        if poller.sameregion:
            # additional check for regions
            region1 = args['gamertag_creator'].split('/',1)[0]
            region2 = args['gamertag_opponent'].split('/',1)[0]
            if region1 != region2:
                abort('You and your opponent should be in the same region; '
                      'but actually you are in {} and your opponent is in {}'.format(
                          region1, region2))

        if poller.twitch == 2 and not args.twitch_handle:
            abort('[twitch_handle]: is mandatory for this game type!',
                  problem='twitch_handle')

        if args.bet < 0.99:
            abort('[bet]: too low amount', problem='bet')
        if args.bet > user.available:
            abort('[bet]: not enough coins', problem='coins')

        if args.twitch_handle and not poller.twitch:
            abort('Twitch streams are not yet supported for this gametype')
        if poller.twitch == 2 and not args.twitch_handle:
            abort('[twitch_handle] mandatory for this gametype',
                  problem='twitch_handle')
        # TODO: validate twitch handle, if any ?

        game = Game()
        game.creator = user
        game.opponent = args.opponent
        game.gamertag_creator = args.gamertag_creator
        game.gamertag_opponent = args.gamertag_opponent
        game.twitch_handle = args.twitch_handle
        game.gametype = args.gametype
        game.gamemode = args.gamemode
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
        ], required=True)
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

        if args.state == 'accepted':
            try:
                poller.gamestarted(game)
            except Exception as e:
                log.exception('Error in gamestarted for {}: {}'.format(
                    poller, e))
                abort('Failed to initialize poller, please contact support!', 500)

        # Now, before we save state change, start twitch stream if required
        # so that we can abort request if it failed
        if game.twitch_handle and args.state == 'accepted':
            ret = requests.put(
                '{}/streams/{}/{}'.format(
                    config.OBSERVER_URL,
                    game.twitch_handle,
                    game.gametype,
                ),
                data = dict(
                    game_id = game.id,
                    creator = game.gamertag_creator,
                    opponent = game.gamertag_opponent,
                ),
            )
            if ret.status_code not in (200, 201):
                jret = ret.json()
                if ret.status_code == 409: # dup
                    # TODO: check it on creation??
                    abort('This twitch stream is already watched '
                          'for another game (or another players)')
                elif ret.status_code == 507: # full
                    abort('Cannot start twitch observing, all servers are busy now; '
                          'please retry later', 500)
                abort('Couldn\'t start Twitch: '+jret.get('error', 'Unknown err'))

        game.state = args.state
        game.accept_date = datetime.utcnow()

        if args.state == 'accepted':
            # bet is locked on creator's account; lock it on opponent's as well
            game.opponent.locked += game.bet
        else:
            # bet was locked on creator's account; unlock it
            game.creator.locked -= game.bet

        db.session.commit()

        notify_users(game)

        return marshal(game, self.fields)


# Beta testers
@api.resource(
    '/betatesters',
    '/betatesters/<int:id>',
)
class BetaResource(restful.Resource):
    @classproperty
    def fields(cls):
        return dict(
            id = fields.Integer,
            email = fields.String,
            name = fields.String,
            gametypes = CommaListField,
            platforms = CommaListField,
            console = CommaListField,
            create_date = fields.DateTime,
            medium = CommaListField,
            flags = CommaListField,
        )
    @require_auth
    def get(self, user, id=None):
        if id:
            raise MethodNotAllowed
        user = check_auth()
        if user.id not in config.ADMIN_IDS:
            raise Forbidden

        return jsonify(
            betatesters = fields.List(fields.Nested(self.fields)).format(
                Beta.query,
            ),
        )

    def post(self, id=None):
        if id:
            raise MethodNotAllowed
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
        return jsonify(
            success = True,
            betatester = marshal(
                beta,
                self.fields,
            ),
        )

    @require_auth
    def patch(self, user, id=None):
        if not id:
            raise MethodNotAllowed

        beta = Beta.query.get(id)
        if not beta:
            raise NotFound

        parser = RequestParser()
        parser.add_argument('medium')
        parser.add_argument('flags')
        args = parser.parse_args()

        for k,v in args.items():
            if v is not None and hasattr(beta, k):
                setattr(beta, k, v)

        db.session.commit()

        return dict(success = True)

# Debugging-related endpoints
@app.route('/debug/push_state/<state>', methods=['POST'])
@require_auth
def push_state(state, user):
    if state not in Game.state.prop.columns[0].type.enums:
        abort('Unknown state '+state, 404)

    parser = GameResource.postparser.copy()
    parser.remove_argument('opponent_id')
    args = parser.parse_args()

    game = Game()
    game.creator = game.opponent = user
    game.state = state
    for k, v in args.items():
        if hasattr(game, k):
            setattr(game, k, v)

    result = notify_users(game, nomail=True)

    return jsonify(
        pushed=result,
        game = marshal(game, GameResource.fields)
    )

@app.route('/debug/echo')
def debug_echo():
    return '<{}>\n{}\n'.format(
        repr(request.get_data()),
        repr(request.form),
    )
