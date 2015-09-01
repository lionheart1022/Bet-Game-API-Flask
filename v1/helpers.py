from flask import request, abort as flask_abort
from flask import g, current_app
from flask.ext.restful.reqparse import RequestParser, Argument
from flask.ext import restful
from flask.ext.restful.utils import http_status_message

from werkzeug.exceptions import HTTPException

import urllib.parse
import jwt
import hashlib, uuid
from urllib.parse import quote
import requests
from functools import wraps
import binascii
import apns_clerk

import config
from .models import *
from .main import db

### Logging ###
class log_cls:
    """
    Just a handy wrapper for current_app.logger
    """
    def __getattr__(self, name):
        return getattr(current_app.logger, name)
log = log_cls()

### Data returning ###
def abort(message, code=400, **kwargs):
    data = {'error_code': code, 'error': message}
    if kwargs:
        data.update(kwargs)

    log.warning('Aborting request {} /{}: {}'.format(
        # GET /v1/smth
        request.method,
        request.base_url.split('//',1)[-1].split('/',1)[-1],
        ', '.join(['{}: {}'.format(*i) for i in data.items()])))

    try:
        flask_abort(code)
    except HTTPException as e:
        e.data = data
        raise
restful.abort = lambda code,message: abort(message,code) # monkey-patch to use our approach to aborting
restful.utils.error_data = lambda code: {
    'error_code': code,
    'error': http_status_message(code)
}

class classproperty:
    """
    Cached class property; evaluated only once
    """
    def __init__(self, fget):
        self.fget = fget
        self.obj = {}
    def __get__(self, owner, cls):
        if cls not in self.obj:
            self.obj[cls] = self.fget(cls)
        return self.obj[cls]


### Tokens ###
def validateFederatedToken(service, refresh_token):
    if service == 'google':
        params = dict(
            refresh_token = refresh_token,
            grant_type = 'refresh_token',
            client_id = config.GOOGLE_AUTH_CLIENT_ID,
            client_secret = config.GOOGLE_AUTH_CLIENT_SECRET,
        )
        ret = requests.post('https://www.googleapis.com/oauth2/v3/token',
                            data = params).json()
        success = 'access_token' in ret
    elif service == 'facebook':
        ret = requests.get('https://graph.facebook.com/me/permissions',
                           params = dict(
                               access_token = refresh_token,
                           )).json()
        success = 'data' in ret
    else:
        raise ValueError('Bad service '+service)

    if not success:
        raise ValueError('Invalid or revoked federated token')
def federatedExchangeGoogle(code):
    post_data = dict(
        code = code,
        client_id = config.GOOGLE_AUTH_CLIENT_ID,
        client_secret = config.GOOGLE_AUTH_CLIENT_SECRET,
        redirect_uri = 'postmessage',
        grant_type = 'authorization_code',
        scope = '',
    )
    ret = requests.post('https://accounts.google.com/o/oauth2/token',
                        data=post_data)
    jret = ret.json()
    if 'access_token' in jret:
        if 'refresh_token' in jret:
            return jret['access_token'], jret['refresh_token']
        else:
            abort('Have access token but no refresh token; '
                    'please include approval_prompt=force '
                    'or revoke access and retry.')
    else:
        err = jret.get('error')
        log.error(ret.text)
        abort('Failed to exchange code for tokens: %d %s: %s' %
                (ret.status_code, jret.get('error', ret.reason),
                jret.get('error_description', 'no details')))
def federatedRenewFacebook(refresh_token):
    ret = requests.get('https://graph.facebook.com/oauth/access_token',
                       params=dict(
                           grant_type='fb_exchange_token',
                           client_id=config.FACEBOOK_AUTH_CLIENT_ID,
                           client_secret=config.FACEBOOK_AUTH_CLIENT_SECRET,
                           fb_exchange_token=refresh_token,
                       ))
    # result is in urlencoded form, so convert it to dict
    jret = dict(urllib.parse.parse_qsl(ret.text))
    if 'access_token' in jret:
        return jret['access_token']
    else:
        try:
            err = ret.json().get('error', {})
        except Exception:
            err = {}
        abort('Failed to renew Facebook token: {} {} ({})'.format(
            err.get('code', ret.status_code),
            err.get('type', ret.reason),
            err.get('message', 'no info')))
def makeToken(user, service=None, refresh_token=None,
              from_token=None, longterm=False, device=None):
    """
    Generate JWT token for given user.
    That token will allow the user to login.
    :param service: if specified, will generate google- or facebook-based token
    :param refresh_token: refresh token for that service
    :param from_token: if specified, should be longterm token;
        if that token is federated, newly generated will be also federated
        from the same service
    :param longterm: if True, will generate longterm token
    """
    if from_token:
        # should be already checked
        header, payload = jwt.verify_jwt(from_token, config.JWT_SECRET, ['HS256'],
                                         checks_optional=True) # allow longterm
        service = payload.get('svc', service)
        if longterm:
            if service == 'facebook': # for FB will generate new LT token
                refresh_token = federatedRenewFacebook(payload['refresh'])
            else:
                # for plain and Google longterm tokens don't expire
                # so just return an old one
                return from_token
    payload = {
        'sub': user.id,
    }
    if device:
        payload['device'] = device.id
    if service: # federated token
        if not isinstance(user, Client):
            raise ValueError("Cannot generate federated token for "
                             + user.__class__.__name__)
        if longterm and not refresh_token:
            # we don't need it for regular tokens
            raise ValueError('No refresh token provided for service '+service)

        payload['svc'] = service
        if longterm: # store service's refresh token for longterms only
            payload['refresh'] = refresh_token
    slt = binascii.hexlify(user.password[-4:]).decode() # last 4 bytes of salt as hex
    payload['pass'] = slt
    if longterm:
        payload['longterm'] = True
    token = jwt.generate_jwt(payload, config.JWT_SECRET, 'HS256',
                             lifetime=None if longterm else config.JWT_LIFETIME)
    return token
class BadUserId(Exception): pass
class TokenExpired(Exception): pass
def parseToken(token, userid=None, allow_longterm=False):
    """
    Returns a Player object if the token is valid,
    raises an exception otherwise.
    """
    try:
        header, payload = jwt.verify_jwt(token, config.JWT_SECRET, ['HS256'],
                                         checks_optional=allow_longterm)
    except ValueError:
        log.info('error in token parsing', exc_info=1)
        raise ValueError("Invalid token provided")
    except Exception as e:
        if str(e) == 'expired':
            raise TokenExpired
        raise ValueError("Bad token: "+str(e))
    if 'sub' not in payload:
        raise ValueError('Invalid token provided')
    if not allow_longterm and 'longterm' in payload:
        raise ValueError('Longterm token not allowed, use short-living one')
    if not payload['sub']:
        raise ValueError('Invalid userid in token: '+str(payload['sub']))
    if userid and payload['sub'] != userid:
        raise BadUserId
    user = Player.query.get(payload['sub'])
    if not user:
        raise ValueError("No such player")
    slt = binascii.hexlify(user.password[-4:]).decode() # last 4 bytes of salt
    if payload.get('pass') != slt:
        raise ValueError('Your password was changed, please login again')
    if 'svc' in payload and cls == Client and 'longterm' in payload:
        if 'longterm' in payload:
            validateFederatedToken(payload.get('svc'), payload.get('refresh'))

    g.device_id = payload.get('device', None)
    # note that this dev id might be obsolete
    # if login was performed without token and then token was specified

    return user

def check_auth(userid=None,
               allow_nonverified=False,
               allow_nonfilled=False,
               allow_banned=False,
               allow_expired=True,
               allow_longterm=False,
               optional=False):
    """
    Check if auth token is passed,
    validate that token
    and return user object.

    :param allow_expired: if we allow access for vendors with expired subscription.
        This defaults to True, so methods should be manually restricted.
    :param optional: for missing tokens return None without aborting request
    """
    # obtain token
    if ('Authorization' in request.headers
        and request.headers['Authorization'].startswith('Bearer ')):
        token = request.headers['Authorization'][7:]
    elif request.json and 'token' in request.json:
        token = request.json['token']
    elif 'token' in request.values:
        token = request.values['token']
    else:
        if optional:
            return None
        abort('Authorization required', 401)
    # check token
    try:
        user = parseToken(token, userid, allow_longterm)
    except ValueError as e:
        abort(str(e), 401)
    except BadUserId:
        abort('You are not authorized to access this method', 403)
    except TokenExpired:
        abort('Token expired, please obtain new one', 403, expired=True)

    if not allow_nonfilled and not user.complete:
        abort('Profile is incomplete, please fill!', 403)

    return user

def require_auth(_func=None, **params):
    """
    Decorator version of check_auth.
    This decorator checks if auth token is passed,
    validates that token
    and passes user object to the decorated function as a `user` argument.
    """
    def decorator(func):
        @wraps(func)
        def caller(*args, **kwargs):
            user = check_auth(**params)
            g.user = user
            # call function
            return func(*args, user=user, **kwargs)
        return caller
    if hasattr(_func, '__call__'): # used as non-function decorator
        return decorator(_func)
    return decorator

def secure_only(func):
    """
    This decorator prohibits access to method by insecure connection,
    excluding development state.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not request.is_secure and not current_app.debug:
            abort('Please use secure connection', 406)
        return func(*args, **kwargs)
    return wrapper

def sendVerificationCode(user):
    'Creates email verification code for user and mails it'
    if not hasattr(user, 'isEmailVerified'):
        raise ValueError('Invalid user type')
    code = uuid.uuid4().hex[:8] # 8 hex digits
    user.email_verification_code = code
    from .apis import mailsend
    mailsend(user, 'verification', code=code)
    # db session will be committed after this method called
def checkVerificationCode(user, code):
    """
    Checks previously generated JWT token and marks user as verified on success.
    Will raise ValueError on failure.
    """
    if not hasattr(user, 'isEmailVerified'):
        raise ValueError('Invalid user type')
    if user.isEmailVerified:
        raise ValueError('User already verified')
    if user.email_verification_code.strip().lower() != code.strip().lower():
        raise ValueError('Incorrect code')
    user.email_verification_code = None
    db.session.commit()
    return True

### Field checkers ###
currency_cache = {}
# FIXME: cache currency queries
def currency(val):
    """
    Checks whether the value provided is a valid currency.
    Raises ValueError if not.
    """
    if not val:
        return None
    val = val.upper()
    if val in currency_cache:
        return currency_cache[val]
    currency = Currency.query.filter_by(name=val).first()
    if not currency:
        raise ValueError('Unknown currency %s' % val)
    #currency_cache[val] = {'name':currency.name, 'iso':currency.iso}
    return currency

def country(val):
    if not isinstance(val, str):
        raise ValueError(val)
    if len(val) != 3:
        raise ValueError("Incorrect country code: %s" % val)
    # TODO: check if country is valid
    return val.upper()

def email(val):
    """
    Should be 3 parts separated by @ and .,
    none of these parts can be empty.
    """
    val = val.strip()
    if not '@' in val:
        raise ValueError('Not a valid e-mail')
    user, domain = val.split('@',1)
    if (not user
        or not '.' in domain):
        raise ValueError('Not a valid e-mail')
    a,b = domain.rsplit('.',1)
    if not a or not b:
        raise ValueError('Not a valid e-mail')
    return val

def phone_field(val):
    if not isinstance(val, str):
        raise ValueError('Bad type '+repr(val))
    pnum = ''.join([c for c in val if c in '+0123456789'])
    if not pnum:
        raise ValueError('No digits in phone number '+repr(val))
    return pnum

def boolean_field(val):
    if hasattr(val,'lower'):
        val = val.lower()
    if val in [0,False,'0','off','false','no']:
        return False
    if val in [1,True,'1','on','true','yes']:
        return True
    raise ValueError(str(val)+' is not boolean')

def gamertag_force_field(val):
    val = boolean_field(val)
    if val:
        g.gamertag_force = True
    return val

gamertag_cache = {}
def gamertag_field(nick):
    if nick.lower() in gamertag_cache:
        if gamertag_cache[nick.lower()]:
            return gamertag_cache[nick.lower()]
        raise ValueError('Unknown gamertag: '+nick)

    url = 'https://www.easports.com/fifa/api/'\
        'fifa15-xboxone/match-history/fut/{}'.format(quote(nick))
    try:
        ret = requests.get(url)
        if ret.status_code == 404:
            # don't cache not-registered nicks as they can appear in future
            #gamertag_cache[nick.lower()] = None
            raise ValueError(
                'Gamertag {} seems to be unknown '
                'for FIFA game servers'.format(nick))
        data = ret.json()['data']
        # normalized gamertag (with correct capitalizing)
        # if no data then cannot know correct capitalizing; return as is
        goodnick = data[0]['self']['user_info'][0] if data else nick
        gamertag_cache[nick.lower()] = goodnick
        return goodnick
    except ValueError:
        log.warning('json error: '+str(ret))
        if getattr(g, 'gamertag_force', False):
            return nick
        raise
    except Exception as e: # json failure or missing key
        log.error('Failed to validate gamertag '+nick, exc_info=True)
        if 'ret' in locals():
            log.error(ret)
        log.error('Allowing it...')
        #raise ValueError('Couldn\'t validate this gamertag: {}'.format(nick))
        return nick

def encrypt_password(val):
    """
    Check password for weakness, and convert it to its hash.
    If password provided is None, will generate a random salt w/o password
    """
    if val is None:
        # just random salt, 16 bytes
        return uuid.uuid4().bytes # 16 bytes
    if not isinstance(val, str):
        raise ValueError(val)
    if len(val) < 4:
        raise ValueError("Too weak password, minimum is 4 characters")
    if len(val) > 1024:
        # prohibit extremely long passwords
        # because they cause resource eating
        raise ValueError("Too long password")

    salt = uuid.uuid4().bytes # 16 bytes
    crypted = hashlib.pbkdf2_hmac('SHA1', val.encode(), salt, 10000)
    return crypted+salt

def check_password(password, reference):
    salt = reference[-16:] # last 16 bytes = uuid length
    crypted = hashlib.pbkdf2_hmac('SHA1', password.encode(), salt, 10000)
    return crypted+salt == reference

def string_field(field, ftype=None, check_unique=True, allow_empty=False):
    """
    This decorator-like function returns a function
    which will assert that given string is not longer than maxsize.
    Also checks for uniqueness if needed.
    """
    maxsize = field.type.length
    def check(val):
        if not isinstance(val, str):
            raise TypeError
        if len(val) > maxsize:
            raise ValueError('Too long string')
        if not val:
            if allow_empty:
                return None
            raise ValueError('Empty value not allowed')
        # check&convert field type (like email) if provided
        if ftype:
            val = ftype(val)
        # now check for uniqueness, if necessary
        if field.unique and check_unique:
            userid = getattr(g, 'userid', None)
            q = field.class_.query.filter(field==val)
            if userid:
                q = q.filter(field.class_.id != userid)
            exists = db.session.query(q.exists()).scalar()
            if exists:
                raise ValueError('Already used by someone')
        return val
    return check

def bitmask_field(options):
    '''
    Converts comma-separated list of options to bitmask.
    '''
    def check(val):
        if not isinstance(val, str):
            raise ValueError
        mask = 0
        parts = val.split(',')
        for part in parts:
            if part in options:
                mask &= options[part]
            elif part == '': # ignore empty parts
                continue
            else:
                raise ValueError('Unknown option: '+part)
        return mask
    return check
def multival_field(options, allow_empty=False):
    """
    Converts comma-separated list to set of strings,
    checking each item for validity.
    """
    def check(val):
        if not isinstance(val, str):
            raise ValueError
        if not val:
            if allow_empty:
                return []
            raise ValueError('Please choose at least one option')
        parts = set(val.split(','))
        for part in parts:
            if part not in options:
                raise ValueError('Unknown option: '+part)
        return parts
    return check

def hex_field(length):
    def check(val):
        if len(val) != length:
            raise ValueError('Should be %d characters' % length)
        for c in val:
            if c not in 'abcdefABCDEF' and not c.isdigit():
                raise ValueError('Bad character %s' % c)
        return val
    return check


### Extension of RequestParser ###
class MyArgument(Argument):
    def handle_validation_error(self, error, bundle_errors=None):
        help_str = '({}) '.format(self.help) if self.help else ''
        msg = '[{}]: {}{}'.format(self.name, help_str, error)
        abort(msg, problem=self.name)
class MyRequestParser(RequestParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.argument_class = MyArgument


# FIXME: cache currency queries
class CurrencyField(restful.fields.Raw):
    def format(self, curr):
        return {'name': curr.name,
                'description': curr.iso,
                }

class InverseBooleanField(restful.fields.Boolean):
    def format(self, val):
        return not bool(val)

class AlternatingNested(restful.fields.Raw):
    """
    Similar to Nested, but allows to pass 2 different structures.
    They are chosen based on result of `condition` proc evaluation
    on surrounding object and value.
    """
    def __init__(self, condition, nested, alternate, **kwargs):
        super().__init__(nested, **kwargs)
        self.condition = condition
        self.alternate = alternate
        self.nested = nested
    def output(self, key, obj):
        value = restful.fields.get_value(
            key if self.attribute is None else self.attribute, obj)
        if value is None:
            return super().output(key, obj)
        return restful.marshal(value, self.nested
                       if self.condition(obj, value) else
                       self.alternate)

class CommaListField(restful.fields.Raw):
    def format(self, val):
        if not isinstance(val, str):
            raise ValueError
        if not val: # empty string?
            return []
        return val.split(',')


# Notification
apns_session = None
def notify_users(game, nomail=False):
    """
    This method sends PUSH notifications about game state change
    to all interested users.
    It will also send congratulations email to game winner.
    """
    msg = {
        'new': '{} invites you to compete'.format(game.creator.nickname),
        'cancelled': '{} cancelled their invitation'.format(game.creator.nickname),
        'accepted': '{} accepted your invitation, start playing now!'
            .format(game.opponent.nickname),
        'declined': '{} declined your invitation'.format(game.opponent.nickname),
        'finished': 'Game finished, coins moved',
    }[game.state]

    players = []
    if game.state in ['new', 'cancelled', 'finished']:
        players.append(game.opponent)
    if game.state in ['accepted', 'declined', 'finished']:
        players.append(game.creator)
    receivers = []
    for p in players:
        for d in p.devices:
            if d.push_token:
                if len(d.push_token) == 64:
                    # 64 hex digits = 32 bytes, valid token length
                    receivers.append(d.push_token)
                else:
                    log.warning('Incorrect push token '+d.push_token)

    from . import routes # for fields list
    message = None
    if receivers:
        # add "mock" device, because without it srv.send() hangs
        receivers.append('0'*64)
        log.debug('recv: '+str(receivers))
        message = apns_clerk.Message(receivers, alert=msg, badge='increment',
                                    content_available=1,
                                    game=restful.marshal(
                                        game, routes.GameResource.fields))
        global apns_session
        try:
            if not apns_session:
                apns_session = apns_clerk.Session()
        except Exception: # import error, OpenSSL error
            log.exception('APNS failure!')
            message = None # will not send PUSH
        else:
            conn = apns_session.get_connection('push_sandbox',
                                                cert_file='apns.pem')

    log.debug('msg: '+str(message))

    def send_push(msg):
        log.debug('srv..')
        srv = apns_clerk.APNs(conn)
        try:
            log.debug('sending..')
            ret = srv.send(message)
            log.info('push sending done for {}'.format(msg))
        except:
            log.error('Failed to connect to APNs', exc_info=True)
            return False
        else:
            for token, reason in ret.failed.items():
                log.warning('Device {} failed by {}, removing'.format(token,reason))
                dev = Device.query.filter_by(push_token=token).first()
                if dev:
                    db.session.delete(dev)
                    db.session.commit()

            for code, error in ret.errors:
                log.warning('Error {}: {}'.format(code, error))

            if ret.needs_retry():
                log.info('needs retry.. so will retry')
                return send_push(ret.retry)
            return True

    from .apis import mailsend
    def send_mail(game):
        if game.state == 'finished':
            if game.winner == 'creator':
                winner = game.creator
            elif game.winner == 'opponent':
                winner = game.opponent
            elif game.winner == 'draw':
                return # will not notify anybody
            else:
                log.error('Internal error: incorrect game winner '+game.winner
                          +' for state '+game.state)
                return
            return mailsend(
                winner, 'win',
                date = game.finish_date.strftime('%d.%m.%Y %H:%M:%S UTC'),
                bet = game.bet,
                balance = winner.available,
            )


    result = True
    if message: # if had any receivers
        result = send_push(message)
    # and send email if applicable
    if not nomail:
        result = result and send_mail(game)
    return result

