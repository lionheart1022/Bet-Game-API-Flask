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

import eventlet
eventlet.monkey_patch() # before loading flask

from flask import Flask, jsonify, request
from flask.ext import restful
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful import fields, marshal
from flask.ext.restful.reqparse import RequestParser
from flask.ext.restful.utils import http_status_message
from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import BadRequest, MethodNotAllowed, Forbidden, NotImplemented, NotFound

import os
from datetime import datetime, timedelta
import subprocess
import requests
import logging

import config
from observer_conf import SELF_URL, PARENT, CHILDREN, MAX_STREAMS

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
log = app.logger
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


# Restrict list of allowed hosts
def getsiblings():
    import socket
    ret = set()
    for host in list(CHILDREN.values()) + [PARENT[1], 'localhost']:
        if not host:
            continue # skip empty addrs, e.g. parent for master node
        host = host.split('://',1)[-1].split(':',1)[0] # cut off protocol and port
        h, a, ips = socket.gethostbyname_ex(host)
        ret.update(ips)
    return ret
NEIGHBOURS = getsiblings()
@app.before_request
def restrict_siblings():
    if request.remote_addr not in NEIGHBOURS:
        log.debug('Attempt to request from unknown address '+request.remote_addr)
        raise Forbidden


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

    # Twitch stream handle
    handle = db.Column(db.String(64), nullable=False, unique=True)

    # Which child handles this stream? None if self
    child = db.Column(db.String(64), default=None)

    # Gametype and other metadata goes below
    gametype = db.Column(db.String(64), default=None)

    # this is an ID of Game object.
    # We don't use foreign key because we may reside on separate server
    # and use separate db.
    game_id = db.Column(db.Integer, unique=True)

    state = db.Column(db.Enum('watching', 'found', 'failed'), default='watching')

    creator = db.Column(db.String(128))
    opponent = db.Column(db.String(128))

    @classmethod
    def find(cls, id):
        try:
            ret = cls.query.get(int(id))
        except ValueError: pass
        if not ret:
            ret = cls.query.filter_by(handle=id)
        return ret


# Main logic
class Handler:
    """
    This hierarchy is similar to Poller's one
    """
    gametypes = []
    path = None
    env = None
    process = None
    quorum = 5 # min results, or
    maxdelta = timedelta(seconds=10)

    @classmethod
    def find(cls, gametype):
        if gametype in cls.gametypes:
            return cls
        for sub in cls.__subclasses__():
            ret = sub.find(gametype)
            if ret:
                return ret

    @classmethod
    def start(cls, stream):
        eventlet.spawn(cls.watch, stream)
        pool.append(stream.handle)

    @classmethod
    def watch(cls, stream):
        # start subprocess and watch its output
        if cls.path:
            os.chdir(cls.path)
        cmd = cls.process.format(handle = stream.handle)
        if cls.env:
            cmd = 'source {}/bin/activate; {}'.format(cls.env, cmd)
        sub = subprocess.Popen(
            cmd,
            bufsize = 1, # line buffered
            universal_newlines = True, # text mode
            shell = True, # interpret ';'-separated commands
            stdout = subprocess.PIPE, # intercept it!
        )

        # and now the main loop starts
        results = []
        first_res = None
        while True:
            line = sub.stdout.readline().strip()
            result = cls.check(stream, line)
            if result is not None:
                stream.state = 'found'
                results.append(result)
                if not first_res:
                    first_res = datetime.utcnow()

            # if process stopped itself and no more output left
            if not line and sub.poll() is not None:
                log.debug('process stopped itself, considering draw')
                stream.state = 'failed'
                result = 'draw'

            # consider game done when either got quorum results
            # or maxdelta passed since first result
            if results and (len(results) >= cls.quorum or
                            datetime.utcnow() > first_res + cls.maxdelta):
                # calculate most trusted result
                freqs = {}
                for r in results:
                    if r in freqs:
                        freqs[r] += 1
                    else:
                        freqs[r] = 1
                pairs = sorted(freqs.items(), key=lambda p: p[1])
                result = pairs[0][0]

                log.debug('got result: %s' % result)
                # handle result
                db.session.commit()
                cls.done(stream, result, first_res.timestamp())
                # and terminate process as we don't need it anymore
                if sub.poll() is None:
                    sub.terminate()
                    eventlet.sleep(3)
                    sub.kill()
                break

            eventlet.sleep(.5)

        # TODO: clean sub?

        # mark that this stream has stopped
        pool.remove(stream.handle)

    @classmethod
    def done(stream, result, timestamp):
        # determine winner and propagate result to master
        requests.patch(
            '{}/streams/{}'.format(SELF_URL, stream.handle),
            data = dict(
                winner = result,
                timestamp = timestamp,
            ),
        )

class FifaHandler(Handler):
    gametypes = [
        'fifa14-xboxone',
        'fifa15-xboxone',
    ]
    path = 'fifastreamer'
    env = '../../env2'
    process = 'python2 fifa_streamer.py "http://twitch.tv/{handle}"'

    @classmethod
    def check(cls, stream, line):
        log.debug(line)
        if 'Impossible to recognize who won' in line:
            log.warning('Couldn\'t get result, skipping')
            return None #'draw'
        if 'Score:' in line:
            nick1, nick2 = line.split('Players:',1)[1].strip().split('\t\t',1)
            score1, score2 = [p for p in line.split('Score: ',1)[1]
                              .split('Players:',1)[0]
                              .split() if '-' in p and p[0].isdigit()][0].split('-')
            nick1, nick2 = map(lambda x: x.lower(), (nick1, nick2))
            score1, score2 = map(int, (score1, score2))

            if score1 == score2:
                log.info('draw detected')
                return 'draw'

            cl = stream.creator.lower()
            ol = stream.opponent.lower()
            creator = opponent = None
            if cl == nick1:
                creator = 1
            elif cl == nick2:
                creator = 2
            if ol == nick1:
                opponent = 1
            elif ol == nick2:
                opponent = 2
            if not creator and not opponent:
                log.warning('defaulting to creator! '+line)
                creator = 1
                opponent = 2
            if not creator:
                creator = 1 if opponent == 2 else 2

            if score1 > score2:
                winner = 1
            else:
                winner = 2
            return 'creator' if winner == creator else 'opponent'
        return None

pool = []
def add_stream(stream):
    """
    Tries to append given stream object (which is not yet committed) to watchlist.
    Returns False on failure (e.g. if list is full).
    """
    if len(pool) >= MAX_STREAMS:
        return 'busy'

    handler = Handler.find(stream.gametype)
    if not handler:
        return 'unsupported'

    handler.start(stream)

    return True

def stream_done(stream, winner, timestamp):
    """
    Runs on master node only.
    Marks given stream as done, and notifies clients etc.
    """
    from v1.helpers import Poller
    from v1.models import Game

    game = Game.query.get(stream.game_id)
    if not game:
        abort('Invalid game ID')

    Poller.gameDone(game, winner, timestamp)

    # no need to remove from pool, because we are on master
    # but now let's delete it from DB
    requests.delete(SELF_URL+'/streams/'+stream.handle)

    return True

def current_load():
    # TODO: use load average as a base, and add some cap on it
    return len(pool) / MAX_STREAMS


# now define our endpoints
def child_url(cname, sid=''):
    if cname in CHILDREN:
        return '{host}/streams/{sid}'.format(
            host = CHILDREN[cname],
            sid = sid,
        )
    return None

@api.resource(
    '/streams',
    '/streams/',
    '/streams/<id>',
)
class StreamResource(restful.Resource):
    fields = dict(
        handle = fields.String,
        gametype = fields.String,
        game_id = fields.Integer,
        state = fields.String,
        creator = fields.String,
        opponent = fields.String,
    )

    def get(self, id=None):
        """
        Returns details (current state) for certain stream.
        """
        if not id:
            # TODO?
            raise NotImplemented

        stream = Stream.find(id)
        if not stream:
            raise NotFound

        if stream.child:
            # forward request
            return requests.get(child_url(stream.child, stream.handle)).json()

        return marshal(stream, self.fields)

    def put(self, id=None):
        """
        Returns 409 on duplicate twitch id.
        Returns 507 if no slots are available.
        Returns newly created stream id otherwise.
        """
        if not id:
            raise MethodNotAllowed

        # id should be stream handle
        if Stream.find(id):
            abort('Duplicate stream handle', 409) # 409 Conflict

        parser = RequestParser()
        parser.add_argument('gametype')
        parser.add_argument('game_id', type=int)
        parser.add_argument('creator')
        parser.add_argument('opponent')
        # TODO...
        args = parser.parse_args()

        stream = Stream()
        stream.handle = id
        for k, v in args.items():
            setattr(stream, k, v)

        ret = None
        # now find the child who will handle this stream
        for child, host in CHILDREN.items():
            # try to delegate this stream to that child
            # FIXME: implement some load balancing
            result = requests.put('{}/streams/{}'.format(host, id),
                                  data = args)
            if result.status_code == 200: # accepted?
                ret = result.json()
                # remember which child accepted this stream
                stream.child = child
                break
        else:
            # nobody accepted? try to handle ourself
            result = add_stream(stream)
            if result == True:
                stream.child = None
            elif result == 'busy':
                abort('All observers are busy', 507) # 507 Insufficient Stroage
            elif result == 'unsupported':
                abort('Gametype not supported')
            else:
                abort('Unknown error '+result, 500)

        db.session.add(stream)
        db.session.commit()

        if ret:
            return ret
        return marshal(stream, self.fields)

    def patch(self, id=None):
        """
        Used to propagate stream result (or status update) from child to parent.
        """
        if not id:
            raise MethodNotAllowed

        # this is called from child to parent
        stream = Stream.find(id)
        if not stream:
            raise NotFound

        parser = RequestParser()
        parser.add_argument('winner')
        args = parser.parse_args()

        if PARENT:
            # send this request upstream
            return requests.patch('{}/streams/{}'.format(*PARENT),
                                  data = args).json()

        stream_done(stream, args.winner)
        return jsonify(success = True)

    def delete(self, id=None):
        """
        Deletes all records for given stream.
        """
        if not id:
            raise MethodNotAllowed
        stream = Stream.find(id)
        if not stream:
            raise NotFound
        if stream.child:
            ret = requests.delete(child_url(stream.child, stream.handle))
            if ret.status_code != 200:
                abort('Couldn\'t delete stream', ret.status_code, details=ret)
        db.session.delete(stream)
        db.session.commit()
        return jsonify(deleted=True)

@app.route('/load')
def load_ep():
    # TODO: allow querying `load average` of each child
    load = current_load()
    for child in CHILDREN.values():
        load += requests.get(child+'/load').json()['load']
    return jsonify(total = load / (len(CHILDREN)+1))


if __name__ == '__main__':
    init_app()
    app.run(port=8021, debug=False, use_debugger=False)
