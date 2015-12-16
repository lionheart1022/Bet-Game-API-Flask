from datetime import datetime, timedelta
from sqlalchemy import or_, and_, case, select
from sqlalchemy.sql.expression import func
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask import g
import os

from .main import db
from .common import *

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(128), nullable=True, unique=True)
    password = db.Column(db.LargeBinary(36))
    facebook_id = db.Column(db.String(64))
    facebook_token = db.Column(db.String(128))
    twitter_id = db.Column(db.Integer)
    twitter_token = db.Column(db.String(256))
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.Text)

    ea_gamertag = db.Column(db.String(64), unique=True)
    fifa_team = db.Column(db.String(64), unique=False)
    riot_summonerName = db.Column(db.String(64), unique=True)
    # in fact, it is integer, but saved as string for compatibility
    steam_id = db.Column(db.String(64), unique=True)
    starcraft_uid = db.Column(db.String(64), unique=True)
    tibia_character = db.Column(db.String(64), unique=True)

    balance = db.Column(db.Float, default=0)
    locked = db.Column(db.Float, default=0)

    @property
    def available(self):
        return self.balance - self.locked
    @property
    def balance_obj(self):
        return {
            'full': self.balance,
            'locked': self.locked,
            'available': self.available,
        }

    @property
    def complete(self):
        return (self.email != None) & (self.nickname != None)
    @hybrid_property
    def games(self):
        return Game.query.filter(
            (Game.creator_id == self.id) | # OR
            (Game.opponent_id == self.id))
    @hybrid_method
    def gamecount_impl(self, *filters):
        return fast_count(self.games.filter(*filters))
    @gamecount_impl.expression
    def gamecount_impl(cls, *filters):
        return (
            cls.games
            .filter(*filters)
            .with_entities(func.count('*'))
            .as_scalar()
        )
    @hybrid_property
    def gamecount(self):
        return self.gamecount_impl()
    @hybrid_method
    def winrate_impl(self, *filters):
        count = 0
        wins = 0
        for game in self.games.filter(Game.state == 'finished', *filters):
            count += 1
            whoami = 'creator' if game.creator_id == self.id else 'opponent'
            if game.winner == 'draw':
                wins += 0.5
            elif game.winner == whoami:
                wins += 1
        if count == 0:
            # no finished games, no data
            return None
        return wins / count
    @hybrid_property
    def mygames(cls):
        return (
            db.select([func.count(Game.id)])
            .where(db.and_(
                Game.state == 'finished',
            ))
        )
    @hybrid_property
    def mygamescount(cls):
        return (
            cls.mygames
            .where(cls.id.in_([
                Game.creator_id,
                Game.opponent_id,
            ]))
            .label('cnt')
        )
    @hybrid_property
    def mygameswon(cls):
        return (
            cls.mygames
            .where(
                (
                    (Game.creator_id == cls.id) &
                    (Game.winner == 'creator')
                ) | (
                    (Game.opponent_id == cls.id) &
                    (Game.winner == 'opponent')
                )
            )
            .label('won')
        )
    @hybrid_property
    def mygamesdraw(cls):
        return (
            cls.mygames.with_only_columns([func.count(Game.id) / 2])
            .where(
                (
                    (Game.creator_id == cls.id) |
                    (Game.opponent_id == cls.id)
                ) &
                Game.winner == 'draw',
            )
            .label('draw')
        )
    @winrate_impl.expression
    def winrate_impl(cls, *filters):
        mygames = (
            db.select([func.count(Game.id)])
            .where(db.and_(
                Game.state == 'finished',
                *filters
            ))
        )
        count = (
            mygames
            .where(cls.id.in_([
                Game.creator_id,
                Game.opponent_id,
            ]))
            .label('cnt')
        )
        won = (
            mygames
            .where(
                (
                    (Game.creator_id == cls.id) &
                    (Game.winner == 'creator')
                ) | (
                    (Game.opponent_id == cls.id) &
                    (Game.winner == 'opponent')
                )
            )
            .label('won')
        )
        draw = (
            mygames.with_only_columns([func.count(Game.id) / 2])
            .where(
                (
                    (Game.creator_id == cls.id) |
                    (Game.opponent_id == cls.id)
                ) &
                Game.winner == 'draw',
            )
            .label('draw')
        )
        return case([
            (count == 0, None), # if count == 0 then NULL else (calc)
        ], else_ =
            (won + draw) / count
        )

    @hybrid_property
    def winrate(self):
        if 'winrate_filt' in g and g.winrate_filt:
            log.debug('winrate: using filt '+','.join(
                str(f) for f in g.winrate_filt
            ))
            return self.winrate_impl(*g.winrate_filt)
        log.debug('winrate: no filt')
        return self.winrate_impl()
    #@hybrid_method
    def winratehist(self, days=None, weeks=None, months=None):
        count = days or weeks or months
        if not count:
            raise ValueError('Please provide something!')
        # 30.5 is approximate number of days in month
        delta = timedelta(days=1 if days else 7 if weeks else 30.5)
        now = datetime.utcnow()
        ret = []
        for i in range(count):
            prev = now - delta

            count, wins = 0, 0
            for game in self.games.filter(
                Game.state == 'finished',
                Game.finish_date > prev,
                Game.finish_date <= now,
            ):
                count += 1
                whoami = 'creator' if game.creator_id == self.id else 'opponent'
                if game.winner == 'draw':
                    wins += 0.5
                elif game.winner == whoami:
                    wins += 1
            rate = (wins / count) if count else 0

            ret.append((prev, count, wins, rate))
            now = prev
        return ret
    @hybrid_property
    def lastbet(self):
        return self.games.order_by(Game.create_date.desc()).first().create_date
    @lastbet.expression
    def lastbet(cls):
        return (
            db.select([Game.create_date])
            .where(cls.id.in_([
                Game.creator_id,
                Game.opponent_id,
            ]))
            .order_by(Game.create_date.desc())
            .limit(1)
            .label('lastbet')
        )

    @hybrid_method
    def popularity_impl(self, *filters):
        return fast_count(
            self.games.filter(
                Game.state == 'accepted',
                *filters
            )
        )
    @popularity_impl.expression
    def popularity_impl(cls, *filters):
        return (
            db.select([func.count(Game.id)])
            .where(
                db.and_(
                    cls.id.in_([
                        Game.creator_id,
                        Game.opponent_id,
                    ]),
                    Game.state == 'accepted',
                    *filters
                )
            )
            .label('popularity')
        )
    @hybrid_property
    def popularity(self):
        return self.popularity_impl() # without filters

    _leadercache = {} # is a class field
    _leadercachetime = None
    @property
    def leaderposition(self):
        if not self._leadercache or self._leadercachetime < datetime.utcnow():
            self._leadercachetime = datetime.utcnow() + \
                timedelta(minutes=5)
            self._leadercache = {}
            # This is dirty way, but "db-related" one did not work..
            # http://stackoverflow.com/questions/7057772/get-row-position-in-mysql-query
            # MySQL kept ordering line numbers according to ID,
            # regardless of ORDER BY clause.
            # Maybe because of joins or so.

            # TODO: maybe cache result in memory for e.g. 5min
            q = Player.query.with_entities(
                Player.id,
            ).order_by(
                # FIXME: hardcoded algorithm is not a good thing?
                Player.winrate.desc(),
                Player.gamecount.desc(),
                Player.id.desc(),
            )
            self._leadercache = {
                row[0]: n+1
                for n, row in enumerate(q)
            }
        return self._leadercache[self.id]
    @hybrid_property
    def recent_opponents(self):
        # last 5 sent and 5 received
        sent, recv = [
            Game.query.filter(field == self.id)
            .order_by(Game.create_date.desc())
            .limit(5).with_entities(other).subquery()
            for field, other in [
                (Game.creator_id, Game.opponent_id),
                (Game.opponent_id, Game.creator_id),
            ]
        ]
        return Player.query.filter(or_(
            Player.id.in_(db.session.query(sent.c.opponent_id)),
            Player.id.in_(db.session.query(recv.c.creator_id)),
        ))

    @property
    def has_userpic(self):
        from .routes import UserpicResource
        return bool(UserpicResource.findfile(self))

    _identities = [
        'nickname',
        'ea_gamertag', 'riot_summonerName', 'steam_id',
    ]
    @classmethod
    def find(cls, key):
        """
        Retrieves user by player id or integer id.
        If id is 'me', will return currently logged in user or None.
        """
        if key == '_':
            from .helpers import MyRequestParser as RequestParser
            parser = RequestParser()
            parser.add_argument('id')
            args = parser.parse_args()
            key = args.id

        if key.lower() == 'me':
            return getattr(g, 'user', None)

        if '@' in key and '.' in key:
            return cls.query.filter_by(email=key).first()

        p = None
        try:
            p = cls.query.get(int(key))
        except ValueError: pass
        for identity in cls._identities:
            if p:
                return p
            p = cls.query.filter_by(**{identity: key}).first()
        return p

    @classmethod
    def find_or_fail(cls, key):
        player = cls.find(key)
        if not player:
            raise ValueError('Player {} is not registered on BetGame'.format(key))
        return player

    @classmethod
    def search(cls, filt, operation='like'):
        """
        Filt should be suitable for SQL LIKE statement.
        E.g. "word%" will search anything starting with word.
        """
        if len(filt) < 1:
            return []
        return cls.query.filter(
            or_(*[
                getattr(
                    getattr(cls, identity),
                    operation,
                )(filt)
                for identity in cls._identities
            ])
        )
    def __repr__(self):
        return '<Player id={} nickname={} balance={}>'.format(
            self.id, self.nickname, self.balance)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    player = db.relationship(Player,
                             backref=db.backref('transactions',
                                                lazy='dynamic') # return query, not list
                             )
    date = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.Enum('deposit', 'withdraw', 'won', 'lost', 'other'), nullable=False)
    sum = db.Column(db.Float, nullable=False)
    balance = db.Column(db.Float, nullable=False) # new balance
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=True)
    game = db.relationship('Game', backref=db.backref('transaction', uselist=False))
    comment = db.Column(db.Text)
    def __repr__(self):
        return '<Transaction id={} sum={}>'.format(self.id, self.sum)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    player = db.relationship(Player, backref=db.backref('devices',
                                                        lazy='dynamic'))
    push_token = db.Column(db.String(128), nullable=True)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    failed = db.Column(db.Boolean, default=False)
    def __repr__(self):
        return '<Device id={}, failed={}>'.format(self.id, self.failed)


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    creator = db.relationship(Player, foreign_keys='Game.creator_id')
    opponent_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    opponent = db.relationship(Player, foreign_keys='Game.opponent_id')
    parent_id = db.Column(db.Integer, db.ForeignKey('game.id'),
                          index=True)
    parent = db.relationship('Game', foreign_keys='Game.parent_id',
                             backref='children', remote_side='Game.id')

    gamertag_creator = db.Column(db.String(128))
    gamertag_opponent = db.Column(db.String(128))
    twitch_handle = db.Column(db.String(128))
    twitch_identity_creator = db.Column(db.String(128))
    twitch_identity_opponent = db.Column(db.String(128))

    gametype = db.Column(db.String(64), nullable=False)
    gamemode = db.Column(db.String(64), nullable=False)
    meta = db.Column(db.Text) # for poller to use

    bet = db.Column(db.Float, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    state = db.Column(db.Enum(
        'new', 'cancelled', 'accepted', 'declined', 'finished', 'aborted',
    ), default='new')
    accept_date = db.Column(db.DateTime, nullable=True)
    aborter_id = db.Column(db.Integer, db.ForeignKey('player.id'))
    aborter = db.relationship(Player, foreign_keys='Game.aborter_id')
    winner = db.Column(db.Enum('creator', 'opponent', 'draw'), nullable=True)
    details = db.Column(db.Text, nullable=True)
    finish_date = db.Column(db.DateTime, nullable=True)

    def _make_identity_getter(kind, prop):
        def _getter(self):
            if not self.gametype:
                return None
            from .polling import Poller
            poller = Poller.findPoller(self.gametype)
            identity = getattr(poller, kind)
            if not identity:
                return None
            return getattr(identity, prop)
        _getter.__name__ = '_'.join((kind,prop))
        return _getter
    for kind in 'identity', 'twitch_identity':
        for prop in 'id', 'name':
            # I know it is not good to modify locals(),
            # but it works here (as we are not in function).
            # At least it works in python 3.4/3.5
            locals()['_'.join((kind, prop))] = property(
                _make_identity_getter(kind, prop)
            )
    del _make_identity_getter
    def _make_identity_splitter(role, prop):
        attr = 'gamertag_'+role
        seq = {'val':0,'text':1}[prop]
        def _getter(self):
            # formatter returns tuple (internal, human_readable)
            return self.identity.formatter(getattr(self, attr))[seq]
        return _getter
    for role in 'creator', 'opponent':
        for prop in 'val', 'text':
            locals()['gamertag_{}_{}'.format(role, prop)] = property(
                _make_identity_splitter(role, prop)
            )
    del _make_identity_splitter

    @property
    def is_root(self):
        """
        Returns true if this game is session starter
        """
        return not bool(self.parent)

    @property
    def root(self):
        """
        Returns root game for this game
        """
        if not self.parent:
            return self
        return self.parent.root

    @property
    def has_message(self):
        from .routes import GameMessageResource
        return bool(GameMessageResource.findfile(self))
    @property
    def is_ingame(self):
        from .polling import Poller
        return (self.gamemode in
                Poller.findPoller(self.gametype).gamemodes_ingame)
    @hybrid_method
    def is_game_player(self, player):
        return (player.id == self.creator_id) | (player.id == self.opponent_id)
    @hybrid_method
    def other(self, player):
        if player.id == self.creator_id:
            return self.opponent
        if player.id == self.opponent_id:
            return self.creator
        return None
    @other.expression
    def other(cls, player):
        return case([
            (player.id == cls.creator_id, cls.opponent),
            (player.id == cls.opponent_id, cls.creator),
        ], else_ = None)

    def __repr__(self):
        return '<Game id={} state={}>'.format(self.id, self.state)


class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    sender = db.relationship(Player, foreign_keys='ChatMessage.sender_id')
    receiver_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    receiver = db.relationship(Player, foreign_keys='ChatMessage.receiver_id')
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), index=True)
    game = db.relationship(Game)
    text = db.Column(db.Text)
    time = db.Column(db.DateTime, default=datetime.utcnow)
    has_attachment = db.Column(db.Boolean, default=False)
    viewed = db.Column(db.Boolean, default=False)

    @hybrid_method
    def is_for(self, user):
        return (user.id == self.sender_id) | (user.id == self.receiver_id)
    def other(self, user):
        if user == self.sender:
            return self.receiver
        if user == self.receiver:
            return self.sender
        raise ValueError('Message is unrelated to user %d' % user.id)
    @classmethod
    def for_user(cls, user):
        return cls.query.filter(or_(
            cls.sender_id == user.id,
            cls.receiver_id == user.id,
        ))
    @classmethod
    def for_users(cls, a, b):
        return cls.query.filter(
            cls.sender_id.in_([a.id, b.id]),
            cls.receiver_id.in_([a.id, b.id]),
        )
    def __repr__(self):
        return '<ChatMessage id={} text={}>'.format(self.id, self.text)


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # game should be the root game of inner challenges hierarchy
    # as it denotes gaming session
    # TODO: maybe make it optional?
    root_id = db.Column(db.Integer, db.ForeignKey('game.id'),
                        index=True, nullable=False)
    root = db.relationship(Game, backref='events', foreign_keys='Event.root_id')
    @db.validates('root')
    def validate_root(self, key, game):
        # ensure it is the root of game session
        return game.root
    time = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    type = db.Column(db.Enum(
        'message', # one user sent message to another
        'system', # system notification about game state, bet state unchanged
        'betstate', # some bet changed its state, or was created
        'abort', # request to abort one of bets in this session
    ), nullable=False)

    # for 'message' type
    message_id = db.Column(db.Integer, db.ForeignKey('chat_message.id'))
    message = db.relationship(ChatMessage)
    # for 'system', 'betstate' and 'abort' types
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'))
    game = db.relationship(Game, foreign_keys='Event.game_id')
    # for 'system' and probably 'betstate' types
    text = db.Column(db.Text)
    # for 'betstate' type
    newstate = db.Column(db.String(128))


class Beta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128))
    name = db.Column(db.String(128))
    gametypes = db.Column(db.Text)
    platforms = db.Column(db.String(128))
    PLATFORMS = [
        'Android',
        'iOS',
        'Windows Mobile',
        'Web',
        'other',
    ]
    console = db.Column(db.String(128))
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    flags = db.Column(db.Text, default='') # probably json
    backup = db.Column(db.Text)
    def __repr__(self):
        return '<Beta id={}>'.format(self.id)


def fast_count_noexec(query):
    return query.statement.with_only_columns([func.count()]).order_by(None)
def fast_count(query):
    """
    Get count of queried items avoiding using subquery (like query.count() does)
    """
    return query.session.execute(fast_count_noexec(query)).scalar()
