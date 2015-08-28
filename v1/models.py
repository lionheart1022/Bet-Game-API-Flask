from datetime import datetime
from sqlalchemy import or_
from sqlalchemy.sql.expression import func
from flask import g

from .main import db

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.LargeBinary(36))
    facebook_token = db.Column(db.String(128))
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    bio = db.Column(db.Text)
    userpic = db.Column(db.LargeBinary)

    ea_gamertag = db.Column(db.String(64), unique=True)
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
        return self.nickname != None
    @property
    def games(self):
        return Game.query.filter(
            (Game.creator_id == self.id) | # OR
            (Game.opponent_id == self.id))
    @property
    def gamecount(self):
        return fast_count(self.games)
    @property
    def winrate(self):
        # FIXME: rewrite in sql?
        count = 0
        wins = 0
        for game in self.games:
            if game.state != 'finished':
                continue
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
        if len(filt) < 2:
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


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    player = db.relationship(Player, backref='transactions')
    date = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.Enum('deposit', 'withdraw', 'won', 'lost', 'other'), nullable=False)
    sum = db.Column(db.Float, nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=True)
    game = db.relationship('Game', backref=db.backref('transaction', uselist=False))
    comment = db.Column(db.Text)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    player = db.relationship(Player, backref='devices')
    push_token = db.Column(db.String(128), nullable=True)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    creator = db.relationship(Player, foreign_keys='Game.creator_id')
    opponent_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    opponent = db.relationship(Player, foreign_keys='Game.opponent_id')

    gamertag_creator = db.Column(db.String(128))
    gamertag_opponent = db.Column(db.String(128))
    twitch_handle = db.Column(db.String(128))

    gametype = db.Column(db.String(64), nullable=False)
    gamemode = db.Column(db.String(64), nullable=False)
    meta = db.Column(db.Text) # for poller to use

    bet = db.Column(db.Float, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    state = db.Column(db.Enum('new', 'cancelled', 'accepted', 'declined', 'finished'), default='new')
    accept_date = db.Column(db.DateTime, nullable=True)
    winner = db.Column(db.Enum('creator', 'opponent', 'draw'), nullable=True)
    finish_date = db.Column(db.DateTime, nullable=True)


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


def fast_count(query):
    """
    Get count of queried items avoiding using subquery (like query.count() does)
    """
    count_query = query.statement.with_only_columns([func.count()]).order_by(None)
    return query.session.execute(count_query).scalar()
