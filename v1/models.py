from datetime import datetime, timedelta
from sqlalchemy import or_, case, select
from sqlalchemy.sql.expression import func
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from flask import g
import os

from .main import db

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
    @hybrid_property
    def gamecount(self):
        return fast_count(self.games)
    @gamecount.expression
    def gamecount(cls):
        return cls.games.with_entities(func.count('*'))
        return (
            db.select([func.count(Game.id)])
            .where(cls.id.in_([
                Game.creator_id,
                Game.opponent_id,
            ]))
        )
    @hybrid_property
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
    @winrate.expression
    def winrate(cls):
        mygames = (
            db.select([func.count(Game.id)])
            .where(Game.state == 'finished')
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

    @hybrid_property
    def popularity(self):
        return fast_count(self.games.filter(Game.state == 'accepted'))
    @popularity.expression
    def popularity(cls):
        return (
            db.select([func.count(Game.id)])
            .where(Game.state == 'accepted')
            .label('popularity')
        )
        return cls.games.filter(Game.state == 'accepted').with_entities(func.count('*'))

    def leaderposition(self):
        initializer = db.session.query('@rownum := 0').subquery()
        q = Player.query._from_selectable(
            initializer,
        ).with_entities(
            '@rownum := @rownum + 1 AS rownum',
            Player.id, # or else Player table will be omitted
        ).order_by(
            Player.winrate.desc(),
        ).filter(
            Player.id == self.id,
        )
        return q.scalar() # get just rownum
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
    details = db.Column(db.Text, nullable=True)
    finish_date = db.Column(db.DateTime, nullable=True)

    @property
    def has_message(self):
        from .routes import GameMessageResource
        return bool(GameMessageResource.findfile(self))


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


def fast_count_noexec(query):
    return query.statement.with_only_columns([func.count()]).order_by(None)
def fast_count(query):
    """
    Get count of queried items avoiding using subquery (like query.count() does)
    """
    return query.session.execute(fast_count_noexec(query)).scalar()
