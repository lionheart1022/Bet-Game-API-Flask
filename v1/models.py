from datetime import datetime
import math
from sqlalchemy import sql
from sqlalchemy.sql.expression import func
import sqlalchemy
from flask import g

from .main import db
import config

class Player(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_nick = db.Column(db.String(64), unique=True)
    email = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.LargeBinary(36))
    facebook_token = db.Column(db.String(128))
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
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
        return self.player_nick != None
    @property
    def games(self):
        return Game.query.filter(
            (Game.creator_id == self.id) | # OR
            (Game.opponent_id == self.id))

    @classmethod
    def find(cls, key):
        """
        Retrieves user by player id or integer id.
        If id is 'me', will return currently logged in user or None.
        """
        if key.lower() == 'me':
            return getattr(g, 'user', None)

        p = None
        try:
            p = cls.query.get(int(key))
        except ValueError: pass
        if not p:
            p = cls.query.filter_by(player_nick=key).first()
        return p

    @classmethod
    def find_or_fail(cls, key):
        player = cls.find(key)
        if not player:
            raise ValueError('Player {} is not registered on BetGame'.format(key))
        return player

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    player = db.relationship(Player, backref='devices')
    push_token = db.Column(db.String(128), nullable=False)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)


class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    creator = db.relationship(Player, foreign_keys='Game.creator_id')
    opponent_id = db.Column(db.Integer, db.ForeignKey('player.id'), index=True)
    opponent = db.relationship(Player, foreign_keys='Game.opponent_id')

    GAMETYPES = [
        'fifa14-xboxone', 'fifa15-xboxone',
    ]
    GAMEMODES = [
        'fifaSeasons',
        'futSeasons',
        'fut',
        'friendlies',
        'coop',
    ]

    gametype = db.Column(db.Enum(*GAMETYPES), nullable=False)
    gamemode = db.Column(db.Enum(*GAMEMODES), nullable=False)

    bet = db.Column(db.Float, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow)
    state = db.Column(db.Enum('new', 'accepted', 'declined', 'finished'), default='new')
    accept_date = db.Column(db.DateTime, nullable=True)
    winner = db.Column(db.Enum('creator', 'opponent', 'draw'), nullable=True)
    finish_date = db.Column(db.DateTime, nullable=True)


def fast_count(query):
    """
    Get count of queried items avoiding using subquery (like query.count() does)
    """
    count_query = query.statement.with_only_columns([func.count()]).order_by(None)
    return query.session.execute(count_query).scalar()
