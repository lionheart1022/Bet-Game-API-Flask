#!/usr/bin/env python3
from flask import Flask, request, session, render_template
from flask import abort, redirect, url_for

import requests

import config

app = Flask(__name__, static_folder = 'static-m')
# for session...
app.config['SECRET_KEY'] = config.JWT_SECRET
app.config['API'] = 'http://betgame.co.uk/v1'
app.config['API_ROOT'] = 'http://betgame.co.uk/v1'

class Gametypes:
    """
    Caching access to /gametypes endpoint
    """
    cache = None
    @classmethod
    def _load(cls):
        # TODO: expiration timeouts
        if not cls.cache:
            cls.cache = requests.get(app.config['API_ROOT']+'/gametypes').json()
            cls.dcache = {x['id']: x for x in cls.cache['gametypes']}
        return cls.dcache

    @classmethod
    def get(cls, name=None):
        if not name:
            return cls._load().values()
        return cls._load().get(name)

@app.route('/')
def bets():
    return render_template('newbet.html')

@app.route('/gametype', methods=['GET','POST'])
def gametype():
    if request.method == 'POST':
        session['gametype'] = request.form.get('gametype')
        return redirect(url_for('bets'))
    # TODO: caching
    ret = requests.get(app.config['API_ROOT']+'/gametypes').json()
    games = ret.get('gametypes')
    modes = None
    print('gt: '+str(session.get('gametype', 'no')))
    if session.get('gametype'):
        game = next(filter(
            lambda g: g['id'] == session['gametype'],
            games,
        ), None)
        modes = game['gamemodes']
        print('t: %s, m:%s' % (game, modes))
    return render_template('gametype.html', games=games, gamemodes=modes)

@app.route('/leaders')
def leaderboard():
    return render_template('leaderboard.html')

@app.route('/challenges')
def challenges():
    return render_template('challenges.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    app.run(debug=True)
