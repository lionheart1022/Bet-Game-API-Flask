#!/usr/bin/env python3
from flask import Flask, request, session, abort, render_template

import config

app = Flask(__name__)
# for session...
app.config['SECRET_KEY'] = config.JWT_SECRET

@app.route('/')
def bets():
    return render_template('newbet.html')

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
