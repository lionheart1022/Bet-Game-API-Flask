#!/usr/bin/env python3

import main, pdb

main.init_app()

with main.app.app_context():

    from v1.models import *
    from v1.helpers import *
    from v1.routes import *

    def add_tournaments():
        dt = datetime.utcnow()
        hour = timedelta(hours=1)
        for i in range(3):
            for j in range(3):
                for m in range(4):
                    t = Tournament(j + 1, dt + hour * i, dt + hour * (i+1), dt + hour * (i+2), m+1)
                    db.session.add(t)
        db.session.commit()

    def add_test_players():
        for i in range(10):
            player = Player()
            player.nickname = 'test_player_' + str(i)
            player.email = player.nickname + '@example.com'
            player.password = encrypt_password('111111')
            db.session.add(player)
        db.session.commit()
    while True:
        pdb.set_trace()
