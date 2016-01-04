#!/usr/bin/env python3

import main, pdb

main.init_app()

with main.app.app_context():
    from v1.models import *
    from v1.helpers import *
    from v1.routes import *
    while True:
        pdb.set_trace()
