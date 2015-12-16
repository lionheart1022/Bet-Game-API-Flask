from flask import request, g, make_response, url_for, redirect

from urllib.parse import urlencode
import requests

import config
from .main import app
from .apis import WilliamHill
from .common import *

def my_url():
    return config.SITE_BASE_URL+url_for('.cas_done')
# this is a primary CAS login endpoint
# https://developer.williamhill.com/cas-implementation-guidelines-developers-0
@app.route('/cas/login')
def cas_login():
    url = WilliamHill.CAS_HOST
    url += '/cas/login?'+urlencode(dict(
        service = my_url(),
        joinin_link = 'test', # FIXME remove this when going to production
    ))
    return redirect(url);
@app.route('/cas/logout')
def cas_logout():
    url = WilliamHill.CAS_HOST + '/cas/logout'
    return redirect(url);
@app.route('/cas/done')
def cas_done():
    ticket = request.args.get('ticket')

    url = WilliamHill.CAS_HOST + '/cas/serviceValidate'
    ret = requests.get(url, params=dict(
        ticket = ticket,
        service = url_for('.cas_done'),
        params = dict(
            service = my_url(),
            ticket = ticket,
            pgtUrl = my_url(),
            # TODO renew?
        ),
    ), verify=False) # FIXME
    log.debug(ret.text)
    lines = ret.text.splitlines()
    if not lines:
        raise ValueError('no response') # TODO
    elif lines[0] == 'no':
        raise ValueError('token not validated')
    elif lines[0] != 'yes':
        raise ValueError('malformed response')
    # now it is 'yes'

    if len(lines) < 2:
        raise ValueError('malformed response')

    user = lines[1].strip()

    # FIXME tree response for validate PGT - see _validatePGT

