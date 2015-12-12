from flask import request, g, make_response, url_for, redirect

from urllib.parse import urlencode
import requests

import config
from .main import app
from .apis import WilliamHill

# this is a primary CAS login endpoint
# https://developer.williamhill.com/cas-implementation-guidelines-developers-0
@app.route('/cas/login')
def cas_login():
    url = WilliamHill.CAS_HOST
    url += '/cas/login?'+urlencode(dict(
        service = config.SITE_BASE_URL+url_for('.cas_done'),
    ))
    return redirect(url);
@app.route('/cas/logout')
def cas_logout():
    url = WilliamHill.CAS_HOST + '/cas/logout'
    return redirect(url);
@app.route('/cas/done')
def cas_done():
    ticket = None # TODO fetch from args
    url = WilliamHill.CAS_HOST
    url += '/cas/serviceValidate'
    ret = requests.get(url, params=dict(
        ticket = ticket,
        service = url_for('.cas_done'),
        # TODO opt?
    ))
    print(ret)
