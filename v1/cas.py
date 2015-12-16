from flask import request, g, make_response, url_for, redirect

from urllib.parse import urlencode
import requests
from xml.etree import ElementTree

import config
from .main import app
from .apis import WilliamHill
from .common import *

# this is a primary CAS login endpoint
# https://developer.williamhill.com/cas-implementation-guidelines-developers-0
@app.route('/cas/login')
def cas_login():
    url = WilliamHill.CAS_HOST
    url += '/cas/login?'+urlencode(dict(
        service = config.SITE_BASE_URL+url_for('.cas_done'),
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
        service = config.SITE_BASE_URL+url_for('.cas_done'),
        ticket = ticket,
        pgtUrl = config.SITE_BASE_URL+url_for('.cas_pgt'),
        # TODO renew?
    ), verify=False) # FIXME
    tree = ElementTree.fromstring(ret.text)
    ns = {'cas': 'http://www.yale.edu/tp/cas'}

    success = tree.find('cas:authenticationSuccess', ns)
    failure = tree.find('cas:authenticationFailure', ns)
    if failure is not None:
        return 'Auth failure! Code: {}<br/>{}'.format(
            failure.get('code', '<no code>'),
            failure.text.strip(),
        )
    if success is None:
        return 'Auth failure, unrecognized response'
    user = success.find('cas:user', ns).text.strip()
    return 'User: '+user

    # TODO - below is obsolete
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

@app.route('/cas/pgt')
def cas_pgt():
    log.debug('PGT endpoint: {}, vals={}, cookies={}'.format(
        request.method,
        request.values,
        request.cookies,
    ))
    return 'PGT'
