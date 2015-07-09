from flask import Flask, jsonify
from flask.ext.restful.utils import http_status_message
from flask.ext.cors import CORS

from werkzeug.exceptions import default_exceptions
from werkzeug.exceptions import HTTPException
import logging
from logging.handlers import SysLogHandler
import socket

import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.DB_URL
app.config['ERROR_404_HELP'] = False # disable this flask_restful feature

# Fix request context's remote_addr property to respect X-Real-IP header
from flask import Request
from werkzeug.utils import cached_property
class MyRequest(Request):
    @cached_property
    def remote_addr(self):
        """The remote address of the client, with respect to X-Real-IP header"""
        return self.headers.get('X-Real-IP') or super().remote_addr
app.request_class = MyRequest

# JSONful error handling
def make_json_error(ex):
    code = getattr(ex, 'code', 500)
    if hasattr(ex, 'data'):
        response = jsonify(**ex.data)
    else:
        response = jsonify(error_code = code, error = http_status_message(code))
    response.status_code = code
    return response
for code in default_exceptions.keys():
    app.error_handler_spec[None][code] = make_json_error


def init_app(app=app):
    if not app.logger:
        raise ValueError('no logger')
    import v1
    v1.init_app(app)

    # disable logging for cors beforehand
    logging.getLogger(app.logger_name+'.cors').disabled = True
    CORS(app, origins=config.CORS_ORIGINS)

    return app

def setup_logging(app, f = None, level = logging.DEBUG):
    app.logger.setLevel(level)

    logger = logging.FileHandler(f) if f else logging.StreamHandler()
    logger.setFormatter(logging.Formatter('[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s'))
    logger.setLevel(level)
    app.logger.addHandler(logger)

    return # no PaperTrail support for now
    if config.LOCAL:
        return
    class ContextFilter(logging.Filter):
        hostname = socket.gethostname()
        def filter(self, record):
            record.hostname = self.hostname
            return True
    # papertail logging
    logger = SysLogHandler(address=(config.PT_HOSTNAME, config.PT_PORT))
    logger.setFormatter(logging.Formatter(
        '%(asctime)s MaxChangeAPI{}: '
        '[%(levelname)s] %(message)s'.format('-test' if config.TEST else ''),
        datefmt='%b %d %H:%M:%S'))
    logger.setLevel(level)
    app.logger.addFilter(ContextFilter())
    app.logger.addHandler(logger)

def live(logfile=None):
    setup_logging(app, logfile)
    return init_app()

def debug():
    app.debug = True #-- this breaks exception handling?..
    setup_logging(app)
    return init_app()
