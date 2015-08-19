from datetime import timedelta
from secret import DB_URL, JWT_SECRET
#from secret import NEXMO_API_KEY, NEXMO_API_SECRET
#from secret import GOOGLE_PUSH_API_KEY, APPLE_PUSH_API_KEY
#from secret import GOOGLE_AUTH_API_KEY
#from secret import GOOGLE_AUTH_CLIENT_ID, GOOGLE_AUTH_CLIENT_SECRET
from secret import FACEBOOK_AUTH_CLIENT_ID, FACEBOOK_AUTH_CLIENT_SECRET
#from secret import ADMIN_USERS
from secret import PAYPAL_CLIENT, PAYPAL_SECRET, PAYPAL_SANDBOX
from secret import MAILGUN_KEY
try:
    from secret import LOCAL
except ImportError:
    LOCAL = False
try:
    from secret import TEST
except ImportError:
    TEST = False
from secret import ADMIN_IDS
from secret import RIOT_KEY, STEAM_KEY, BATTLENET_KEY, SC2RANKS_KEY

# DB_URL format: "mysql+mysqlconnector://USER:PASSWORD@HOST/DATABASE"

JWT_LIFETIME = timedelta(days=365)

# for Nexmo phone number verification
SMS_BRAND = "Bet Game"
SMS_SENDER = "BetGame"

# for mail sending
MAIL_DOMAIN = 'mg.betgame.co.uk'
MAIL_SENDER = 'BetGame <noreply@betgame.co.uk>'

CORS_ORIGINS = [
    'https://betgame.co.uk',
    'http://betgame.co.uk',
    'https://www.betgame.co.uk',
    'http://www.betgame.co.uk',
    'http://127.0.0.1:8080',
    'http://localhost:8080',
]
if 'test' in __file__:
    CORS_ORIGINS.append('http://test.betgame.co.uk')

# Papertail logging
#PT_HOSTNAME = 'logs3.papertrailapp.com'
#PT_PORT = 12345

# in coins
WITHDRAW_MINIMUM = 40

