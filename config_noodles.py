# -*- coding: utf-8 -*-
'''
filedesc: default boilerplate config for a new noodles project
'''
import os

DEBUG = True
TESTING = True
AUTO_RELOAD = False
USE_ALCHEMY_MW=False
# Specify the server port
PORT = 8090
HOST='0.0.0.0'
ENCODING = 'utf-8'  # default application encoding

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Specify URL resolver module, this must contain get_map
# function which returnes mapper object
# urls.py module is default
URL_RESOLVER = 'urls'

# Specify controllers modules
CONTROLLERS = ['controllers', 'noodles.utils.static']

# Specify Redis-server host there
REDIS_HOST = 'localhost'

# Specify root dir for static content here
STATIC_ROOT = os.path.join(APP_DIR, 'static')

# Specify here a template directories
TEMPLATE_DIRS = [
    os.path.join(APP_DIR, 'templates'),
# Add here other directories if you need
]

# Specify here mako temporary dir for precompiled templates
MAKO_TMP_DIR = os.path.join(APP_DIR, 'tmp/modules')

#SESSION STUFF
MIDDLEWARES=[]

TIME_TO_OVERWRITE_CLIENT_COOKIE=86400
SESSION_COOKIE='hsess_id'

SERVER_LOGTYPE = 'default'
####Mail parameters
NOODLES_ERROR_RECIPIENT = [
    #List with default error mail recipient
]
EXCEPTION_FLAVOR='text'

# PLEASE SET THESE:

NOODLES_ERROR_SENDER = 'noodles_error@example.com'
MAIL_SERVER = 'smtp.CHANGEME.com'
MAIL_PORT = 587
# CHANGEME!
MAIL_LOGIN = 'CHANGEME'
MAIL_PASSWORD = 'CHANGEME!'

