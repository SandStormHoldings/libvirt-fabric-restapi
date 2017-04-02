"""
Simple digest user storage
"""
import json
from config import AUTH_DB_FILE


def init_storage():
    try:
        return json.load(open(AUTH_DB_FILE, 'r'))['users']
        json_data_h = open(AUTH_DB_FILE, 'r')
        json_data = json_data_h.read()
        json_data_h.close()
        return json.loads(json_data)
    except IOError:
        raise Exception('Storage file not found')


DIGEST_USER = init_storage()
