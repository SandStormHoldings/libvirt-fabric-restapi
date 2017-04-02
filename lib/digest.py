"""
Authenticator
"""
from builtins import object
import hashlib
from lib.storage import DIGEST_USER
from noodles.utils.helpers import get_config, is_ascii


class SimpleDigestAuth(object):
    def __init__(self):
        self.storage = DIGEST_USER

    def get_partial_digest(self, login):
        pw = self.storage.get(login, {})
        return self._generate_partial_digest(
            login, pw, get_config('DIGEST_REALM'))

    def _generate_partial_digest(self, login, password, zone):
        if not is_ascii(login) or not is_ascii(password) or not is_ascii(zone):
            return False
        return hashlib.md5('%s:%s:%s' % (login, zone, password)).hexdigest()

    def is_admin(self, login):
        return True
        user = self.storage.get(login, {})
        return user.get('is_admin', False)

    def get_by_login(self, login):
        if self.storage.get(login):
            return self.storage.get(login, {})
