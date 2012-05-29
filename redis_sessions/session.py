import redis, base64
from django.utils import simplejson as json
from django.core.exceptions import SuspiciousOperation
from django.utils.hashcompat import md5_constructor
from django.utils.encoding import force_unicode
from django.contrib.sessions.backends.base import SessionBase, CreateError
from django.conf import settings
from django.utils.crypto import constant_time_compare

class SessionStore(SessionBase):
    """
    Implements Redis database session store.
    """
    def __init__(self, session_key=None):
        super(SessionStore, self).__init__(session_key)
        self.server = redis.StrictRedis(
            host=getattr(settings, 'SESSION_REDIS_HOST', 'localhost'),
            port=getattr(settings, 'SESSION_REDIS_PORT', 6379),
            db=getattr(settings, 'SESSION_REDIS_DB', 0),
            password=getattr(settings, 'SESSION_REDIS_PASSWORD', None)
        )

    def load(self):
        try:
            session_data = self.server.get(self.get_real_stored_key(self.session_key))
            return self.decode(force_unicode(session_data))
        except:
            self.create()
            return {}

    def exists(self, session_key):
        return self.server.exists(self.get_real_stored_key(session_key))

    def create(self):
        while True:
            self._session_key = self._get_new_session_key()

            try:
                self.save(must_create=True)
            except CreateError:
                continue
            self.modified = True
            return

    def save(self, must_create=False):
        if must_create and self.exists(self.session_key):
            raise CreateError
        data = self.encode(self._get_session(no_load=must_create))
        self.server.set(self.get_real_stored_key(self.session_key), data)
        self.server.expire(self.get_real_stored_key(self.session_key), self.get_expiry_age())

    def delete(self, session_key=None):
        if session_key is None:
            if self._session_key is None:
                return
            session_key = self._session_key
        try:
            self.server.delete(self.get_real_stored_key(session_key))
        except:
            pass

    def get_real_stored_key(self, session_key):
        """Return the real key name in redis storage
        @return string
        """
        prefix = getattr(settings, 'SESSION_REDIS_PREFIX', '')
        if not prefix:
            return session_key
        return ':'.join([prefix, session_key])

    def encode(self, session_dict):
        "Returns the given session dictionary pickled and encoded as a string."
        session_obj = {}
        session_obj['user'] = {'user_id': session_dict['user'].id, 'username':session_dict['user'].username}
        pickled = pickle.dumps(session_dict, pickle.HIGHEST_PROTOCOL)
        session_obj['pickled'] = base64.encodestring(pickled)
        session_obj['hash'] = base64.encodestring(self._hash(pickled))
        return json.dumps(session_obj)

    def decode(self, session_data):
        session = json.loads(session_data)
        pickled = base64.decodestring(session['pickled'])
        expected_hash = self._hash(pickled)
        if not constant_time_compare(base64.decodestring(session['hash']), expected_hash):
            raise SuspiciousOperation("Session data corrupted")
        else:
            return pickle.loads(pickled)
