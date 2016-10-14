"""Interface for sending REST API requests. Compatible with Python 2 and 3."""

import hashlib
import random
import re
import sys

import requests

URL_TEMPLATE = "{proto}://{host}/nbi/nbi-{api_name}{path}"
AUTH_URL_TEMPLATE = "{proto}://{host}/auth/authenticate.php?sessid={sessid}&username={username}&pwdigest={pwdigest}&pkey={pkey}"
LOGIN_URL_TEMPLATE = "{proto}://{host}/auth/login.php?api=true"
LOGOUT_URL_TEMPLATE = "{proto}://{host}/auth/logout.php"

# Various string constants.
DOMAIN = "domain"
NONCE = "nonce"
PKEY = "pkey"
SESSID = "sessid"
PHPSESSID = "PHPSESSID"

class RestApiConnection(object):
    """
    Interface for sending REST API requests.

    This class can perform the REST API authentication sequence, keep track of
    the session ID, and send GET, POST, PUT, and DELETE requests that
    automatically pass the session ID.
    """

    def __init__(self, secure=False, verify=False):
        """
        Construct a REST API connection object.

        Keyword arguments:

        secure -- whether to connect via HTTPS
        verify -- whether to verify the server certificate (if connecting via HTTPS)
        """
        self.host = None
        self.sess_id = None
        self.response = None
        self.verify = verify
        self.subs = {
            "proto": "https" if secure else "http"
        }

    def connect(self, host, username, password, **kwargs):
        """Authenticate with the server and obtain a session ID."""
        self.subs["host"] = host
        self.subs["username"] = username
        self.subs["password"] = password

        url = LOGIN_URL_TEMPLATE.format(**self.subs)
        response = requests.get(url, verify=self.verify, **kwargs)
        kv_str_pairs = response.text.split("\n")

        # We should now have a list like this:
        #
        # ['domain=http://10.0.0.1:80/',
        #  'nonce=c80556a629d608fe948239dfff7edae9',
        #  'pkey=2acd700decba9869',
        #  'sessid=4b82a802a446ad22197bc53dd0a1c0ef',
        #  ''
        # ]
        kv = {}
        for pair in kv_str_pairs:
            pair = pair.split("=", 1)
            if len(pair) == 2:
                (key, val) = pair
                kv[key] = val

        # Verify that required keys are present.
        required_keys = [DOMAIN, NONCE, SESSID]
        for key in required_keys:
            if key not in kv:
                raise RuntimeError("missing required value for '{}'".format(key))

        # Authenticate using the local or TACACS+ sequence, as appropriate.
        if kv[NONCE]:
            pwdigest = self._auth_local(username, password, kv[DOMAIN], kv[NONCE])
            pkey = "0" # Client's public key (not used in local auth).
        else:
            (pwdigest, pkey) = self._auth_tacacs(username, password, kv[PKEY])

        self.subs["sessid"] = kv[SESSID]
        auth_url = AUTH_URL_TEMPLATE.format(pwdigest=pwdigest, pkey=pkey, **self.subs)
        response = requests.get(auth_url, verify=self.verify, **kwargs)
        status = response.text.strip()
        if (status == "success"):
            self.host = host
            self.sess_id = {PHPSESSID: kv[SESSID]}
        else:
            raise RuntimeError("failed to authenticate (response = '{}')".format(status))

    @staticmethod
    def _auth_local(username, password, domain, nonce):
        """Compute local-only authentication parameters."""
        # The web user passwords are stored in a hashed form, specifically:
        # password_hash = SHA-1(salt, username, password), where salt = "04581273"
        sha1 = hashlib.sha1()
        sha1.update("04581273".encode())
        sha1.update(username.encode())
        sha1.update(password.encode())
        password_hash = sha1.hexdigest()

        md5 = hashlib.md5()
        md5.update(domain.encode())
        md5.update(nonce.encode())
        md5.update(username.encode())
        md5.update(password_hash.encode())
        pwdigest = md5.hexdigest()
        return pwdigest

    @staticmethod
    def _auth_tacacs(username, password, server_pkey):
        """Compute TACACS+ authentication parameters."""
        # <key> must be a string of hex digits of length 32 (e.g., an MD5 hash).
        def encode(msg, key):
            result = ""
            for (i, c) in enumerate(msg):
                # Convert a pair of hex digits in the key into a byte value.
                j = (i*2) % 32
                key_byte = int(key[j:j+2], 16)
                # Encode a byte of the message and append it to the result string.
                msg_byte = ord(c)
                result += format(msg_byte ^ key_byte, "02x")
            return result

        # Not used on the client side (included here only for reference/testing).
        def decode(msg, key):
            result = ""
            for i in range(0, len(msg), 2):
                # Convert a pair of hex digits in the message into a byte value.
                msg_byte = int(msg[i:i+2], 16)
                # Convert a corresponding pair of hex digits in the key into a byte value.
                j = i % 32
                key_byte = int(key[j:j+2], 16)
                # Decode the byte and append it to the result string.
                result += chr(msg_byte ^ key_byte)
            return result

        # Diffie-Hellman parameters.
        generator = 0x527d44089958ca1e
        modulus   = 0x5c13ada6c91d2ba3

        # Server's public key.
        server_pub_key = int(server_pkey, base=16)

        # Client's private key (256-bit cryptographically-secure random number).
        client_priv_key = random.SystemRandom().getrandbits(256)
        # Alternative implementation:
        # client_priv_key = 0
        # random_bytes = os.urandom(32)
        # for (i, b) in enumerate(random_bytes): client_priv_key |= (ord(b) << (i*8))

        # Client's public key.
        client_pub_key = pow(generator, client_priv_key, modulus)
        client_pub_key_str = format(client_pub_key, "016x")

        # Shared secret (MD5-hashed).
        shared_secret = pow(server_pub_key, client_priv_key, modulus)
        shared_secret_str = format(shared_secret, "016x")
        md5 = hashlib.md5()
        md5.update(shared_secret_str.encode())
        shared_secret_md5 = md5.hexdigest()

        # Password digest (original password encoded using the shared secret).
        pwdigest = encode(password, shared_secret_md5);

        return (pwdigest, client_pub_key_str)

    def get(self, api, path, **kwargs):
        """Send a GET request."""
        return self._send_request(requests.get, api, path, **kwargs)

    def post(self, api, path, data, **kwargs):
        """Send a POST request."""
        return self._send_request(requests.post, api, path, data, **kwargs)

    def put(self, api, path, data, **kwargs):
        """Send a PUT request."""
        return self._send_request(requests.put, api, path, data, **kwargs)

    def delete(self, api, path, **kwargs):
        """Send a DELETE request."""
        return self._send_request(requests.delete, api, path, **kwargs)

    def _send_request(self, request_func, api, path, xml_req=None, **kwargs):
        """Send a REST API request."""
        url = URL_TEMPLATE.format(api_name=api, path=path, **self.subs)
        self.response = request_func(url, data=xml_req, cookies=self.sess_id,
                                     verify=self.verify, **kwargs)
        # TODO: check response to make sure the session didn't time out?
        return self.response

    def get_session_id(self):
        """Return the session ID/token associated with this REST API session."""
        if self.sess_id:
            return self.sess_id[PHPSESSID];
        else:
            return None
    
    def disconnect(self, **kwargs):
        """
        Terminate the current REST API session, if any.

        Return True if the session was successfully terminated, or False if
        there is no current session (or the session timed out).
        """
        if self.sess_id:
            url = LOGOUT_URL_TEMPLATE.format(**self.subs)
            response = requests.get(url, cookies=self.sess_id, verify=self.verify, **kwargs)
            self.sess_id = None
            if response.text.find("Login session terminated.") != -1:
                return True
            if response.text.find("No valid session.") != -1:
                return False
        else:
            return False
