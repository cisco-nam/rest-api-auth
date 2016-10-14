#!/usr/bin/env python
#
# Sample script that obtains a session ID (e.g., for sending API requests
# via an external tool like curl).
#
import getopt
import getpass
import re
import sys

from rest_api_connection import RestApiConnection

# You can fill in these values for scripted operation, or pass them via the command line.
# Otherwise, the script will prompt for them interactively.
HOST_URL = None  # E.g. http://host.example.com:8080 or https://host.example.com
USERNAME = None
PASSWORD = None

# Whether to verify HTTPS certificates.
VERIFY_CERTS = False

# These will be set later, based on HOST_URL:
#
# The hostname or IP address.
HOST = None
# Whether to connect to the host via HTTPS.
SECURE = None

# input() in Python 3 is basically raw_input() in Python 2.
# Normalize to a single function name.
try:
    input = raw_input
except:
    pass

def usage():
        print("""
usage: {} [-h <host-url>] [-u <username>] [-p <password>] [--verify-certs]

 -h <host-url>    Host URL. This may include an optional port number,
                  only needed if listening on a non-default port.

                  Examples: http://1.2.3.4:8080 or https://1.2.3.4/

 -u <username>    Username of the web user to use for the API session.

 -p <password>    Password of the web user to use for the API session.

 --verify-certs   Enable HTTPS certificate verification.

 --help           Show this help message and exit.
""".format(sys.argv[0]))

def process_cmd_line():
    global HOST_URL, USERNAME, PASSWORD, VERIFY_CERTS
    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "h:u:p:",
                                   ["verify-certs", "help"])
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    for o, a in opts:
        if o in ("-h"):
            HOST_URL = a
        elif o in ("-u"):
            USERNAME = a
        elif o in ("-p"):
            PASSWORD = a
        elif o in ("--verify-certs"):
            VERIFY_CERTS = True
        elif o in ("--help"):
            usage()
            sys.exit(0)

def process_host_url():
    global HOST_URL, HOST, SECURE
    if not HOST_URL:
        HOST_URL = input("Host URL: ")

    # Parse host URL.
    url_parse_re = re.compile(
        r"(http|https)" # Supported URL schemes.
        r"://"
        r"([^/]+)"      # Hostname or IP (everything up to the first '/', if any).
    )
    match = url_parse_re.match(HOST_URL)
    if match:
        scheme = match.group(1)
        HOST = match.group(2)
    else:
        print("Unrecognized host URL format.")
        sys.exit(1)

    SECURE = (scheme == "https")

def process_username():
    global USERNAME
    if not USERNAME:
        USERNAME = input("Username: ")

def process_password():
    global PASSWORD
    if not PASSWORD:
        PASSWORD = getpass.getpass("Password: ")

def process_cert_verification():
    if not VERIFY_CERTS:
        # Since we don't care to verify certs, disable warnings accordingly.
        import requests
        requests.packages.urllib3.disable_warnings()

if __name__ == "__main__":
    process_cmd_line()
    process_host_url()
    process_username()
    process_password()
    process_cert_verification()

    conn = RestApiConnection(secure=SECURE, verify=VERIFY_CERTS)
    conn.connect(HOST, USERNAME, PASSWORD)
    print(conn.get_session_id())
