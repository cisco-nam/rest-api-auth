# REST API Authentication Sample Code

This repository contains sample Python code for obtaining a session ID for
use with the REST API, along with some code demonstrating its use:

* [`rest_api_connection.py`](rest_api_connection.py) provides a
  `RestApiConnection` class that can obtain a session ID and and send API
  requests.
* [`test_rest_api_connection.py`](test_rest_api_connection.py) demonstrates
  how to use the `RestApiConnection` class.
* [`get_session_id.py`](get_session_id.py) is a convenience script that uses
  the `RestApiConnection` class to obtain a session ID, and then prints it to
  standard output. This can be useful if you just want a session ID for use
  in another tool.

## Prerequisites

The sample code should be compatible with Python 2.7+ and Python 3, and depends
on the Python [Requests](http://docs.python-requests.org/en/master/user/install/)
package.

## Sending requests with `curl`

The `get_session_id.py` script can be used to obtain a session ID for use
with external tools, like [`curl`](https://curl.haxx.se/). For example:

```sh
sessid=$(python get_session_id.py -h https://1.2.3.4/ -u admin -p my_password)

# Send a POST request to create a test capture session:
curl -k -s -X POST -H "Cookie: PHPSESSID=${sessid}" -d @create-capture-session.xml http://`host`/nbi/nbi-capture/session | xmllint --format -

# Send a GET request to list all capture sessions:
curl -k -s -H "Cookie: PHPSESSID=${sessid}" http://`host`/nbi/nbi-capture/session | xmllint --format -
```

In the `curl` commands above, piping the output to `xmllint` for
pretty-printing is optional, and the `-k` flag is only necessary if you use
HTTPS with a certificate that is self-signed or signed by a CA that is not
recognized by your system.
