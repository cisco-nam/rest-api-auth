#!/usr/bin/env python

from rest_api_connection import RestApiConnection

#####################################
# Change these to appropriate values.
#####################################
host = "1.2.3.4"
username = "my-username"
password = "my-password"
#####################################

# Disable HTTPS cert warnings to keep the output cleaner.
import requests
requests.packages.urllib3.disable_warnings()

# If the HTTPS server is not enabled, use secure=False below.
conn = RestApiConnection(secure=True)
conn.connect(host, username, password)
print("Session ID: " + conn.get_session_id() + "\n")

# Send a few different requests.
print(">>> GET /nbi/nbi-datasource")
response = conn.get("datasource", "")
print(response.text + "\n")

print(">>> POST /nbi/nbi-capture/session")
post_data = open("sample-requests/create-capture-session.xml").read()
print(post_data)
response = conn.post("capture/session", "", post_data)
print(response.text + "\n")

print(">>> DELETE /nbi/nbi-appsetup/protocolpack")
response = conn.delete("appsetup", "/protocolpack")
print(response.text + "\n")
