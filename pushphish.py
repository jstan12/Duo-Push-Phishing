# Purpose: Duo Push Phishing
# Author - Joe Stanulis
# Date: 10/18/2019

## TO DO
# Pagination - Script is currently limited to 100 users
# User groups - Send a push to users based on user group

import base64, email, hmac, hashlib, urllib, requests
import json

def sign(method, host, path, params, skey, ikey):
    """
    Return HTTP Basic Authentication ("Authorization" and "Date") headers.
    method, host, path: strings from request
    params: dict of request parameters
    skey: secret key
    ikey: integration key
    HMAC: https://en.wikipedia.org/wiki/HMAC
    """

    # create canonical string
    now = email.Utils.formatdate()
    canon = [now, method.upper(), host.lower(), path]
    args = []
    for key in sorted(params.keys()):
        val = params[key]
        if isinstance(val, unicode):
            val = val.encode("utf-8")
        args.append(
            '%s=%s' % (urllib.quote(key, '~'), urllib.quote(val, '~')))
    canon.append('&'.join(args))
    canon = '\n'.join(canon)

    # sign canonical string
    sig = hmac.new(skey, canon, hashlib.sha1)
    auth = '%s:%s' % (ikey, sig.hexdigest())

    # return headers
    return {'Date': now, 'Authorization': 'Basic %s' % base64.b64encode(auth)}

# Duo host API
duo_host = "api-XXXXXXXX.duosecurity.com"

# Duo Admin API keys
duo_admin_ikey = "DXXXXXXXXXXXXXXXXXXX"
duo_admin_skey = "XXXXXXXXXXXXXXXXXXX"

# Duo Auth API keys
duo_auth_ikey = "DXXXXXXXXXXXXXXXXXXX"
duo_auth_skey = "XXXXXXXXXXXXXXXXXXX"

params = {}
sign_params = {}

# Get list of Duo users
admin_sign_params = sign("GET", duo_host, "/admin/v1/users", params, duo_admin_skey, duo_admin_ikey)
response = requests.get(("https://" + duo_host + "/admin/v1/users"), headers={'username': duo_admin_ikey, 'Authorization': admin_sign_params["Authorization"], 'date': admin_sign_params["Date"]}, params=params)

# Load into JSON format
json_response = json.loads(response.text)

# Auth API
for response in json_response['response']:
	params = {'username': (response['username']),'factor':'auto','device':'auto'}
	auth_sign_params = sign("POST", duo_host, "/auth/v2/auth", params, duo_auth_skey, duo_auth_ikey)
	auth_response = requests.post(("https://" + duo_host + "/auth/v2/auth"), headers={'username': duo_auth_ikey, 'Authorization': auth_sign_params["Authorization"], 'date': auth_sign_params["Date"]}, params=params)
	print response['username']
	print(auth_response.json())

	# Clear params for next post to Duo
	params = {}
	sign_params = {}
