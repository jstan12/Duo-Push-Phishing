# Purpose: Duo Push Phishing
# Author - Joe Stanulis
# Created Date: 10/18/2019
# Updated Date: 10/24/2019
##
# Reference Links:
# https://duo.com/docs/authapi
# https://duo.com/docs/adminapi

## TO DO
# User Pagination - Script is currently limited to 300 users
# Group Pagination - Script is currently limited to 100 groups
##

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

#### Duo Keys ####
# Duo host API
duo_host = "api-XXXXXXXX.duosecurity.com"
# Duo Admin API keys
duo_admin_ikey = "DXXXXXXXXXXXXXXXXXXX"
duo_admin_skey = "XXXXXXXXXXXXXXXXXXXX"
# Duo Auth API keys
duo_auth_ikey = "XXXXXXXXXXXXXXXXXXXX"
duo_auth_skey = "XXXXXXXXXXXXXXXXXXXX"
#### Duo Keys ####

admin_params = {}
auth_params = {}
admin_sign_params = {}
auth_sign_params = {}

# Get list of Duo Groups
# https://duo.com/docs/adminapi#retrieve-groups
admin_sign_params = sign("GET", duo_host, "/admin/v1/groups", admin_params, duo_admin_skey, duo_admin_ikey)
admin_response = requests.get(("https://" + duo_host + "/admin/v1/groups"), headers={'username': duo_admin_ikey, 'Authorization': admin_sign_params["Authorization"], 'date': admin_sign_params["Date"]}, params=admin_params)

# Load groups into JSON format
json_admin_response = json.loads(admin_response.text)

# Array for groups
groups_list = []
i = int(0)
x = int(0)

# Iterate through groups list
for groups in json_admin_response['response']:
    groups_list.append(groups['group_id'])
    print(i,groups['name'])
    i += 1
    x += 1

    # Display 10 user groups at a time
    if x > 10: 
        more_groups = raw_input("View more groups?? [y/n] ")
        if more_groups == 'y':
            x = 0
            continue
        else:
            break

# Select group to pass to Duo           
group_select = raw_input("Input a group number: ")
group_select = int(group_select)

# Create API string
group_api = "/admin/v2/groups/"+groups_list[group_select]+"/users"

# Get list of users in Duo Group
# https://duo.com/docs/adminapi#v2-groups-get-users
admin_sign_params = sign("GET", duo_host, group_api, admin_params, duo_admin_skey, duo_admin_ikey)
admin_group_response = requests.get(("https://" + duo_host + group_api), headers={'username': duo_admin_ikey, 'Authorization': admin_sign_params["Authorization"], 'date': admin_sign_params["Date"]}, params=admin_params)

# Load Duo users into JSON format
json_admin_group_response = json.loads(admin_group_response.text)

# Auth API
for response in json_admin_group_response['response']:
    auth_params = {'username': (response['username']),'factor':'auto','device':'auto','async':'1'}
    auth_sign_params = sign("POST", duo_host, "/auth/v2/auth", auth_params, duo_auth_skey, duo_auth_ikey)

    auth_response = requests.post(("https://" + duo_host + "/auth/v2/auth"), headers={'username': duo_auth_ikey, 'Authorization': auth_sign_params["Authorization"], 'date': auth_sign_params["Date"]}, params=auth_params)
    print(response['username'])

    # Clear params for next post to Duo
    auth_params = {}
    auth_sign_params = {}
