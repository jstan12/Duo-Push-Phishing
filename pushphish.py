####
# Duo Push Phishing
# Author: Joe Stanulis
### Reference Links ###
# https://duo.com/docs/authapi
# https://duo.com/docs/adminapi
### TO DO ###
# User Pagination - Script is currently limited to 300 users
# Group Pagination - Script is currently limited to 100 groups
####

import base64, email, hmac, hashlib, urllib, requests, json

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

############ Duo Keys ############
# Duo host API
duo_host = "api-XXXXXXXX.duosecurity.com"
# Duo Admin API keys
duo_admin_ikey = "DXXXXXXXXXXXXXXXXXXX"
duo_admin_skey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
# Duo Auth API keys
duo_auth_ikey = "DXXXXXXXXXXXXXXXXXXX"
duo_auth_skey = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
############ Duo Keys ############

admin_params = {}
auth_params = {}
admin_sign_params = {}
auth_sign_params = {}

# Get list of all Duo Groups
# Admin API
admin_sign_params = sign("GET", duo_host, "/admin/v1/groups", admin_params, duo_admin_skey, duo_admin_ikey)
admin_response = requests.get(("https://" + duo_host + "/admin/v1/groups"), headers={'username': duo_admin_ikey, 'Authorization': admin_sign_params["Authorization"], 'date': admin_sign_params["Date"]}, params=admin_params)

# Load groups into JSON format
json_admin_response = json.loads(admin_response.text)

# Array for groups
groups_list = []
# Number for group in array
x = int(0)
# Increment counter
i = int(0)
print("\nSelect a Duo group to phish")

# Iterate through groups list
for groups in json_admin_response['response']:
	groups_list.append(groups['group_id'])
	print(x,groups['name'])
	x += 1
	i += 1

	# Display 10 Duo groups at a time
	while i >= 10: 
		more_groups = raw_input("View more groups? [y/n] ").lower()
		if more_groups == 'y':
			# Reset counter
			i = int(0)
			continue
		elif more_groups == 'n':
			break
		else:
			print("Invalid response. Respond with 'y' or 'n' to continue")
	if i >= 10:
		break

# Select a group number to pass to Duo			
group_select = raw_input("Input a group number: ")
group_select = int(group_select)

# Create API string
group_api = "/admin/v2/groups/"+groups_list[group_select]+"/users"

# Get list of all users in Duo Group
# Admin API
admin_sign_params = sign("GET", duo_host, group_api, admin_params, duo_admin_skey, duo_admin_ikey)
admin_group_response = requests.get(("https://" + duo_host + group_api), headers={'username': duo_admin_ikey, 'Authorization': admin_sign_params["Authorization"], 'date': admin_sign_params["Date"]}, params=admin_params)

# Load Duo users into JSON format
json_admin_group_response = json.loads(admin_group_response.text)
print("Phishing Duo users...")

# Send a push to all users in selected Duo group
# Auth API
for response in json_admin_group_response['response']:
	auth_params = {'username': (response['username']),'factor':'auto','device':'auto','async':'1'}
	auth_sign_params = sign("POST", duo_host, "/auth/v2/auth", auth_params, duo_auth_skey, duo_auth_ikey)

	auth_response = requests.post(("https://" + duo_host + "/auth/v2/auth"), headers={'username': duo_auth_ikey, 'Authorization': auth_sign_params["Authorization"], 'date': auth_sign_params["Date"]}, params=auth_params)
	print(response['username'])

	# Clear params for next post to Duo
	auth_params = {}
	auth_sign_params = {}

print("Phishing completed!")
print("View Duo admin panel for results")
