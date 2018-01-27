#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''

'''

EXAMPLES = '''

'''

import requests
import json
import urllib3

#from ansible.module_utils.urls import fetch_url
from ansible.module_utils.basic import AnsibleModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from OpenSSL.crypto import FILETYPE_PEM, load_privatekey, sign
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

def candid_argument_spec():
    return dict(
        #private_key=dict(type='path', aliases=['cert_key']),  # Beware, this is not the same as client_key !
        #certificate_name=dict(type='str', aliases=['cert_name']),  # Beware, this is not the same as client_cert !
        #timeout=dict(type='int', default=30),
        use_proxy=dict(type='bool', default=True),
        use_ssl=dict(type='bool', default=True),
        validate_certs=dict(type='bool', default=True),
    )

class User(object):
    def __init__(self, module):
        self.module= module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        self.base_url = "https://" + self.params['host'] + "/api/v1/"

    def login(self):

        whoami_url = self.base_url + 'whoami'

        wmi_response = requests.get(url=whoami_url, headers=self.headers, verify=False)
        if wmi_response.status_code is 200:
            login_body = {
                "username": self.params['username'],
                "password": self.params['password']
            }
            cookie = wmi_response.headers['Set-Cookie']
            cookie = str(cookie).split(';')[0]
            self.headers["X-CANDID-LOGIN-OTP"] = wmi_response.headers['X-CANDID-LOGIN-OTP']
            self.headers['Cookie'] = cookie

            login_url = self.base_url + "login"
            login_resp = requests.post(url=login_url, data=json.dumps(login_body), headers=self.headers, verify=False)
            token = login_resp.headers['X-CANDID-CSRF-TOKEN']
            sid = login_resp.headers['Set-Cookie']

            log_cookie = str(sid).split(';')[0]
            # rest_header = dict()
            self.headers['Cookie'] = log_cookie
            self.headers['X-CANDID-CSRF-TOKEN'] = token

            return login_resp.status_code

    def create_user(self):
        create_url = self.base_url + '/users'
        config_data = {
            "system_object": self.params['system_object'],
            "email": self.params['email'],
            "password": self.params['user_password'],
            "confirm_password": self.params['confirm_user_password'],
            "username": self.params['user']
        }

        create_resp = requests.post(url=create_url, headers=self.headers,
                                      data=json.dumps(config_data), verify=False)

        resp = json.dumps(create_resp.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = create_resp.status_code

    def update_user(self):
        resp = self.get_all_user_data()
        data_no = len(resp['value']['data'])
        for key in range(0, data_no):
            if resp['value']['data'][key]['username'] == self.params['user']:
                fabric_id = resp['value']['data'][key]['uuid']
        update_url = self.base_url + 'users/{0}'.format(fabric_id)
        update_payload = {'uuid': fabric_id}
        for key, value in self.params.items():
            if self.params[key]:
               update_payload[key] = value
        update_resp = requests.put(url=update_url, headers=self.headers, data=json.dumps(update_payload), verify=False)
        resp = json.dumps(update_resp.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = update_resp.status_code

    def get_user_data(self):
        resp = self.get_all_user_data()
        data_no = len(resp['value']['data'])
        for key in range(0, data_no):
            if resp['value']['data'][key]['username'] == self.params['user']:
                fabric_id = resp['value']['data'][key]['uuid']
        get_user_data_url = self.base_url + 'users/{0}'.format(fabric_id)
        user_data = requests.get(url=get_user_data_url, headers=self.headers, verify=False)
        resp = json.dumps(user_data.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = user_data.status_code

    def delete_user(self):
        resp = self.get_all_user_data()
        data_no = len(resp['value']['data'])
        for key in range(0, data_no):
            if resp['value']['data'][key]['username'] == self.params['user']:
                fabric_id = resp['value']['data'][key]['uuid']

        delete_user_url = self.base_url + 'users/{0}'.format(fabric_id)
        delete_user = requests.delete(url=delete_user_url, headers=self.headers, verify=False)

        resp = json.dumps(delete_user.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = delete_user.status_code

    def get_all_user_data(self):
        user_url = self.base_url + 'users'
        all_user_data = requests.get(url=user_url, headers=self.headers, verify=False)
        resp = json.dumps(all_user_data.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = all_user_data.status_code

        return resp



def main():
    argument_spec = candid_argument_spec()
    argument_spec.update(
        host=dict(required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        method=dict(type='str', choices=['create_user', 'update_user', 'delete_user', 'user_info', 'all_user_data'],
                    aliases=['action'], required=True),
        system_object=dict(type='bool', default='False'),
        email=dict(type='str'),
        user=dict(type='str'),
        user_password=dict(type='str', no_log=True),
        confirm_user_password=dict(type='str', no_log=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    method = module.params['method']
    system_object = module.params['system_object']
    email = module.params['email']
    user = module.params['user']
    user_password = module.params['user_password']
    confirm_user_password = module.params['confirm_user_password']

    if user_password != confirm_user_password:
        module.fail_json(msg='user_password and confirm_user_password do no match!')

    else:
        candid = User(module)

        resp = candid.login()

        if resp is 200 or resp is 201:
            try:
                if method == 'create_user':
                    candid.create_user()
                elif method == 'update_user':
                     candid.update_user()
                elif method == 'user_info':
                    candid.get_user_data()
                elif method == 'delete_user':
                    candid.delete_user()
                elif method == 'all_user_data':
                    candid.get_all_user_data()

            except Exception:
                pass

        module.exit_json(**candid.result)


if __name__ == '__main__':
    main()

