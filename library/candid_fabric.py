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

# from ansible.module_utils.urls import fetch_url
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

class Fabric(object):
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

    def create_fabric(self):
        create_url = self.base_url + '/assured-networks/aci-fabric'
        config_data = {
            "system_object": self.params['system_object'],
            "tags": self.params['tags'],
            "display_name": self.params['display_name'],
            "interval": self.params['interval'],
            "analysis_timeout_in_secs": self.params['analysis_timeout'],
            "unique_name": self.params['unique_name'],
            "assured_network_type": self.params['assured_network_type'],
            "apic_hostnames": self.params['apic_hostnames'],
            "application_id": self.params['application_id'],
            "active": self.params['active'],
            "operational_mode": self.params['operational_mode'],
            "username": self.params['username'],
            "password": self.params['password']

        }

        create_resp = requests.post(url=create_url, headers=self.headers, data=json.dumps(config_data), verify=False)
        resp = json.dumps(create_resp.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = create_resp.status_code


    def update_fabric(self):
        resp = self.get_fabric()
        data_no = len(resp['value']['data'])
        for key in range(0, data_no):
            if resp['value']['data'][key]['unique_name'] == self.params['unique_name']:
                    fabric_id = resp['value']['data'][key]['uuid']
        update_url = self.base_url + 'assured-networks/aci-fabric/' + fabric_id
        update_payload = {}
        for key, value in self.params.items():
            if self.params[key]:
               update_payload[key] = value
        update_fabric = requests.put(url=update_url, headers=self.headers, data=json.dumps(update_payload), verify=False)
        resp = json.dumps(update_fabric.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = update_fabric.status_code

    def retrieve_fabric(self):
        resp = self.get_fabric()
        data_no = len(resp['value']['data'])
        for key in range(0, data_no):
             if resp['value']['data'][key]['unique_name'] == self.params['unique_name']:
                fabric_id = resp['value']['data'][key]['uuid']
        retrieve_url = self.base_url + 'assured-networks/aci-fabric/' + fabric_id
        retrieve_fabric_data = requests.get(url=retrieve_url, headers=self.headers, verify=False)
        resp = json.dumps(retrieve_fabric_data.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = retrieve_fabric_data.status_code

    def start_stop_analysis(self, method):
        resp = self.get_fabric()
        data_no = len(resp['value']['data'])
        for key in range(0, data_no):
            if resp['value']['data'][key]['unique_name'] == self.params['unique_name']:
                fabric_id = resp['value']['data'][key]['uuid']
        analysis_url = self.base_url + 'assured-networks/aci-fabric/{0}/{1}'.format(fabric_id, method)
        analysis_response = requests.post(url=analysis_url, headers=self.headers, verify=False)
        resp = json.dumps(analysis_response.json(), indent=4, sort_keys=True)
        resp = json.loads(resp)

        self.result['response'] = resp
        self.result['status'] = analysis_response.status_code

    def get_fabric(self):
        fabric_url = self.base_url + "assured-networks/aci-fabric"
        fabrics = requests.get(url=fabric_url, headers=self.headers, verify=False)
        if fabrics.status_code is 200 or fabrics.status_code is 201:
            resp = json.dumps(fabrics.json())
            resp = json.loads(resp)

        return resp

def main():
    argument_spec = candid_argument_spec()
    argument_spec.update(
        host=dict(required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        method=dict(type='str', choices=['create_fabric', 'update_fabric', 'retrieve_fabric', 'start-analysis', 'stop-analysis'],
                    aliases=['action'], removed_in_version='2.6', required=True),
        system_object=dict(type='bool', default='False'),
        tags=dict(type='list'),
        display_name=dict(type='str'),
        interval=dict(type='int'),
        analysis_timeout=dict(type='int'),
        unique_name=dict(type='str', required=True),
        assured_network_type=dict(type='str'),
        apic_hostnames=dict(type='list'),
        application_id=dict(type='str'),
        active=dict(type='bool'),
        operational_mode=dict(type='str')
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username=module.params['username']
    password=module.params['password']
    method=module.params['method']
    system_object=module.params['system_object']
    tags=module.params['tags']
    display_name=module.params['display_name']
    interval=module.params['interval']
    analysis_timeout=module.params['analysis_timeout']
    unique_name=module.params['unique_name']
    assured_network_type=module.params['assured_network_type']
    apic_hostnames=module.params['apic_hostnames']
    application_id=module.params['application_id']
    active=module.params['active']
    operational_mode=module.params['operational_mode']

    candid = Fabric(module)

    resp = candid.login()

    if resp is 200 or resp is 201:
        try:
            if method == 'create_fabric':
                    candid.create_fabric()
            elif method == 'update_fabric':
                    candid.update_fabric()
            elif method == 'retrieve_fabric':
                    candid.retrieve_fabric()
            elif method == 'start-analysis' or method == 'stop-analysis':
                    candid.start_stop_analysis(method)
        except Exception:
                pass

    module.exit_json(**candid.result)


if __name__ == '__main__':
    main()