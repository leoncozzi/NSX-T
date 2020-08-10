import json
from sys import argv
import csv
import sys
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
nsx_username = "admin"
nsx_password = "VMware1!VMware1!"
nsx_manager = "nsxmgr-01a.corp.local"

nsx = requests.Session()
nsx.verify = False
nsx.auth = (nsx_username, nsx_password)
nsx.headers = {'Content-Type': 'application/json','x-allow-overwrite' : 'true' }

data = '''{
            "id": "10255",
            "display_name": "ir-pks-ba416113-bbce-4783-90b4-7cae46c57f6c-leon-nginxv3-network-policy-all",
            "sources_excluded": false,
            "destinations_excluded": false,
            "sources": [
                {
                    "target_id": "45a2ed64-acc8-46e5-993a-a9d6634f36e6",
                    "target_display_name": "src-pks-ba416113-bbce-4783-90b4-7cae46c57f6c-leon-nginxv3-network-policy-all",
                    "target_type": "IPSet",
                    "is_valid": true
                }
            ],
            "destinations": [
                {
                    "target_id": "59abaac1-5b61-4322-a67b-2cb7c7bcf70c",
                    "target_display_name": "tgt-pks-ba416113-bbce-4783-90b4-7cae46c57f6c-leon-nginxv3-network-policy",
                    "target_type": "IPSet",
                    "is_valid": true
                }
            ],
            "applied_tos": [
                {
                    "target_id": "5de49608-a27e-45a2-a412-5188bd13a75e",
                    "target_display_name": "proj-pks-ba416113-bbce-4783-90b4-7cae46c57f6c-leon",
                    "target_type": "NSGroup",
                    "is_valid": true
                }
            ],
            "action": "ALLOW",
            "disabled": false,
            "logged": true,
            "direction": "IN",
            "ip_protocol": "IPV4_IPV6",
            "is_default": false,
            "_revision": 2
        }
'''
output = nsx.put('https://nsxmgr-01a.corp.local/api/v1/firewall/sections/373a9354-20d1-4db3-8d8e-f2f3a3cd036d/rules/10255', data=data)
print(output.text)
# sections = nsx.get('https://nsxmgr-01a.corp.local/api/v1/firewall/sections')
# Convert JSON response to python dict
# section = json.loads(sections.text)
# print(sections.text)
# for sec in section['results']:
#  #   if 'id' in sec:
    #     rule = nsx.get('https://' + nsx_manager + '/api/v1/firewall/sections/' + sec['id'] + '/rules')
      #   ruled = json.loads(rule.text)
        #print(rule.text)
