#!/usr/bin/python
# This Script is for demo purposes only. If to be adapted for production the users should test and validate operations.
# Author leoncozzi@gmail.com

import json
from sys import argv
import csv
import sys
import requests

# If using a valid certificate, these two lines can and SHOULD be removed.
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

if len(argv) == 5:
    script, filename, nsx_manager, nsx_username, nsx_password = argv
else:
    print('Syntax: dfw-export.py [target_file_name] [nsx_manager_ip_or_hostname] [nsx_username] [nsx_password]')
    sys.exit()
# Set HTTP parameters for REST API call
# If you want to verify SSL, set nsx.verify = '/path/to/cert.pem'
nsx = requests.Session()
nsx.verify = False
nsx.auth = (nsx_username, nsx_password)
nsx.headers = {'Accept': 'application/json'}

filename += '.csv'
target = open(filename, 'w')
target.truncate()
csv_file = csv.writer(target)

print ("CSV: Opened file", filename)

# CSV Header
csv_file.writerow(("Rule ID", "Name", "Services", "Applied To", "Action", "Direction", "Destination", "Destination Contents", "Sources", "Source Contents"))
print
"CSV: Added CSV header row.."
# Get DFW Rulebase
sections = nsx.get('https://' + nsx_manager + '/api/v1/firewall/sections')
# Convert JSON response to python dict
section = json.loads(sections.text)

# print(section)
# print rulebase
# Iterate every layer 3 section in the rulebase
for sec in section['results']:
    # grab each section id in turn from the sections response
    if 'id' in sec:
       section_row = "Section:" + sec['display_name'] + ", ID: " + sec['id']
       csv_file.writerow([section_row])
       # Get all the rules for the section 'id'
       rule = nsx.get('https://' + nsx_manager + '/api/v1/firewall/sections/' + sec['id'] + '/rules')
       # Convert JSON response rule to python dict ruled
       ruled = json.loads(rule.text)
       for rule in ruled['results']:
         this = dict()
         this['destination includes'] = ' '
         this['destination'] = 'ANY'
         this['sources includes'] = ' '
         this['sources'] = 'ANY'
         this['id'] = ' '
         this['display_name'] = ' '
         this['services'] = ' '
         this['applied_tos'] = ' '
         this['action'] = ' '
         this['direction'] = ' '
         if rule.get('id'):
             this['id'] = rule['id']
         if rule.get('display_name'):
             this['display_name'] = rule['display_name']
         if rule.get('services'):
             this['services'] = rule['services']
         if rule.get('applied_tos'):
             this['applied_tos'] = rule['applied_tos']
         if rule.get('action'):
             this['action'] = rule['action']
         if rule.get('direction'):
            this['direction'] = rule['direction']
         if rule.get('destinations'):
            if 'target_id' in rule['destinations'][0]:
                this['destination'] = rule['destinations'][0]['target_display_name']
                if rule['destinations'][0]['target_type'] == 'IPSet':
                    ipset = nsx.get('https://' + nsx_manager + '/api/v1/ip-sets/' + rule['destinations'][0]['target_id'])
                    # Convert JSON res
                    # ponse ipset rule to python dict ipsetd
                    ipsetd = json.loads(ipset.text)
                    this['destination includes'] = [ipsetd][0]['ip_addresses']
                if rule['destinations'][0]['target_type'] == 'NSGroup':
                    nsgroup = nsx.get('https://' + nsx_manager + '/api/v1/ns-groups/' + rule['destinations'][0]['target_id'])
                    # Convert JSON res
                    # ponse ipset rule to python dict ipsetd
                    nsgroupd = json.loads(nsgroup.text)
                    # this['destination includes'] = [nsgroupd][0]
                    try:
                     this['destination includes'] = [nsgroupd][0]['membership_criteria']
                    except:
                     this['destination includes'] = [nsgroupd][0]['members']
                if rule['destinations'][0]['target_type'] == 'IPv4Address':
                    this['destination includes'] = rule['destinations'][0]['target_display_name']
         if rule.get('sources'):
            if 'target_id' in rule['sources'][0]:
                this['sources'] = rule['sources'][0]['target_display_name']
                if rule['sources'][0]['target_type'] == 'IPSet':
                    ipset = nsx.get('https://' + nsx_manager + '/api/v1/ip-sets/' + rule['sources'][0]['target_id'])
                    # Convert JSON res
                    # ponse ipset rule to python dict ipsetd
                    ipsetd = json.loads(ipset.text)
                    this['sources includes'] = [ipsetd][0]['ip_addresses']
                if rule['sources'][0]['target_type'] == 'NSGroup':
                    nsgroup = nsx.get('https://' + nsx_manager + '/api/v1/ns-groups/' + rule['sources'][0]['target_id'])
                    # Convert JSON res
                    # ponse ipset rule to python dict ipsetd
                    nsgroupd = json.loads(nsgroup.text)
                    # this['destination includes'] = [nsgroupd][0]
                    try:
                     this['sources includes'] = [nsgroupd][0]['membership_criteria']
                    except:
                     this['sources includes'] = [nsgroupd][0]['members']
                if rule['sources'][0]['target_type'] == 'IPv4Address':
                    this['sources includes'] = rule['sources'][0]['target_display_name']
         csv_rule = ([this['id'], this['display_name'], this['services'], this['applied_tos'], this['action'], this['direction'],this['destination'], this['destination includes'], this['sources'], this['sources includes']])
         csv_file.writerow(csv_rule)

print("CSV: Closing file..")
target.close()
print("CSV: File closed.")