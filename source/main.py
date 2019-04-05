import re
import json
import os
from urllib import request, parse

with open(os.getcwd() + '/credentials/messaging.json') as json_file:
    data = json.load(json_file)
    print(data['slack-webhooks'])

def send_message_to_slack(text):
    post = {"text": "{0}".format(text)}

    try:
        json_data = json.dumps(post)
        req = request.Request("https://hooks.slack.com/services/" + data['slack-webhooks'],
                              data=json_data.encode('ascii'),
                              headers={'Content-Type': 'application/json'})
        resp = request.urlopen(req)
    except Exception as em:
        print("EXCEPTION: " + str(em))

f=open("/var/log/fail2ban.log", "r")
regex = '(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\sfail2ban.actions:\sWARNING\s\[ssh\]\sBan\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
while True:
    if f.mode == 'r':
        contents = f.readlines()
        for lines in contents:
            match = re.search(regex, lines)
            if (match):
                send_message_to_slack(match.group(2) + " is attempting to breach! All connections will be terminated from this IP.")
                print(match.group(2) + " is attempting to breach! All connections will be terminated from this IP.")
