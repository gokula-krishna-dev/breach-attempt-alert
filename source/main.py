import re, pyinotify, difflib, psutil, json, os
from urllib import request

fail2ban_log_file_name = '/var/log/fail2ban.log.1'

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


def filter_new_lines(line=''):
    return line.startswith('+ ')


def convert_delta_to_raw(line=''):
    return line.replace('+ ', '', 1).rstrip()


class FileMonitors(pyinotify.ProcessEvent):
    ban_regex_log = '(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\sfail2ban.actions:\sWARNING\s\[ssh\]\sBan\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    unban_regex_log = '(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})\sfail2ban.actions:\sWARNING\s\[ssh\]\sUnban\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    fail2ban_log_file_frame_prev = None

    # data structure to track banned hosts
    banned_hosts = []

    def __init__(self):
        # make a initial check for the list of banned user
        self.parse_banned_users()

    # TODO: Error handling
    def parse_banned_users(self):
        fail2ban_file_pointer = open(fail2ban_log_file_name, 'r')
        self.fail2ban_log_file_frame_prev = fail2ban_file_pointer.readlines()
        self.detect_ban_unban_logic(self.fail2ban_log_file_frame_prev)

        print(self.banned_hosts)

        fail2ban_file_pointer.close()

    def process_IN_CLOSE_WRITE(self, evt):
        fail2ban_file_pointer = open(fail2ban_log_file_name, 'r')
        fail2ban_log_file_frame_current = fail2ban_file_pointer.readlines()
        differ_instance = difflib.Differ()
        diff_list_delta = list(differ_instance.compare(self.fail2ban_log_file_frame_prev, fail2ban_log_file_frame_current))
        self.fail2ban_log_file_frame_prev = fail2ban_log_file_frame_current
        diff_list_filtered_delta = filter(filter_new_lines, diff_list_delta)
        diff_list = map(convert_delta_to_raw, list(diff_list_filtered_delta))
        self.detect_ban_unban_logic(diff_list)

        print(self.banned_hosts)

        fail2ban_file_pointer.close()

    def detect_ban_unban_logic(self, lines):
        lines.rstrip()
        for line in lines:
            ban_match = re.search(self.ban_regex_log, line)
            if ban_match:
                self.banned_hosts.append(ban_match.group(2))

            unban_match = re.search(self.unban_regex_log, line)
            if unban_match:
                del self.banned_hosts[self.banned_hosts.index(unban_match.group(2))]

def main():
    watch_manager = pyinotify.WatchManager()
    watch_manager.add_watch(fail2ban_log_file_name, pyinotify.ALL_EVENTS)
    file_monitor = FileMonitors()
    notifier = pyinotify.Notifier(watch_manager, file_monitor)
    notifier.loop()


if __name__ == "__main__":
    main()
