import re, pyinotify, difflib, psutil, json, os, asyncio, websockets, socket, time
from urllib import request


auth_log_file_name = '/var/log/auth.log'

# TODO: reconnect on connection drop
# TODO: error handlind if the agent is restarted prevent duplicate entries
# TODO: Pool the Websocket connection
@asyncio.coroutine
def send_message_shellwatch(ip='', type='', username=''):
    agent_data = {
        'ip': ip,
        'host-key': '9e3fa814ac268c254f5ea7ba7cf68cb6',
        'type': type,
        'host': socket.gethostname(),
        'username': username
    }
    try:
        websocket = yield from websockets.connect('ws://192.168.33.12:3000/agent')
        yield from websocket.send(json.dumps(agent_data))
    except:
        print('Error')
    finally:
        yield from websocket.close()

def filter_new_lines(line=''):
    return line.startswith('+ ')

# This function is required because pyinotify will check the diff and + on starting for new line
def convert_delta_to_raw(line=''):
    return line.replace('+ ', '', 1).rstrip()


class Fail2banFileMonitors(pyinotify.ProcessEvent):
    # data structure to track banned hosts
    banned_hosts = []
    login_hosts = []

    fail2ban_log_file_frame_prev = None
    login_log_file_frame_prev = None
    fail2ban_log_file_name = '/var/log/fail2ban.log'
    auth_log_file_name = '/var/log/auth.log'

    ban_regex_log = '.*fail2ban\.actions.+\[sshd{0,1}\]\s+(Ban)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    unban_regex_log = '.*fail2ban\.actions.+\[sshd{0,1}\]\s+(Unban)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    login_regex = '.*sshd.*Accepted\s(publickey|password)\sfor\s([a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$))\sfrom\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    def __init__(self):
        # make a initial check for the list of banned user
        self.parse_banned_users()
        self.parse_login_users()

    # TODO: Error handling
    def parse_banned_users(self):
        fail2ban_file_pointer = open(self.fail2ban_log_file_name, 'r')
        self.fail2ban_log_file_frame_prev = fail2ban_file_pointer.readlines()

        fail2ban_file_pointer.close()
        pass

    # TODO: Error handling
    def parse_login_users(self):
        login_file_pointer = open(auth_log_file_name, 'r')
        self.login_log_file_frame_prev = login_file_pointer.readlines()
        login_file_pointer.close()

    # This is a event callback from pyinotify
    # This will look for file changes and send data accordingly
    def  process_IN_MODIFY(self, evt):
        if evt.pathname == self.auth_log_file_name:
            self.process_login_success()
        elif evt.pathname == self.fail2ban_log_file_name:
            self.process_login_failure()

    def process_login_failure(self):
        fail2ban_file_pointer = open(self.fail2ban_log_file_name, 'r')
        fail2ban_log_file_frame_current = fail2ban_file_pointer.readlines()
        differ_instance = difflib.Differ()
        diff_list_delta = list(differ_instance.compare(self.fail2ban_log_file_frame_prev, fail2ban_log_file_frame_current))
        self.fail2ban_log_file_frame_prev = fail2ban_log_file_frame_current
        diff_list_filtered_delta = filter(filter_new_lines, diff_list_delta)
        diff_list = map(convert_delta_to_raw, list(diff_list_filtered_delta))
        self.detect_ban_unban_logic(diff_list)

        fail2ban_file_pointer.close()

    def process_login_success(self):
        auth_file_pointer = open(self.auth_log_file_name, 'r')
        login_log_file_frame_current = auth_file_pointer.readlines()
        differ_instance = difflib.Differ()
        diff_list_delta = list(differ_instance.compare(self.login_log_file_frame_prev, login_log_file_frame_current))
        self.login_log_file_frame_prev = login_log_file_frame_current
        diff_list_filtered_delta = filter(filter_new_lines, diff_list_delta)
        diff_list = map(convert_delta_to_raw, list(diff_list_filtered_delta))
        self.detect_login_logic(diff_list)

        auth_file_pointer.close()

    def detect_ban_unban_logic(self, lines):
        for line in lines:
            line.rstrip()
            ban_match = re.search(self.ban_regex_log, line)
            if ban_match:
                self.banned_hosts.append(ban_match.group(2))
                asyncio.get_event_loop().run_until_complete(send_message_shellwatch(ban_match.group(2), 'ban'))

            unban_match = re.search(self.unban_regex_log, line)
            if unban_match:
                del self.banned_hosts[self.banned_hosts.index(unban_match.group(2))]
                asyncio.get_event_loop().run_until_complete(send_message_shellwatch(unban_match.group(2), 'unban'))

    def detect_login_logic(self, lines):
        for line in lines:
            line.rstrip()
            login_match = re.search(self.login_regex, line)
            if login_match:
                self.login_hosts.append(login_match.group(2))
                asyncio.get_event_loop().run_until_complete(send_message_shellwatch(login_match.group(4), 'login', login_match.group(2)))

def main():
    log_path = '/var/log/'
    watch_manager = pyinotify.WatchManager()
    watch_manager.add_watch(log_path, pyinotify.IN_MODIFY)
    file_monitor = Fail2banFileMonitors()
    notifier = pyinotify.Notifier(watch_manager, file_monitor)
    notifier.loop()


if __name__ == "__main__":
    main()
