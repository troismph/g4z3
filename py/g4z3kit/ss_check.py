#!/usr/bin/env python3
import subprocess
import requests
import json
import time
import os
import argparse
import functools
from watcher import Watcher


TEST_URLS = [
    "http://bing.com",
    "http://api.ipify.org?format=json",
    "https://www.google.com",
    "https://www.twitter.com",
    "https://www.facebook.com",
    "http://www.baidu.com"
]


class SSChecker(object):

    def __init__(self, config_dir, test_urls):
        self._config_dir = config_dir
        self._test_urls = test_urls

    def _check_server(self, config_path):
        p = subprocess.Popen(['sslocal', '-c', config_path])
        time.sleep(3)
        c = json.load(open(config_path))
        local_port = c.get('local_port', 1080)
        proxies = {
            'http': 'socks5h://127.0.0.1:' + str(local_port),
            'https': 'socks5h://127.0.0.1:' + str(local_port)
        }
        ret = {}
        for u in self._test_urls:
            try:
                print("testing url {u}".format(u=u))
                resp = requests.get(u, proxies=proxies, verify=False)
                ret[u] = resp.ok
            except:
                ret[u] = False
        p.kill()
        return ret

    def do(self):
        msgs = []
        all_pass = True
        for x in os.listdir(self._config_dir):
            msgs.append(x)
            ret = self._check_server(os.path.join(self._config_dir, x))
            msgs.append(json.dumps(ret, ensure_ascii=False, indent=4))
            all_pass = all_pass and functools.reduce(lambda x, y: x and y, ret.values())
        subject = "SS OK" if all_pass else "SS ERROR!!!"
        msg = '\n\n'.join(msgs)
        return subject, msg


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("config", help="watch's own config file path")
    parser.add_argument("config_dir", help="ss local config files directory")
    parser.add_argument("interval", help="report interval, in minutes")
    args = parser.parse_args()
    checker = SSChecker(args.config_dir, TEST_URLS)
    m = Watcher(checker, int(args.interval) * 60, args.config)
    m.run()


if __name__ == '__main__':
    run()
