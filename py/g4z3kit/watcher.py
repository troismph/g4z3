#!/usr/bin/env python
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import sched
import time


class MsgSender(object):
    def __init__(self, accnt, passwd, server, port):
        self._accnt = accnt
        self._passwd = passwd
        self._server = server
        self._port = port

    def send(self, dst, subject, content):
        msg = MIMEMultipart()
        msg['From'] = self._accnt
        msg['To'] = dst
        msg['Subject'] = subject
        msg.attach(MIMEText(content))
        mailserver = smtplib.SMTP(self._server, self._port)
        # identify ourselves to smtp gmail client
        mailserver.ehlo()
        # secure our email with tls encryption
        mailserver.starttls()
        # re-identify ourselves as an encrypted connection
        mailserver.ehlo()
        mailserver.login(self._accnt, self._passwd)
        mailserver.sendmail(self._accnt, dst, msg.as_string())
        mailserver.quit()


def test_msgsender():
    sender = MsgSender(ME_ACCOUNT, ME_PASSWORD, "smtp.exmail.qq.com", 587)
    sender.send('kiwi@mini-monster.net', 'greeting from python', 'hahahaha')


class Watcher(object):
    def __init__(self, collector, interval, config_path):
        self._scheduler = sched.scheduler(time.time, time.sleep)
        self._interval = interval
        self._collector = collector
        self._config = json.load(open(config_path))

    def collect(self):
        subject, msg = self._collector.do()
        sender = MsgSender(
            self._config['ME_ACCOUNT'],
            self._config['ME_PASSWORD'],
            self._config['ME_SERVER'],
            self._config['ME_PORT']
        )
        print("sending msg")
        sender.send(self._config['THEM_ACCOUNT'], subject, msg)
        print("msg sent")
        self._scheduler.enter(self._interval, 1, self.collect)

    def run(self):
        self.collect()
        self._scheduler.run()
