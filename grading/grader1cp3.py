#!/usr/bin/env python
import socket
import requests
import os
import time
from grader import grader, tester
import hashlib
import random
from subprocess import Popen, PIPE, STDOUT
import os.path
import signal


BIN = "../lisod"

MIME = {
    '.html' : 'text/html',
    '.css'  : 'text/css',
    '.png'  : 'image/png',
    '.jpg'  : 'image/jpeg',
    '.gif'  : 'image/gif',
    ''      : 'application/octet-stream'
}

BAD_POST_DATA = 'asldksjdklfjaskldfjlksdjgjksdhfjkgdhjkfshcvkljsdclk\
mzxvm,xcnm,vnsdilfuodghiouwerhfguiohsdiourghiousdrhguio'
TEST_DOMAIN = 'https://localhost'
SIGNER_CERT = 'signer.crt'


class project1cp3tester(tester):

    def __init__(self, test_name, testsuit):
        super(project1cp3tester, self).__init__(test_name, testsuit)

    def test_kill(self):
        if self.testsuite.server_pid is None:
            self.skipTest("server failed to start. skip kill")
        print "kill it"
        os.kill(self.testsuite.server_pid, signal.SIGKILL)
        return

    def test_using_select(self):
        print "Simple checker to tell if you are using select(). \
        We will check it manually later."
        p = Popen("grep -rq 'select' ./ ", \
            shell=True, stdout=PIPE, stderr=STDOUT)
        rc = p.wait()
        if rc == 0:
            self.testsuite.scores['use_select'] = 1
            return
        else:
            raise Exception("You probably did not use select.")

    def start_server(self):
        if self.testsuite.scores['use_select'] <= 0:
            self.skipTest("Select() is not used. Skip this test")
        if not os.path.isfile("../lisod"):
            if os.path.isfile("../echo_server"):
                print "Your makefile should make a binary called lisod, \
                        not echo_server!"
            self.skipTest("lisod not found. Skip this test")

        print "Try to start server!"
        cmd = '%s %d %d %slisod.log %slisod.lock %s %s %s %s' % \
                (BIN, self.testsuite.port, self.testsuite.tls_port, \
                self.testsuite.tmp_dir, self.testsuite.tmp_dir, \
                self.testsuite.www[:-1], self.testsuite.cgi, \
                self.testsuite.priv_key, self.testsuite.cert)
        print cmd
        fp = open(os.devnull, 'w')
        p = Popen(cmd.split(' '), stdout=fp, stderr=fp)
        print "Wait 2 seconds."
        time.sleep(2)
        rc = p.poll()
        if rc is None:
            raise Exception("Daemonizer should exit!")
        if rc != 0:
            raise Exception("Daemonizer failed with return code %d" % rc)
        fp.close()
        self.testsuite.scores['server_start'] = 1

    def test_daemonization(self):
        if self.testsuite.scores['server_start'] != 1:
            self.skipTest("server failed to start. skip this test")
        try:
            f = open('%slisod.lock'%self.testsuite.tmp_dir, 'r')
        except IOError:
            raise Exception("Lockfile does not exist!")
        pid = f.readline().strip()
        try:
            pid = int(pid)
        except ValueError:
            raise Exception("Lockfile does not have a valid pid!")
        if pid <= 0:
            raise Exception("Lockfile does have an invalid pid!")
        print "Server running on pid %d" % pid
        try:
            os.kill(pid, 0)
        except OSError:
            Exception("But pid %d is dead or never lived before!" % pid)
        self.testsuite.server_pid = pid
        self.testsuite.scores['test_daemonization'] = 1
        return

    def test_pipelining_keepalive(self):
        if self.testsuite.scores['test_daemonization'] != 1:
            self.skipTest("server failed to start. skip this test")
        print "Testing pipelining"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', self.testsuite.port))
        s.settimeout(4)
        pipe = "HEAD /index.html HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: Keep-Alive\r\n\r\n"\
        %self.testsuite.port*5
        s.send(pipe)
        while True:
            try:
                buf = s.recv(1024)
            except socket.timeout:
                self.testsuite.scores['test_pipelining_keepalive'] += 0.5
                break
            if buf == "":
                print "Server connection does not keepalive!"
                break
        s.close()

        print "Testing pipelining with Connection: Close"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', self.testsuite.port))
        s.settimeout(4)
        pipe2 = pipe+"HEAD /index.html HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: Close\r\n\r\n"%self.testsuite.port
        s.send(pipe2)
        while True:
            try:
                buf = s.recv(1024)
            except socket.timeout:
                print "Server doesn't close connections as requested!"
                break
            if buf == "":
                self.testsuite.scores['test_pipelining_keepalive'] += 0.5
                break
        s.close()
        if self.testsuite.scores['test_pipelining_keepalive'] < 1:
            raise Exception("Failed in some of the testcases of keepalive")

    def test_invalidPUT(self):
        print '----- Testing PUT via SSL -----'
        if self.testsuite.scores['test_daemonization'] != 1:
            self.skipTest("server failed to start. skip this test")
        time.sleep(1)
        for test in self.testsuite.SSL_tests:
            try:
                response = requests.put(test % self.testsuite.tls_port,\
                    timeout=3.0, verify=SIGNER_CERT)
            except requests.exceptions.SSLError:
                raise Exception("Failed to connect via SSL!")

            self.pAssertEqual(501, response.status_code)
        self.testsuite.scores['test_invalidPUT'] = 1

    def test_invalidLENGTH(self):
        print '----- Testing Bad Length Post via http-----'
        if self.testsuite.scores['test_daemonization'] != 1:
            self.skipTest("server failed to start. skip this test")
        s = requests.Session()
        prepped = requests.Request('POST', 'http://127.0.0.1:%d/cgi/' \
            % self.testsuite.port, data=BAD_POST_DATA, \
            headers={'Connection':'Close'}).prepare()
        prepped.headers['Content-Length'] = -1000
        response = s.send(prepped, timeout=10.0)
        print response.status_code
        reasonable_codes = [400, 411, 413]
        self.pAssertEqual(True, response.status_code in reasonable_codes)
        self.testsuite.scores['test_invalidLENGTH'] = 1

    def test_browserTLS(self):
        print '----- Testing TLS Browser -----'
        if self.testsuite.scores['test_daemonization'] != 1:
            self.skipTest("server failed to start. skip this test")
        for test in self.testsuite.SSL_tests:
            try:
                response = requests.get(test % self.testsuite.tls_port,\
                    verify=SIGNER_CERT, timeout=1.0)
            except requests.exceptions.SSLError as e:
                raise Exception("Failed to connect via SSL!",e)
            contenthash = hashlib.sha256(response.content).hexdigest()
            self.pAssertEqual(200, response.status_code)
            self.pAssertEqual(contenthash, self.testsuite.SSL_tests[test][0])
        self.testsuite.scores['test_browserTLS'] = 1

    def test_cgi(self):
        print '----- Testing CGI -----'
        if self.testsuite.scores['test_daemonization'] != 1:
            self.skipTest("server failed to start. skip this test")
        response = requests.get('http://localhost:%d/cgi/'\
            % (self.testsuite.port), timeout=1.0)
        self.pAssertEqual(200, response.status_code)
        rm = [l for l in response.text.split('\n') if 'REQUEST_METHOD' in l][0]
        method = rm.split('<DD>')[1].strip()
        self.pAssertEqual('GET', method)
        self.testsuite.scores['test_cgi'] = 1



class project1cp3grader(grader):

    def __init__(self, checkpoint):
        super(project1cp3grader, self).__init__()
        self.process = None
        self.checkpoint = checkpoint
        self.tests = {
            'http://localhost:%d/index.html' :
            ('f5cacdcb48b7d85ff48da4653f8bf8a7c94fb8fb43407a8e82322302ab13becd', 802),
            'http://localhost:%d/images/liso_header.png' :
            ('abf1a740b8951ae46212eb0b61a20c403c92b45ed447fe1143264c637c2e0786', 17431),
            'http://localhost:%d/style.css' :
            ('575150c0258a3016223dd99bd46e203a820eef4f6f5486f7789eb7076e46736a', 301)
        }
        self.SSL_tests = {
            'https://localhost:%d/index.html' :
            ('f5cacdcb48b7d85ff48da4653f8bf8a7c94fb8fb43407a8e82322302ab13becd', 802),
            'https://localhost:%d/images/liso_header.png' :
            ('abf1a740b8951ae46212eb0b61a20c403c92b45ed447fe1143264c637c2e0786', 17431),
            'https://localhost:%d/style.css' :
            ('575150c0258a3016223dd99bd46e203a820eef4f6f5486f7789eb7076e46736a', 301)
        }

    def prepareTestSuite(self):
        self.suite.addTest(project1cp3tester('test_using_select', self))
        self.suite.addTest(project1cp3tester('start_server', self))
        self.suite.addTest(project1cp3tester('test_daemonization', self))
        self.suite.addTest(project1cp3tester('test_pipelining_keepalive', self))
        self.suite.addTest(project1cp3tester('test_invalidLENGTH', self))
        self.suite.addTest(project1cp3tester('test_browserTLS', self))
        self.suite.addTest(project1cp3tester('test_invalidPUT', self))
        self.suite.addTest(project1cp3tester('test_cgi', self))
        self.suite.addTest(project1cp3tester('test_kill', self))
        self.scores['use_select'] = 0
        self.scores['server_start'] = 0
        self.scores['test_daemonization'] = 0
        self.scores['test_pipelining_keepalive'] = 0
        self.scores['test_invalidLENGTH'] = 0
        self.scores['test_browserTLS'] = 0
        self.scores['test_invalidPUT'] = 0
        self.scores['test_cgi'] = 0

    def setUp(self):
        self.port = random.randint(1025, 9999)
        #self.port = 9999
        self.tls_port = random.randint(1025, 9999)
        self.tmp_dir = ""
        self.priv_key = os.path.join(self.tmp_dir, 'grader.key')
        self.cert = os.path.join(self.tmp_dir, 'grader.crt')
        self.www = os.path.join(self.tmp_dir, 'www/')
        self.cgi = os.path.join(self.tmp_dir, 'cgi/cgi_script.py')
        self.tmp_dir = "../"
        print '\nUsing ports: %d,%d' % (self.port, self.tls_port)


if __name__ == '__main__':
    p1cp2grader = project1cp3grader("checkpoint-3")
    p1cp2grader.prepareTestSuite()
    p1cp2grader.setUp()
    results = p1cp2grader.runTests()
    p1cp2grader.reportScores()
