#!/usr/bin/env python
from __future__ import print_function
import subprocess
import requests
import time
import re
import os
import sys
import logging
import hashlib
import socket
from tempfile import mkstemp
from collections import namedtuple, defaultdict
from random import randint

LOG = logging.getLogger(__name__)

PHP_GLOBALS = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES']

RE_FILE_ON_LINE = '(\s+in\s+(?P<file>[^\s]+)\s+on\s+line\s+(?P<line>[0-9]+))'

ERRORLOG_RE = re.compile('^\[[^\]]+\] PHP (?P<msg>.*?)' +
                         RE_FILE_ON_LINE + '$', re.MULTILINE)

TRACELOG_RE = re.compile('^\s+([0-9\.]+)'+'\s+([0-9]+)'+'\s+(?P<msg>.+?)\s+' +
                         '(?P<file>/[^:]+)'+':(?P<line>[0-9]+)$', re.MULTILINE)
# Catch caustom warnings made by _PHPAUDFUZZ in _preload.php
TRACEVAR_RE = re.compile('TRACE (GET|EXISTS) (?P<name>_[A-Z]+) (?P<key>.+?)' +
                         '('+RE_FILE_ON_LINE+'|\'\) .*)?$', re.MULTILINE)
# Parse function calls in xdebug trace log
FUNCALL_RE = re.compile('^-> ((?P<cls>[^\-]+)->)?(?P<fnc>[^\s\(]+)' +
                        '\((?P<args>.*?)\)$')
# Separate agruments to functions, from xdebug trace log
CALLARGS_RE = re.compile('(?P<args>(^|\s*,\s*)?(' +
                         '\'(?P<str>(\\.|[^\']+)*)\'' +
                         '|(?P<val>[^,\)]+)' +
                         '))')


FileLocation = namedtuple('FileLocation', ['file', 'line'])
LogMessage = namedtuple('LogMessage', ['msg', 'loc'])
Var = namedtuple('Var', ['name', 'key', 'value', 'loc'])
Funcall = namedtuple('Funcall', ['fun', 'args', 'loc'])


def unlink(*args):
    for arg in args:
        if arg and os.path.exists(arg):
            try:
                os.unlink(arg)
            except:
                pass


def snapshot(*files):
    ret = []
    for file in files:
        data = None
        try:
            if os.path.exists(file):
                with open(file, "r") as fh:
                    data = fh.read()
                    fh.truncate(0)
        except:
            pass
        unlink(file)
        ret.append(data)
    return ret


def parse_logs(regex, data):
    return [] if not data else [
        LogMessage(match.group('msg'),
                   FileLocation(match.group('file'), match.group('line')))
        for match in regex.finditer(data)]


def calls_scan_vars(entries):
    return set([
        Var(entry.fun[0], entry.args[0], None, entry.loc)
        for entry in entries
        if len(entry.fun) == 2 and entry.fun[0] in PHP_GLOBALS])


def hash_trace(entries):
    md5 = hashlib.md5()
    for entry in entries:
        md5.update(str(entry.loc))
        md5.update(md5.digest())
    return md5.hexdigest()


class PHPHarness(object):
    def __init__(self, listen, root, preload=None, ini={}):
        self._check()
        self.proc = None
        self.listen = listen
        self.root = root
        self.preload = preload
        self.xdebug_path = mkstemp('.xdebug')[1]
        if preload:
            ini["auto_prepend_file"] = preload
        self.ini = self._config(ini)

    def _config(self, extra):
        ini = {
            'html_errors': 0,
            'ignore_repeated_errors': 1,
            'log_errors_max_len': 4096,
            'log_errors': 0,
            'display_errors': 0,
            'error_reporting': 32767,  # E_ALL
            'xdebug.auto_trace': 1,
            'xdebug.collect_assignments': 1,
            'xdebug.collect_params': 3,
            'xdebug.collect_return': 1,
            'xdebug.collect_vars': 1,
            'xdebug.trace_format': 0,
            'xdebug.trace_output_name': self.xdebug_path,
            'xdebug.trace_output_dir': '/',
        }
        ini.update(extra)
        return ini

    def _check(self):
        mods_needed = ['Xdebug']
        mods = subprocess.check_output(["php", "-m"]).split("\n")
        for mod in mods_needed:
            if mod not in mods:
                raise RuntimeError("Error: php doesn't have the module:", mod)

    def _connect(self):
        try:
            sock = socket.create_connection(self.listen, 1)
            sock.close()
            return True
        except:
            return False

    def start(self, args=[]):
        cmd = ['php'] + ["-d %s=%s" % (K, V) for K, V in self.ini.items()]
        cmd += ['-S', ':'.join(self.listen), '-t', self.root] + args
        self.proc = subprocess.Popen(cmd)
        for N in range(1, 3):
            if self._connect():
                LOG.debug("Waiting for server...")
            if self.proc.poll() is not None:
                raise RuntimeError("Could not start PHP with: ", ' '.join(cmd))
            time.sleep(0.5)

    def stop(self):
        if self.proc:
            self.proc.terminate()
            unlink(self.xdebug_path + '.xt')


class Trace(object):
    def __init__(self, analyzer, resp, xdebug):
        self.analyzer = analyzer
        self.resp = resp
        self.xdebug = xdebug
        self.tags = None
        # varnames = set([(var.name, var.key) for var in newvars])

    def calls(self):
        """Extract all function calls from Xdebug trace entries"""
        out = []
        for entry in self.xdebug:
            match = FUNCALL_RE.match(entry.msg)
            if match:
                args = []
                for arg in CALLARGS_RE.finditer(match.group('args')):
                    row = arg.groupdict()
                    if row['val']:
                        args.append(row['val'])  # verbatim
                    else:
                        try:
                            data = row['str'].decode('string_escape')
                        except:
                            data = row['str']
                        args.append(data)
                data = match.groupdict()
                func = Funcall(filter(None, [data['cls'], data['fnc']]), args, entry.loc)
                out.append(func)
        return out


class Analyzer(object):
    def __init__(self, php):
        self.php = php
        self.traces = defaultdict(list)
        interwebs = requests.Session()
        interwebs.max_redirects = 0
        interwebs.max_retries = 0
        interwebs.danger_mode = True
        self.interwebs = interwebs

    def _collect(self, resp):
        xdebug = snapshot(self.php.xdebug_path + '.xt')[0]
        xdebug = filter(lambda L: L.loc.file != self.php.preload,
                        parse_logs(TRACELOG_RE, xdebug))
        trace_hash = hash_trace(xdebug)
        trace = Trace(self, resp, xdebug)

        self.traces[trace_hash].append(trace)
        return trace

    def trace(self, url, params=None):
        # TODO: handle POST, cookies, files etc.
        LOG.debug('Retrieving %r', url)
        resp = self.interwebs.get(url, params=params, allow_redirects=False)
        return self._collect(resp)

    def run_file(self, filepath):
        webpath = filepath[len(self.php.root):]
        url = "http://%s:%s%s" % (self.php.listen[0], str(self.php.listen[1]), webpath)
        self.run(url)

    def run(self, url):
        new_states = True
        while new_states:
            trace = self.trace(url)
            calls = trace.calls()
            newvars = calls_scan_vars(calls)
            print('Newvars', newvars)
            print('Calls', calls)
            print()
            if len(newvars):
                varnames = [(entry.name, entry.key)
                            for entry in newvars]
                new_states = True
            else:
                new_states = False
            break


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    port = randint(8192, 50000)
    root = os.getcwd()
    self_file = os.path.abspath(sys.modules['__main__'].__file__)
    preload = os.path.join(os.path.dirname(self_file), '_preload.php')

    server = PHPHarness(('127.0.0.1', str(port)), root, preload)
    server.start()
    worker = Analyzer(server)

    try:
        for path, dirs, files in os.walk(root):
            php_files = filter(lambda X: os.path.splitext(X)[1] == '.php', files)
            for filename in php_files:
                # url = "http://%s%s/%s" % (listen, ctx.path, filename)
                worker.run_file(os.path.join(path, filename))
    except:
        LOG.exception("FAIL...")

    server.stop()
