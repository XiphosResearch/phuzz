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
from random import randint
from base64 import b32encode
from tempfile import mkstemp
from collections import namedtuple, defaultdict

LOG = logging.getLogger(__name__)

PHP_GLOBALS = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES']

TRACELOG_RE = re.compile('^\s+([0-9\.]+)'+'\s+([0-9]+)'+'\s+(?P<msg>.+?)\s+' +
                         '(?P<file>/[^:]+)'+':(?P<line>[0-9]+)$', re.MULTILINE)
# Parse function calls in xdebug trace log
FUNCALL_RE = re.compile('^-> ((?P<cls>[^\-]+)->)?(?P<fnc>[^\s\(]+)' +
                        '\((?P<args>.*?)\)$')
# Separate agruments to functions, from xdebug trace log
CALLARGS_RE = re.compile('(?P<args>(^|\s*,\s*)?(' +
                         '\'(?P<str>(\\.|[^\']+)*)\'' +
                         '|(?P<val>[^,\)]+)' +
                         '))')


Loc = namedtuple('Loc', ['file', 'line'])
LogMessage = namedtuple('LogMessage', ['msg', 'loc'])
Var = namedtuple('Var', ['name', 'key', 'value', 'loc'])
Func = namedtuple('Func', ['fun', 'args', 'loc'])


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


def try_connect(listen):
    try:
        sock = socket.create_connection(listen, 1)
        sock.close()
        return True
    except:
        return False


def parse_logs(regex, data):
    return [] if not data else [
        LogMessage(match.group('msg'),
                   Loc(match.group('file'), match.group('line')))
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
        self.builtins = self._builtins()
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

    def _builtins(self):
        allfuncs_php = """
<?php
echo implode("\n", get_declared_classes())."\n";
foreach( get_loaded_extensions() AS $extn ) {
    $funcs = get_extension_funcs($extn);
    if( ! $funcs ) continue;
    foreach( get_extension_funcs($extn) AS $fun ) {
        if( $fun ) {
            echo "$fun\n";
        }
    }
}
"""
        proc = subprocess.Popen(['php', '/dev/stdin'], bufsize=1,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout = proc.communicate(input=allfuncs_php)[0]
        return stdout.split()

    def _check(self):
        mods_needed = ['Xdebug']
        mods = subprocess.check_output(["php", "-m"]).split("\n")
        for mod in mods_needed:
            if mod not in mods:
                raise RuntimeError("Error: php doesn't have the module:", mod)

    def start(self, args=[]):
        cmd = ['php'] + ["-d %s=%s" % (K, V) for K, V in self.ini.items()]
        cmd += ['-S', ':'.join(self.listen), '-t', self.root] + args
        self.proc = subprocess.Popen(cmd)
        for N in range(1, 3):
            if try_connect(self.listen):
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
                fun = filter(None, [data['cls'], data['fnc']])
                func = Func(fun, args, entry.loc)
                out.append(func)
        return out


class Analyzer(object):
    def __init__(self, php):
        self.php = php
        self.traces = defaultdict(list)
        interwebs = requests.Session()
        interwebs.max_redirects = 0
        interwebs.max_retries = 0
        interwebs.danger_mode = True  # Yay danger!
        self.interwebs = interwebs

    def _collect(self, resp):
        xdebug = snapshot(self.php.xdebug_path + '.xt')[0]
        xdebug = filter(lambda L: L.loc.file != self.php.preload,
                        parse_logs(TRACELOG_RE, xdebug))
        trace_hash = hash_trace(xdebug)
        trace = Trace(self, resp, xdebug)

        self.traces[trace_hash].append(trace)
        return trace

    def trace(self, url, state=None):
        # TODO: handle POST, cookies, files etc.
        if state is None:
            state = defaultdict(dict)
        if '_POST' not in state and '_FILES' not in state:
            LOG.debug('Retrieving %r', url)
            resp = self.interwebs.get(url, params=state['_GET'],
                                      allow_redirects=False)
        else:
            resp = None
            print('Requires POST, skipping!')
        if resp:
            return self._collect(resp)

    def _scan(self, state, trace, calls):
        loc = None
        for call in calls:
            if loc is None or loc.file != call.loc.file:
                loc = call.loc
                print(loc.file, ":")
            print("   ", call.fun, "(", call.args, ")")
        print()

    def run_file(self, filepath):
        webpath = filepath[len(self.php.root):]
        server = ':'.join([self.php.listen[0], str(self.php.listen[1])])
        url = "http://%s%s" % (server, webpath)
        self.run(url)

    def run(self, url, state=None):
        if state is None:
            state = defaultdict(dict)
        new_states = True
        while new_states:
            new_states = False
            trace = self.trace(url, state)
            if not trace:
                continue
            calls = trace.calls()
            input_vars = calls_scan_vars(calls)
            if len(input_vars):
                newvars = set([(entry.name, entry.key)
                               for entry in input_vars
                               if entry.name not in state
                               or entry.key not in state[entry.name]])
                for K, V in newvars:
                    state[K][V] = b32encode(os.urandom(randint(1, 4) * 5))
                new_states = len(newvars) > 0
            self._scan(state, trace, calls)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    port = randint(8192, 50000)
    root = os.getcwd() + '/tests'
    self_file = os.path.abspath(sys.modules['__main__'].__file__)
    preload = os.path.join(os.path.dirname(self_file), '_preload.php')

    server = PHPHarness(('127.0.0.1', str(port)), root, preload)
    server.start()
    worker = Analyzer(server)

    try:
        for path, dirs, files in os.walk(root):
            php_files = filter(lambda X: os.path.splitext(X)[1] == '.php',
                               files)
            for filename in php_files:
                worker.run_file(os.path.join(path, filename))
    except:
        LOG.exception("FAIL...")

    server.stop()
