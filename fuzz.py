#!/usr/bin/env python
from __future__ import print_function
import subprocess
import requests
import time
import re
import hashlib
from collections import namedtuple, defaultdict
from random import randint
import os

PHP_GLOBALS = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES']

RE_FILE_ON_LINE = '(\s+in\s+(?P<file>[^\s]+)\s+on\s+line\s+(?P<line>[0-9]+))'

ERRORLOG_RE = re.compile('^\[[^\]]+\] PHP (?P<msg>.*?)' +
                         RE_FILE_ON_LINE + '$', re.MULTILINE)

TRACELOG_RE = re.compile('^\s+([0-9\.]+)'+'\s+([0-9]+)'+'\s+(?P<msg>.+?)\s+' +
                         '(?P<file>/[^:]+)'+':(?P<line>[0-9]+)$', re.MULTILINE)

TRACEVAR_RE = re.compile('TRACE (GET|EXISTS) (?P<name>_[A-Z]+) (?P<key>.+?)' +
                         '('+RE_FILE_ON_LINE+'|\'\) .*)?$', re.MULTILINE)

FUNCALL_RE = re.compile('^-> ((?P<cls>[^\-]+)->)?(?P<fnc>[^\s\(]+)' +
                        '\((?P<args>.*?)\)$')

CALLARGS_RE = re.compile('(?P<args>(^|\s*,\s*)?(' +
                         '\'(?P<str>(\\.|[^\']+)*)\'' +
                         '|(?P<val>[^,\)]+)' +
                         '))')


Entry = namedtuple('Entry', ['msg', 'file', 'line'])
Var = namedtuple('Var', ['name', 'key', 'value', 'file', 'line'])
Funcall = namedtuple('Funcall', ['cls', 'fnc', 'args', 'file', 'line'])
Context = namedtuple('Context', ['path', 'preload', 'phplog', 'xdebug'])


def php_check():
    mods_needed = ['Xdebug']
    mods = subprocess.check_output(["php", "-m"]).split("\n")
    for mod in mods_needed:
        if mod not in mods:
            raise RuntimeError("Error: php doesn't have the module:", mod)


def run_php(name, ini=None, args=[], preload=None):
    """
    Forces correct xdebug options when running PHP
    """
    phplog = os.getcwd() + '/.phplog.' + name
    xdebug = os.getcwd() + '/.xdebug.' + name
    ini_extra = {
        'auto_prepend_file': preload,
        'html_errors': 0,
        'ignore_repeated_errors': 1,
        'log_errors_max_len': 4096,
        'log_errors': 1,
        'phplog': phplog,
        'display_errors': 0,
        'error_reporting': 32767,  # E_ALL
        'xdebug.auto_trace': 1,
        'xdebug.collect_assignments': 1,
        'xdebug.collect_params': 3,
        'xdebug.collect_return': 1,
        'xdebug.collect_vars': 1,
        'xdebug.trace_format': 0,
        'xdebug.trace_output_name': xdebug,
        'xdebug.trace_output_dir': '/',
    }
    if ini:
        ini_extra.update(ini)
    cmd = ['php']
    for K, V in ini_extra.items():
        cmd.append("-d %s=%s" % (K, V))
    if args:
        cmd += args
    proc = subprocess.Popen(cmd, bufsize=1, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    time.sleep(0.5)
    if proc.poll() is not None:
        raise RuntimeError("Could not start PHP with: ", ' '.join(cmd))
    # print(' '.join(cmd))
    # TODO: wait until port is listening or process dies...
    return proc, phplog, xdebug + '.xt'


def snap_file(filename):
    """Snapshot of file, unlink after"""
    data = None
    try:
        if os.path.exists(filename):
            with open(filename, "r") as fh:
                data = fh.read()
            os.unlink(filename)
    except:
        pass
    return data


def parse_re(regex, data):
    return [] if not data else [
        Entry(*[match.group(K) for K in ['msg', 'file', 'line']])
        for match in regex.finditer(data)]


def calls_scan_vars(entries):
    return set([
        Var(entry.cls, entry.args[0], None, entry.file, entry.line)
        for entry in entries
        if entry.cls in PHP_GLOBALS])


def hash_trace(entries):
    md5 = hashlib.md5()
    for entry in entries:
        md5.update(entry.file)
        md5.update(md5.digest())
        md5.update(entry.line)
        md5.update(md5.digest())
    return md5.hexdigest()


class Tag(object):
    __slots__ = ('name', 'next')

    def __init__(self, name, next=None):
        self.name = name
        self.next = next

    def tags(self):
        ret = [self.name]
        entry = self.next
        while entry:
            ret.append(entry.name)
            entry = entry.next
        return ret


class Trace(object):
    def __init__(self, analyzer, resp, newvars, phplog, xdebug):
        self.analyzer = analyzer
        self.newvars = newvars
        self.resp = resp
        self.phplog = phplog
        self.xdebug = xdebug
        self.tags = None
        # varnames = set([(var.name, var.key) for var in newvars])


def find_function_calls(entries):
    """Extract all function calls from Xdebug trace entries"""
    out = []
    for entry in entries:
        match = FUNCALL_RE.match(entry.msg)
        if match:
            args = []
            for arg in CALLARGS_RE.finditer(match.group('args')):
                row = arg.groupdict()
                if row['val']:
                    args.append(row['val'])
                else:
                    args.append(row['str'])
            data = match.groupdict()
            out.append(Funcall(data['cls'], data['fnc'], args, entry.file, entry.line))
    return out


class Analyzer(object):
    def __init__(self, ctx, interwebs, url):
        self.ctx = ctx
        self.interwebs = interwebs
        self.url = url
        self.traces = defaultdict(list)

    def _collect(self, resp):
        phplog, xdebug = snap_file(self.ctx.phplog), snap_file(self.ctx.xdebug)
        phplog = filter(lambda L: L.file != self.ctx.preload,
                        parse_re(ERRORLOG_RE, phplog))
        xdebug = filter(lambda L: L.file != self.ctx.preload,
                        parse_re(TRACELOG_RE, xdebug))
        calls = find_function_calls(xdebug)
        newvars = calls_scan_vars(calls)

        trace_hash = hash_trace(phplog), hash_trace(xdebug)
        trace = Trace(self, resp, newvars, phplog, xdebug)
        self.traces[trace_hash].append(trace)        
        return trace

    def trace(self, params=None):
        # TODO: handle POST, cookies, files etc.
        resp = self.interwebs.get(self.url, params=params,
                                  allow_redirects=False)
        return self._collect(resp)

    def run(self):
        new_states = True
        while new_states:
            trace = self.trace()
            if len(trace.newvars):
                varnames = [(entry.name, entry.key)
                            for entry in trace.newvars]
                print(varnames)
                new_states = True
            else:
                new_states = False
            break


if __name__ == "__main__":
    php_check()
    port = randint(8192, 50000)
    root = os.getcwd()
    preload = os.getcwd() + '/_preload.php'
    listen = '127.0.0.1:%d' % (port,)
    proc, phplog, xdebug = run_php(
        'www',
        preload=preload,
        args=[
            '-t', root,
            '-S', listen
        ])
    interwebs = requests.Session()
    interwebs.max_redirects = 0
    interwebs.max_retries = 0
    interwebs.danger_mode = True
    for path, dirs, files in os.walk(root):
        php_files = filter(lambda X: os.path.splitext(X)[1] == '.php', files)
        ctx = Context(path[len(root):], preload, phplog, xdebug)
        for filename in php_files:
            url = "http://%s%s/%s" % (listen, ctx.path, filename)
            worker = Analyzer(ctx, interwebs, url)
            worker.run()
    proc.terminate()
