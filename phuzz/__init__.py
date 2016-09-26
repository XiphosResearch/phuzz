#!/usr/bin/env python
from __future__ import print_function
import subprocess
import time
import re
import os
import logging
import socket
import pickle
from hashlib import md5
from random import randint
from base64 import b32encode
from tempfile import mkstemp
from collections import namedtuple, defaultdict
import requests

LOG = logging.getLogger(__name__)

PHP_GLOBALS = ['_GET', '_POST', '_COOKIE', '_SERVER', '_REQUEST', '_FILES']

TRACELOG_RE = re.compile(r'^\s+([0-9\.]+)\s+([0-9]+)\s+(?P<msg>.+?)\s+' +
                         r'(?P<file>/[^:]+):(?P<line>[0-9]+)$', re.MULTILINE)
# Parse function calls in xdebug trace log
FUNCALL_RE = re.compile(r'^-> ((?P<cls>[^\-]+)->)?(?P<fnc>[^\s\(]+)' +
                        r'\((?P<args>.*?)\)$')
# C-style quoted and escaped string
CSTRING_RE = (r'(?P<quo>[\'"])' +
              r'(?P<val>(\\.|[^(?P=quo)])*)' +
              r'(?P=quo)')
# Separate agruments to functions, from xdebug trace log
CALLARGS_RE = re.compile(r'(?P<args>(^|\s*,\s*)(' + r'(?P<str>'
                         + CSTRING_RE + r'|[^,\)]+' + r')))', re.MULTILINE)
STRACE_RE = re.compile(
    r'^(\[[^\]]*\]\s+)?' + r'(?P<fun>[^\(]+)' + r'\((?P<args>.*?)\)' +
    r'\s*=\s*(?P<ret>[^\'" ]+)(\s+[^\'"]+)?$')

DTRUSS_RE = re.compile(
    r'[^:]+:\s*' + r'(?P<fun>[^\(]+)' + r'\((?P<args>.*?)\)' +
    r'\s*=\s*(?P<ret>[^\'" ]+)(\s+[^\'"]+)?$')


Loc = namedtuple('Loc', ['file', 'line'])
LogMessage = namedtuple('LogMessage', ['msg', 'loc'])
Var = namedtuple('Var', ['name', 'key', 'value', 'loc'])
Func = namedtuple('Func', ['fun', 'args', 'loc'])
PhuzzCase = namedtuple('PhuzzCase', ['url', 'root', 'state', 'traces'])


def which(program):
    try:
        ret = subprocess.check_output(['which', program])
    except subprocess.CalledProcessError:
        return None
    return ret


def unescape(data):
    if data[0] in ["'", '"']:
        return data[1:-1].decode('string_escape')
    return data


def unlink(*args):
    for arg in args:
        if arg and os.path.exists(arg):
            try:
                os.unlink(arg)
            except Exception:
                pass


def snapshot(*files, **kwa):
    ret = []
    for filename in files:
        data = None
        try:
            if os.path.exists(filename):
                with open(filename, "r+") as handle:
                    data = handle.read()
                    handle.truncate(0)
        except Exception:
            pass
        if kwa.get('remove'):
            unlink(filename)
        ret.append(data)
    return ret


def try_connect(addr):
    try:
        sock = socket.create_connection(addr, 1)
        sock.close()
        return True
    except Exception:
        return False


def wait_for_proc_death(proc):
    while True:
        if proc.poll() is not None:
            break
        LOG.debug('Waiting for process to stop: %r', proc.pid)
        time.sleep(0.5)


def parse_logs(regex, data):
    return [] if not data else [
        LogMessage(match.group('msg'),
                   Loc(match.group('file'), match.group('line')))
        for match in regex.finditer(data)]


def calls_scan_vars(entries):
    return set([
        Var(entry.fun[0], unescape(entry.args[0]), None, entry.loc)
        for entry in entries
        if len(entry.fun) == 2 and entry.fun[0] in PHP_GLOBALS])


class DoubleHasher(object):
    def __init__(self):
        self.hasher = md5()

    def update(self, val):
        """Prevents concatenation from resulting in identical hashes"""
        self.hasher.update(str(val))
        self.hasher.update(self.hasher.digest())

    def hexdigest(self):
        return self.hasher.hexdigest()


class SyscallTracer(object):
    def __init__(self, target):
        self.target = target
        self.proc = None
        self.logfile = mkstemp('strace')[1]
        self.logfh = None
        self.cmd = None
        self.regex = None
        self.sudo_kill = False
        self._setup()

    def _wait_for_logfile(self, escape=10):
        while escape > 0:
            escape -= 1
            if os.path.getsize(self.logfile) > 20:
                return True
            try:
                time.sleep(1)
            except KeyboardInterrupt:
                return False
            LOG.debug('Waiting for system call trace log...')
        return False

    def _setup(self):
        # TODO: implement dtrace, systemtap etc.
        LOG.debug('SyscallTracer logging to %s', self.logfile)
        if which('strace'):  # First try strace...
            self.cmd = ' '.join([
                'exec', 'strace', '-qyfy', '-s', '4096',
                '-p', str(self.target.pid), '2>', self.logfile
            ])
            self.regex = STRACE_RE
            yama_ptrace_scope = '/proc/sys/kernel/yama/ptrace_scope'
            if os.getuid() != 0 and os.path.exists(yama_ptrace_scope):
                with open(yama_ptrace_scope, 'r') as handle:
                    if handle.read() != "0\n":
                        print("On Linux, this may only work after you run:")
                        print("  echo 0 | sudo tee " + yama_ptrace_scope)
                        raise RuntimeError(yama_ptrace_scope + " must be 0")
        elif which('dtruss'):
            self.cmd = ' '.join([
                'exec', 'sudo', '-s', 'exec',  # Requires sudo, !elegant
                'dtruss', '-b', '32m', '-f', '-p', str(self.target.pid),
                '&>', self.logfile,
            ])
            self.sudo_kill = True
            self.regex = DTRUSS_RE
        else:
            LOG.warning('Unable to find a system call tracer!')

    def _parse_strace(self, data, ignore_files=None):
        ret = []
        if not data:
            return ret
        for entry in data.split("\n"):
            match = self.regex.match(entry)
            if match:
                mdat = match.groupdict()
                if mdat['fun'] == 'write_nocancel':
                    if mdat['args'][:4] in ['0x5,', '0x2,']:
                        # XXX: on OSX, explicitly ignore console & error log
                        continue
                ignored = [X in mdat['args'] for X in ignore_files]
                if not any(ignored):
                    ret.append(Func([mdat['fun']], mdat['args'], None))
        return ret

    def start(self):
        self.stop()
        self.logfh = open(self.logfile, "w")
        self.proc = subprocess.Popen(self.cmd, universal_newlines=True,
                                     shell=True, preexec_fn=os.setsid)
        if self.proc.poll() is not None:
            raise RuntimeError("Could not syscall trace: " + str(self.cmd))
        if not self._wait_for_logfile():
            raise RuntimeError("syscall trace log not filling!")
        LOG.info('SyscallTracer started, pid: %r', self.proc.pid)

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                if self.sudo_kill:
                    pgrp = os.getpgid(self.proc.pid)
                    subprocess.check_call([
                        'sudo', 'pkill', '-TERM', '-g', str(pgrp)
                    ])
            wait_for_proc_death(self.proc)
            LOG.debug('SyscallTracer stopped, pid: %r', self.proc.pid)
            self.proc = None
        if self.logfh:
            self.logfh.close()
            self.logfh = None

    def reset(self):
        snapshot(*(self.logfile,), remove=False)

    def snapshot(self, ignore_files):
        self._wait_for_logfile()
        data = snapshot(*(self.logfile,), remove=False)[0]
        return self._parse_strace(data, ignore_files)


class PHPHarness(object):
    def __init__(self, listen, root, preload=None, ini=None):
        self._check_php_modules()
        self.proc = None
        self.listen = listen
        self.root = root
        self.preload = preload
        self.strace = None
        self.xdebug_path = mkstemp('.xdebug')[1]
        self.logs = [self.xdebug_path + '.xt']
        if ini is None:
            ini = dict()
        if preload:
            ini["auto_prepend_file"] = preload
        self.ini = self._config(ini)

    def translate_path(self, path):
        if path == self.preload:
            return '<preload>'
        if self.root in path:
            return path.replace(self.root, '<webroot>')
        return path

    def _config(self, extra):
        ini = {
            'html_errors': 0,
            'ignore_repeated_errors': 1,
            'log_errors_max_len': 4096,
            'log_errors': 0,
            'display_errors': 0,
            'error_reporting': 32767,  # E_ALL
            'xdebug.auto_trace': 1,
            'xdebug.collect_params': 3,
            # 'xdebug.collect_assignments': 1,
            # 'xdebug.collect_return': 1,
            # 'xdebug.collect_vars': 1,
            'xdebug.trace_format': 0,
            'xdebug.trace_output_name': self.xdebug_path,
            'xdebug.trace_output_dir': '/',
        }
        ini.update(extra)
        return ini

    def _check_php_modules(self):
        mods_needed = ['Xdebug']
        mods = subprocess.check_output(["php", "-m"]).split("\n")
        for mod in mods_needed:
            if mod not in mods:
                raise RuntimeError("Error: php doesn't have the module:", mod)

    def start(self, args=None):
        if args is None:
            args = []
        cmd = ['php'] + ["-d %s=%s" % (K, V) for K, V in self.ini.items()]
        cmd += ['-S', ':'.join(self.listen), '-t', self.root] + args
        self.proc = subprocess.Popen(cmd)
        for _ in range(1, 5):
            if try_connect(self.listen):
                break
            if self.proc.poll() is not None:
                raise RuntimeError("Could not start PHP with: ", ' '.join(cmd))
            LOG.debug("Waiting for server...")
            time.sleep(0.5)
        self.strace = SyscallTracer(self.proc)
        self.strace.start()

    def stop(self):
        if self.proc:
            self.proc.terminate()
            wait_for_proc_death(self.proc)
            self.proc = None
        if self.strace:
            self.strace.stop()
            self.strace = None
        unlink(*self.logs)

    def trace_begin(self):
        snapshot(*self.logs)
        self.strace.reset()

    def trace_finish(self, ignore_files):
        logdata = snapshot(*self.logs)
        strace_out = self.strace.snapshot(ignore_files)
        logdata.append(strace_out)
        return logdata


class Trace(object):
    __slots__ = ('resp', 'xdebug', 'syslog')

    def __init__(self, resp, xdebug, syslog):
        self.resp = resp
        self.xdebug = xdebug
        self.syslog = syslog

    def calls(self):
        """Extract all function calls from Xdebug trace entries"""
        out = []
        for entry in self.xdebug:
            match = FUNCALL_RE.match(entry.msg)
            if match:
                args = []
                for arg in CALLARGS_RE.finditer(match.group('args')):
                    row = arg.groupdict()
                    val = row['str'] if 'str' in row else row['val']
                    args.append(val)
                data = match.groupdict()
                fun = filter(None, [data['cls'], data['fnc']])
                func = Func(fun, args, entry.loc)
                out.append(func)
        return out


class CaseManager(object):
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def _is_interesting(self, case):
        for _, trace in case.traces.items():
            for entry in trace:
                if entry[0]:
                    return True

    def _hash_traces(self, traces):
        hasher = DoubleHasher()
        for subsys, trace in traces.items():
            hasher.update(subsys)
            for varsused, entry in trace:
                # Arguments to the function are ignored as they change often
                hasher.update(entry.fun)
                if varsused:
                    for what, name in varsused:
                        hasher.update(what)
                        hasher.update(name)
                loc = entry.loc
                if loc:
                    hasher.update(loc.file)
                    hasher.update(loc.line)
        return hasher.hexdigest()

    def _display(self, case):
        overview = {}
        for subsys, call_list in case.traces.items():
            highlights = []
            loc = None
            for values, call in call_list:
                if not values:
                    continue
                args = call.args
                if not isinstance(args, list):
                    args = [args]
                if loc is None or (call.loc and loc.file != call.loc.file):
                    loc = call.loc
                    if loc:
                        highlights.append(loc.file)
                    highlights.append(' '.join(["\t", '->'.join(call.fun),
                                                "(", ', '.join(args), ")"]))
            if highlights:
                overview[subsys] = highlights
        if overview:
            for subsys, highlights in overview.items():
                print(subsys)
                print("\n".join(highlights))
            print()

    def ingest(self, case):
        if not self._is_interesting(case):
            return False
        self._display(case)
        if self.output_dir:
            digest = self._hash_traces(case.traces)
            filename = os.path.join(self.output_dir, digest + '.phuzz')
            if not os.path.exists(filename):
                with open(filename, 'wb') as handle:
                    pickle.dump(case, handle)


class Phuzzer(object):
    __slots__ = ('php', 'interwebs', 'manager')

    def __init__(self, php, manager):
        self.php = php
        self.manager = manager
        interwebs = requests.Session()
        interwebs.max_redirects = 0
        interwebs.max_retries = 0
        interwebs.danger_mode = True  # Yay danger!
        self.interwebs = interwebs

    def _ignored_files(self):
        return ['2</dev/pts'] + self.php.logs

    def _collect(self, resp):
        xdebug, strace = self.php.trace_finish(self._ignored_files())
        xdebug = filter(lambda L: L.loc.file != self.php.preload,
                        parse_logs(TRACELOG_RE, xdebug))
        return Trace(resp, xdebug, strace)

    def _request_for_state(self, url, state):
        params = state['_REQUEST']
        params.update(state['_GET'])
        needs_post = any(['_POST' in state, '_FILES' in state])
        method = state.get('METHOD', 'POST' if needs_post else 'GET')
        return self.interwebs.request(method, url, params=params,
                                      cookies=state['_COOKIE'],
                                      allow_redirects=False)

    def trace(self, url, state=None):
        if state is None:
            state = defaultdict(dict)
        LOG.debug('Retrieving %r', url)
        self.php.trace_begin()
        resp = self._request_for_state(url, state)
        if resp:
            return self._collect(resp)
        self.php.trace_finish(self._ignored_files())

    def _scan_calls(self, calls, state):
        return [(self._scan_call(call, state), call)
                for call in calls]

    def _scan_call(self, call, state):
        """Annotates calls with which values from input state were found"""
        if call.fun[0] in PHP_GLOBALS:
            return None  # Exclude these?
        found = []
        for topkey, val in state.items():
            for subkey, subval in val.items():
                args = call.args
                if not isinstance(args, list):
                    args = [args]
                for arg_val in args:
                    if subval in arg_val:
                        found.append((topkey, subkey))
        return found

    def _scan(self, url, state, phpcalls, syscalls):
        phpcalls = self._scan_calls(phpcalls, state)
        syscalls = self._scan_calls(syscalls, state)
        traces = dict(php=phpcalls, sys=syscalls)
        return PhuzzCase(url, self.php.root, state, traces)

    def run_file(self, filepath):
        webpath = filepath[len(self.php.root):]
        if webpath is None:
            raise RuntimeError("Path not under document root!")
        return self.run_path(webpath)

    def run_path(self, webpath):
        server = ':'.join([self.php.listen[0], str(self.php.listen[1])])
        if len(webpath) and webpath[0] != '/':
            webpath = '/' + webpath
        url = ''.join(['http://', server, webpath])
        return self.run(url)

    def run(self, url, state=None):
        if state is None:
            state = defaultdict(dict)
        new_states = True
        escape = 100  # Avoid infinite loops
        while new_states and escape > 0:
            escape -= 1
            new_states = False
            trace = self.trace(url, state)
            if not trace:
                break
            phpcalls = trace.calls()
            input_vars = calls_scan_vars(phpcalls)
            if len(input_vars):
                # TODO: permute through each of variables?
                newvars = set([(entry.name, entry.key)
                               for entry in input_vars
                               if entry.name not in state
                               or entry.key not in state[entry.name]])
                for key, val in newvars:
                    state[key][val] = b32encode(os.urandom(randint(1, 4) * 5))
                new_states = len(newvars) > 0
            result = self._scan(url, state, phpcalls, trace.syslog)
            if result:
                self.manager.ingest(result)
