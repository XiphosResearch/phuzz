#!/usr/bin/env python
from __future__ import print_function
import sys
import subprocess
import requests
import time
import re
import hashlib
from collections import namedtuple
from random import randint
import os


RE_IN_FILE_ON_LINE = '(\s+in\s+(?P<file>[^\s]+)\s+on\s+line\s+(?P<line>[0-9]+))'

ERRORLOG_RE = re.compile('^\[[^\]]+\] PHP (?P<msg>.*?)'+RE_IN_FILE_ON_LINE+'$', re.MULTILINE)
TRACELOG_RE = re.compile('^\s+([0-9\.]+)'+'\s+([0-9]+)'+'\s+(?P<msg>.+?)'+'\s+(?P<file>/[^:]+)'+':(?P<line>[0-9]+)$', re.MULTILINE)

TRACEVAR_RE = re.compile('TRACE (GET|EXISTS) (?P<name>_[A-Z]+) (?P<key>.+?)('+RE_IN_FILE_ON_LINE+'|\'\) .*)?$', re.MULTILINE)


Trace = namedtuple('Trace', ['ctx', 'data', 'phplog', 'xdebug'])
Entry = namedtuple('Entry', ['msg', 'file', 'line'])
Var = namedtuple('Var', ['name', 'key', 'value', 'file', 'line'])
Context = namedtuple('Context', ['url', 'root', 'preload', 'error_log', 'trace_log'])


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
	error_log = os.getcwd() + '/.phplog.' + name
	trace_log = os.getcwd() + '/.xtrace.' + name	
	ini_extra = {
		'auto_prepend_file': preload,
		'html_errors': 0,
		'ignore_repeated_errors': 1,
		'log_errors_max_len': 4096,
		'log_errors': 1,
		'error_log': error_log,
		'display_errors': 0,
		'error_reporting': 32767,  # E_ALL
		'xdebug.auto_trace': 1,
		'xdebug.collect_assignments': 1,
		'xdebug.collect_params': 3,
		'xdebug.collect_return': 1,
		'xdebug.collect_vars': 1,
		'xdebug.trace_format': 0,
		'xdebug.trace_output_name': trace_log,
		'xdebug.trace_output_dir': '/',
	}
	if ini:
		ini_extra.update(ini)
	cmd = ['php']
	for K, V in ini_extra.items():
		cmd.append("-d %s=%s" % (K, V))
	if args:
		cmd += args
	proc = subprocess.Popen(cmd, bufsize=1, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	time.sleep(0.5)
	if proc.poll() is not None:
		raise RuntimeError("Could not start PHP with: ", ' '.join(cmd))
	# print(' '.join(cmd))
	return proc, error_log, trace_log + '.xt'


def snap_file(filename):
	"""Snapshot of file, unlink after"""
	try:
		if os.path.exists(filename):
			with open(filename, "r") as fh:
				data = fh.read()
			os.unlink(filename)
			return data
	except:
		return None


def parse_re(regex, data):
	if data:
		return [
			Entry(*[G.group(K) for K in ['msg', 'file', 'line']])
			for G in regex.finditer(data)]
	return []


def scan_new_vars(phplog):
	if phplog:
		return set(filter(None,
			map(lambda M:
					Var(*[M.groupdict().get(K)
						  for K in ['name', 'key', 'value', 'file', 'line']]),
				TRACEVAR_RE.finditer(phplog))))
	return []


def hash_trace(entries):
	md5 = hashlib.md5()
	for entry in entries:
		md5.update(entry.file)
		md5.update(md5.digest())
		md5.update(entry.line)
		md5.update(md5.digest())
	return md5.hexdigest()


def analyze(interwebs, trace, state=None):
	"""Snapshot log files, and analyze them"""
	if state is None:
		state = []
	newvars = scan_new_vars(trace.phplog)
	varnames = []
	if newvars:
		varnames = set([(var.name, var.key) for var in newvars])
	phplog = filter(lambda L: L.file != trace.ctx.preload,
					parse_re(ERRORLOG_RE, trace.phplog))
	xdebug = filter(lambda L: L.file != trace.ctx.preload,
					parse_re(TRACELOG_RE, trace.xdebug))
	phplog_hash = hash_trace(phplog)
	xdebug_hash = hash_trace(xdebug)
	# TODO: construct a list of new requests
	# TODO: find which functions we control input to
	# TODO: output new variables to test
	print('Newvars', varnames, newvars)
	print('Errors', phplog_hash, phplog)
	print('Trace', xdebug_hash, xdebug)


def run_trace(interwebs, ctx):
	resp = interwebs.get(ctx.url, allow_redirects=False)
	errors, trace = snap_file(ctx.error_log), snap_file(ctx.trace_log)
	trace = Trace(ctx, resp.text, errors, trace)
	analyze(interwebs, trace)


if __name__ == "__main__":
	php_check()
	port = randint(8192, 50000)
	root = os.getcwd()
	preload = os.getcwd() + '/_preload.php'
	listen = '127.0.0.1:%d' % (port,)
	proc, error_log, trace_log = run_php(
		'www', preload=preload,
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
		webpath = path[len(root):]
		for filename in php_files:
			url = "http://%s%s/%s" % (listen, webpath, filename)
			ctx = Context(url, webpath, preload, error_log, trace_log)
			run_trace(interwebs, ctx)
	proc.terminate()
