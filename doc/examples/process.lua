#!/usr/bin/env lua

local M = require 'sysutil'
local C = require 'sysutil.syscon'

local pid = M.getpid()
assert(type(pid) == 'number',	'getpid: expected number')
assert(pid > 0,					'getpid: expected positive')
assert(pid < 2^22,				'getpid: PID out of range')
assert(M.getpid() == pid,		'getpid: twice calls should be equal')

local ppid = M.getppid()
assert(type(ppid) == "number", 'getppid: expected number')
assert(ppid > 0,               'getppid: expected positive')
assert(ppid ~= pid,            'getppid: should differ from getpid')

local tid, phd = M.getid()
-- tid: gettid()
-- pthread handle: pthread_self()
assert(type(tid) == 'number',	'getid: tid expected number')
assert(type(phd) == 'number',	'getid: pthread handle expected number')
assert(tid > 0,		'getid: tid expected positive')
assert(phd > 0,		'getid: pthread handle expected positive')
assert(tid == pid,	'getid: tid should equal getpid in main thread')

local rc, out = M.call(M.OPT_OUTPUT + M.OPT_RSTRIP, 'echo', '-n', 'hello')
assert(rc == 0,                  'call(echo): expected 0')
assert(out == 'hello',           'call(echo): output mismatch')

local cpid = M.call(M.OPT_NOWAIT + M.OPT_NULLIO, 'true')
assert(cpid > 0,                 'call(NOWAIT): expected pid > 0')

-- waitpid(pid [, nohang])
-- RETURN
--  alive: true/false/nil
--  exit value
--  rpid == cpid
local alive, est, rpid = M.waitpid(cpid)
assert(alive == false,           'waitpid: child should have exited')
assert(rpid == cpid,             'waitpid: pid mismatch')

-- parse the cause of est returned by waitpid
local ok, status = M.exitval(est)
assert(ok == true,               'exitval: expected normal exit')
assert(status == 0,              "exitval: expected status 0")

-- kill(pid [, sig])
assert(M.kill(pid, 0) == 0,      'kill(pid, 0): expected 0')

-- killpg(pgrp [, sig])
assert(M.killpg(pid, 0) == 0,    'killpg(pid, 0): expected 0')

-- killid(tid [, sig]): pthread_kill
assert(M.killid(phd, 0) == 0,    'killid(phd, 0): expected 0')

-- signal(signo, handler)
assert(M.signal(1, true) == 0,   'signal(SIGHUP, IGN): expected 0')
assert(M.signal(1, false) == 0,  'signal(SIGHUP, DFL): expected 0')

-- setname(name [, pthread])
-- pthread: false -> prctl(PR_SET_NAME) ; true: pthread_setname_np()
assert(M.setname('sysutil-test') == 0, 'setname: expected 0')

-- zipstdio([dev]): redirect stdin/stdout/stderr to [dev]
-- dev: default to /dev/null
assert(M.zipstdio() == 0,        'zipstdio: expected 0')

-- getrlimit(what)
local cur, max = M.getrlimit(C.RLIMIT_NOFILE)
assert(type(cur) == 'number',    'getrlimit: cur expected number')
assert(cur > 0,                  'getrlimit: cur should be > 0')

-- setrlimit(what, cur [, max])
assert(M.setrlimit(C.RLIMIT_NOFILE, cur, max) == 0, 'setrlimit: expected 0')

