#!/usr/bin/env lua

local M = require 'sysutil'

-- get current work directory
local cwd = M.getcwd()
assert(type(cwd) == 'string',    "getcwd: expected string")
assert(#cwd > 0,                 "getcwd: expected non-empty")

local r = M.chdir('/tmp')
assert(r == 0,                   "chdir('/tmp'): expected 0")
assert(M.getcwd() == '/tmp',     "chdir('/tmp'): verify failed")
M.chdir(cwd)

-- mkdir(path [, mode [, parents]])
local d = '/tmp/sysutil-test-dir'
local r2 = M.mkdir(d)
assert(r2 == 0,                  'mkdir: expected 0')

local nested = d .. '/parent/leaf'
assert(M.mkdir(nested, tonumber('0700', 8), true) == 0,
	'mkdir parents: expected 0')
assert(M.mkdir(nested, nil, true) == 0,
	'mkdir parents: existing directory succeeds')
assert(M.rmdir(nested, d .. '/parent') == 2,
	'rmdir: expected two nested directories')

-- rmdir(path [, path1 [, path2 [, ...]]])
local n, err = M.rmdir(d)
assert(n == 1,                   'rmdir: expected 1')
assert(err == 0,                 'rmdir: expected err 0')
