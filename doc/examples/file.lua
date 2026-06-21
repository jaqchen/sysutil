#!/usr/bin/env lua

local M = require 'sysutil'
local C = require 'sysutil.syscon'

local f = '/tmp/sysutil-test'

assert(M.write(f, 'hello world\n') > 0, 'write: expected > 0')

-- open(path [, flags [, mode]])
local fd = M.open(f, C.O_RDWR + C.O_CREAT)
assert(fd > 2,                   'open: expected fd > 2')

assert(M.read(fd, 128) == 'hello world\n', 'read: content mismatch')

-- lseek(fd, offset, whence)
assert(M.lseek(fd, 0, M.SEEK_END) == 12, "lseek(SEEK_END): expected 12")

M.truncate(fd, 5)
M.lseek(fd, 0, M.SEEK_SET)
assert(M.read(fd, 32) == 'hello', 'truncate: verify failed')

assert(M.sync(fd) == 0,          'sync(fd): expected 0')

-- stat(path [, lstat])
local st = M.stat(f)
assert(st.isreg == true,         'stat: expected isreg')
assert(st.st_size == 5,          'stat: expected st_size 5')

assert(M.chmod(fd, tonumber('0644', 8)) == 0,   'chmod(fd): expected 0')

local f2 = f .. '-renamed'
M.rename(f, f2)
assert(M.open(f2) ~= nil,        'rename: new file should exist')

-- symlink(src, dst [, hardlink])
local ln = f2 .. '-link'
assert(M.symlink(f2, ln) == 0,   'symlink: expected 0')
assert(M.readlink(ln) == f2,     'readlink: expected target')

-- mkfifo(path [, mode])
assert(M.mkfifo(f) == 0,         'mkfifo: expected 0')
st = M.stat(f)
assert(st.isfifo == true,        'mkfifo: expected isfifo')

assert(type(M.mountpoint('/')) == 'boolean',
                                  "mountpoint('/'): expected boolean")

-- inotify(mask, timeout, path, ...)
local res, err = M.inotify(C.IN_CLOSE_WRITE, 10, f2)
-- no write within 10ms: expect ETIMEDOUT
assert(res == nil,				'inotify: expected nil')
assert(err == M.ETIMEDOUT,		'inotify: expected ETIMEDOUT')

-- lockfile(path [, msg [, timeout]])
local lk = f .. '.lock'
local lfd = M.lockfile(lk)
assert(lfd > 0,                  'lockfile: expected fd > 0')
M.close(lfd)

-- glob(pattern [, flags])
assert(#M.glob('/tmp/sysutil-test*') > 0, 'glob: expected matches')

-- close(fd, ...)
assert(M.close(fd) == 1,         'close: expected 1')

-- unlink(path, ...)
M.unlink(f2, ln, f, lk)
assert(M.open(f2) == nil,        'unlink: file should be gone')
