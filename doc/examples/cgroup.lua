#!/usr/bin/env lua

local M = require 'sysutil'
local C = require 'sysutil.cgroup'

local exitcode = M.call(M.OPT_NULLIO, 'which', 'stress')
assert(exitcode == 0, 'cgroup: command stress not found')

local cgrp, err = C.create('sysutil-cgroup', '+cpu')
assert(cgrp, M.strerror(err))
assert(C.set(cgrp, 'cpu.max', '10000 100000'))
assert(C.get(cgrp, 'cpu.max') == '10000 100000')

-- stress will fork, in embeded device with weak cpu, attach maybe execute after children has forked
-- so attach main lua progress at first, detach it after stress test over
local mpid = M.getpid()
local raw, err = C.attach(cgrp, mpid)
assert(type(raw) == 'string', M.strerror(raw))
assert(string.find(M.read('/proc/self/cgroup'), '0::/sysutil-cgroup', 1, true),
   'cgroup_attach: failed attach')

local pid = M.call(M.OPT_NULLIO + M.OPT_NOWAIT, 'stress', '--cpu', '1')

local ok, err = C.detach(cgrp, mpid, raw)
assert(ok, M.strerror(err))
assert(M.read('/proc/self/cgroup') == raw, 'cgroup_detach: failed detach')
M.mdelay(500) -- jump over boot time

local exitcode, output = M.call(M.OPT_OUTPUT + M.OPT_RSTRIP,
   '/bin/sh', '-c', "ps -C stress -o %cpu | tail -1 | awk '{print $1}'")
assert(exitcode == 0, 'cgroup: failed to count cpu usage')
assert(tonumber(output) < 11, 'cgroup: expect ~10% limit of cpu')

M.kill(pid, 9)
M.waitpid(pid)

-- stress workers may still linger in the cgroup
local procs = C.get(cgrp, 'cgroup.procs')
if procs and #procs > 0 then
   for p in procs:gmatch('%S+') do
      M.kill(tonumber(p) or 0, 9)
   end
   M.mdelay(114)
end

local ok, err = C.destroy(cgrp)
assert(ok, M.strerror(err))
