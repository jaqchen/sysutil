#!/usr/bin/env lua

local M = require 'sysutil'
local C = require 'sysutil.syscon'

-- TCP
local srv = M.socket(C.AF_INET, C.SOCK_STREAM, C.IPPROTO_TCP)
assert(srv > 0, 'socket(server): expected fd > 0')
assert(M.bind(srv, C.AF_INET, '127.0.0.1', 0) == 0, 'bind: expected 0')

local _, port = M.getsockname(srv)
assert(port > 0,				'getsockname: expected port > 0')
assert(port < 65536,			'getsockname: expected port < 65536')

-- listen(fd [, backlog])
assert(M.listen(srv, 1) == 0,   'listen: expected 0')

local cli = M.socket(C.AF_INET, C.SOCK_STREAM, C.IPPROTO_TCP)
assert(cli > 0,                  'socket(client): expected fd > 0')
assert(M.connect(cli, C.AF_INET, '127.0.0.1', port) == 0,
                                  'connect: expected 0')
local newfd, addr = M.accept(srv)
assert(newfd > 0,               'accept: expected fd > 0')
assert(addr == '127.0.0.1',     'accept: expected 127.0.0.1')

local paddr = M.getpeername(newfd)
assert(paddr == '127.0.0.1',    'getpeername: expected 127.0.0.1')

-- sendto(fd, data, flags [, addr, port])
assert(M.sendto(cli, 'ping', 0) > 0,   'client sendto: expected > 0')
assert(M.read(newfd, 4) == 'ping',     'server read: expected "ping"')
assert(M.sendto(newfd, 'pong', 0) > 0, 'server sendto: expected > 0')
assert(M.read(cli, 4) == 'pong',       'client read: expected "pong"')
M.close(srv, newfd, cli)


-- UDP
local udp = M.socket(C.AF_INET, C.SOCK_DGRAM, C.IPPROTO_UDP)
assert(udp > 0, 'socket(UDP): expected fd > 0')
assert(M.bind(udp, C.AF_INET, '127.0.0.1', 0) == 0, 'bind(udp): expected 0')

-- bindto(fd, ifname)
assert(M.bindto(udp, 'lo') == 0, 'bindto(lo): expected 0')

M.nonblock(udp, true)
-- connect(fd, family, addr, port [, timeout])
local r, err = M.connect(udp, C.AF_INET, '127.0.0.1', 1, 200)
assert(r == 0 or err == M.ECONNREFUSED, 'connect: expected 0 or ECONNREFUSED')

assert(M.sendto(udp, 'test', 0) ~= nil, 'sendto: expected non-nil')
-- recvfrom(fd, len, flags)
local data = M.recvfrom(udp, 256, C.MSG_DONTWAIT)
assert(data == nil or type(data) == 'string', 'recvfrom: expected nil or string')

-- tcpcheck(host, port [, timeout])
assert(type(M.tcpcheck('127.0.0.1', 1, 200)) == 'number', 'tcpcheck: expected number')
assert(M.checkip('127.0.0.1') == true,   'checkip(v4): expected true')
assert(M.checkmask('255.255.255.0') == 24, 'checkmask: expected 24')

-- poll(fd_table, timeout)
local _, rerr = M.poll({[udp] = C.POLLIN}, 10)
assert(rerr == M.ETIMEDOUT,      'poll: expected ETIMEDOUT')

-- sockopt(fd, is_get, level, optname, optval)
assert(M.sockopt(udp, false, C.SOL_SOCKET, C.SO_REUSEADDR, 1) == 0,
                                  'sockopt(set): expected 0')
-- socktime(fd, is_recv, seconds)
assert(M.socktime(udp,  true, 5) == 0, 'socktime(recv): expected 0')
assert(M.socktime(udp, false, 5) == 0, 'socktime(send): expected 0')

assert(M.nonblock(udp,  true) == 0,  'nonblock(on): expected 0')
assert(M.nonblock(udp, false) == 0,  'nonblock(off): expected 0')
assert(M.cloexec(udp,  true) == 0,   'cloexec(on): expected 0')
assert(M.cloexec(udp, false) == 0,   'cloexec(off): expected 0')
-- fcntl(fd, op [, arg])
assert(M.fcntl(udp, C.F_GETFL) >= 0, 'fcntl(F_GETFL): expected >= 0')

-- multicast(fd, maddr, ifname [, src_addr])
local r2, e2 = M.multicast(udp, '224.0.0.251', 'lo')
assert(r2 == 0 or e2 ~= nil,    'multicast: expected 0 or err')

M.close(udp)
