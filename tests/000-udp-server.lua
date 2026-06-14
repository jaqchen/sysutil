#!/usr/bin/lua5.1

local sysutil = require "sysutil"

local ufd = sysutil.socket(0x2, 0x2, 0x11)
if not ufd then
	io.stderr:write("Error, failed to create an UDP socket\n")
	io.stderr:flush()
	os.exit(1)
end

if not sysutil.nonblock(ufd, true) then
	io.stderr:write("Error, failed to enable NONBLOCKed IO\n")
	io.stderr:flush()
	os.exit(1)
end

if sysutil.sockopt(ufd, nil, 0x1, 0x2, 0x1) ~= 0 then
	io.stderr:write("Error, failed to reuse socket address.\n")
	io.stderr:flush()
	os.exit(2)
end

if sysutil.sockopt(ufd, nil, 0x1, 0xf, 0x1) ~= 0 then
	io.stderr:write("Error, failed to reuse socket port.\n")
	io.stderr:flush()
	os.exit(3)
end

if sysutil.bind(ufd, 0x2, "0.0.0.0", 9876) ~= 0 then
	io.stderr:write("Error, failed to bind to local port.\n")
	io.stderr:flush()
	os.exit(4)
end

local msgcnt = 0
while true do
	local rmsg, raddr, rport = sysutil.recvfrom(ufd, 8192, 0)
	while rmsg do
		msgcnt = msgcnt + 1
		io.stdout:write(string.format("New Message %d from %s:%d: %s\n", msgcnt, raddr, rport, rmsg))
		io.stdout:flush()
		sysutil.sendto(ufd, rmsg, 0, raddr, rport)
		rmsg, raddr, rport = sysutil.recvfrom(ufd, 8192, 0)
	end

	local nfd, nerr = sysutil.poll({ [ufd] = 0x1 }, 15000)
	if not nfd then
		io.stderr:write(string.format("UDP socket poll error: %s\n", sysutil.strerror(nerr)))
		io.stderr:flush()
	else
		for k, v in pairs(nfd) do
			io.stdout:write(string.format("Activity for %d: %d\n", k, v))
			io.stdout:flush()
		end
	end
end
