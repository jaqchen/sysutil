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

if sysutil.connect(ufd, 0x2, "127.0.0.1", 9876) ~= 0 then
	io.stderr:write("Error, failed to bind to local port.\n")
	io.stderr:flush()
	os.exit(4)
end

sysutil.write(ufd, string.format("[%s] WHAT THE FUCK", os.date()))
local nfd, nerr = sysutil.poll({ [ufd] = 0x1 }, 2000)
if not nfd then
	sysutil.close(ufd)
	io.stderr:write(string.format("UDP socket poll error: %s\n", sysutil.strerror(nerr)))
	io.stderr:flush()
	os.exit(5)
end

local rmsg = sysutil.read(ufd, 8192)
while rmsg do
	io.stdout:write(string.format("New Message: %s\n", rmsg))
	io.stdout:flush()
	rmsg = sysutil.read(ufd, 8192)
end
sysutil.close(ufd)
