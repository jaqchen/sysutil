#!/usr/bin/lua5.1

local sysutil = require "sysutil"

local nfd = sysutil.socket(0x10, 0x2, 0xf)
if not nfd then
	io.stderr:write("Error, failed to create NETLINK socket.\n")
	io.stderr:flush()
	os.exit(1)
end

if sysutil.bind(nfd, 0x10, "0", 1) ~= 0 then
	io.stderr:write("Error, failed to bind NETLINK/UEVENT socket.\n")
	io.stderr:flush()
	os.exit(2)
end

while true do
	local rmsg = sysutil.read(nfd, 8192)
	if rmsg then
		rmsg = string.gsub(rmsg, "%z", "\n")
		io.stdout:write(rmsg)
		io.stdout:write("===========================================================================\n")
		io.stdout:flush()
	end
end
