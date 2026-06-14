#!/usr/bin/lua5.1

local sysutil = require "sysutil"

local ufd = sysutil.socket(0x2, 0x1, 0x6)
if not ufd then
	io.stderr:write("Error, failed to create an TCP socket\n")
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
sysutil.listen(ufd)

local socks_ft = {}

local function get_poll_table()
	local pftab = {}
	pftab[ufd] = 0x1
	for fd, _ in pairs(socks_ft) do
		-- 0x19 -- "POLLIN | POLLERR | POLLHUP"
		pftab[fd] = 0x19
	end
	return pftab
end

while true do
	local nfd, nerr = sysutil.poll(get_poll_table(), 15000)
	if not nfd then
		io.stderr:write(string.format("TCP socket poll error: %s\n", sysutil.strerror(nerr)))
		io.stderr:flush()
	else
		for k, v in pairs(nfd) do
			-- io.stdout:write(string.format("[%s] Activity for %d: %d\n", sysutil.timestr(), k, v))
			-- io.stdout:flush()
			if k == ufd then
				local newfd, addr, pno = sysutil.accept(ufd)
				if newfd then
					sysutil.nonblock(newfd, true)
					socks_ft[newfd] = string.format("%s:%d", addr, pno)
					io.stdout:write(string.format("New TCP client from: %s\n", socks_ft[newfd]))
					io.stdout:flush()
				end
			else
				local rmsg = sysutil.read(k, 8192)
				while rmsg do
					if #rmsg == 0 then
						io.stderr:write(string.format("Client has disconnected for %d, %s\n",
							k, socks_ft[k] or "unknown"))
						io.stderr:flush()
						socks_ft[k] = nil
						sysutil.close(k)
						break
					end
					io.stdout:write(string.format("New Message from %s: %s\n", socks_ft[k] or "unknown", rmsg))
					io.stdout:flush()
					sysutil.sendto(k, rmsg, 0x4000)
					rmsg = sysutil.read(k, 8192)
				end
			end
		end
	end

end
