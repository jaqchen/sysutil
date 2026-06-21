--
-- cgroup v2 control module
--

local U = require 'sysutil'
local C = require 'sysutil.syscon'

local CGROUP_PATH_MAX = 512

local M = {}

function M.create(grpnam, controllers)
	if type(grpnam) ~= 'string' or #grpnam == 0 then
		return nil, C.EINVAL
	end
	local path = string.format('/sys/fs/cgroup/%s', grpnam)
	if #path > CGROUP_PATH_MAX then
		return nil, C.ENAMETOOLONG
	end
	if type(controllers) == 'string' and #controllers > 0 then
		local fd, err = U.open('/sys/fs/cgroup/cgroup.subtree_control', C.O_WRONLY + C.O_CLOEXEC)
		if not fd then
			return nil, err
		end
		local n, err = U.write(fd, controllers)
		U.close(fd)
		if not n then return nil, err end
		if n ~= #controllers then
			return nil, C.EIO
		end
	end
	local ok, err = U.mkdir(path, tonumber('0755', 8))
	if not ok and err ~= C.EEXIST then
		return nil, err
	end
	return path
end

function M.attach(cgrp, pid)
	if type(cgrp) ~= 'string' or #cgrp == 0 then
		return nil, C.EBADF
	end
	if type(pid) ~= 'number' or pid <= 0 then
		return nil, C.EINVAL
	end

	local raw, err = U.read(string.format('/proc/%d/cgroup', pid))
	if not raw then
		return nil, err
	end

	local fd, err = U.open(string.format('%s/cgroup.procs', cgrp), C.O_WRONLY + C.O_CLOEXEC)
	if not fd then
		return nil, err
	end
	local data = string.format('%d\n', pid)
	local n, err = U.write(fd, data)
	U.close(fd)
	if not n then return nil, err end
	if n ~= #data then
		return nil, C.EIO
	end

	return raw
end

function M.detach(cgrp, pid, rawcgrp)
	if type(cgrp) ~= 'string' or #cgrp == 0 then
		return nil, C.EBADF
	end
	if type(pid) ~= 'number' or pid <= 0 then
		return nil, C.EINVAL
	end
	if type(rawcgrp) ~= 'string' or #rawcgrp == 0 then
		return nil, C.EINVAL
	end

	local pos = string.find(rawcgrp, '0::', 1, true)
	if not pos then
		return nil, C.EINVAL
	end

	local p = string.sub(rawcgrp, pos + 3)
	if #p == 0 or string.sub(p, 1, 1) ~= '/' then
		return nil, C.EINVAL
	end

	local npos = string.find(p, '\n', 1, true)
	local rpos = string.find(p, '\r', 1, true)
	local plen = #p
	if npos then plen = npos - 1 end
	if rpos and rpos - 1 < plen then plen = rpos - 1 end

	local fd, err = U.open(
		string.format('/sys/fs/cgroup%s/cgroup.procs', string.sub(p, 1, plen)),
		C.O_WRONLY + C.O_CLOEXEC)
	if not fd then
		return nil, err
	end
	local data = string.format('%d\n', pid)
	local n, err = U.write(fd, data)
	U.close(fd)
	if not n then return nil, err end
	if n ~= #data then
		return nil, C.EIO
	end

	return n
end

function M.set(cgrp, attr, val)
	if type(cgrp) ~= 'string' or #cgrp == 0 then
		return nil, C.EBADF
	end
	if type(attr) ~= 'string' or #attr == 0 then
		return nil, C.ENOENT
	end
	if type(val) ~= 'string' or #val == 0 then
		return nil, C.EINVAL
	end

	local fd, err = U.open(string.format('%s/%s', cgrp, attr), C.O_WRONLY + C.O_CLOEXEC)
	if not fd then
		return nil, err
	end
	local n, err = U.write(fd, val)
	U.close(fd)
	if not n then return nil, err end
	if n ~= #val then
		return nil, C.EIO
	end

	return n
end

function M.get(cgrp, attr)
	if type(cgrp) ~= 'string' or #cgrp == 0 then
		return nil, C.EBADF
	end
	if type(attr) ~= 'string' or #attr == 0 then
		return nil, C.EINVAL
	end

	local val, err = U.read(string.format('%s/%s', cgrp, attr))
	if not val then
		return nil, err
	end

	local nl = string.find(val, '\n', 1, true)
	if nl and nl > 1 then
		return string.sub(val, 1, nl - 1)
	end
	return val
end

function M.destroy(cgrp)
	if type(cgrp) ~= 'string' or #cgrp == 0 then
		return nil, C.EBADF
	end

	local n, err = U.rmdir(cgrp)
	if n == 0 then
		return nil, err ~= 0 and err or C.EPERM
	end
	return 0
end

return M
