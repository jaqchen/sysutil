package = "sysutil"
version = "1.0.2-0"

source = {
	url = "git://github.com/jaqchen/sysutil",
}

description = {
   summary = "System Utility for Lua — embedded Linux system programming",
   detailed = [[
	 sysutil provides common system-level operations for embedded Linux programming,
	 the companion module 'sysutil.syscon' provides portable system constant
	 definitions (O_*, AF_*, SOCK_*, E*, etc.).
	 'sysutil.cgroup' provides the control methods of cgroup v2.
   ]],
   homepage = "https://github.com/jaqchen/sysutil",
   license = "Apache-2.0",
}

dependencies = {
   "lua >= 5.1",
}

build = {
   type = "make",

   build_target = "sysutil.so",
   build_variables = {
      LUA_INCDIR = "$(LUA_INCDIR)",
   },

   install = {
	  lib = {
		 ["sysutil"] = "sysutil.so",
	  },
	  lua = {
		 ["sysutil.syscon"] = "sysutil/syscon.lua",
		 ["sysutil.cgroup"] = "sysutil/cgroup.lua",
	  },
   },
}
