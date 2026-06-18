package = "sysutil"
version = "1.0.0-1"

source = {
	url = "git://github.com/jaqchen/sysutil",
}

description = {
   summary = "System Utility for Lua — embedded Linux system programming",
   detailed = [[
	 sysutil provides common system-level operations for embedded Linux programming,
	 the companion module 'syscon' provides portable system constant
	 definitions (O_*, AF_*, SOCK_*, E*, etc.).
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
		 ["syscon"] = "syscon.lua",
	  },
   },
}
