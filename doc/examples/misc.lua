#!/usr/bin/env lua

local M = require 'sysutil'
local C = require 'sysutil.syscon'

local s = M.strerror(C.ENOENT)
assert(type(s) == 'string',      "strerror(ENOENT): expected string")
assert(#s > 0,                   "strerror(ENOENT): expected non-empty")

-- readpass([verbose])
-- verbose: true -> each character is echoed with '*'

--[[
local pwd, err = M.readpass(true)
assert(pwd == nil or type(pwd) == 'string', 'readpass: expected nil or string')
]]
