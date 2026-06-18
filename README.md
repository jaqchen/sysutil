# System Utility For Lua

### Motive and Use-cases

This repository contains the System Utility (`sysutil`) commonly used in embedded Linux programming. As a simple [Lua](https://lua.org) module, `sysutil` has relatively a small number of methods compared to [luaposix](https://github.com/luaposix/luaposix) or [lua-socket](https://lunarmodules.github.io/luasocket/), but enough for system level operations.

The most important method provided by `sysutil`, is the command executor `call`, which forks the application and then loads a new executable file to run. Please refer to the documentation for the details.

### Plans and roadmap

The `sysutil` is now under heavy development, but not for long. It does not employ complex objects or data structures provided by Lua, such as `userdata` or `lightusedata` types; just to keep the code less complex and compatible with newer version of Lua interpreters. Bug fixes are welcome, but any changes that introduces third-party dependencies are discouraged. There is a list of goals that are to be accomplished:

- [x] Compatibility with `Lua5.2/Lua5.3/Lua5.4` (without using `lua-compat-5.3`).
- [ ] All the methods should be tested, any test-cases are welcome.
- [ ] All the methods should be documented.
- [ ] The Lua module should be able to release via [LuaRocks](https://luarocks.org/).
- [ ] Windows/MacOS2 support?

### Related Project

The `sysutil` was originally written as part for [Fighters](https://github.com/jaqchen/fighters), as encouraged by my former colleague.
