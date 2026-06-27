/*
 * Copyright 2026 Ye Jiaqiang <yejq.jiaqiang@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The constants defined in `syscon.lua` vary significantly
 * in different platforms and/or architectures. So it is
 * neccessary to implement another simple Lua module to provide them.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <poll.h>
#include <glob.h>

#include <lua.h>
#include <lauxlib.h>

#define SYSCON_ADD(__SC_VAL, __topn) \
	do { \
		const char * sc_name_ = #__SC_VAL; \
		const lua_Integer sc_val_ = (lua_Integer) __SC_VAL; \
		lua_pushinteger(L, sc_val_); \
		lua_setfield(L, __topn, sc_name_); \
	} while (0)

extern int luaopen_syscon(lua_State * L)
	__attribute__((visibility("default")));

int luaopen_syscon(lua_State * L)
{
#if LUA_VERSION_NUM >= 502
	luaL_checkversion(L);
#endif
	lua_createtable(L, 0, 200);
	const int ntop = lua_gettop(L);

	SYSCON_ADD(O_RDONLY, ntop);
	SYSCON_ADD(O_RDWR, ntop);
	SYSCON_ADD(O_WRONLY, ntop);
	SYSCON_ADD(O_APPEND, ntop);
	SYSCON_ADD(O_ASYNC, ntop);
	SYSCON_ADD(O_CLOEXEC, ntop);
	SYSCON_ADD(O_CREAT, ntop);
	SYSCON_ADD(O_DIRECT, ntop);
	SYSCON_ADD(O_DIRECTORY, ntop);
	SYSCON_ADD(O_DSYNC, ntop);
	SYSCON_ADD(O_EXCL, ntop);
	SYSCON_ADD(O_LARGEFILE, ntop);
	SYSCON_ADD(O_NOATIME, ntop);
	SYSCON_ADD(O_NOCTTY, ntop);
	SYSCON_ADD(O_NOFOLLOW, ntop);
	SYSCON_ADD(O_NONBLOCK, ntop);
	SYSCON_ADD(O_PATH, ntop);
	SYSCON_ADD(O_SYNC, ntop);
	SYSCON_ADD(O_TMPFILE, ntop);
	SYSCON_ADD(O_TRUNC, ntop);

	SYSCON_ADD(AF_INET, ntop);
	SYSCON_ADD(AF_INET6, ntop);
	SYSCON_ADD(AF_UNIX, ntop);
	SYSCON_ADD(AF_NETLINK, ntop);

	SYSCON_ADD(SOCK_STREAM, ntop);
	SYSCON_ADD(SOCK_DGRAM, ntop);
	SYSCON_ADD(SOCK_SEQPACKET, ntop);
	SYSCON_ADD(SOCK_RAW, ntop);
	SYSCON_ADD(SOCK_PACKET, ntop);
	SYSCON_ADD(SOCK_NONBLOCK, ntop);
	SYSCON_ADD(SOCK_CLOEXEC, ntop);

	SYSCON_ADD(IPPROTO_IP, ntop);
	SYSCON_ADD(IPPROTO_ICMP, ntop);
	SYSCON_ADD(IPPROTO_UDP, ntop);
	SYSCON_ADD(IPPROTO_UDPLITE, ntop);
	SYSCON_ADD(IPPROTO_TCP, ntop);
	SYSCON_ADD(IPPROTO_IGMP, ntop);

	SYSCON_ADD(SOL_SOCKET, ntop);
	SYSCON_ADD(SOL_TCP, ntop);
	SYSCON_ADD(SO_BROADCAST, ntop);
	SYSCON_ADD(SO_ERROR, ntop);
	SYSCON_ADD(SO_DONTROUTE, ntop);
	SYSCON_ADD(SO_KEEPALIVE, ntop);
	SYSCON_ADD(SO_RCVBUF, ntop);
	SYSCON_ADD(SO_REUSEADDR, ntop);
	SYSCON_ADD(SO_REUSEPORT, ntop);
	SYSCON_ADD(SO_SNDBUF, ntop);
	SYSCON_ADD(SO_TIMESTAMP, ntop);

	SYSCON_ADD(TCP_NODELAY, ntop);
	SYSCON_ADD(TCP_CORK, ntop);
	SYSCON_ADD(TCP_KEEPIDLE, ntop);
	SYSCON_ADD(TCP_KEEPINTVL, ntop);
	SYSCON_ADD(TCP_KEEPCNT, ntop);
	SYSCON_ADD(TCP_SYNCNT, ntop);

	SYSCON_ADD(NETLINK_ROUTE, ntop);
	SYSCON_ADD(NETLINK_SELINUX, ntop);
	SYSCON_ADD(NETLINK_AUDIT, ntop);
	SYSCON_ADD(NETLINK_CONNECTOR, ntop);
	SYSCON_ADD(NETLINK_NETFILTER, ntop);
	SYSCON_ADD(NETLINK_SOCK_DIAG, ntop);
	SYSCON_ADD(NETLINK_KOBJECT_UEVENT, ntop);
	SYSCON_ADD(NETLINK_GENERIC, ntop);

	SYSCON_ADD(MSG_CONFIRM, ntop);
	SYSCON_ADD(MSG_DONTROUTE, ntop);
	SYSCON_ADD(MSG_DONTWAIT, ntop);
	SYSCON_ADD(MSG_EOR, ntop);
	SYSCON_ADD(MSG_MORE, ntop);
	SYSCON_ADD(MSG_NOSIGNAL, ntop);
	SYSCON_ADD(MSG_OOB, ntop);
	SYSCON_ADD(MSG_PEEK, ntop);
	SYSCON_ADD(MSG_TRUNC, ntop);
	SYSCON_ADD(MSG_WAITALL, ntop);

	SYSCON_ADD(POLLIN, ntop);
	SYSCON_ADD(POLLPRI, ntop);
	SYSCON_ADD(POLLOUT, ntop);
	SYSCON_ADD(POLLERR, ntop);
	SYSCON_ADD(POLLHUP, ntop);
	SYSCON_ADD(POLLNVAL, ntop);

	SYSCON_ADD(IN_ACCESS, ntop);
	SYSCON_ADD(IN_ATTRIB, ntop);
	SYSCON_ADD(IN_CLOSE_WRITE, ntop);
	SYSCON_ADD(IN_CLOSE_NOWRITE, ntop);
	SYSCON_ADD(IN_CREATE, ntop);
	SYSCON_ADD(IN_DELETE, ntop);
	SYSCON_ADD(IN_DELETE_SELF, ntop);
	SYSCON_ADD(IN_MODIFY, ntop);
	SYSCON_ADD(IN_MOVE_SELF, ntop);
	SYSCON_ADD(IN_MOVED_FROM, ntop);
	SYSCON_ADD(IN_MOVED_TO, ntop);
	SYSCON_ADD(IN_OPEN, ntop);
	SYSCON_ADD(IN_MOVE, ntop);
	SYSCON_ADD(IN_CLOSE, ntop);
	SYSCON_ADD(IN_DONT_FOLLOW, ntop);
	SYSCON_ADD(IN_EXCL_UNLINK, ntop);
	SYSCON_ADD(IN_MASK_ADD, ntop);
	SYSCON_ADD(IN_ONESHOT, ntop);
	SYSCON_ADD(IN_ONLYDIR, ntop);
#ifdef IN_MASK_CREATE
	SYSCON_ADD(IN_MASK_CREATE, ntop);
#endif
	SYSCON_ADD(IN_IGNORED, ntop);
	SYSCON_ADD(IN_ISDIR, ntop);
	SYSCON_ADD(IN_Q_OVERFLOW, ntop);
	SYSCON_ADD(IN_UNMOUNT, ntop);

	SYSCON_ADD(GLOB_ERR, ntop);
	SYSCON_ADD(GLOB_MARK, ntop);
	SYSCON_ADD(GLOB_NOSORT, ntop);
	SYSCON_ADD(GLOB_DOOFFS, ntop);
	SYSCON_ADD(GLOB_NOCHECK, ntop);
	SYSCON_ADD(GLOB_APPEND, ntop);
	SYSCON_ADD(GLOB_NOESCAPE, ntop);

	SYSCON_ADD(F_DUPFD, ntop);
	SYSCON_ADD(F_DUPFD_CLOEXEC, ntop);
	SYSCON_ADD(F_GETFD, ntop);
	SYSCON_ADD(F_SETFD, ntop);
	SYSCON_ADD(FD_CLOEXEC, ntop);
	SYSCON_ADD(F_GETFL, ntop);
	SYSCON_ADD(F_SETFL, ntop);
	SYSCON_ADD(F_NOTIFY, ntop);
	SYSCON_ADD(F_SETPIPE_SZ, ntop);
	SYSCON_ADD(F_GETPIPE_SZ, ntop);

	SYSCON_ADD(EPERM, ntop);
	SYSCON_ADD(ENOENT, ntop);
	SYSCON_ADD(ESRCH, ntop);
	SYSCON_ADD(EINTR, ntop);
	SYSCON_ADD(EIO, ntop);
	SYSCON_ADD(ENXIO, ntop);
	SYSCON_ADD(E2BIG, ntop);
	SYSCON_ADD(ENOEXEC, ntop);
	SYSCON_ADD(EBADF, ntop);
	SYSCON_ADD(ECHILD, ntop);
	SYSCON_ADD(EAGAIN, ntop);
	SYSCON_ADD(ENOMEM, ntop);
	SYSCON_ADD(EACCES, ntop);
	SYSCON_ADD(EFAULT, ntop);
	SYSCON_ADD(ENOTBLK, ntop);
	SYSCON_ADD(EBUSY, ntop);
	SYSCON_ADD(EEXIST, ntop);
	SYSCON_ADD(EXDEV, ntop);
	SYSCON_ADD(ENODEV, ntop);
	SYSCON_ADD(ENOTDIR, ntop);
	SYSCON_ADD(EISDIR, ntop);
	SYSCON_ADD(EINVAL, ntop);
	SYSCON_ADD(ENFILE, ntop);
	SYSCON_ADD(EMFILE, ntop);
	SYSCON_ADD(ENOTTY, ntop);
	SYSCON_ADD(ETXTBSY, ntop);
	SYSCON_ADD(EFBIG, ntop);
	SYSCON_ADD(ENOSPC, ntop);
	SYSCON_ADD(ESPIPE, ntop);
	SYSCON_ADD(EROFS, ntop);
	SYSCON_ADD(EMLINK, ntop);
	SYSCON_ADD(EPIPE, ntop);
	SYSCON_ADD(EDOM, ntop);
	SYSCON_ADD(ERANGE, ntop);
	SYSCON_ADD(EDEADLK, ntop);
	SYSCON_ADD(ENAMETOOLONG, ntop);
	SYSCON_ADD(ENOLCK, ntop);
	SYSCON_ADD(ENOSYS, ntop);
	SYSCON_ADD(ENOTEMPTY, ntop);
	SYSCON_ADD(ELOOP, ntop);
	SYSCON_ADD(EWOULDBLOCK, ntop);
	SYSCON_ADD(ENOMSG, ntop);
	SYSCON_ADD(EDEADLOCK, ntop);
	SYSCON_ADD(ENOSTR, ntop);
	SYSCON_ADD(ENODATA, ntop);
	SYSCON_ADD(ENONET, ntop);
	SYSCON_ADD(ENOLINK, ntop);
	SYSCON_ADD(EPROTO, ntop);
	SYSCON_ADD(EMULTIHOP, ntop);
	SYSCON_ADD(EDOTDOT, ntop);
	SYSCON_ADD(EBADMSG, ntop);
	SYSCON_ADD(EOVERFLOW, ntop);
	SYSCON_ADD(EBADFD, ntop);
	SYSCON_ADD(ESTRPIPE, ntop);
	SYSCON_ADD(EUSERS, ntop);
	SYSCON_ADD(ENOTSOCK, ntop);

	return 1;
}
