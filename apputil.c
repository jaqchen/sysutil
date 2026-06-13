/*
 * Copyright 2022 Ye Jiaqiang <yejq.jiaqiang@gmail.com>
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sched.h>
#include <sys/syscall.h>

#include "apputil.h"

struct apputil {
	int numargs;            /* current number of arguments */
	int maxargs;            /* maximum number arguments available */
	int stdin_fd;           /* standard input file descriptor for child process */
	int stdout_fd;          /* standard output file descriptor for child process */
	unsigned int options;   /* application running options */
	int exitval;            /* exit status for child process */
	pid_t pid;              /* PID of child process */
	char * * appargs;       /* array of command-line arguments */
	/* default argument array */
	char * dftargs[APPUTIL_DFTARGS + 1];
};

#define DECLARE_APPUTIL(x_, y_) \
	struct apputil * x_ = (struct apputil *) y_
#define APPUTIL_CLOSE(pfd_) \
	if (pfd_ != -1) { \
		close(pfd_); \
		pfd_ = -1; \
	}

unsigned char * appf_readfile(const char * filp,
	unsigned int maxsize, unsigned int * filesize, int verb)
{
	int error;
	int fd, ret;
	ssize_t rl1;
	struct stat fst;
	unsigned int rsize;
	unsigned char * rbuf;

	fd = -1;
	error = 0;
	rbuf = NULL;
	ret = stat(filp, &fst);
	if (ret == -1) {
		if (verb) {
			error = errno;
			fprintf(stderr, "Error, failed to stat(%p): %s\n",
				filp ? : "unknown", strerror(error));
			fflush(stderr);
			errno = error;
		}
		return NULL;
	}

	if (!S_ISREG(fst.st_mode)) {
		error = ENOENT;
		if (verb) {
			fprintf(stderr, "Error, not a regular file: %s\n", filp);
			fflush(stderr);
		}
		errno = error;
		return NULL;
	}

	rsize = maxsize;
	if (maxsize > (unsigned int) fst.st_size)
		rsize = (unsigned int) fst.st_size;

	fd = open(filp, O_RDONLY | O_CLOEXEC);
	if (fd == -1) {
		if (verb) {
			error = errno;
			fprintf(stderr, "Error, failed to open(%s): %s\n",
				filp, strerror(error));
			fflush(stderr);
			errno = error;
		}
		return NULL;
	}

	rbuf = (unsigned char *) malloc((size_t) (rsize + 1));
	if (rbuf == NULL) {
		error = errno;
		if (verb) {
			fprintf(stderr, "Error, system out of memory: %u\n", rsize);
			fflush(stderr);
		}
		close(fd);
		errno = error;
		return NULL;
	}

	rl1 = read(fd, rbuf, rsize);
	if (rl1 == -1) {
		error = errno;
		if (verb) {
			fprintf(stderr, "Error, failed to read(%p): %s\n",
				filp, strerror(error));
			fflush(stderr);
		}
		close(fd);
		free(rbuf);
		errno = error;
		return NULL;
	}

	close(fd);
	*filesize = (unsigned int) rl1;
	rbuf[rl1] = (unsigned char) 0;
	return rbuf;
}

int appf_mountpoint(const char * path)
{
	int ret;
	char * newpath;
	struct stat pst;
	struct stat ppst;

	newpath = NULL;
	ret = stat(path, &pst);
	if (ret == -1)
		return -1;
	if (!S_ISDIR(pst.st_mode))
		return -2;

	ret = asprintf(&newpath, "%s/..", path);
	if (ret <= 0)
		return -3;

	ret = stat(newpath, &ppst);
	free(newpath);
	newpath = NULL;
	if (ret == -1)
		return -4;

	if (pst.st_dev != ppst.st_dev)
		return 0;
	if (pst.st_ino == ppst.st_ino)
		return 0;
	return -5;
}

#ifndef SYS_close_range
  #ifdef __NR_close_range
    #define SYS_close_range __NR_close_range
  #else
    #define SYS_close_range -1l
  #endif
#endif
int appf_closefds(int fd, int maxfd, int verb)
{
	long sysno;
	int ret, error;

	sysno = SYS_close_range;
	if (sysno < 0)
		goto slow_close;
	errno = 0;
	ret = syscall(sysno, fd, maxfd, 0);
	if (ret < 0) {
		error = errno;
		if (error == ENOSYS)
			goto slow_close;
		fprintf(stderr, "Error, close_range(%d, %d) has failed: %s\n",
			fd, maxfd, strerror(error));
		fflush(stderr);
		errno = error;
		return -1;
	}
	return 0;

slow_close:
	while (fd < maxfd) {
		close(fd);
		fd++;
	}
	return 0;
}

static void close_fd2(int * pfds)
{
	if (pfds[0] != -1) {
		close(pfds[0]);
		pfds[0] = -1;
	}

	if (pfds[1] != -1) {
		close(pfds[1]);
		pfds[1] = -1;
	}
}

int appf_fdblock(int fd, int blocking, int verb)
{
	int error = 0;
	int ret, flags;

	ret = fcntl(fd, F_GETFL, 0);
	if (ret == -1) {
		error = errno;
err0:
		if (verb != 0) {
			fprintf(stderr, "Error, fdblock(%d) has failed: %s\n",
				fd, strerror(error));
			fflush(stderr);
		}
		errno = error;
		return -1;
	}

	flags = ret;
	if (blocking != 0)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;
	if (ret == flags)
		return 0;

	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1) {
		error = errno;
		goto err0;
	}
	return 0;
}

int appf_cloexec(int fd, int cloexec, int verb)
{
	int error;
	int ret, flags;

	ret = fcntl(fd, F_GETFD, 0);
	if (ret == -1) {
		if (verb != 0) {
			error = errno;
err0:
			fprintf(stderr, "Error, cloexec(%d) has failed: %s\n",
				fd, strerror(error));
			fflush(stderr);
			errno = error;
		}
		return -1;
	}

	flags = ret;
	if (cloexec != 0)
		flags |= FD_CLOEXEC;
	else
		flags &= ~FD_CLOEXEC;
	if (ret == flags)
		return 0;

	ret = fcntl(fd, F_SETFD, flags);
	if (ret == -1) {
		if (verb != 0) {
			error = errno;
			goto err0;
		}
		return -1;
	}
	return 0;
}

int appf_pipesize(int fd, int maxSize, int verb)
{
	int error = 0;
	int curSize, ret;

	ret = fcntl(fd, F_GETPIPE_SZ, 0);
	if (ret == -1) {
		error = errno;
err0:
		if (verb != 0) {
			fprintf(stderr, "Error, pipesize(%d) has failed: %s\n",
				fd, strerror(error));
			fflush(stderr);
			errno = error;
		}
		return -1;
	}

	curSize = ret;
	if (curSize >= maxSize)
		return curSize;
	ret = fcntl(fd, F_SETPIPE_SZ, maxSize);
	if (ret == -1) {
		error = errno;
		goto err0;
	}
	return maxSize;
}

int appf_zipstdio(const char * ndev, int verb)
{
	int nfd;
	int error = 0;
	if (ndev == NULL)
		ndev = "/dev/null";
	nfd = open(ndev, O_RDWR | O_CLOEXEC);
	if (nfd >= 0) {
		if (nfd != STDIN_FILENO)
			error += dup2(nfd, STDIN_FILENO) == -1;
		if (nfd != STDOUT_FILENO)
			error += dup2(nfd, STDOUT_FILENO) == -1;
		if (nfd != STDERR_FILENO)
			error += dup2(nfd, STDERR_FILENO) == -1;
		if (nfd > STDERR_FILENO)
			close(nfd);
		appf_cloexec(STDIN_FILENO, 0, verb);
		appf_cloexec(STDOUT_FILENO, 0, verb);
		appf_cloexec(STDERR_FILENO, 0, verb);
		if (error > 0)
			return -1;
		return 0;
	}

	if (verb != 0) {
		error = errno;
		fprintf(stderr, "Error, failed to open null device: %s\n",
			strerror(error));
		fflush(stderr);
		errno = error;
	}
	return -1;
}

apputil_t apputil_new(const char * appname, unsigned int opts)
{
	int idx;
	struct apputil * app = NULL;

	app = (struct apputil *) malloc(sizeof(*app));
	if (app == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		return (apputil_t) app;
	}

	app->numargs = 0;
	app->maxargs = APPUTIL_DFTARGS;
	app->stdin_fd = -1;
	app->stdout_fd = -1;
	app->options = opts;
	app->exitval = 0;
	app->pid = 0;
	app->appargs = app->dftargs;
	for (idx = 0; idx <= APPUTIL_DFTARGS; ++idx)
		app->dftargs[idx] = NULL;

	if (appname && appname[0]) {
		app->appargs[0] = strdup(appname);
		if (app->appargs[0] == NULL) {
			free(app);
			app = NULL;
			fprintf(stderr, "Error, failed to duplicate '%s'!\n", appname);
			fflush(stderr);
		} else {
			app->numargs = 1;
		}
	}
	return (apputil_t) app;
}

int apputil_arg(apputil_t app_, const char * arg, unsigned int arglen)
{
	char * newarg;
	int nargs, margs;
	DECLARE_APPUTIL(app, app_);

	if (arg == NULL)
		return -EINVAL;

	nargs = app->numargs;
	margs = app->maxargs;
	if (nargs >= margs) {
		int idx;
		char * * newargs;

		if (margs != APPUTIL_DFTARGS)
			return -ERANGE;
		newargs = (char * *) calloc(APPUTIL_MAXARGS + 1, sizeof(char *));
		if (newargs == NULL) {
			fputs("Error, system out of memory!\n", stderr);
			fflush(stderr);
			return -ENOMEM;
		}
		for (idx = 0; idx < margs; ++idx) {
			newargs[idx] = app->dftargs[idx];
			app->dftargs[idx] = NULL;
		}

		margs = APPUTIL_MAXARGS;
		app->maxargs = margs;
		app->appargs = newargs;
	}

	newarg = (char *) malloc((size_t) (arglen + 1));
	if (newarg == NULL) {
		fputs("Error, system out of memory!\n", stderr);
		fflush(stderr);
		return -ENOMEM;
	}
	if (arglen > 0) {
		memcpy(newarg, arg, arglen);
	}
	newarg[arglen] = '\0';

	app->numargs = nargs + 1;
	app->appargs[nargs] = newarg;
	return 0;
}

int apputil_args(apputil_t app_, const char * * args)
{
	int idx, ret;

	idx = ret = 0;
	if (args == NULL)
		return -EINVAL;
	for (;;) {
		size_t len;
		const char * arg;

		arg = args[idx];
		if (arg == NULL)
			break;
		len = strlen(arg);

		ret = apputil_arg(app_, arg, (unsigned int) len);
		if (ret < 0)
			break;
		idx++;
	}
	return ret;
}

long apputil_getpid(apputil_t app_, int move)
{
	long ret;
	DECLARE_APPUTIL(app, app_);
	ret = (long) app->pid;
	if (move)
		app->pid = 0;
	return ret;
}

int apputil_stdin(apputil_t app_, int move)
{
	int ret;
	DECLARE_APPUTIL(app, app_);
	ret = app->stdin_fd;
	if (move)
		app->stdin_fd = -1;
	return ret;
}

int apputil_stdout(apputil_t app_, int move)
{
	int ret;
	DECLARE_APPUTIL(app, app_);
	ret = app->stdout_fd;
	if (move)
		app->stdout_fd = -1;
	return ret;
}

int apputil_call(apputil_t app_, const void * indata, unsigned int inlen)
{
	pid_t pid;
	int infd[2];
	int outfd[2];
	unsigned int opts;
	const char * newapp;
	int ret, error, write0;
	DECLARE_APPUTIL(app, app_);

	pid = 0;
	error = 0;
	write0 = 0;
	infd[0] = infd[1] = -1;
	outfd[0] = outfd[1] = -1;
	newapp = app ? app->appargs[0] : NULL;
	if (newapp == NULL)
		return -EINVAL;

	if (app->pid != 0) {
		/* applicate already running */
		return -EBUSY;
	}

	opts = app->options;
	if ((opts & APPUTIL_OPTION_INPUT) &&
		(opts & APPUTIL_OPTION_NOWAIT) == 0) {
		fputs("Error, must not wait if write to stdin.\n", stderr);
		fflush(stderr);
		return -EINVAL;
	}

	app->exitval = 0;
	APPUTIL_CLOSE(app->stdin_fd);
	APPUTIL_CLOSE(app->stdout_fd);
	write0 = (indata != NULL) && (inlen > 0);
	if ((opts & APPUTIL_OPTION_INPUT) || write0) {
		ret = pipe2(infd, O_CLOEXEC);
		if (ret == -1) {
			error = errno;
			fprintf(stderr, "Error, failed to create pipe: %s\n", strerror(error));
			fflush(stderr);
			goto err0;
		}
	}

	/* write data to pipe */
	if (write0) {
		ssize_t rl1;

		ret = appf_pipesize(infd[1], (int) (inlen + 1), 1);
		if (ret < 0)
			goto err0;

		appf_fdblock(infd[1], 0, 1);
		rl1 = write(infd[1], indata, (size_t) inlen);
		if (rl1 != (ssize_t) inlen) {
			error = errno;
			fprintf(stderr, "Error, failed to write pipe %d: %s\n",
				infd[1], strerror(error));
			fflush(stderr);
			goto err0;
		}
	}

	/* read the standard output from child process: */
	if (opts & (APPUTIL_OPTION_OUTPUT | APPUTIL_OPTION_OUTALL)) {
		int psize;
		ret = pipe2(outfd, O_CLOEXEC);
		if (ret == -1) {
			error = errno;
			fprintf(stderr, "Error, failed to create pipe: %s\n", strerror(error));
			fflush(stderr);
			goto err0;
		}

		/* set large pipe size */
		psize = opts & APPUTIL_PIPE_MASK;
		if (psize == 0)
			psize = APPUTIL_BUFSIZE;
		appf_pipesize(outfd[1], psize, 1);
	}

	pid = fork();
	if (pid == -1) {
		error = errno;
		fprintf(stderr, "Error, failed to fork child process: %s\n", strerror(error));
		fflush(stderr);
		goto err0;
	}

	if (pid == 0) {
		char * const * args;
		APPUTIL_CLOSE(infd[1]);
		APPUTIL_CLOSE(outfd[0]);

		if ((opts & APPUTIL_OPTION_NULLIO) &&
			appf_zipstdio(NULL, 1) < 0) {
			_exit(90);
		}

		if ((opts & APPUTIL_OPTION_INPUT) != 0 || write0) {
			if (infd[0] != STDIN_FILENO) {
				ret = dup2(infd[0], STDIN_FILENO);
				if (ret == -1) {
					error = errno;
					fprintf(stderr, "Error, failed to replace stdin: %s\n",
						strerror(error));
					fflush(stderr);
					_exit(91);
				}
				APPUTIL_CLOSE(infd[0]);
			}
			appf_cloexec(STDIN_FILENO, 0, 1);
			appf_fdblock(STDIN_FILENO, write0 == 0, 1);
		}

		if (opts & (APPUTIL_OPTION_OUTPUT | APPUTIL_OPTION_OUTALL)) {
			if (outfd[1] != STDOUT_FILENO) {
				ret = dup2(outfd[1], STDOUT_FILENO);
				if (ret == -1) {
					error = errno;
					fprintf(stderr, "Error, failed to replace stdout: %s\n",
						strerror(error));
					fflush(stderr);
					_exit(92);
				}
				APPUTIL_CLOSE(outfd[1]);
			}
			appf_cloexec(STDOUT_FILENO, 0, 1);
		}

		if (opts & APPUTIL_OPTION_OUTALL) {
			ret = dup2(STDOUT_FILENO, STDERR_FILENO);
			if (ret == -1) {
				error = errno;
				fprintf(stderr, "Error, failed to replace stderr: %s\n",
					strerror(error));
				fflush(stderr);
				_exit(93);
			}
			appf_cloexec(STDERR_FILENO, 0, 1);
		}

		if (opts & APPUTIL_OPTION_CLOSER) {
			int startfd = STDERR_FILENO + 1;
			long maxfd = sysconf(_SC_OPEN_MAX);
			if (maxfd <= startfd)
				maxfd = 1024;
			appf_closefds(startfd, maxfd, 1);
		}

		if (opts & APPUTIL_OPTION_LOWPRI) {
			struct sched_param spa;
			errno = 0;
			ret = nice(0);
			ret = (errno == 0 && ret < 19) ? nice(19 - ret) : 0;
			if (ret == -1) {
				error = errno;
				fprintf(stderr, "Error, nice(19) has failed: %s\n",
					strerror(error));
				fflush(stderr);
			}
			spa.sched_priority = 0;
			ret = sched_setscheduler(0, SCHED_IDLE, &spa);
			if (ret == -1) {
				error = errno;
				if (error != ENOSYS) {
					fprintf(stderr, "Error, failed to set idle scheduler: %s\n",
						strerror(error));
					fflush(stderr);
				}
			}
		}

		newapp = app->appargs[0];
		args = app->appargs;
		if (args[1] != NULL &&
			(opts & APPUTIL_OPTION_SYMLINK) != 0)
			args = &(app->appargs[1]);
		if (newapp[0] == '/') {
			execv(newapp, args);
		} else {
			execvp(newapp, args);
		}
		error = errno;
		fprintf(stderr, "Error, failed to run application '%s': %s\n",
			newapp, strerror(error));
		fflush(stderr);
		_exit(94);
	}

	APPUTIL_CLOSE(infd[0]);
	APPUTIL_CLOSE(outfd[1]);
	app->stdin_fd = infd[1];
	if ((opts & APPUTIL_OPTION_INPUT) == 0) {
		APPUTIL_CLOSE(infd[1]);
		app->stdin_fd = -1;
	}
	app->stdout_fd = outfd[0];
	app->pid = pid;
	if (opts & APPUTIL_OPTION_NOWAIT)
		return 0;
	return apputil_wait(app_, 0, NULL);

err0:
	close_fd2(infd);
	close_fd2(outfd);
	return -1;
}

int apputil_exitval(apputil_t app_)
{
	DECLARE_APPUTIL(app, app_);
	return app->exitval;
}

char * apputil_read(apputil_t app_,
	unsigned int buflen, unsigned int * realen)
{
	ssize_t rl1;
	int rfd, error;
	char * pbuf;
	DECLARE_APPUTIL(app, app_);

	if (app == NULL || buflen == 0)
		return NULL;

	rfd = app->stdout_fd;
	if (rfd == -1) {
		fputs("Error, invalid stdout pipe fd.\n", stderr);
		fflush(stderr);
		return NULL;
	}

	pbuf = (char *) malloc((size_t) (buflen + 1));
	if (pbuf == NULL) {
		fprintf(stderr, "Error, system out of memory: %u\n", buflen);
		fflush(stderr);
		return NULL;
	}

	rl1 = read(rfd, pbuf, (size_t) buflen);
	if (rl1 == -1) {
		error = errno;
		free(pbuf);
		fprintf(stderr, "Error, failed to read pipe %d: %s\n",
			rfd, strerror(error));
		fflush(stderr);
		return NULL;
	}

	pbuf[rl1] = '\0';
	*realen = (unsigned int) rl1;
	if (rl1 == 0) {
		free(pbuf);
		return NULL;
	}
	return pbuf;
}

int apputil_write(apputil_t app_, const void * indata, unsigned int inlen)
{
	ssize_t rl1;
	int wfd, error;
	DECLARE_APPUTIL(app, app_);

	if (indata == NULL || inlen == 0)
		return -EINVAL;
	wfd = app ? app->stdin_fd : -1;
	if (wfd == -1) {
		fputs("Error, invalid stdin pipe fd.\n", stderr);
		fflush(stderr);
		return -EBADF;
	}

	rl1 = write(wfd, indata, (size_t) inlen);
	if (rl1 != (ssize_t) inlen) {
		error = errno;
		fprintf(stderr, "Error, failed to write pipe %d: %s\n",
			wfd, strerror(error));
		fflush(stderr);
		return (error > 0) ? -error : -1;
	}
	return 0;
}

int apputil_wait(apputil_t app_, int nohang, int * pexit)
{
	int exitval;
	pid_t rpid, pid;
	DECLARE_APPUTIL(app, app_);

	pid = app ? app->pid : 0;
	if (pid <= 0)
		return -ECHILD;

	for (;;) {
		int error;
		exitval = 0;
		rpid = waitpid(pid, &exitval, nohang ? WNOHANG : 0);
		if (rpid == pid)
			break;

		if (rpid == 0) {
			/* wait with WNOHANG, and child process happily running */
			if (pexit != NULL)
				*pexit = 0;
			return 0;
		}
		error = errno;
		if (error != EINTR) {
			fprintf(stderr, "Error, waitpid(%ld) has failed: %s\n",
				(long) pid, strerror(error));
			fflush(stderr);
			return -1;
		}
	}

	/* child process exited */
	app->pid = 0;
	app->exitval = exitval;
	if (pexit != NULL)
		*pexit = exitval;
	return 1;
}

int apputil_free(apputil_t app_)
{
	int idx, maxargs;
	char * * dftargs;
	DECLARE_APPUTIL(app, app_);

	if (app == NULL)
		return -EINVAL;

	APPUTIL_CLOSE(app->stdin_fd);
	APPUTIL_CLOSE(app->stdout_fd);
	if (app->pid > 0) {
		kill(app->pid, SIGKILL);
		apputil_wait(app_, 0, NULL);
	}

	maxargs = app->maxargs;
	for (idx = 0; idx < maxargs; ++idx) {
		if (app->appargs[idx] != NULL) {
			free(app->appargs[idx]);
			app->appargs[idx] = NULL;
		}
	}

	dftargs = (char * *) app->dftargs;
	if (app->appargs != dftargs)
		free(app->appargs);
	app->numargs = 0;
	app->maxargs = 0;
	app->appargs = NULL;
	free(app);
	return 0;
}
