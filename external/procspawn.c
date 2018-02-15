#include <string.h>
#include <errno.h>
#include "procspawn.h"

pid_t proc_spawn(const char *command, char *const arg[], char *const env[], int *pipes, short handle_err)
{
	int in[2];
	int out[2];
	int err[2];
	int pid, i;
	int saveerrno = 0;
	struct rlimit rl;

	if (pipe(in) < 0)
		goto ERR_IN;

	if (pipe(out) < 0)
		goto ERR_OUT;

	if (handle_err && pipe(err) < 0)
		goto ERR_ERR;

	if ((pid = fork()) > 0) { /* parent */
		close(in[0]);
		close(out[1]);
		pipes[0] = in[1];
		pipes[1] = out[0];
		if (handle_err)
		{
			close(err[1]);
			pipes[2] = err[0];
		}
		return pid;
	} else if (pid == 0) { /* child */
		close(in[1]);
		close(out[0]);
		
		close(STDIN_FILENO); /* replace stdin */
 		if (dup2(in[0], STDIN_FILENO) == -1) {
			_exit(127);

		}
		close(STDOUT_FILENO); /* replace stout */
		if (dup2(out[1], STDOUT_FILENO) == -1) {
			_exit(127);

		}
		if (handle_err) 
		{
			close(err[0]);
			close(STDERR_FILENO); /* replace sterr */
			if (dup2(err[1], STDERR_FILENO == -1)) {
				exit(127);
			}
		}

		if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
			_exit(126);

		/* close all open file descriptors */
		if (rl.rlim_max == RLIM_INFINITY)
			rl.rlim_max = 1024;
		for (i = rl.rlim_max - 1; i >= 0; i--)
			if (i > 2 && i != pipes[0] && i != pipes[1] && i != pipes[2]) 
				close(i);
        
		if (arg == NULL || arg[0] == NULL)
		{
			if (env == NULL)
				execl( "/bin/sh", "/bin/sh", "-c", command, NULL );
			else
				execle( "/bin/sh", "/bin/sh", "-c", command, NULL, env );
		}
		else if (env == NULL || env[0] == NULL)
			execvp( command, arg );
		else
			execve( command, arg, env );

		perror(command);
		_exit(127);
	} else
		goto ERR_FORK;

	return pid;

ERR_FORK:
	if (handle_err)
	{
		if (errno && saveerrno == 0) saveerrno = errno;
		close(err[0]);
		close(err[1]);
	}
ERR_ERR:
	if (errno && saveerrno == 0) saveerrno = errno;
	close(out[0]);
	close(out[1]);
ERR_OUT:
	if (errno && saveerrno == 0) saveerrno = errno;
	close(in[0]);
	close(in[1]);
ERR_IN:
	if (saveerrno) errno = saveerrno;
	return -1;
}

void proc_close_pipes(int *pipes)
{
        if (pipes[0] > 0) {
                close(pipes[0]);
                pipes[0] = -1;
        }
        if (pipes[1] > 0) {
                close(pipes[1]);
                pipes[1] = -1;
        }
        if (pipes[2] > 0) {
                close(pipes[2]);
                pipes[2] = -1;
        }
}

int proc_close(const pid_t pid, int *pipes, int *status)
{
	proc_close_pipes(pipes);
	if (pid < 0)
		return -1;
	return waitpid(pid, status, 0);
}

int proc_status(const pid_t pid, int *status)
{
    return waitpid(pid, status, WNOHANG);
}
