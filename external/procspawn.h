/*
 * Based on popenRWE
 *
 * https://github.com/sni/mod_gearman/blob/master/common/popenRWE.c
 *
 * Copyright 2009-2010 Bart Trojanowski <bart@jukie.net>
 * Licensed under GPLv2, or later, at your choosing.
*/
#ifndef _PROCSPAWN_H_
#define _PROCSPAWN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct proc_pipes {
     pid_t pid;
     int pipes[3];
};

typedef struct proc_pipes proc_pipes;

#define PROC_PIPES_INIT(p) do { p.pid = -1; p.pipes[0] = -1; p.pipes[1] = -1; p.pipes[2] = -1; } while(0)
#define PROC_PIPES_INIT_P(p) do { p->pid = -1; p->pipes[0] = -1; p->pipes[1] = -1; p->pipes[2] = -1; } while(0)

#define PROC_CLOSE_STDIN(pp) if (pp[0]) { close(pp[0]); pp[0] = -1; }
#define PROC_CLOSE_STDOUT(pp) if (pp[1]) { close(pp[1]); pp[1] = -1; }
#define PROC_CLOSE_STDERR(pp) if (pp[2]) { close(pp[2]); pp[2] = -1; }

#define PROC_CLOSE(p, s) proc_close(p.pid, p.pipes, s)
#define PROC_CLOSE_P(p, s) proc_close(p->pid, p->pipes, s)

/*
 * bidirectional popen call
 *
 * @param command - program to run
 * @param arg - param to commands (NULL-terminated array like 
 *              char *arg[] = { "-l", "-i", NULL };
 *              if NULL, command executed with 'sh -c' - pass parameters with command
 * #param env - enviriment variables (NULL-terminated array like arg).
 * @param pipes - int array of size three (int[3])
 * @param handle_err - set to 1 to handle stderr or 0 if not
 * @return pid or -1 on error
 *
 * The caller passes an array of three integers (int pipes[3]), 
 * on successful execution it can then write to element 0 (stdin of exe), 
 * and read from * element 1 (stdout) and 2 (stderr).
 */
pid_t proc_spawn(const char *command, char *const arg[], char *const env[], int *pipes, short handle_err);

/*
 * process close pipes call (close pipes)
 *
 * @param pid - pid of the child process
 * @param pipes - int array of size three (int[3])
 * @param status - int * for return process status (by waitpid)
 * @return value returned by waitpid (-1 on error)
 *
*/
void proc_close_pipes(int *pipes);

/*
 * process close call (close pipes and run waitpid for wait process ending)
 *
 * @param pipes - int array of size three (int[3])
 *
*/
int proc_close(const pid_t pid, int *pipes, int *status);

/*
 * process status call (run waitpid with WNOHANG)
 *
 * @param pid - pid of the child process
 * @param status - int * for return process status (by waitpid)
 * @return value returned by waitpid (-1 on error)
 *
*/
int proc_status(const pid_t pid, int *status);

#ifdef __cplusplus
}
#endif

#endif /* _PROCSPAWN_H_ */
