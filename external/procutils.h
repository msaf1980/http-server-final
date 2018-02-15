#ifndef _PROCUTILS_H_
#define _PROCUTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

char **arg_parse(const char *cmd, int *n_arg, char delim);
void arg_free(char*** arg);

#ifdef __cplusplus
}
#endif

#endif /* _PROCUTILS_H_ */
