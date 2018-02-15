#include <stdlib.h>
#include <string.h>

#include "procutils.h"

#define SIZE_INC 7

char **arg_parse(const char *cmd, int *n_arg, char delim)
{
	const char *p, *s;
	char **new_arg;
	short space;

	int asize = SIZE_INC; /* allocated_size - 1 */
	char **arg = malloc((asize + 1) * sizeof(char *));
	if (arg == NULL)
		return NULL;
	*n_arg = 0;

	space = 1; s = NULL;
	p = cmd;
	while (1)
	{
		if (*p == '\0' && s == NULL)
			break;
		else if (*p == '\0' || (*p == delim && space && s != NULL))
		{
			if (*n_arg == asize)
			{
				asize += SIZE_INC + 1;
				new_arg = realloc(arg, (asize + 1) * sizeof(char *));
				if (new_arg == NULL)
				{
					arg_free(&arg);
					return NULL;
				}
				else
					arg = new_arg;
			}
			arg[*n_arg] = strndup(s, p - s);
			(*n_arg)++;
		
			if (*p == '\0')
				break;
			s = NULL;
		}
		else if (*p != delim)
		{
			if (*p == '"')
			{
				if (space)
				{
					space = 0;
				}
				else
					space = 1;
			}
			if (s == NULL)	
				s = p;
		}
		p++;	
	}
	arg[*n_arg] = NULL;
	if (*n_arg < asize)
	{
		new_arg = realloc(arg, (*n_arg + 1) * sizeof(char *));
		if (new_arg != NULL)
			return new_arg;
	}
	return arg;
}

void arg_free(char ***arg)
{
	char **p;
	if (*arg == NULL)
		return;
	p = *arg;
	while (1)
	{
		if (*p == NULL)
			break;
		free(*p);
		p++;
	}
	free(*arg);
}
