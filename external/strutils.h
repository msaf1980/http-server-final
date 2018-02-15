#ifndef _STRUTILS_H_
#define _STRUTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vsnprintf with dynamically allocated buffer (need to bee free, if function return value >=0)
 * @param p - pointer to allocated buffer 
 *      free memory before pass pointer or will be !!! MEMORY LEAK !!! after allocation)
 * @param initsize - initial size for allocated buffer, set 0 to autosize
 * @param maxsize - limit allocated memory, set 0 to unlimit
 * @param fmt - format string
 * @param .. VARAGS
 * @return like vsnprintf
 *      >= maxsize (maxsize > 0) Maxsize too small
 *      < 0 output error
 *      -2 allocation error
 *      > 0,  < maxsize (maxsize > 0) Success
 *
 * use like
 *   char *p = NULL;
 *   if  (vsnprintf_l(&p, 0, "c = %d, n = %d\n", c, n) > 0)
 *   {
 *   ..
 *   }
 *   
 *
 */
int vsnprintf_l(char **p, size_t initsize, size_t maxsize, const char *fmt, ...);

/* return 1 if string contain only digits, else return 0 */
int is_num(char *str);

#ifdef __cplusplus
}
#endif

#endif /* _STRUTILS_H_ */
