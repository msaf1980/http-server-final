/*  EC macros for check condition. If condition coincidence, 
set ec to code, execute  x, and goto to label
For use set label choosen in parameter label and set ec variable */
#define EC(cond, label, code, x) if (cond) { ec = code; x; goto label; }

/* silent EC without execution additional instruction on condition */
#define ECS(cond, label, code) if (cond) { ec = code; goto label; }

/* like EC but without set additional code to ec (use errno) */
#define EC_ERRNO(cond, label, x) if (cond) { ec = errno; x; goto label; }

/* silent EC_ERRNO */ 
#define ECS_ERRNO(cond, label) if (cond) { ec = errno; goto label; }

/* like EC but without set additional code to ec */
#define ECN(cond, label, x) if (cond) { x; goto label; }

/* perror on error code */
#define PERROR(str, code) fprintf(stderr, "%s: %s\n", str, strerror(code))

/* perror on error code with double prefix */        
#define PERROR2(str, str2, code) fprintf(stderr, "%s %s: %s\n", str, str2, strerror(code))

/* thread-safe perror on error code */
#define PERROR_R(str, code, buf, bufsize) do { strerror_r(code, buf, bufsize); \
    fprintf(stderr, "%s: %s\n", str, buf); } while(0)

/* thread-safe perror on error code with double prefix */        
#define PERROR_R2(str, str2, code, buf, bufsize) do { strerror_r(code, buf, bufsize); \
    fprintf(stderr, "%s %s: %s\n", str, str2, buf); } while(0)

