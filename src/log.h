#ifndef LOG_H
#define LOG_H

/* ------------------------------------------------------------------------ */

#include <stdio.h>

/* ------------------------------------------------------------------------ */

#include "nspr.h"

/* ------------------------------------------------------------------------ */

#ifdef DEBUG
	#define ASSERTLOG(condition, ...) if (condition) fprintf(stderr, __VA_ARGS__)
	#define DEBUGLOG(...) fprintf(stderr, __VA_ARGS__)
	#define ERRORLOG() fprintf(stderr, "[!] %d\n", PR_GetError());
#else
	#define ASSERTLOG(condition, ...)
	#define DEBUGLOG(...)
	#define ERRORLOG()
#endif

/* ------------------------------------------------------------------------ */

#define RUNLOG(...) fprintf(stderr, __VA_ARGS__)

#endif
