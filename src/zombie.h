#ifndef ZOMBIE_H
#define ZOMBIE_H

/* ------------------------------------------------------------------------ */

#include "common.h"

/* ------------------------------------------------------------------------ */

#ifdef LINUX

#define INSTALL_ZOMBIE_VACCINE()

#endif

/* ------------------------------------------------------------------------ */

#ifdef WINNT

#include <windows.h>
#include <tlhelp32.h>

void PR_CALLBACK checkSelfIfZombie(void* argument);

#define INSTALL_ZOMBIE_VACCINE() PR_QueueJob(threadPool, checkSelfIfZombie, NULL, PR_FALSE)

#endif

/* ------------------------------------------------------------------------ */

#ifndef INSTALL_ZOMBIE_VACCINE

#define INSTALL_ZOMBIE_VACCINE()

#endif

/* ------------------------------------------------------------------------ */

#endif
