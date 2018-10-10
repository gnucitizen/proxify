#ifndef TEST_H
#define TEST_H

/* ------------------------------------------------------------------------ */

int tests_run = 0;

/* ------------------------------------------------------------------------ */

#define ASSERT(message, test) do { if (!(test)) return message; } while (0)
#define RUN(test) do { char* message = test(); tests_run++; if (message) return message; } while (0)

/* ------------------------------------------------------------------------ */

#endif
