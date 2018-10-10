#ifndef NET_H
#define NET_H

/* ------------------------------------------------------------------------ */

#include "common.h"
#include "cert.h"

/* ------------------------------------------------------------------------ */

#include "plgetopt.h"

/* ------------------------------------------------------------------------ */

#define is_PR_Send_FAILURE < 0
#define is_PR_Send_CLOSED == 0
#define is_PR_Recv_FAILURE < 0
#define is_PR_Recv_CLOSED == 0
#define is_PR_Poll_FAILURE < 0
#define is_PR_Poll_TIMEOUT == 0

/* ------------------------------------------------------------------------ */

#define DEFAULT_IO_TIMEOUT (PR_TicksPerSecond() * 4 * 60)
#define DEFAULT_ACCEPT_TIMEOUT PR_INTERVAL_NO_TIMEOUT
#define DEFAULT_CONNECT_TIMEOUT (PR_TicksPerSecond() * 4 * 60)
#define DEFAULT_SEND_TIMEOUT (PR_TicksPerSecond() * 4 * 60)
#define DEFAULT_RECV_TIMEOUT (PR_TicksPerSecond() * 4 * 60)

/* ------------------------------------------------------------------------ */

PRStatus getLocalNetAddr(PRUint16 port, PRNetAddr* netAddr);
PRStatus getRemoteNetAddr(char* host, PRUint16 port, PRNetAddr* netAddr);

/* ------------------------------------------------------------------------ */

PRFileDesc* connectToLocal(PRUint16 port, PRBool isBlocking, PRBool isSsl);
PRFileDesc* connectToRemote(char* host, PRUint16 port, PRBool isBlocking, PRBool isSsl);

/* ------------------------------------------------------------------------ */

PRInt32 forwardSocketDataChunk(PRFileDesc* fromSocket, PRFileDesc* toSocket);
PRInt32 duplicateSocketData(PRFileDesc* socketA, PRFileDesc* socketB);

/* ------------------------------------------------------------------------ */

PRStatus makeSocketBlocking(PRFileDesc* socket);
PRStatus reuseSocketAddress(PRFileDesc* socket);
PRStatus keepSocketAlive(PRFileDesc* socket);

/* ------------------------------------------------------------------------ */

char* readCrlfLine(PRFileDesc* fd, char* buf, int len);

/* ------------------------------------------------------------------------ */

#endif
