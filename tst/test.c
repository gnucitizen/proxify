#include "test.h"

/* ------------------------------------------------------------------------ */

#include "../src/common.c"
#include "../src/cert.c"
#include "../src/net.c"
#include "../src/hexdmp.c"
#include "../src/httpdm.c"
#include "../src/httpst.c"
#include "../src/augment.c"
#include "../src/struct.c"
#include "../src/direct.c"
#include "../src/forwrd.c"
#include "../src/simple.c"
#include "../src/zombie.c"

/* ------------------------------------------------------------------------ */

static char* mixConnectRequestLines01() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET / HTTP/1.0\r\n";
	char prefix[] = "http://";
	char destination[10240];
	char* p = mixConnectRequestLines(connectLine, requestLine, prefix, destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines01: checking for equality", strcmp(p, "GET http://test.com:443/ HTTP/1.0\r\n") == 0);
	
	return 0;
}

static char* mixConnectRequestLines02() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET / HTTP/1.0\r\n";
	char prefix[] = "http://";
	char destination[5];
	char* p = mixConnectRequestLines(connectLine, requestLine, prefix, destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines02: checking for equality", strcmp(p, "GET ") == 0);
	
	return 0;
}

static char* mixConnectRequestLines03() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET / HTTP/1.0\r\n";
	char prefix[] = "http://";
	char destination[1];
	char* p = mixConnectRequestLines(connectLine, requestLine, prefix, destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines03: checking for equality", strcmp(p, "") == 0);
	
	return 0;
}

static char* mixConnectRequestLines04() {
	char requestLine[] = "GET / HTTP/1.0\r\n";
	char prefix[] = "http://";
	char destination[10240];
	char* p = mixConnectRequestLines(NULL, requestLine, prefix, destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines04: checking for equality", strcmp(p, "GET http:/// HTTP/1.0\r\n") == 0);
	
	return 0;
}

static char* mixConnectRequestLines05() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char prefix[] = "http://";
	char destination[10240];
	char* p = mixConnectRequestLines(connectLine, NULL, prefix, destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines05: checking for equality", strcmp(p, "http://test.com:443") == 0);
	
	return 0;
}

static char* mixConnectRequestLines06() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET / HTTP/1.0\r\n";
	char destination[10240];
	char* p = mixConnectRequestLines(connectLine, requestLine, NULL, destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines06: checking for equality", strcmp(p, "GET test.com:443/ HTTP/1.0\r\n") == 0);
	
	return 0;
}

static char* mixConnectRequestLines07() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET http://acme.com/ HTTP/1.0\r\n";
	char destination[10240];
	char* p = mixConnectRequestLines(connectLine, requestLine, "http://", destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines07: checking for equality", strcmp(p, "GET http://acme.com/ HTTP/1.0\r\n") == 0);
	
	return 0;
}

static char* mixConnectRequestLines08() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET proto://acme.com/ HTTP/1.0\r\n";
	char destination[10240];
	char* p = mixConnectRequestLines(connectLine, requestLine, "http://", destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines08: checking for equality", strcmp(p, "GET proto://acme.com/ HTTP/1.0\r\n") == 0);
	
	return 0;
}

static char* mixConnectRequestLines09() {
	char connectLine[] = "CONNECT test.com:443 HTTP/1.0\r\n";
	char requestLine[] = "GET proto://acme.com/ HTTP/1.0\r\n";
	char destination[10240];
	char* p = mixConnectRequestLines(connectLine, requestLine, "", destination, sizeof(destination));
	
	ASSERT("mixConnectRequestLines09: checking for equality", strcmp(p, "GET proto://acme.com/ HTTP/1.0\r\n") == 0);
	
	return 0;
}

static char* shortenRawInitialRequestLine01() {
	char s1[] = "GET http://test HTTP/1.0";
	char s2[sizeof(s1)];
	PRUint32 s = shortenRawInitialRequestLine(s1, sizeof(s1), s2, sizeof(s2));
	
	ASSERT("shortenRawInitialRequestLine01: check size", s == 15);
	ASSERT("shortenRawInitialRequestLine01: check value", strcmp(s2, "GET / HTTP/1.0") == 0);
	
	return 0;
}

static char* shortenRawInitialRequestLine02() {
	char s1[] = "GET http://test/ HTTP/1.0";
	char s2[sizeof(s1)];
	PRUint32 s = shortenRawInitialRequestLine(s1, sizeof(s1), s2, sizeof(s2));
	
	ASSERT("shortenRawInitialRequestLine02: check size", s == 15);
	ASSERT("shortenRawInitialRequestLine02: check value", strcmp(s2, "GET / HTTP/1.0") == 0);
	
	return 0;
}

static char* shortenRawInitialRequestLine03() {
	char s1[] = "GET / HTTP/1.0";
	char s2[sizeof(s1)];
	PRUint32 s = shortenRawInitialRequestLine(s1, sizeof(s1), s2, sizeof(s2));
	
	ASSERT("shortenRawInitialRequestLine03: check size", s == 15);
	ASSERT("shortenRawInitialRequestLine03: check value", strcmp(s2, "GET / HTTP/1.0") == 0);
	
	return 0;
}

static char* shortenRawInitialRequestLine04() {
	char s1[] = "GET HTTP/1.0";
	char s2[sizeof(s1)];
	PRUint32 s = shortenRawInitialRequestLine(s1, sizeof(s1), s2, sizeof(s2));
	
	ASSERT("shortenRawInitialRequestLine04: check size", s == 3);
	
	return 0;
}

static char* shortenRawInitialRequestLine05() {
	char s1[] = "GET / HTTP/1.0";
	char s2[1];
	PRUint32 s = shortenRawInitialRequestLine(s1, sizeof(s1), s2, sizeof(s2));
	
	ASSERT("shortenRawInitialRequestLine03: check size", s == 1);
	
	return 0;
}

/* ------------------------------------------------------------------------ */

static char* all() {
	RUN(mixConnectRequestLines01);
	RUN(mixConnectRequestLines02);
	RUN(mixConnectRequestLines03);
	RUN(mixConnectRequestLines04);
	RUN(mixConnectRequestLines05);
	RUN(mixConnectRequestLines06);
	RUN(mixConnectRequestLines07);
	RUN(mixConnectRequestLines08);
	RUN(mixConnectRequestLines09);
	RUN(shortenRawInitialRequestLine01);
	RUN(shortenRawInitialRequestLine02);
	RUN(shortenRawInitialRequestLine03);
	RUN(shortenRawInitialRequestLine04);
	RUN(shortenRawInitialRequestLine05);
	
	// ---
	
	return 0;
}

/* ------------------------------------------------------------------------ */

int main(int argc, char** argv) {
	char* result = all();
	
	// ---
	
	if (result != 0) {
		printf("%s\n", result);
	} else {
		printf("ALL TESTS PASSED\n");
	}
	
	// ---
	
	printf("Tests run: %d\n", tests_run);
	
	// ---
	
	return result != 0;
}
