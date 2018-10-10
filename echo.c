#include <stdio.h>
#include <curses.h>

/* ------------------------------------------------------------------------ */

int main(int argc, char** argv) {
	char c;
	
	// ---
	
	fprintf(stderr, ">>> echo started\n");
	
	// ---
	
	initscr();
	clear();
	noecho();
	cbreak();
	
	// ---
	
	while ((c = getch()) != EOF) {
		putc(c, stdout);
		putc(c, stderr);
	}
	
	// ---
	
	clrtoeol();
	refresh();
	
	// ---
	
	return 0;
}
