ifdef DEBUG
	CFLAGS=-Wall -O0 -ggdb -Wno-pointer-sign
else
	CFLAGS=-Wall -O3 -Wno-pointer-sign -I /usr/local/Cellar/nspr/4.10/include/nspr/ -L /usr/local/Cellar/nspr/4.10/lib/ -I /usr/local/Cellar/nss/3.14.1/include/nss/ -L /usr/local/Cellar/nss/3.14.1/lib/
endif

LDFLAGS=-lnspr4 -lplds4 -lnss3 -lssl3 -lplc4

debug: CFLAGS += -DDEBUG
debug: release test

release: src/*.h src/*.c
	mkdir -p obj
	$(CC) -o obj/proxify $(CFLAGS) src/*.c $(LDFLAGS) $(CCINCLUDES) $(CCLIBS)

test: src/*.h src/*.c tst/*.h tst/*.c
	mkdir -p obj
	$(CC) -o obj/proxify-test $(CFLAGS) tst/*.c $(LDFLAGS) $(CCINCLUDES) $(CCLIBS)
	obj/proxify-test

clean:
	rm -rf obj
