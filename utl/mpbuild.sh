#!/bin/sh

if [ $DEBUG ]
then
	make debug CCINCLUDES='-I/opt/local/include/nspr/ -I/opt/local/include/nss/' CCLIBS='-L/opt/local/lib/nss/ -L/opt/local/lib/nspr/'
else
	make release CCINCLUDES='-I/opt/local/include/nspr/ -I/opt/local/include/nss/' CCLIBS='-L/opt/local/lib/nss/ -L/opt/local/lib/nspr/'
fi
