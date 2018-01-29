#!/bin/bash

doxygen Doxyfile
RET=$?
if [ $RET -ne 0 ]; then
	exit $RET
fi

./autogen.sh
RET=$?
if [ $RET -ne 0 ]; then
	exit $RET
fi

./configure --disable-all-drivers --enable-pslela --enable-fx2lafw
RET=$?
if [ $RET -ne 0 ]; then
	exit $RET
fi

make -j 4
RET=$?
if [ $RET -ne 0 ]; then
	exit $RET
fi

