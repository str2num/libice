#BUILDMAKE edit-mode: -*- Makefile -*-
####################64Bit Mode####################
ifeq ($(shell uname -m), x86_64)
CC=gcc
CXX=g++
CPPFLAGS=-D_GNU_SOURCE \
  -D__STDC_LIMIT_MACROS \
  -DVERSION=\"1.9.8.7\"
CFLAGS=-g \
  -pipe \
  -W \
  -Wall \
  -fPIC
CXXFLAGS=-g \
  -pipe \
  -W \
  -Wall \
  -fPIC \
  -std=gnu++11
INCPATH=-I. \
  -I./include \
  -I./output \
  -I./output/include \
  -I../src \
  -I../../librtcbase/output/include \
  -I../output/include
DEP_INCPATH=


#BUILDMAKE UUID
BUILDMAKE_MD5=20bb0b9cf1844a7a067ff1123494f4c0  BUILDMAKE


.PHONY:all
all:buildmake_makefile_check test 
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mall[0m']"
	@echo "make all done"

PHONY:buildmake_makefile_check
buildmake_makefile_check:
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mbuildmake_makefile_check[0m']"
	#in case of error, update "Makefile" by "buildmake"
	@echo "$(BUILDMAKE_MD5)" > buildmake.md5
	@md5sum -c --status buildmake.md5
	@rm -f buildmake.md5

.PHONY:clean
clean:
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mclean[0m']"
	rm -rf test
	rm -rf ./output/bin/test
	rm -rf test_allocation_sequence_test.o
	rm -rf test_p2p_transport_channel_test.o
	rm -rf test_port_allocator_test.o
	rm -rf test_test.o

.PHONY:dist
dist:
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mdist[0m']"
	tar czvf output.tar.gz output
	@echo "make dist done"

.PHONY:distclean
distclean:clean
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mdistclean[0m']"
	rm -f output.tar.gz
	@echo "make distclean done"

.PHONY:love
love:
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mlove[0m']"
	@echo "make love done"

test:test_allocation_sequence_test.o \
  test_p2p_transport_channel_test.o \
  test_port_allocator_test.o \
  test_test.o \
  ../libice.a \
  ../../librtcbase/output/lib/librtcbase.a \
  ../../librtcbase/deps/libev-4.11/lib/libev.a
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mtest[0m']"
	$(CXX) test_allocation_sequence_test.o \
  test_p2p_transport_channel_test.o \
  test_port_allocator_test.o \
  test_test.o -Xlinker "-(" ../libice.a \
  ../../librtcbase/output/lib/librtcbase.a \
  ../../librtcbase/deps/libev-4.11/lib/libev.a  -lpthread \
  -lcrypto \
  -lrt -Xlinker "-)" -o test
	mkdir -p ./output/bin
	cp -f --link test ./output/bin

test_allocation_sequence_test.o:allocation_sequence_test.cpp
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mtest_allocation_sequence_test.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o test_allocation_sequence_test.o allocation_sequence_test.cpp

test_p2p_transport_channel_test.o:p2p_transport_channel_test.cpp
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mtest_p2p_transport_channel_test.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o test_p2p_transport_channel_test.o p2p_transport_channel_test.cpp

test_port_allocator_test.o:port_allocator_test.cpp
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mtest_port_allocator_test.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o test_port_allocator_test.o port_allocator_test.cpp

test_test.o:test.cpp \
  test.h
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mtest_test.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o test_test.o test.cpp

endif #ifeq ($(shell uname -m), x86_64)


