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
BUILDMAKE_MD5=5a3cc0df3b24124dd18a8422ca1d8443  BUILDMAKE


.PHONY:all
all:buildmake_makefile_check peerconnection 
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
	rm -rf peerconnection
	rm -rf ./output/bin/peerconnection
	rm -rf peerconnection_main.o
	rm -rf peerconnection_peerconnection.o
	rm -rf peerconnection_worker.o

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

peerconnection:peerconnection_main.o \
  peerconnection_peerconnection.o \
  peerconnection_worker.o \
  ../libice.a \
  ../../librtcbase/output/lib/librtcbase.a \
  ../../librtcbase/deps/libev/lib/libev.a
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mpeerconnection[0m']"
	$(CXX) peerconnection_main.o \
  peerconnection_peerconnection.o \
  peerconnection_worker.o -Xlinker "-(" ../libice.a \
  ../../librtcbase/output/lib/librtcbase.a \
  ../../librtcbase/deps/libev/lib/libev.a  -lpthread \
  -lcrypto \
  -lrt -Xlinker "-)" -o peerconnection
	mkdir -p ./output/bin
	cp -f --link peerconnection ./output/bin

peerconnection_main.o:main.cpp \
  worker.h \
  peerconnection.h
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mpeerconnection_main.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o peerconnection_main.o main.cpp

peerconnection_peerconnection.o:peerconnection.cpp \
  peerconnection.h
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mpeerconnection_peerconnection.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o peerconnection_peerconnection.o peerconnection.cpp

peerconnection_worker.o:worker.cpp \
  worker.h \
  peerconnection.h
	@echo "[[1;32;40mBUILDMAKE:BUILD[0m][Target:'[1;32;40mpeerconnection_worker.o[0m']"
	$(CXX) -c $(INCPATH) $(DEP_INCPATH) $(CPPFLAGS) $(CXXFLAGS)  -o peerconnection_worker.o worker.cpp

endif #ifeq ($(shell uname -m), x86_64)


