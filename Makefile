# ISO Builder (C++) — compilação simples:  make
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
LDFLAGS  += -pthread

SRC = src/main.cpp src/iso_builder.cpp
HDR = src/iso_builder.hpp src/sha512.hpp third_party/httplib.h

iso-builder: $(SRC) $(HDR)
	$(CXX) $(CXXFLAGS) -Ithird_party $(SRC) -o $@ $(LDFLAGS)

clean:
	rm -f iso-builder

.PHONY: clean
