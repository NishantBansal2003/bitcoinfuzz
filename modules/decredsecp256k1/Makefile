CXXFLAGS += -Wall -Wextra -std=c++20 -I. -I ../../include -I./decredsecp256k1_wrapper

all: module.a

module.a: golang module.o decredsecp256k1_wrapper/libdecredsecp256k1_wrapper.a
	bash ../../merge.sh module.a decredsecp256k1_wrapper/libdecredsecp256k1_wrapper.a module.o
	ranlib module.a

golang:
	cd decredsecp256k1_wrapper && go build -o libdecredsecp256k1_wrapper.a -buildmode=c-archive -tags=libfuzzer -gcflags=all=-d=libfuzzer wrapper.go

module.o: module.cpp
	$(CXX) $(CXXFLAGS) -lscript -L. -fPIC -c module.cpp -o module.o

clean:
	rm -f *.o *.a decredsecp256k1_wrapper/*.a
