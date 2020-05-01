include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ -std=c++11 $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main_test.cpp
	g++ -std=c++11 $(PCAPPP_LIBS_DIR) -static-libstdc++ -o Bin main.o $(PCAPPP_LIBS)
	rm main.o

# Clean Target
clean:
	rm main.o
	rm Bin
