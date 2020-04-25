include ~/Documents/PcapPlusPlus/mk/PcapPlusPlus.mk

# All Target
all:
	g++ -std=c++11 $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -g -c -o main.o main.cpp
	g++ -std=c++11 $(PCAPPP_LIBS_DIR) -static-libstdc++ -g -o Bin main.o $(PCAPPP_LIBS)
	rm main.o

# Clean Target
clean:
	rm main.o
	rm Bin
