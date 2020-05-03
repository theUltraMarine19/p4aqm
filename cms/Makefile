include ~/Documents/PcapPlusPlus/mk/PcapPlusPlus.mk

# All Target
all:
	g++ -std=c++11 $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ -std=c++11 $(PCAPPP_LIBS_DIR) -static-libstdc++ -o Bin main.o count_min_sketch.cpp $(PCAPPP_LIBS)
	rm main.o

pr:
	g++ -std=c++11 $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main_pr.cpp
	g++ -std=c++11 $(PCAPPP_LIBS_DIR) -static-libstdc++ -o Bin1 main.o count_min_sketch.cpp $(PCAPPP_LIBS)
	rm main.o

# Clean Target
clean:
	rm main.o
	rm Bin
