# include <iostream>
# include <map>
# include <cstdlib>
# include <cmath>
# include "count_min_sketch.hpp"
using namespace std;

int main(int argc, char **argv) {
  
    int h = 4, w = 4, d = 4;
    
    int hashes[][4] = { { 0x04C11DB7, 0x0DB88320, 0x0B710641, 0x02608EDB }, { 0x041B8CD7, 0x0B31D82E, 0x0D663B05, 0x0A0DC66B }, { 0x02583499, 0x092C1A4C, 0x0D663B05, 0x0A0DC66B }, { 0x02583499, 0x04C11DB7, 0x0B710641, 0x041B8CD7 } };   
    
    CountMinSketch c[4];
    for (int i = 0; i < h; i++) {
        c[i].set(w, d, hashes[i]);
    }
    unsigned int i, total = 0;

    for (int i = 0; i < 4; i++) {
        c[0].update(5, 1);
    }

    cout << c[0].estimate(5) << endl;

    return 0;
}


