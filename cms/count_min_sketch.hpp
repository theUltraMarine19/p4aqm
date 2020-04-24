# define MIN(a,b)  (a < b ? a : b)

/** CountMinSketch class definition here **/
class CountMinSketch {
  // width, depth 
  unsigned int w,d;
  
  // total count so far
  unsigned int total; 

  // array of arrays of counters (P4 register arrays)
  int **C;

  // array of hash values for a particular item 
  // contains two element arrays {aj,bj}
  int *hashes;

public:
  // default constructor
  CountMinSketch();

  // constructor
  void set(int width, int depth, int* hash_gens);
  
  // update item (int) by count c
  void update(int item, int c);
  
  // estimate count of item i and return count
  unsigned int estimate(int item);
  
  // return total count
  unsigned int totalcount();

  void view_snapshot();

  // destructor
  ~CountMinSketch();
};


