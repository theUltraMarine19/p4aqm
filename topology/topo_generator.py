import sys

if(len(sys.argv) < 2):
	print("format: python topo_generator.py <number of switches>")
	exit(0)

num_switches = int(sys.argv[1])

with open('topo.txt','w') as f:
	f.write('switches %d\n'%num_switches)
	f.write('hosts %d\n'%num_switches)

	host_id = 1
	for i in range(num_switches):
		f.write('h%d s%d\n' % (host_id,i+1))
		host_id+=1

	for i in range(num_switches):
		f.write('s%d s%d\n' % (i+1, (i+1)%num_switches+1))