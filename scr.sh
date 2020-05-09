cd pkt_gen ; make all ; cd ..
pkt_gen/Bin 10.0.0.1 12300 2200 7900 &
pkt_gen/Bin 10.0.0.1 12305 2200 7950 &
pkt_gen/Bin 10.0.0.1 12310 2200 7300 &
pkt_gen/Bin 10.0.0.1 12325 900 1500 &
sleep 1.0
pkt_gen/Bin 10.0.0.1 12330 500 2100 &
sleep 2.5
pkt_gen/Bin 10.0.0.1 12335 900 1800 &
sleep 10