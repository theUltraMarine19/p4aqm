cd pkt_gen ; make all ; cd ..
pkt_gen/Bin 10.0.0.1 12300 2200 8900 &
# pkt_gen/Bin 10.0.0.1 12305 2200 5950 &
# pkt_gen/Bin 10.0.0.1 12310 2200 5300 &
pkt_gen/Bin 10.0.0.1 12325 900 2300 &
# sleep 1.0
pkt_gen/Bin 10.0.0.1 12330 500 2900 &
# sleep 2.5
pkt_gen/Bin 10.0.0.1 12335 900 2700 &
sleep 15