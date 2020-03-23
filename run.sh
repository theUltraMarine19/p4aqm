#!/bin/bash

###--- Remove stale json
for j in `seq 1 1`	# Change!
do
	rm ./json/ecn.json  # Change!
done

###--- Setup Environment
sudo rm -f *.pcap
sudo mn -c
THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ) # get the current working directory
THRIFT_BASE_PORT=9090

source env.sh

P4C=$P4C_PATH

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch # executable to start the switch

# CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py
CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py # runtime CLI for switch

###--- Read topo, create json dump of topology
cd topology
python3 topo_to_json.py
cd ..

# This reads the topo.txt file and creates a dictionary with the following things:
# 1. Number of switches
# 2. Number of hosts
# 3. All the links (pair)

# ------------------------------------------------------------

# ###--- Compile p4 for all switches
for j in `seq 1 $(echo $(head -n 1 topology/topo.txt) | cut -d ' ' -f 2)`
do
    # cd p4/   # Change!
    $P4C --target bmv2 --arch v1model ecn.p4 ; mv ecn.json json/ ; rm ecn.p4i   # Change!
    # cd -     # Change!  
done

###--- Burn json for each switch individually using start_mininet.py

# Change! --json
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python start_mininet.py \
    --behavioral-exe $SWITCH_PATH \
    --json ./json/ecn \
    --cli $CLI_PATH
