#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"

#define BUCKET_SIZE 128
#define CELL_SIZE 32

// Can read from atmost 2
#define NUM_SNAPSHOTS 4 
#define NUM_PKTS_PER_SNAPSHOT 512
#define LOG_NUM_PKTS_PER_SNAPSHOT 9

#define COMPUTE(num) compute##num() 

typedef bit<9>  egressSpec_t;

const bit<19> ECN_THRESHOLD = 50; // 3
const bit<19> CONG_FRAC_INV = 10; // 4
const bit<32> E2E_CLONE_SESSION_ID_H1 = 500;
const bit<32> E2E_CLONE_SESSION_ID_H2 = 450;
const bit<32> E2E_CLONE_SESSION_ID_H3 = 400;
const bit<32> E2E_CLONE_SESSION_ID_H4 = 300;
const bit<32> QD_THRESHOLD = 20; // us
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE = 2;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

	action no_op() {}

	action drop() {
        mark_to_drop(standard_metadata);
    }

	action ipv4_forward(bit<9> port) {
		standard_metadata.egress_spec = port;
		// Not making modifications to L2 MAC addresses
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	table ipv4_fwd {
		key = {
			hdr.ipv4.dstAddr : exact;
		}
		actions = {
			ipv4_forward;
			drop;
			no_op;
		}
		default_action = no_op();
	}

	apply {
		// put pkt on destined egress port
		if (hdr.ipv4.isValid())
			ipv4_fwd.apply();		
	}

}


// No checksum verification
control vrfy(inout headers h, inout metadata meta) { apply {} }

// No checksum update
control updt(inout headers h, inout metadata meta) { apply {} }

// No per-port specific modification in egress
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
	
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg11;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg12;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg13;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg14;

	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg21;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg22;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg23;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg24;

	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg31;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg32;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg33;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg34;

	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg41;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg42;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg43;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg44;

	register<bit<CELL_SIZE>>(1) cnt;

	action no_op() {}

	action mark_ecn() {
		hdr.ipv4.ecn = 3;
		hdr.udp.checksum = (bit<16>)standard_metadata.deq_qdepth;; // Queue length at enqueue
		// Not using queueing delay yet
	}

	action compute1() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx11, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg11.read(meta.val11, meta.idx11);
		meta.val11 = meta.val11 + 1;
		reg11.write(meta.idx11, meta.val11);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx12, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg12.read(meta.val12, meta.idx12);
		meta.val12 = meta.val12 + 1;
		reg12.write(meta.idx12, meta.val12);
		
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx13, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg13.read(meta.val13, meta.idx13);
		meta.val13 = meta.val13 + 1;
		reg13.write(meta.idx13, meta.val13);
		
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx14, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg14.read(meta.val14, meta.idx14);
		meta.val14 = meta.val14 + 1;
		reg14.write(meta.idx14, meta.val14);
	}

	action compute2() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx21, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg21.read(meta.val21, meta.idx21);
		meta.val21 = meta.val21 + 1;
		reg21.write(meta.idx21, meta.val21);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx22, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg22.read(meta.val22, meta.idx22);
		meta.val22 = meta.val22 + 1;
		reg22.write(meta.idx22, meta.val22);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx23, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg23.read(meta.val23, meta.idx23);
		meta.val23 = meta.val23 + 1;
		reg23.write(meta.idx23, meta.val23);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx24, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg24.read(meta.val24, meta.idx24);
		meta.val24 = meta.val24 + 1;
		reg24.write(meta.idx24, meta.val24);
	}

	action compute3() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx31, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg31.read(meta.val31, meta.idx31);
		meta.val31 = meta.val31 + 1;
		reg31.write(meta.idx31, meta.val31);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx32, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg32.read(meta.val32, meta.idx32);
		meta.val32 = meta.val32 + 1;
		reg32.write(meta.idx32, meta.val32);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx33, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg33.read(meta.val33, meta.idx33);
		meta.val33 = meta.val33 + 1;
		reg33.write(meta.idx33, meta.val33);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx34, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg34.read(meta.val34, meta.idx34);
		meta.val34 = meta.val34 + 1;
		reg34.write(meta.idx34, meta.val34);
	}

	action compute4() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx41, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg41.read(meta.val41, meta.idx41);
		meta.val41 = meta.val41 + 1;
		reg41.write(meta.idx41, meta.val41);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx42, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg42.read(meta.val42, meta.idx42);
		meta.val42 = meta.val42 + 1;
		reg42.write(meta.idx42, meta.val42);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx43, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg43.read(meta.val43, meta.idx43);
		meta.val43 = meta.val43 + 1;
		reg43.write(meta.idx43, meta.val43);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx44, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg44.read(meta.val44, meta.idx44);
		meta.val44 = meta.val44 + 1;
		reg44.write(meta.idx44, meta.val44);
	}

	// Owing to recycled snapshots 
	

	action read1() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx11, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx12, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx13, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx14, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg11.read(meta.val11, meta.idx11);
		reg12.read(meta.val12, meta.idx12);
		reg13.read(meta.val13, meta.idx13);
		reg14.read(meta.val14, meta.idx14);
		// meta.min1 = 32w2147483647;
		// if (meta.val11 != 0)
		// 	meta.min1 = meta.val11;
		// if (meta.val12 < meta.min1 && meta.val12 != 0)
		// 	meta.min1 = meta.val12;
		// if (meta.val13 < meta.min1 && meta.val13 != 0)
		// 	meta.min1 = meta.val13;
		// if (meta.val14 < meta.min1 && meta.val14 != 0)
		// 	meta.min1 = meta.val14;
		// if (meta.min1 == 32w2147483647)
		// 	meta.min1 = 32w0;

		meta.min1 = meta.val11;
		if (meta.val12 < meta.min1)
			meta.min1 = meta.val12;
		if (meta.val13 < meta.min1)
			meta.min1 = meta.val13;
		if (meta.val14 < meta.min1)
			meta.min1 = meta.val14;
	}

	action read2() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx21, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx22, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx23, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx24, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg21.read(meta.val21, meta.idx21);
		reg22.read(meta.val22, meta.idx22);
		reg23.read(meta.val23, meta.idx23);
		reg24.read(meta.val24, meta.idx24);
		// meta.min2 = 32w2147483647;
		// if (meta.val21 != 0)
		// 	meta.min2 = meta.val21;
		// if (meta.val22 < meta.min2 && meta.val22 != 0)
		// 	meta.min2 = meta.val22;
		// if (meta.val23 < meta.min2 && meta.val23 != 0)
		// 	meta.min2 = meta.val23;
		// if (meta.val24 < meta.min2 && meta.val24 != 0)
		// 	meta.min2 = meta.val24;
		// if (meta.min2 == 32w2147483647)
		// 	meta.min2 = 32w0;

		meta.min2 = meta.val21;
		if (meta.val22 < meta.min2)
			meta.min2 = meta.val22;
		if (meta.val23 < meta.min2)
			meta.min2 = meta.val23;
		if (meta.val24 < meta.min2)
			meta.min2 = meta.val24;
	}

	action read3() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx31, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx32, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx33, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx34, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg31.read(meta.val31, meta.idx31);
		reg32.read(meta.val32, meta.idx32);
		reg33.read(meta.val33, meta.idx33);
		reg34.read(meta.val34, meta.idx34);
		// meta.min3 = 32w2147483647;
		// if (meta.val31 != 0)
		// 	meta.min3 = meta.val31;
		// if (meta.val32 < meta.min3 && meta.val32 != 0)
		// 	meta.min3 = meta.val32;
		// if (meta.val33 < meta.min3 && meta.val33 != 0)
		// 	meta.min3 = meta.val33;
		// if (meta.val34 < meta.min3 && meta.val34 != 0)
		// 	meta.min3 = meta.val34;
		// if (meta.min3 == 32w2147483647)
		// 	meta.min3 = 32w0;

		meta.min3 = meta.val31;
		if (meta.val32 < meta.min3)
			meta.min3 = meta.val32;
		if (meta.val33 < meta.min3)
			meta.min3 = meta.val33;
		if (meta.val34 < meta.min3)
			meta.min3 = meta.val34;
	}

	action read4() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx41, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx42, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx43, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx44, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg41.read(meta.val41, meta.idx41);
		reg42.read(meta.val42, meta.idx42);
		reg43.read(meta.val43, meta.idx43);
		reg44.read(meta.val44, meta.idx44);
		meta.min4 = 32w2147483647;
		// if (meta.val41 != 0)
		// 	meta.min4 = meta.val41;
		// if (meta.val42 < meta.min4 && meta.val42 != 0)
		// 	meta.min4 = meta.val42;
		// if (meta.val43 < meta.min4 && meta.val43 != 0)
		// 	meta.min4 = meta.val43;
		// if (meta.val44 < meta.min4 && meta.val44 != 0)
		// 	meta.min4 = meta.val44;
		// if (meta.min4 == 32w2147483647)
		// 	meta.min4 = 32w0;

		meta.min4 = meta.val41;
		if (meta.val42 < meta.min4)
			meta.min4 = meta.val42;
		if (meta.val43 < meta.min4)
			meta.min4 = meta.val43;
		if (meta.val44 < meta.min4)
			meta.min4 = meta.val44;
	}

	table invoke {
		key = {
			meta.ws : exact;
		}
		actions = {
			COMPUTE(1);
			COMPUTE(2);
			COMPUTE(3);
			COMPUTE(4);			
		}
	}

	action clear1() {
		bit<32> idx = meta.cnt & (BUCKET_SIZE-1);
		reg11.write(idx, 0);
		reg12.write(idx, 0);
		reg13.write(idx, 0);
		reg14.write(idx, 0);
	}

	action clear2() {
		bit<32> idx = meta.cnt & (BUCKET_SIZE-1);
		reg21.write(idx, 0);
		reg22.write(idx, 0);
		reg23.write(idx, 0);
		reg24.write(idx, 0);
	}

	action clear3() {
		bit<32> idx = meta.cnt & (BUCKET_SIZE-1);
		reg31.write(idx, 0);
		reg32.write(idx, 0);
		reg33.write(idx, 0);
		reg34.write(idx, 0);
	}

	action clear4() {
		bit<32> idx = meta.cnt & (BUCKET_SIZE-1);
		reg41.write(idx, 0);
		reg42.write(idx, 0);
		reg43.write(idx, 0);
		reg44.write(idx, 0);
	}

	table clear {
		key = {
			meta.ws : exact;
		}
		actions = {
			clear1;
			clear2;
			clear3;
			clear4;
		}
	}

	action clone_h1() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H1, {standard_metadata}); // clone the pkt
	}

	action clone_h2() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H2, {standard_metadata}); // clone the pkt
	}

	action clone_h3() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H3, {standard_metadata}); // clone the pkt
	}

	action clone_h4() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H4, {standard_metadata}); // clone the pkt
	}

	table hclone {
		key = { 
			hdr.ipv4.srcAddr : exact; 
		}
		actions = { 
			clone_h1; 
			clone_h2; 
			clone_h3; 
			clone_h4; 
		}
	}

	action read1_0() {
		read4();
		meta.total = meta.min4;
	}

	action read2_0() {
		read1();
		meta.total = meta.min1;
	}

	action read3_0() {
		read2();
		meta.total = meta.min2;
	}

	action read4_0() {
		read3();
		meta.total = meta.min3;
	}

	action read1_1() {
		read4();
		read3();
		meta.total = meta.min4+meta.min3;
	}

	action read2_1() {
		read1();
		read4();
		meta.total = meta.min1+meta.min4;
	}

	action read3_1() {
		read2();
		read1();
		meta.total = meta.min2+meta.min1;
	}

	action read4_1() {
		read3();
		read2();
		meta.total = meta.min3+meta.min2;
	}

	table reader {
		key = {
			meta.ws : exact;
			meta.diff : exact;
		}
		actions = {
			read1_0;
			read2_0;
			read3_0;
			read4_0;
			read1_1;
			read2_1;
			read3_1;
			read4_1;
			no_op;
		}
		const default_action = no_op();
	}


	apply {
		// Cloned pkt
		if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
			// return the pkt to host (port already set)
			// standard_metadata fields have been preserved
			macAddr_t tempMac;
            tempMac = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = tempMac;

            ip4Addr_t tempip4;
            tempip4 = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = tempip4;

            bit<16> tempPort;
            tempPort = hdr.udp.srcPort;
            hdr.udp.srcPort = hdr.udp.dstPort;
            hdr.udp.dstPort = tempPort;

            // hdr.udp.checksum = (bit<16>)standard_metadata.deq_timedelta;
		}
		else if (hdr.debug.isValid()) { // No if-else nesting more than two levels
			
			// just to check the register values (Do it from switch_CLI)
			if (hdr.debug.ws == 5) {
				read1();
				read2();
				read3();
				read4();
				hdr.debug.min1 = meta.min1;
				hdr.debug.min2 = meta.min2;
				hdr.debug.min3 = meta.min3;
				hdr.debug.min4 = meta.min4;
				return;
			}

			// increment pkt counter
			cnt.read(meta.cnt, 0);
			meta.cnt = meta.cnt + 1;
			cnt.write(0, meta.cnt);

			// identify writing snapshot and hash into it
			meta.ws = (meta.cnt >> LOG_NUM_PKTS_PER_SNAPSHOT) & (NUM_SNAPSHOTS-1); // Both are almost equally precise
			bit<32> as = ((meta.cnt - (bit<32>)standard_metadata.enq_qdepth) >> LOG_NUM_PKTS_PER_SNAPSHOT) & (NUM_SNAPSHOTS-1);
			invoke.apply();

			if (meta.ws >= as)
				meta.diff = meta.ws - as-1;
			else
				meta.diff = meta.ws + NUM_SNAPSHOTS - as-1;
			
			reader.apply();		
			
			if (standard_metadata.deq_qdepth >= ECN_THRESHOLD) { // threshold on egress queue since egress proessing is more comp. intensive
				
				hclone.apply();
				
				// Mark for ECN
				// mark_ecn();

			}

			mark_ecn();

			clear.apply();

			hdr.debug.ws = (bit<32>)standard_metadata.enq_qdepth;
			hdr.debug.min1 = meta.diff;
			hdr.debug.min2 = meta.ws;
			hdr.debug.min3 = as;
			hdr.debug.min4 = meta.total;
			// hdr.debug.min4 = (bit<32>)standard_metadata.deq_qdepth;
		}		
		
	} 
}	

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;

// Debug configs

// hdr.debug.ws = meta.ws;
// hdr.debug.egr_ts = departure;
// hdr.debug.dep = standard_metadata.enq_timestamp + standard_metadata.deq_timedelta;	