make pr
for w in 4 8 16 32 64 128 256 512
do
	for h in 4 8 16 32 64
	do
		./Bin1 $h $w 0.1 
		# echo "$h $w"
	done
	echo "---------- w = $w -----------"
done
