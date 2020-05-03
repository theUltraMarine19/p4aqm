make all
for w in 4 8 16 32 64 128 256 512
do
	for h in 4 8 16 32 64
	do
		./Bin $h $w 
		# echo "$h $w"
	done
	echo "--------- w = ${w} ----------"
done
