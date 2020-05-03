make all
for h in 4 8 16 32 64
do
	for w in 4 8 16 32 64 128 256 512
	do
		./Bin $h $w 
		# echo "$h $w"
	done
	echo "--------- h = ${h} ----------"
done
