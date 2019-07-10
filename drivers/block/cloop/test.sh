#/bin/sh -e

INPUTDEVICE="/tmp/file.fs"
OUTPUTFILE="/tmp/filefs.cloop.img"
BLOCKSIZE="1048576"
#NUMBLOCKS="2000"
NUMBLOCKS="200"
COMPRESSIONLEVEL="9"
#COMPRESSIONLEVEL="-1" # for 7zip compression (untested)
CLOOPLOGFILE="/tmp/cloop-creation.log"
CLOOPBLOCKSIZE="64K"


echo "-----------------> Clearing envs <..."
if [ -d /mnt/cloop ]; then
	umount /mnt/cloop/
	rmmod cloop
fi

echo "------------------> Making file fs <..."
dd if=/dev/zero of="$INPUTDEVICE" bs="$BLOCKSIZE" count="$NUMBLOCKS" | pv -s "$((NUMBLOCKS * BLOCKSIZE))" -Wpetr  
mkfs.ext4 $INPUTDEVICE

if [ ! -d /mnt/tmp ]; then
	mkdir /mnt/tmp
fi
mount $INPUTDEVICE /mnt/tmp 
touch /mnt/tmp/testfile
sleep .5
umount /mnt/tmp
echo "-------------------> Making compressed image <..."

dd if="$INPUTDEVICE"  bs="$BLOCKSIZE" count="$NUMBLOCKS" | pv -s "$((NUMBLOCKS * BLOCKSIZE))" -Wpetr | create_compressed_fs -L "$COMPRESSIONLEVEL" -B "$CLOOPBLOCKSIZE" -s "$NUMBLOCKS"M - "$OUTPUTFILE" > "$CLOOPLOGFILE" 2>&1

#insmod /lib/modules/`uname -r`/cloop.ko file="$OUTPUTFILE"
insmod ../../../../hyperblock_loop/drivers/block/cloop/cloop.ko file="$OUTPUTFILE"

mkdir -p /mnt/cloop
mount -o ro /dev/cloop0 /mnt/cloop
ls /mnt/cloop

