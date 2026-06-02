#!/bin/bash

if [[ " $* " =~ -[Yy] ]]; then
	echo yes
fi
exit


if [ -s bluetooth_capture.zip ]; then
	if [[ " $* " =~ -[Yy] ]]; then
		rm -rf bluetooth_capture.zip
	else
		echo -n "bluetooth_capture.zip already exists, delete it? (Y/n)"
		read f
		if [[ "$f" =~ -[Yy] ]]; then
			rm -rf bluetooth_capture.zip
		fi
	fi
fi

if [ ! -s bluetooth_capture.zip ]; then
	adb bugreport bluetooth_capture.zip
fi

unzip -o bluetooth_capture.zip

tshark -2 -V -P -t ad --hexdump all  --hexdump delimit -r FS/data/misc/bluetooth/logs/btsnoop_hci.log | gzip >btsnoop_hci.txt.gz

ls -al btsnoop_hci.txt.gz

echo "The output is in btsnoop_hci.txt.gz , you can now run btsnoop_parser.py on it."

