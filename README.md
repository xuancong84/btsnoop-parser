# BTSnoop text parser

This project provides an example python code to control bluetooth speaker LG-XO3Q(C3) by capturing bluetooth packets using Android HCI btsnoop log and analyzing them using tshark.

For LG-XO3Q(C3) bluetooth speaker (or other similar bluetooth speakers), disconnecting the bluetooth (using `bluetoothctl disconnect <speaker-mac>`) will NOT put the speaker into standby mode, neither will it turn off the speaker RGB light. You will need to send a specific command (that is proprietary) to trigger a host-initiated disconnect.

For btsnoop parser, you first need to connect your Android phone to your PC; run `capture.sh` to generate the report that will contain btsnoop log and convert it into text using `tshark`; then you can run `btsnoop_parser.py` to parse and filter the Wireshark/tshark text exports of Bluetooth btsnoop/HCI logs.


## Requirements
- adb : for connecting to Android devices to get HCI btsnoop log.
- tshark : for parsing btsnoop log.
- python3 : for analyzing btsnoop log.

## Run examples

### For LG-XO3Q(C3) bluetooth speaker control:
To toggle speaker light:

`sudo ./lg_xboom_ctl.py -mac <your-speaker-mac> toggle_light`

To disconnect and enter standby:

`sudo ./lg_xboom_ctl.py -mac <your-speaker-mac> enter_standby`

To set RGB light (to red):

`sudo ./lg_xboom_ctl.py -mac <your-speaker-mac> set_rgb ff0000`


### For the btsnoop parser:
```bash
python btsnoop_parser.py btsnoop_hci.txt.gz --packet-type HCI_CMD --limit 5
python btsnoop_parser.py btsnoop_hci.txt.gz --from-datetime "2026-05-31 19:29:36.838015" --to-datetime "2026-05-31 19:29:36.840217"
python btsnoop_parser.py btsnoop_hci.txt.gz --any-mac 00:fa:de:0a:86:95 --format json
python btsnoop_parser.py btsnoop_hci.txt.gz --source host --destination controller --direction Sent --format csv -o sent.csv
```
