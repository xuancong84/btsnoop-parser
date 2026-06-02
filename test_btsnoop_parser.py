from datetime import datetime
from pathlib import Path

from btsnoop_parser import filter_packets, parse_file, iter_packets, write_csv, write_json

SAMPLE = Path('/mnt/data/btsnoop_hci1929.log.txt.gz')


def test_parse_sample_has_packets():
    packets = parse_file(SAMPLE)
    assert len(packets) > 100
    assert packets[0].number == 1
    assert packets[0].packet_type == 'HCI_CMD'
    assert packets[0].source == 'host'
    assert packets[0].destination == 'controller'
    assert packets[0].payload_hex.startswith('01030c00')


def test_packet_type_filter():
    packets = parse_file(SAMPLE)
    cmds = filter_packets(packets, packet_type='HCI_CMD')
    evts = filter_packets(packets, packet_type='HCI_EVT')
    assert cmds
    assert evts
    assert all(p.packet_type == 'HCI_CMD' for p in cmds)
    assert all(p.packet_type == 'HCI_EVT' for p in evts)


def test_datetime_filter():
    packets = parse_file(SAMPLE)
    subset = filter_packets(
        packets,
        from_datetime='2026-05-31 19:29:36.838015',
        to_datetime='2026-05-31 19:29:36.840217',
    )
    assert [p.number for p in subset] == [2, 3]


def test_source_destination_direction_filters():
    packets = parse_file(SAMPLE)
    sent = filter_packets(packets, source='host', destination='controller', direction='Sent')
    received = filter_packets(packets, source='controller', destination='host', direction='Rcvd')
    assert sent
    assert received
    assert all(p.source == 'host' and p.destination == 'controller' for p in sent)
    assert all(p.source == 'controller' and p.destination == 'host' for p in received)


def test_text_and_any_mac_filter():
    packets = parse_file(SAMPLE)
    bd_addr_packets = filter_packets(packets, text='BD_ADDR')
    assert any('00:fa:de:0a:86:95' in p.addresses for p in bd_addr_packets)
    by_mac = filter_packets(packets, any_mac='00:fa:de:0a:86:95')
    assert by_mac
    assert all('00:fa:de:0a:86:95' in p.addresses for p in by_mac)


def test_export_json_and_csv(tmp_path):
    packets = filter_packets(iter_packets(SAMPLE), packet_type='HCI_CMD')[:3]
    json_path = tmp_path / 'out.json'
    csv_path = tmp_path / 'out.csv'
    write_json(packets, json_path)
    write_csv(packets, csv_path)
    assert json_path.read_text().lstrip().startswith('[')
    assert 'packet_type' in csv_path.read_text().splitlines()[0]
