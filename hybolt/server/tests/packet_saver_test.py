from pathlib import Path

from hybolt.server.packet_saver import PacketSaver
from hybolt.encryption.block import Block


def test_given_packets_and_servers_when_saving_then_distributes_packets(tmp_path):
    packets = [Block(0, 1, [0], b"data1")]
    input_path = Path("test.txt")
    server_list = [{"id": 1, "storage_location": str(tmp_path / "server1")}]

    saver = PacketSaver(packets, input_path, server_list=server_list)

    saver.save()

    server_dir = tmp_path / "server1"
    assert (server_dir / "test_packet_0.pkl").exists()
    assert packets[0].server is not None
    assert packets[0].server._storage_location == str(server_dir)


def test_given_multiple_packets_and_servers_when_saving_then_assigns_each_block_a_server(
    tmp_path,
):
    packets = [
        Block(0, 1, [0], b"data1"),
        Block(1, 1, [1], b"data2"),
    ]
    input_path = Path("test.txt")
    server_list = [
        {"id": 1, "storage_location": str(tmp_path / "server1")},
        {"id": 2, "storage_location": str(tmp_path / "server2")},
    ]

    saver = PacketSaver(packets, input_path, server_list=server_list)

    saver.save()

    assert packets[0].server is not None
    assert packets[1].server is not None
    assert packets[0].server._storage_location in {
        str(tmp_path / "server1"),
        str(tmp_path / "server2"),
    }
    assert packets[1].server._storage_location in {
        str(tmp_path / "server1"),
        str(tmp_path / "server2"),
    }


def _server_dirs(tmp_path, count):
    return [
        {"id": index, "storage_location": str(tmp_path / f"server{index}")}
        for index in range(count)
    ]


def test_given_many_packets_when_saving_then_balances_load_across_servers(tmp_path):
    packets = [Block(index, 1, [index], b"data") for index in range(10)]
    server_list = _server_dirs(tmp_path, 3)

    PacketSaver(packets, Path("test.txt"), server_list=server_list).save()

    counts = [
        len(list((tmp_path / f"server{index}").glob("*.pkl"))) for index in range(3)
    ]
    assert sorted(counts) == [3, 3, 4]


def test_given_shuffled_packets_when_saving_then_server_follows_shuffled_position(
    tmp_path, monkeypatch
):
    packets = [Block(index, 1, [index], b"data") for index in range(4)]
    server_list = _server_dirs(tmp_path, 2)
    monkeypatch.setattr(
        "hybolt.server.packet_saver.random.shuffle", lambda items: items.reverse()
    )

    saver = PacketSaver(packets, Path("test.txt"), server_list=server_list)
    saver.save()

    servers = {meta.packet_index: meta.server for meta in saver.packet_metadata}
    assert servers[3] == str(tmp_path / "server0")
    assert servers[2] == str(tmp_path / "server1")
    assert servers[1] == str(tmp_path / "server0")
    assert servers[0] == str(tmp_path / "server1")
