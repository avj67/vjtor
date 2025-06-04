#!/bin/bash
import json
import os
import random
import string
import sys
import socket
import struct
import urllib.parse

import bencodepy
import hashlib
import requests

from typing import Tuple, List, Optional


def find_bencoded_dict_bounds(data: bytes, start: int) -> Tuple[Optional[None], int]:
    """
    Finds the bounds of a bencoded dictionary in a byte sequence.
    Returns a tuple: (None, index after dict)
    """
    f = start + 1  # skip 'd'
    while data[f:f + 1] != b'e':
        # Parse key (bencoded strings)
        colon = data.find(b':', f)
        if colon == -1:
            raise ValueError('Invalid bencode: no colon found for key')
        strlen = int(data[f:colon])
        key_start = colon + 1
        key_end = key_start + strlen
        f = key_end
        # Now decode value based on the leading char
        if data[f:f + 1] == b'd':
            _, f = find_bencoded_dict_bounds(data, f)
        elif data[f:f + 1] == b'l':
            # find list end (could be recursive)
            depth = 1
            f += 1
            while depth > 0:
                if data[f:f + 1] == b'l':
                    depth += 1
                elif data[f:f + 1] == b'e':
                    depth -= 1
                elif data[f:f + 1] == b'd':
                    _, f = find_bencoded_dict_bounds(data, f)
                else:
                    # Skip value (string or int)
                    if data[f:f + 1] == b'i':
                        end = data.find(b'e', f)
                        f = end + 1
                    else:
                        colon = data.find(b':', f)
                        strlen = int(data[f:colon])
                        f = colon + 1 + strlen
                if depth > 0:
                    pass
            f += 1
        elif data[f:f + 1] == b'i':
            end = data.find(b'e', f)
            f = end + 1
        else:
            colon = data.find(b':', f)
            strlen = int(data[f:colon])
            f = colon + 1 + strlen
    return None, f + 1  # return new offset (after 'e')


def extract_all_dicts(data: bytes) -> List[bytes]:
    """
    Extracts all top-level bencoded dicts from a bytes sequence.
    Returns a list of bytes, each representing a full bencoded dict.
    """
    i = 0
    dicts = []
    while i < len(data):
        if data[i] == ord('d'):
            _, end = find_bencoded_dict_bounds(data, i)
            dicts.append(data[i:end])
            i = end
        else:
            i += 1
    return dicts


def generate_peer_id() -> bytes:
    prefix = b'-PC0001-'  # Example: "PC" for "Python Client", version 0.0.1
    suffix: bytes = ''.join(random.choices(string.ascii_letters + string.digits, k=12)).encode('ascii')
    return prefix + suffix


def discover_peers(tracker_url: str, file_length: int, filepath: str) -> list[str | None]:
    peer_id: str = generate_peer_id().decode("ascii", errors="ignore")

    params = {
        "info_hash": hash_bytes(get_raw_info_bytes(filepath)),
        "peer_id": peer_id,
        "port": "6881",
        "uploaded": "0",
        "downloaded": "0",
        "left": str(file_length),
        "compact": "1"
    }

    response = requests.get(tracker_url, params=params)
    peers_raw: bytes = decode_bencode(response.content).get(b'peers')

    peers = []
    for i in range(0, len(peers_raw), 6):
        raw_ip = peers_raw[i:i + 4]
        raw_port = peers_raw[i + 4:i + 6]
        ip = ".".join(str(b) for b in raw_ip)
        port = int.from_bytes(raw_port, byteorder='big')
        peers.append(f"{ip}:{port}")

    return peers


def perform_handshake(sock, filepath: str) -> None:
    protocol = b'BitTorrent protocol'
    l_protocol: bytes = (len(protocol).to_bytes(1, byteorder='big'))  # b'\x13'
    reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    self_peer_id = generate_peer_id()
    handshake_data: bytes = (
            l_protocol +
            protocol +
            reserved +
            hash_bytes(get_raw_info_bytes(filepath)) +
            self_peer_id
    )

    try:
        sock.send(handshake_data)
    except ConnectionResetError:
        print("ConnectionResetError, Closing socket")
        sock.close()
        raise ConnectionResetError


def read_peer_message(sock) -> tuple[int | None, bytes | None]:
    length_bytes = read_n_bytes(sock, 4)
    msg_length = int.from_bytes(length_bytes, byteorder='big')
    if msg_length == 0:
        print("Keep-alive message received")
        return None, None
    msg_id_bytes = read_n_bytes(sock, 1)
    msg_id = msg_id_bytes[0]
    payload = b''
    if msg_length > 1:
        payload = read_n_bytes(sock, msg_length - 1)
    return msg_id, payload


def send_interested(sock: socket) -> None:
    interested_msg = b'\x00\x00\x00\x01\x02'
    sock.sendall(interested_msg)


def wait_for_unchoke(sock: socket) -> None:
    while True:
        msg_id, _ = read_peer_message(sock)
        if msg_id == 1:
            break


def request_piece_blocks(sock: socket, piece_index, piece_length, block_size=16384) -> None:
    num_blocks = (piece_length + block_size - 1) // block_size
    for i in range(num_blocks):
        begin = i * block_size
        length = min(block_size, piece_length - begin)
        msg: bytes = struct.pack(">IBIII", 13, 6, piece_index, begin, length)
        sock.sendall(msg)


def receive_piece_block(sock: socket) -> tuple[int, int, bytes | None]:
    while True:
        msg_id, payload = read_peer_message(sock)
        # 7 is a piece message
        if msg_id == 7:
            piece_index = int.from_bytes(payload[:4], 'big')
            begin_offset = int.from_bytes(payload[4:8], 'big')
            block_data: bytes = payload[8:]
            return piece_index, begin_offset, block_data
        else:
            print(f"Not a piece, got {msg_id}")


def receive_all_blocks(sock: socket, piece_index, piece_length, block_size=16384) -> bytes:
    num_blocks = (piece_length + block_size - 1) // block_size
    piece_data = bytearray(piece_length)
    bytes_received = 0
    while bytes_received < piece_length:
        recv_piece_index, begin_offset, block_data = receive_piece_block(sock)
        if recv_piece_index == piece_index:
            piece_data[begin_offset:begin_offset + len(block_data)] = block_data
            bytes_received += len(block_data)
        else:
            print(f"ERROR: Piece {piece_index} does not match block {bytes_received}.")

    return bytes(piece_data)


def verify_piece(data: bytes, expected_hash: bytes) -> bool:
    hashed_piece = hash_bytes(data)
    if expected_hash == hashed_piece:
        return True
    else:
        return False


def save_piece(data: bytes, out_path: str):
    with open(out_path, 'wb') as f:
        f.write(data)


def download_piece(peer, expected_hash: bytes, piece_index, piece_length, block_size, output_path, reuse_socket=False):
    ip = peer.split(':')[0]
    port = int(peer.split(':')[1])
    sock = socket.create_connection((ip, port))
    filepath = os.path.abspath(sys.argv[4])

    try:
        # 1. Send handshake
        perform_handshake(sock, filepath)

        # 2. Read peer handshake response (68 bytes)
        peer_handshake = read_n_bytes(sock, 68)

        # 3. Now start reading protocol messages!
        msg_id, payload = read_peer_message(sock)  # This should be the bitfield
        # 3. Send interested
        send_interested(sock)
        # 4. Wait for unchoke
        wait_for_unchoke(sock)
        # 5. Request all blocks for the piece
        request_piece_blocks(sock, piece_index, piece_length, block_size)
        # 6. Receive all blocks, assemble
        piece_data = receive_all_blocks(sock, piece_index, piece_length)
        # 7. Verify and save
        if verify_piece(piece_data, expected_hash):
            save_piece(piece_data, output_path)
        else:
            print("Hash mismatch!")
    finally:
        if not reuse_socket:
            sock.close()


def download_piece_and_return(peer, expected_hash, piece_index, piece_length, block_size) -> bytes:
    ip = peer.split(':')[0]
    port = int(peer.split(':')[1])
    sock = socket.create_connection((ip, port))
    filepath = os.path.abspath(sys.argv[4])

    try:
        perform_handshake(sock, filepath)
        peer_handshake = read_n_bytes(sock, 68)
        msg_id, payload = read_peer_message(sock)
        send_interested(sock)
        wait_for_unchoke(sock)
        request_piece_blocks(sock, piece_index, piece_length, block_size)
        piece_data = receive_all_blocks(sock, piece_index, piece_length)
        if verify_piece(piece_data, expected_hash):
            return piece_data
        else:
            print("Hash mismatch!")
    finally:
        sock.close()


def download_file(torrent_path: str, output_path: str):
    tracker_url, file_length, info, info_hash, piece_length, parts_hash = decode_metainfo_file(torrent_path)
    num_pieces = len(parts_hash)
    peers = discover_peers(tracker_url, file_length, torrent_path)
    peer = peers[0]  # only uses the first peer right now

    with open(output_path, 'wb') as f:
        f.truncate(file_length)

        for piece_index in range(num_pieces):
            if piece_index == num_pieces - 1:
                this_piece_length = file_length - (piece_length * (num_pieces - 1))
            else:
                this_piece_length = piece_length
            expected_hash = bytes.fromhex(parts_hash[piece_index])
            piece_data = download_piece_and_return(peer, expected_hash, piece_index, this_piece_length, 16384)

            f.seek(piece_index * piece_length)
            f.write(piece_data)

    print("Successfully downloaded file!")


def download_magnet_file(torrent_path: str, output_path: str):
    tracker_url, file_length, info, info_hash, piece_length, parts_hash = decode_metainfo_file(torrent_path)
    num_pieces = len(parts_hash)
    peers = discover_peers(tracker_url, file_length, torrent_path)
    peer = peers[0]  # only uses the first peer right now

    with open(output_path, 'wb') as f:
        f.truncate(file_length)

        for piece_index in range(num_pieces):
            if piece_index == num_pieces - 1:
                this_piece_length = file_length - (piece_length * (num_pieces - 1))
            else:
                this_piece_length = piece_length
            expected_hash = bytes.fromhex(parts_hash[piece_index])
            piece_data = download_piece_and_return(peer, expected_hash, piece_index, this_piece_length, 16384)

            f.seek(piece_index * piece_length)
            f.write(piece_data)

    print("Successfully downloaded file!")


def download_piece_magnet(peer, expected_hash: bytes, piece_index, piece_length, block_size, output_path, info_hash,
                          reuse_socket=False):
    """
    Download a specific piece from a peer using the BitTorrent protocol via magnet link (info_hash only).
    """
    ip, port = peer.split(':')
    port = int(port)
    sock = socket.create_connection((ip, port))

    try:
        # 1. Send handshake with the info_hash from magnet metadata exchange
        perform_handshake_with_info_hash(sock, info_hash)

        # 2. Read peer's handshake response
        peer_handshake = read_n_bytes(sock, 68)

        # 3. Read bitfield or next message from peer
        try:
            msg_id, payload = read_peer_message(sock)  # Usually a bitfield
        except TimeoutError:
            print("Timeout while reading peer message after handshake.")

        # 4. Send 'interested' message to indicate we want data
        send_interested(sock)

        # 5. Wait until peer unchokes us
        wait_for_unchoke(sock)

        # 6. Request all blocks from the specific piece
        request_piece_blocks(sock, piece_index, piece_length, block_size)

        # 7. Receive all requested blocks and assemble the full piece
        piece_data = receive_all_blocks(sock, piece_index, piece_length)

        # 8. Verify piece hash against expected
        if verify_piece(piece_data, expected_hash):
            save_piece(piece_data, output_path)
            print(f"Piece {piece_index} downloaded and verified successfully.")
        else:
            print("Hash mismatch on piece download!")
    finally:
        if not reuse_socket:
            sock.close()



def perform_handshake_with_info_hash(sock, info_hash: bytes):
    protocol = b'BitTorrent protocol'
    l_protocol = len(protocol).to_bytes(1, byteorder='big')
    reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    self_peer_id = generate_peer_id()
    handshake_data = (
            l_protocol +
            protocol +
            reserved +
            info_hash +
            self_peer_id
    )
    try:
        sock.send(handshake_data)
    except ConnectionResetError:
        print("ConnectionResetError, Closing socket")
        sock.close()
        raise ConnectionResetError


def get_raw_info_bytes(file_path: str) -> bytes:
    with open(file_path, 'rb') as file:
        data: bytes = file.read()
        i = 0
        while i < len(data):
            if data[i:i + 6] == b'4:info':
                value: bytes = data[i + 6:-1]
                i += 6
                return value
            else:
                i += 1


def read_n_bytes(sock: socket, n: int) -> bytes:
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise EOFError('Socket closed unexpectedly')
        data += packet
    return data


def bytes_to_str(data):
    if isinstance(data, bytes):
        return data.decode()
    raise TypeError(f"Type not serializable: {type(data)}")


def decode_bencode(bencoded_value):
    return bencodepy.Bencode().decode(bencoded_value)


def bencode_to_json_safe(obj):
    if isinstance(obj, dict):
        return {bencode_to_json_safe(k): bencode_to_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [bencode_to_json_safe(item) for item in obj]
    elif isinstance(obj, bytes):
        return obj.decode("utf-8")
    else:
        return obj


def hash_bytes(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def decode_metainfo_file(filepath: str):
    metadata = bencodepy.Bencode().read(filepath)
    # print(metadata)
    tracker_url = metadata.get(b"announce").decode("utf-8")
    length = metadata.get(b"info", {}).get(b"length")
    # print(f'Length: {length}')
    info = metadata.get(b"info")
    piece_length = info.get(b"piece length")

    pieces = info.get(b"pieces")
    parts = [pieces[i:i + 20] for i in range(0, len(pieces), 20)]
    parts_hash = []
    for part in parts:
        parts_hash.append(part.hex())

    def hash_info() -> bytes:
        bencoded_info = bencodepy.Bencode().encode(info)
        # print(bencoded_info)
        h = hash_bytes(bencoded_info)
        return h

    info_hash = hash_info()
    return tracker_url, length, info, info_hash, piece_length, parts_hash


def parse_magnet_link(link: str):
    parsed = urllib.parse.urlparse(link)
    qs = urllib.parse.parse_qs(parsed.query)
    xt = qs['xt'][0]  # 'urn:btih:ad42ce8109f54c99613ce38f9b4d87e70f24a165'
    if xt.startswith('urn:btih:'):
        info_hash_hex = xt[9:]
    else:
        raise ValueError("Invalid magnet link (xt)")
    tracker_url = qs['tr'][0]
    file_name = qs.get('dn', [''])[0]
    return info_hash_hex, file_name, tracker_url


def discover_magnet_peers(tracker_url: str, file_length: int, info_hash: str) -> list[str | None]:
    peer_id: str = generate_peer_id().decode("ascii", errors="ignore")

    params = {
        "info_hash": bytes.fromhex(info_hash),
        "peer_id": peer_id,
        "port": "6881",
        "uploaded": "0",
        "downloaded": "0",
        "left": str(file_length),
        "compact": "1"
    }

    response = requests.get(tracker_url, params=params)
    peers_raw: bytes = decode_bencode(response.content).get(b'peers')

    peers = []
    for i in range(0, len(peers_raw), 6):
        raw_ip = peers_raw[i:i + 4]
        raw_port = peers_raw[i + 4:i + 6]
        ip = ".".join(str(b) for b in raw_ip)
        port = int.from_bytes(raw_port, byteorder='big')
        peers.append(f"{ip}:{port}")

    return peers


def magnet_handshake(info_hash: str, sock: socket):
    reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    dec = int.from_bytes(reserved, byteorder='big')
    bits = dec | (1 << 20)
    reserved_extensions = bits.to_bytes(len(reserved), byteorder='big')
    protocol = b'BitTorrent protocol'
    l_protocol: bytes = (len(protocol).to_bytes(1, byteorder='big'))  # b'\x13'
    self_peer_id = generate_peer_id()
    handshake_data: bytes = (
            l_protocol +
            protocol +
            reserved_extensions +
            bytes.fromhex(info_hash) +
            self_peer_id
    )

    try:
        sock.send(handshake_data)
    except ConnectionResetError:
        print("ConnectionResetError, Closing socket")
        sock.close()
        raise ConnectionResetError


def extract_peer_info(peer):
    ip = peer.split(':')[0]
    port = int(peer.split(':')[1])
    return ip, port

def perform_peer_handshake(sock, hex_encoded_hash):
    magnet_handshake(hex_encoded_hash, sock)
    return read_n_bytes(sock, 68)

def parse_peer_handshake(peer_handshake_bytes):
    pstrlen = peer_handshake_bytes[0]
    protocol = peer_handshake_bytes[1:1 + pstrlen]
    reserved = peer_handshake_bytes[1 + pstrlen:1 + pstrlen + 8]
    info_hash = peer_handshake_bytes[1 + pstrlen + 8:1 + pstrlen + 8 + 20]
    peer_id = peer_handshake_bytes[1 + pstrlen + 8 + 20:]
    return protocol, reserved, info_hash, peer_id

def perform_extension_handshake(sock):
    extension_handshake_msg = {
        "m": {
            "ut_metadata": 16,
        }
    }
    bencoded = bencodepy.encode(extension_handshake_msg)
    msg_len = 2 + len(bencoded)
    message = struct.pack(">IBB", msg_len, 20, 0) + bencoded  # ID 20, ext ID 0
    sock.sendall(message)


def read_extended_handshake(sock):
    """
    Reads messages until it finds the extended handshake (msg_id=20, ext_msg_id=0)
    """
    while True:
        length_bytes = read_n_bytes(sock, 4)
        msg_length = int.from_bytes(length_bytes, 'big')
        if msg_length == 0:
            continue  # keep-alive

        msg = read_n_bytes(sock, msg_length)
        msg_id = msg[0]

        if msg_id == 20:
            ext_msg_id = msg[1]
            if ext_msg_id == 0:
                return decode_bencode(msg[2:])
            else:
                continue  # other extended message, ignore
        else:
            continue  # not an extended message


def request_metadata_piece(sock, ut_metadata, piece=0):
    request_dict = {b'msg_type': 0, b'piece': piece}
    b_request_dict = bencodepy.encode(request_dict)
    msg_length = 2 + len(b_request_dict)
    request_msg = (
        msg_length.to_bytes(4, byteorder='big') +
        int.to_bytes(20, 1, byteorder='big') +
        int.to_bytes(ut_metadata, 1, byteorder='big') +
        b_request_dict
    )
    sock.sendall(request_msg)
    return sock.recv(1024)

def parse_metadata(response):
    b_dicts = extract_all_dicts(response[6:])
    decoded = bencodepy.decode(b_dicts[1])
    piece_length = int(decoded.get(b'piece length'))
    file_length = int(decoded.get(b'length'))
    pieces = decoded.get(b'pieces')
    parts_hash = [pieces[i:i + 20].hex() for i in range(0, len(pieces), 20)]
    return piece_length, file_length, parts_hash, decoded.get(b'name')

def calculate_piece_length(piece_index, piece_length, file_length):
    total_pieces = file_length // piece_length + (1 if file_length % piece_length != 0 else 0)
    if piece_index >= total_pieces:
        raise ValueError(f"Requested piece_index {piece_index} >= number of pieces {total_pieces}")
    if piece_index == total_pieces - 1:
        return file_length - (piece_length * (total_pieces - 1))
    return piece_length


def read_peer_handshake(sock: socket):
    handshake = read_n_bytes(sock, 68)
    pstrlen = handshake[0]
    protocol = handshake[1:1 + pstrlen]
    reserved = handshake[1 + pstrlen:1 + pstrlen + 8]
    info_hash = handshake[1 + pstrlen + 8:1 + pstrlen + 8 + 20]
    peer_id = handshake[1 + pstrlen + 8 + 20:]
    return protocol, reserved, info_hash, peer_id


def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoded = decode_bencode(bencoded_value)
        json_safe = bencode_to_json_safe(decoded)
        print(json.dumps(json_safe))

    elif command == "info":
        filepath = sys.argv[2]
        try:
            os.path.exists(filepath)

        except FileNotFoundError:
            raise NotImplementedError("File not found")
        (tracker_url, length, info,
         info_hash, piece_length, parts_hash) = decode_metainfo_file(filepath)

        print("Tracker URL:", tracker_url, "\nLength:", length)
        print("Info Hash:", info_hash.hex())
        print("Piece Length:", piece_length)
        print("Piece Hashes:")
        for part in parts_hash:
            print(part)

    elif command == "peers":
        filepath = sys.argv[2]
        tracker_url, length, _, _, _, _ = decode_metainfo_file(filepath)

        peers = discover_peers(tracker_url, length, filepath)
        for peer in peers:
            print(peer)

    elif command == "handshake":
        filepath = os.path.abspath(sys.argv[2])
        peer = sys.argv[3]
        ip = peer.split(':')[0]
        port = int(peer.split(':')[1])
        sock = socket.create_connection((ip, port))
        perform_handshake(sock, filepath)
        peer_handshake = read_n_bytes(sock, 68)
        peer_id = peer_handshake[48:]
        print(f"Peer ID: {peer_id.hex()}")
        sock.close()

    elif command == "download_piece":
        output_path = sys.argv[3]
        filepath = os.path.abspath(sys.argv[4])
        piece_index = int(sys.argv[5])

        tracker_url, length, info, info_hash, piece_length, parts_hash = decode_metainfo_file(filepath)
        peers = discover_peers(tracker_url, length, filepath)
        peer = peers[0]
        expected_hash = bytes.fromhex(parts_hash[piece_index])

        if piece_index == len(parts_hash) - 1:
            this_piece_length = length - (piece_length * (len(parts_hash) - 1))
        else:
            this_piece_length = piece_length

        download_piece(peer, expected_hash, piece_index, this_piece_length, 16384, output_path, False)

    elif command == "download":
        output_path = sys.argv[3]
        torrent_path = os.path.abspath(sys.argv[4])
        download_file(torrent_path, output_path)

    elif command == "magnet_parse":
        magnet_link = sys.argv[2]
        hex_encoded_hash, file_name, tracker_url = parse_magnet_link(magnet_link)
        print(f"Tracker URL: {tracker_url}\nInfo Hash: {hex_encoded_hash}")

    elif command == "magnet_handshake":
        magnet_link = sys.argv[2]
        hex_encoded_hash, file_name, tracker_url = parse_magnet_link(magnet_link)
        peer = discover_magnet_peers(tracker_url, 999, hex_encoded_hash)[0]
        ip = peer.split(':')[0]
        port = int(peer.split(':')[1])
        sock = socket.create_connection((ip, port))
        magnet_handshake(hex_encoded_hash, sock)
        peer_handshake_bytes = read_n_bytes(sock, 68)

        pstrlen = peer_handshake_bytes[0]
        protocol = peer_handshake_bytes[1:1 + pstrlen]
        reserved = peer_handshake_bytes[1 + pstrlen:1 + pstrlen + 8]
        info_hash = peer_handshake_bytes[1 + pstrlen + 8:1 + pstrlen + 8 + 20]
        peer_id = peer_handshake_bytes[1 + pstrlen + 8 + 20:]

        print(f"Peer ID: {peer_id.hex()}")

        msg_id, payload = read_peer_message(sock)

        supports_extensions = (reserved[5] & 0x10) != 0

        if supports_extensions:
            extension_handshake_msg: dict = \
                {
                    "m": {
                        "ut_metadata": 16,
                    }
                }
            bencoded = bencodepy.encode(extension_handshake_msg)
            msg_len = 2 + len(bencoded)
            message = struct.pack(">IBB", msg_len, 20, 0) + bencoded
            sock.sendall(message)
            response = sock.recv(1024)
            bencode = decode_bencode(response[6:])
            ut_metadata = bencode.get(b'm').get(b'ut_metadata')
            print(f"Peer Metadata Extension ID: {ut_metadata}")

        sock.close()

    elif command == "magnet_info":
        magnet_link = sys.argv[2]
        hex_encoded_hash, file_name, tracker_url = parse_magnet_link(magnet_link)
        peer = discover_magnet_peers(tracker_url, 999, hex_encoded_hash)[0]
        ip = peer.split(':')[0]
        port = int(peer.split(':')[1])
        sock = socket.create_connection((ip, port))
        magnet_handshake(hex_encoded_hash, sock)
        peer_handshake_bytes = read_n_bytes(sock, 68)

        pstrlen = peer_handshake_bytes[0]
        protocol = peer_handshake_bytes[1:1 + pstrlen]
        reserved = peer_handshake_bytes[1 + pstrlen:1 + pstrlen + 8]
        info_hash = peer_handshake_bytes[1 + pstrlen + 8:1 + pstrlen + 8 + 20]
        peer_id = peer_handshake_bytes[1 + pstrlen + 8 + 20:]

        msg_id, payload = read_peer_message(sock)

        supports_extensions = (reserved[5] & 0x10) != 0

        if supports_extensions:
            extension_handshake_msg: dict = \
                {
                    "m": {
                        "ut_metadata": 16,
                    }
                }
            bencoded = bencodepy.encode(extension_handshake_msg)
            msg_len = 2 + len(bencoded)
            message = struct.pack(">IBB", msg_len, 20, 0) + bencoded
            sock.sendall(message)
            response = sock.recv(1024)
            bencode = decode_bencode(response[6:])
            ut_metadata = bencode.get(b'm').get(b'ut_metadata')
            request_dict = {b'msg_type': 0, b'piece': 0}
            b_request_dict = bencodepy.encode(request_dict)
            length = 2 + len(b_request_dict)
            request_msg = b''
            request_msg += length.to_bytes(4, byteorder='big')
            request_msg += int.to_bytes(20, 1, byteorder='big')
            request_msg += int.to_bytes(ut_metadata, 1, byteorder='big')
            request_msg += b_request_dict
            sock.sendall(request_msg)
            response = sock.recv(1024)
            b_dicts = extract_all_dicts(response[6:])

            decoded = bencodepy.decode(b_dicts[1])
            piece_length = decoded.get(b'piece length')
            pieces = decoded.get(b'pieces')
            name = decoded.get(b'name')
            length = decoded.get(b'length')

            print(f'Tracker URL: {tracker_url}\n'
                  f'Length: {length}\n'
                  f'Info Hash: {info_hash.hex()}\n'
                  f'Piece Length: {piece_length}\n'
                  f'Piece Hashes: ')

            parts = [pieces[i:i + 20] for i in range(0, len(pieces), 20)]
            for part in parts:
                print(part.hex())

    elif command == "magnet_download_piece":
        output_path = sys.argv[3]
        magnet_link = os.path.abspath(sys.argv[4])
        piece_index = int(sys.argv[5])

        hex_encoded_hash, file_name, tracker_url = parse_magnet_link(magnet_link)
        peer = discover_magnet_peers(tracker_url, 999, hex_encoded_hash)[0]
        ip, port = extract_peer_info(peer)

        with socket.create_connection((ip, port)) as sock:
            peer_handshake_bytes = perform_peer_handshake(sock, hex_encoded_hash)
            protocol, reserved, info_hash, _ = parse_peer_handshake(peer_handshake_bytes)

            supports_extensions = (reserved[5] & 0x10) != 0
            if not supports_extensions:
                raise RuntimeError("Peer does not support extension protocol.")

            perform_extension_handshake(sock)
            bencode = read_extended_handshake(sock)
            ut_metadata = bencode.get(b'm').get(b'ut_metadata')

            metadata_response = request_metadata_piece(sock, ut_metadata)
            piece_length, file_length, parts_hash, _ = parse_metadata(metadata_response)

        expected_hash = bytes.fromhex(parts_hash[piece_index])
        this_piece_length = calculate_piece_length(piece_index, piece_length, file_length)

        peer = discover_magnet_peers(tracker_url, file_length, info_hash.hex())[0]

        download_piece_magnet(
            peer, expected_hash, piece_index, this_piece_length, 16384, output_path, info_hash
        )

    elif command == "magnet_download":
        output_path = sys.argv[3]
        magnet_link = os.path.abspath(sys.argv[4])

        # 1. Parse the magnet link to get info_hash, file name, tracker URL
        hex_encoded_hash, file_name, tracker_url = parse_magnet_link(magnet_link)

        # 2. Discover a peer using DHT or tracker
        peer = discover_magnet_peers(tracker_url, 999, hex_encoded_hash)[0]
        ip, port = peer.split(':')
        port = int(port)

        # 3. Connect and handshake
        sock = socket.create_connection((ip, port))
        try:
            # 3a. Perform standard handshake using info_hash
            magnet_handshake(hex_encoded_hash, sock)
            peer_handshake_bytes = read_n_bytes(sock, 68)

            # 3b. Parse handshake to check extension support
            pstrlen = peer_handshake_bytes[0]
            reserved = peer_handshake_bytes[1 + pstrlen:1 + pstrlen + 8]
            supports_extensions = (reserved[5] & 0x10) != 0
            if not supports_extensions:
                raise RuntimeError("Peer does not support extensions for magnet metadata exchange")

            # 4. Extension handshake to get ut_metadata ID
            perform_extension_handshake(sock)
            ext_bencode = read_extended_handshake(sock)
            ut_metadata = ext_bencode.get(b'm').get(b'ut_metadata')

            # 5. Request piece 0 of metadata to get info_dict
            metadata_response = request_metadata_piece(sock, ut_metadata)
            piece_length, file_length, parts_hash, name = parse_metadata(metadata_response)

        finally:
            sock.close()

        # 6. Discover a peer again for actual piece downloading
        peer = discover_magnet_peers(tracker_url, file_length, hex_encoded_hash)[0]
        ip, port = peer.split(':')
        port = int(port)

        num_pieces = len(parts_hash)
        piece_data_list = [None] * num_pieces

        with socket.create_connection((ip, port)) as sock:
            # Send handshake again
            perform_handshake_with_info_hash(sock, bytes.fromhex(hex_encoded_hash))
            _ = read_n_bytes(sock, 68)
            send_interested(sock)
            wait_for_unchoke(sock)

            for piece_index in range(num_pieces):
                # Determine piece size
                if piece_index == num_pieces - 1:
                    this_piece_length = file_length - piece_length * (num_pieces - 1)
                else:
                    this_piece_length = piece_length

                request_piece_blocks(sock, piece_index, this_piece_length, 16384)
                piece_data = receive_all_blocks(sock, piece_index, this_piece_length)

                expected_hash = bytes.fromhex(parts_hash[piece_index])
                if verify_piece(piece_data, expected_hash):
                    piece_data_list[piece_index] = piece_data
                    print(f"Downloaded and verified piece {piece_index + 1}/{num_pieces}")
                else:
                    raise ValueError(f"Hash mismatch on piece {piece_index}")

        # 7. Save full file
        full_data = b''.join(piece_data_list)

        with open(output_path, 'wb') as f:
            f.write(full_data)

        print(f"File saved to {output_path}")


    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()