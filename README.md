# VjTor Client in Python

This project is a BitTorrent client implemented in Python.

It demonstrates core BitTorrent protocol features, including peer communication, torrent file parsing, and file downloading.

## Features

- Parses `.torrent` files
- Connects to trackers and peers
- Downloads files using the BitTorrent protocol
- Command-line interface

## Getting Started

### Prerequisites

- Python 3.7+
- `requests` library (install with `pip install requests`)

### Installation

```bash
git clone https://github.com/avj67/vjtor.git
cd app
```

### Usage

```bash
python main.py <path-to-torrent-file>
```

## Project Structure

- `main.py` - Entry point for the client
- `torrent.py` - Torrent file parsing logic
- `peer.py` - Peer communication logic

## License

This project is licensed under the MIT License.

