# Encrypted P2P Chat Application

A lightweight, terminal-based encrypted peer-to-peer messenger written in Python. Supports both direct 1-on-1 messaging and encrypted group chat.

## Features

✅ **End-to-End Encryption** - All messages encrypted using Fernet (symmetric encryption)  
✅ **Peer-to-Peer Architecture** - Direct connections between users  
✅ **Dynamic Peer Discovery** - Connect to any peer by IP and port  
✅ **Group Messaging** - Send encrypted messages to multiple peers simultaneously  
✅ **Message History** - View recent message exchanges  
✅ **Simple CLI Interface** - Easy-to-use command-based interface  

## Installation

### Prerequisites
- Python 3.7+

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Aristotill/encrypted_p2p-chat-.git
cd encrypted_p2p-chat-
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Starting the Application

```bash
python3 secure_chat.py
```

You'll be prompted to enter:
- **Username**: Your display name in the chat
- **Port**: The port to listen on (default: 5000)

### Available Commands

| Command | Description |
|---------|-------------|
| `help` | Show all available commands |
| `peers` | List all connected peers |
| `connect <host> <port>` | Connect to a peer (e.g., `connect 192.168.1.100 5000`) |
| `send <peer_id> <message>` | Send a direct message to a specific peer |
| `group <peer_ids> <message>` | Send message to multiple peers (comma-separated IDs) |
| `key` | Display your encryption key for sharing |
| `history` | Show last 10 messages |
| `quit` | Exit the application |

## Security

- **Encryption**: Uses Fernet (AES-128 in CBC mode) from the `cryptography` library
- **Key Generation**: Unique encryption key generated for each session
- **Message Integrity**: Fernet provides authenticated encryption with built-in integrity checks
- **No Central Server**: Pure P2P architecture - your messages never touch a central server

## License

MIT License
