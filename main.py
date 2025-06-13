import asyncio
import logging
import json
import time
import uuid
import re
import os
import atexit # For graceful shutdown persistence
from collections import deque # For storing recent logs in memory
from aiohttp import web # For the web server
import random # For randomization in INFO output
import datetime # For dynamic timestamps

# --- Configuration ---
HOST = '0.0.0.0'  # Bind to all available interfaces for external access
PORT = 6379       # Standard Redis port
LOG_FILE = 'redis_honeypot.log'
STORAGE_FILE = 'redis_honeypot_data.json' # File for key-value store persistence
PAYLOADS_DIR = 'payloads' # Directory to store captured SLAVEOF payloads
AUTH_REQUIRED = False     # Set to True to require AUTH command
EXPECTED_PASSWORD = "my_secure_password" # Change this if AUTH_REQUIRED is True

WEB_PORT = 8080   # Port for the web-based log viewer

# --- Default Dummy Keys for Honeypot Session ---
# This dictionary defines a set of default keys and values that will be present
# in the emulated Redis database for each new client session.
# These keys are designed to make the honeypot appear more realistic and
# provide a starting point for attackers to interact with.
# Note: For new data types (lists, hashes, sets, zsets), values should be
# stored in a way that allows easy reconstruction, e.g., JSON strings or specific structures.
DEFAULT_DUMMY_KEYS = {
    "web_cache:user_sessions": "a:1:{s:6:\\\"active\\\";b:1;}\"",
    "config:app_version": "1.0.5",
    "users:last_login:admin": str(int(time.time())), # Example timestamp
    "temp_data:processing_queue_size": "50",
    "app:status": "UP",
    "metrics:cpu_usage": "25.7",
    "inventory:product_stock:A123": "150",
    "cache:item:XYZ": "cached_value_123",
    "logs:error_count": "5",
    "queue:messages_pending": "10",
    "user:profile:john_doe": json.dumps({"name": "John Doe", "email": "john@example.com", "age": 30}),
    "settings:theme": "dark",
    "status:service_uptime": "36000", # Seconds
    "geo:ip_blacklist": "192.168.1.1,10.0.0.5",
    "api:rate_limit:user1": "100/hour",
    "backup:last_run": "2024-06-12T03:00:00Z",
    "customers:active": "1000",
    "orders:pending": "50",
    "sessions:active:web": "250",
    "sessions:active:mobile": "150",
    "sensor:data:temp:room1": "22.5",
    "sensor:data:humidity:room1": "60.2",
    "service:status:payment_gateway": "healthy"
}


# --- Logging Configuration ---
# Use a custom deque handler to store recent logs in memory for the web UI
# Limit to 1000 most recent logs
recent_logs = deque(maxlen=1000)

class DequeHandler(logging.Handler):
    """Custom logging handler to store recent logs in a deque for web UI."""
    def emit(self, record):
        try:
            # Format the log record as a dictionary (JSON-friendly)
            log_entry = {
                "timestamp": time.time(), # Unix timestamp
                "asctime": self.format(record).split(' - ')[0], # Extract formatted time
                "levelname": record.levelname,
                "client_addr": getattr(record, 'client_addr', 'SERVER'), # Use 'SERVER' if client_addr is not set
                "message": record.message,
                "full_message": self.format(record) # Store full formatted message as well
            }
            # Add extra fields if they exist
            for key, value in record.__dict__.items():
                if key not in ['name', 'levelname', 'pathname', 'lineno', 'asctime', 'message',
                               'args', 'exc_info', 'funcName', 'created', 'msecs', 'process',
                               'thread', 'threadName', 'processName', 'client_addr', 'relativeCreated', 'stack_info', 'filename', 'module', 'levelno',
                               'lineno', 'pathname', 'funcName', 'exc_text', 'stack_info', 'thread', 'threadName', 'process', 'processName', 'relativeCreated']:
                    log_entry[key] = value

            recent_logs.append(log_entry)
        except Exception:
            self.handleError(record)

# Custom formatter to handle missing client_addr gracefully for file and console handlers
class CustomFormatter(logging.Formatter):
    """A formatter that ensures 'client_addr' is always present in log records."""
    def format(self, record):
        if not hasattr(record, 'client_addr'):
            record.client_addr = 'N/A' # Default value if not explicitly set
        return super().format(record)

# Setup logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set base logging level

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(CustomFormatter('%(asctime)s - %(levelname)s - %(client_addr)s - %(message)s'))
logger.addHandler(console_handler)

# File Handler (for persistent logs)
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(CustomFormatter('%(asctime)s - %(levelname)s - %(client_addr)s - %(message)s'))
logger.addHandler(file_handler)

# Deque Handler for web UI
deque_handler = DequeHandler()
# The deque handler doesn't strictly need its own formatter for internal dict, but the base class does for self.format(record)
deque_handler.setFormatter(CustomFormatter('%(asctime)s - %(levelname)s - %(client_addr)s - %(message)s'))
logger.addHandler(deque_handler)

# Ensure payloads directory exists
os.makedirs(PAYLOADS_DIR, exist_ok=True)

# --- RESP (Redis Serialization Protocol) Parser and Serializer ---

# RESP documentation reference: https://redis.io/docs/latest/develop/reference/protocol-spec/

class RESPError(Exception):
    """Custom exception for RESP parsing errors, used internally."""
    pass

def resp_encode(data):
    """
    Encodes Python data types into RESP byte format.

    Args:
        data: The Python object to encode (str, int, list, None, bytes).
              If data is an Exception, it's encoded as a Redis error.

    Returns:
        bytes: The RESP encoded byte string.
    """
    if isinstance(data, str):
        # Simple String (e.g., "+OK\r\n") if no special chars, otherwise Bulk String
        if '\n' in data or '\r' in data or ' ' in data or data == "OK" or data == "PONG" or data == "QUEUED":
            return f"${len(data)}\r\n{data}\r\n".encode('utf-8')
        return f"+{data}\r\n".encode('utf-8')
    elif isinstance(data, int):
        # Integer (e.g., ":123\r\n")
        return f":{data}\r\n".encode('utf-8')
    elif isinstance(data, bytes):
        # Bulk String (bytes)
        return f"${len(data)}\r\n".encode('utf-8') + data + b"\r\n"
    elif data is None:
        # Null Bulk String (e.g., "$-1\r\n")
        return b"$-1\r\n"
    elif isinstance(data, list):
        # Array (e.g., "*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")
        encoded_elements = []
        for item in data:
            # Recursively encode list elements. If an element is bytes, ensure it's treated as a bulk string.
            if isinstance(item, bytes):
                encoded_elements.append(resp_encode(item))
            elif isinstance(item, RESPError): # Handle internal RESPError objects for nested responses (e.g. in EXEC)
                encoded_elements.append(resp_encode(item))
            else:
                encoded_elements.append(resp_encode(item))
        return f"*{len(data)}\r\n".encode('utf-8') + b"".join(encoded_elements)
    elif isinstance(data, Exception):
        # Error (e.g., "-ERR invalid password\r\n")
        error_msg = str(data)
        # Ensure it starts with ERR if it's a generic error from our side
        if not error_msg.upper().startswith("NOAUTH") and not error_msg.upper().startswith("ERR"):
            error_msg = f"ERR {error_msg}"
        return f"-{error_msg}\r\n".encode('utf-8')
    else:
        # Attempt to convert other types to string for bulk string encoding
        try:
            str_data = str(data)
            return f"${len(str_data)}\r\n{str_data}\r\n".encode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encode unsupported data type {type(data)}: {e}", exc_info=True, extra={'client_addr': 'ENCODING_ERROR'})
            # Fallback to a generic Redis internal error for unencodable data
            return b"-ERR internal server error\r\n"


async def _read_until_crlf(reader):
    """Reads bytes from the reader until a CRLF (\\r\\n) is encountered."""
    buffer = bytearray()
    while True:
        try:
            char = await reader.readexactly(1)
            if char == b'\r':
                next_char = await reader.readexactly(1)
                if next_char == b'\n':
                    return buffer.decode('utf-8')
                else:
                    buffer.extend(b'\r' + next_char) # If it's not \n, put both back
            else:
                buffer.extend(char)
        except asyncio.IncompleteReadError:
            # This happens when the client closes the connection mid-read
            raise # Re-raise to be handled by the main client handler


async def _parse_bulk_string(reader):
    """Parses a RESP Bulk String."""
    length_str = await _read_until_crlf(reader)
    try:
        length = int(length_str)
    except ValueError:
        raise RESPError(f"Protocol error: invalid bulk string length '{length_str}'")
    
    if length == -1:
        return None  # Null Bulk String
    
    # Read the exact number of bytes for the bulk string
    data = await reader.readexactly(length)
    
    # Read the trailing CRLF
    crlf = await reader.readexactly(2) 
    if crlf != b'\r\n':
        raise RESPError("Protocol error: malformed bulk string (missing CRLF)")
    
    return data.decode('utf-8', errors='ignore') # Ignore decoding errors for robustness


async def resp_decode(reader):
    """
    Decodes RESP bytes from an asyncio StreamReader into Python data types.

    Args:
        reader (asyncio.StreamReader): The stream reader to read from.

    Returns:
        The decoded Python object (str, int, list, None).

    Raises:
        RESPError: If the RESP message is malformed or invalid.
        asyncio.IncompleteReadError: If the connection closes prematurely.
    """
    try:
        initial_byte = await reader.readexactly(1)
    except asyncio.IncompleteReadError:
        # This is typically a clean client disconnect
        raise # Let the calling function handle this graceful exit

    if initial_byte == b'+':
        # Simple String
        return await _read_until_crlf(reader)
    elif initial_byte == b'-':
        # Error
        return RESPError(await _read_until_crlf(reader))
    elif initial_byte == b':':
        # Integer
        try:
            return int(await _read_until_crlf(reader))
        except ValueError:
            raise RESPError("Protocol error: invalid integer format")
    elif initial_byte == b'$':
        # Bulk String
        return await _parse_bulk_string(reader)
    elif initial_byte == b'*':
        # Array
        length_str = await _read_until_crlf(reader)
        try:
            num_elements = int(length_str)
        except ValueError:
            raise RESPError(f"Protocol error: invalid array length '{length_str}'")

        if num_elements == -1:
            return None # Null Array
        
        elements = []
        for _ in range(num_elements):
            elements.append(await resp_decode(reader)) # Recursively decode array elements
        return elements
    else:
        # This is crucial for Nmap. If the first byte is not a RESP prefix,
        # it's likely a non-Redis probe (e.g., HTTP GET, SSL handshake).
        # We raise a specific RESPError that the caller can convert to a generic Redis error.
        raise RESPError(f"Protocol error: invalid multibulk length {initial_byte!r}")


# --- Honeypot Core Logic ---

class RedisHoneypot:
    """
    Manages the emulated Redis state and handles commands.
    """
    def __init__(self):
        # In-memory key-value store for each database
        self.databases = {i: {} for i in range(16)} # Redis typically supports 16 databases
        self.current_db_index = 0
        self.authenticated = not AUTH_REQUIRED
        self.transaction_queue = [] # For MULTI/EXEC
        self.in_transaction = False
        self.master_info = None # For SLAVEOF
        self.start_time = time.time() # Track honeypot start time for INFO command

        # Load data from disk on initialization
        self._load_data_from_disk()

        # Populate the default database (db0) with dummy keys for each new session
        self._populate_dummy_keys()

    def _load_data_from_disk(self):
        """Loads the key-value store from the persistence file."""
        if os.path.exists(STORAGE_FILE):
            try:
                with open(STORAGE_FILE, 'r') as f:
                    data = json.load(f)
                    # Convert list/set/zset representations back to native Python types
                    for db_idx_str, db_data in data.items():
                        db_idx = int(db_idx_str)
                        current_db = {}
                        for k, v_meta in db_data.items():
                            if isinstance(v_meta, dict) and 'type' in v_meta and 'value' in v_meta:
                                if v_meta['type'] == 'list':
                                    current_db[k] = v_meta['value']
                                elif v_meta['type'] == 'hash':
                                    current_db[k] = v_meta['value']
                                elif v_meta['type'] == 'set':
                                    current_db[k] = set(v_meta['value'])
                                elif v_meta['type'] == 'zset':
                                    current_db[k] = [(member, score) for member, score in v_meta['value']]
                                else:
                                    current_db[k] = v_meta['value'] # Assume string if unknown type
                            else:
                                current_db[k] = v_meta # Assume string if not dict meta
                        self.databases[db_idx] = current_db
                logger.info("Loaded data from %s", STORAGE_FILE, extra={'client_addr': 'SERVER'})
            except (json.JSONDecodeError, IOError) as e:
                logger.error("Failed to load data from %s: %s. Starting with empty data.", STORAGE_FILE, e, extra={'client_addr': 'SERVER'})
                self.databases = {i: {} for i in range(16)} # Reset to empty on error
        else:
            logger.info("No persistence file found at %s. Starting with empty databases.", STORAGE_FILE, extra={'client_addr': 'SERVER'})

    def _save_data_to_disk(self):
        """Saves the key-value store to the persistence file."""
        serializable_data = {}
        for db_idx, db_data in self.databases.items():
            serializable_db = {}
            for k, v in db_data.items():
                if isinstance(v, list) and not all(isinstance(x, tuple) and len(x) == 2 for x in v): # Regular list
                    serializable_db[k] = {'type': 'list', 'value': v}
                elif isinstance(v, dict): # Hash
                    serializable_db[k] = {'type': 'hash', 'value': v}
                elif isinstance(v, set): # Set
                    serializable_db[k] = {'type': 'set', 'value': list(v)} # Sets are not JSON serializable directly
                elif isinstance(v, list) and all(isinstance(x, tuple) and len(x) == 2 for x in v): # Sorted Set
                    serializable_db[k] = {'type': 'zset', 'value': [[m, s] for m, s in v]} # Tuples are not JSON serializable directly
                else:
                    serializable_db[k] = v # Assume string for other types
            serializable_data[str(db_idx)] = serializable_db
        
        try:
            # Ensure the directory for STORAGE_FILE exists
            os.makedirs(os.path.dirname(STORAGE_FILE) or '.', exist_ok=True)
            with open(STORAGE_FILE, 'w') as f:
                json.dump(serializable_data, f, indent=4)
            logger.info("Saved data to %s", STORAGE_FILE, extra={'client_addr': 'SERVER'})
        except IOError as e:
            logger.error("Failed to save data to %s: %s", STORAGE_FILE, e, exc_info=True, extra={'client_addr': 'SERVER'})

    def _populate_dummy_keys(self):
        """Populates the default database (db0) with predefined dummy keys."""
        logger.info("Populating DB0 with default dummy keys.", extra={'client_addr': 'SERVER'})
        # Deep copy to ensure each session gets a fresh set of dummy data, and to handle sets/lists correctly
        for key, value in DEFAULT_DUMMY_KEYS.items():
            if isinstance(value, set):
                self.databases[0][key] = value.copy()
            elif isinstance(value, list) and all(isinstance(x, tuple) for x in value): # For zsets (list of tuples)
                self.databases[0][key] = [list(x) for x in value] # Convert tuples to lists for mutability
            elif isinstance(value, dict):
                self.databases[0][key] = value.copy()
            else:
                self.databases[0][key] = value

    def get_current_db(self):
        """Returns the currently selected database."""
        return self.databases[self.current_db_index]

    async def handle_command(self, command_parts, client_addr_tuple):
        """
        Dispatches incoming Redis commands to their respective handlers.
        Args:
            command_parts (list): List of strings representing the command and its arguments.
            client_addr_tuple (tuple): (IP address, port) of the client.
        Returns:
            The RESP encoded response bytes.
        """
        client_addr = f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"
        log_extra = {'client_addr': client_addr}

        if not command_parts:
            logger.warning("Received empty command from %s.", client_addr, extra=log_extra)
            return resp_encode(RESPError("ERR unknown command")) # Generic Redis error

        command = command_parts[0].upper()
        args = command_parts[1:]

        logger.info("Received command: %s %s", command, args, extra=log_extra)

        # Check authentication first (if enabled)
        if not self.authenticated and command != "AUTH":
            logger.warning("Unauthorized access attempt for command: %s", command, extra=log_extra)
            return resp_encode(RESPError("NOAUTH Authentication required."))

        # If in transaction mode, queue commands except EXEC, DISCARD, WATCH
        if self.in_transaction and command not in ("EXEC", "DISCARD", "WATCH"):
            self.transaction_queue.append(command_parts)
            logger.info("Command '%s' queued in transaction.", command, extra=log_extra)
            return resp_encode("QUEUED")

        # Command dispatch table (all handlers are async methods)
        handlers = {
            "PING": self.handle_ping,
            "INFO": self.handle_info,
            "SET": self.handle_set,
            "GET": self.handle_get,
            "DEL": self.handle_del,
            "EXISTS": self.handle_exists,
            "KEYS": self.handle_keys,
            "FLUSHALL": self.handle_flushall,
            "FLUSHDB": self.handle_flushdb,
            "SAVE": self.handle_save,
            "SELECT": self.handle_select,
            "DBSIZE": self.handle_dbsize,
            "CONFIG": self.handle_config,
            "EVAL": self.handle_eval,
            "EVALSHA": self.handle_eval, # Treat EVALSHA same as EVAL for simplicity
            "AUTH": self.handle_auth,
            "MULTI": self.handle_multi,
            "EXEC": self.handle_exec,
            "DISCARD": self.handle_discard,
            "QUIT": self.handle_quit,
            "SLAVEOF": self.handle_slaveof,
            "REPLCONF": self.handle_replconf,
            "PSYNC": self.handle_psync,
            "PUBLISH": self.handle_publish,
            "SUBSCRIBE": self.handle_subscribe,
            "PSUBSCRIBE": self.handle_psubscribe,
            "UNSUBSCRIBE": self.handle_unsubscribe,
            "PUNSUBSCRIBE": self.handle_punsubscribe,
            "CLIENT": self.handle_client_command,
            "COMMAND": self.handle_command_command,
            "ECHO": self.handle_echo,
            "TTL": self.handle_ttl,
            "INCR": self.handle_incr,
            "DECR": self.handle_decr,
            # Hash Commands
            "HSET": self.handle_hset,
            "HGET": self.handle_hget,
            "HGETALL": self.handle_hgetall,
            "HDEL": self.handle_hdel,
            "HEXISTS": self.handle_hexists,
            # List Commands
            "LPUSH": self.handle_lpush,
            "RPUSH": self.handle_rpush,
            "LPOP": self.handle_lpop,
            "RPOP": self.handle_rpop,
            "LRANGE": self.handle_lrange,
            "LLEN": self.handle_llen,
            # Set Commands
            "SADD": self.handle_sadd,
            "SMEMBERS": self.handle_smembers,
            "SREM": self.handle_srem,
            "SISMEMBER": self.handle_sismember,
            "SCARD": self.handle_scard,
            # Sorted Set Commands (simplified)
            "ZADD": self.handle_zadd,
            "ZRANGE": self.handle_zrange,
            "ZREM": self.handle_zrem,
            "ZCARD": self.handle_zcard,
        }

        handler = handlers.get(command)
        if handler:
            try:
                response = await handler(args, client_addr_tuple)
                # Automatically save data on successful modification commands
                if command in ["SET", "DEL", "FLUSHALL", "FLUSHDB", "HSET", "HDEL",
                               "LPUSH", "RPUSH", "LPOP", "RPOP", "SADD", "SREM", "ZADD", "ZREM"]:
                    self._save_data_to_disk()
                return response
            except RESPError as e:
                # Handled expected RESP errors from within command handlers
                logger.warning("Command '%s' failed for %s: %s", command, client_addr, e, extra=log_extra)
                return resp_encode(e)
            except Exception as e:
                logger.error("Error executing command '%s' for %s: %s", command, client_addr, e, exc_info=True, extra=log_extra)
                # Generic internal error for unexpected exceptions during command execution
                return resp_encode(RESPError(f"ERR An internal error occurred while processing '{command}'."))
        else:
            logger.warning("Unknown command received from %s: %s %s", client_addr, command, args, extra=log_extra)
            # Generic unknown command error, crucial for Nmap
            return resp_encode(RESPError(f"ERR unknown command '{command}'"))

    # --- Command Handlers (implementations for all commands) ---

    async def handle_ping(self, args, client_addr_tuple):
        """Handles the PING command."""
        # PING returns "PONG" with no args, or the argument as a bulk string if provided.
        if not args:
            return resp_encode("PONG")
        else:
            return resp_encode(args[0])

    async def handle_info(self, args, client_addr_tuple):
        """
        Handles the INFO command, providing realistic Redis server information.
        This is critical for Nmap service detection.
        """
        uptime_seconds = int(time.time() - self.start_time)
        uptime_days = uptime_seconds // (24 * 3600)

        # Generate dynamic and realistic values
        redis_version = "6.0.9" # Match the version Nmap often expects for older Redis, or choose a common one
        redis_git_sha1 = ''.join(random.choices('0123456789abcdef', k=40))
        redis_build_id = "c0ffee" # A common placeholder
        process_id = os.getpid() # Use actual PID for the honeypot process
        run_id = ''.join(random.choices('0123456789abcdef', k=40))
        lru_clock = int(time.time()) % (2**24) # Realistic LRU clock

        # Simulate dynamic memory usage within a believable range
        used_memory = random.randint(1000000, 50000000) # 1MB to 50MB
        used_memory_human = f"{used_memory / (1024*1024):.2f}M"
        used_memory_rss = used_memory * random.uniform(1.2, 1.8) # RSS is usually higher than used_memory
        used_memory_rss_human = f"{used_memory_rss / (1024*1024):.2f}M"
        used_memory_peak = used_memory * random.uniform(1.0, 1.1)
        used_memory_peak_human = f"{used_memory_peak / (1024*1024):.2f}M"
        total_system_memory = 8 * (1024**3) # 8GB
        total_system_memory_human = "8.00G"

        info_output = f"""# Server
redis_version:{redis_version}
redis_git_sha1:{redis_git_sha1}
redis_build_id:{redis_build_id}
redis_mode:standalone
os:Linux 5.4.0-105-generic x86_64
arch_bits:64
multiplexing_api:epoll
gcc_version:9.3.0
process_id:{process_id}
run_id:{run_id}
tcp_port:{PORT}
uptime_in_seconds:{uptime_seconds}
uptime_in_days:{uptime_days}
hz:10
lru_clock:{lru_clock}
executable:/usr/local/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_recent_max_input_buffer:2
client_recent_max_output_buffer:0
blocked_clients:0

# Memory
used_memory:{int(used_memory)}
used_memory_human:{used_memory_human}
used_memory_rss:{int(used_memory_rss)}
used_memory_rss_human:{used_memory_rss_human}
used_memory_peak:{int(used_memory_peak)}
used_memory_peak_human:{used_memory_peak_human}
total_system_memory:{int(total_system_memory)}
total_system_memory_human:{total_system_memory_human}
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_allocator:jemalloc-5.1.0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:{int(time.time()) - random.randint(3600, 86400)}
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_last_sample_ms:0
rdb_bgsave_current_fork_pid:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_size:0
aof_base_size:0
aof_pending_bio_fsync:0
aof_delayed_fdatasync:0
aof_last_bgrewrite_status:ok
aof_last_write_status:ok
aof_last_cow_size:0

# Stats
total_connections_received:10
total_commands_processed:50
instantaneous_ops_per_sec:1
total_net_input_bytes:10240
total_net_output_bytes:20480
instantaneous_input_kbps:{random.uniform(0.1, 1.0):.2f}
instantaneous_output_kbps:{random.uniform(0.1, 1.0):.2f}
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:{random.randint(50, 5000)}
keyspace_misses:{random.randint(10, 1000)}
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:{random.randint(1000, 50000)}
migrate_cached_sockets:0
slave_expires_tracked_keys:0
active_defrag_hits:0
active_defrag_misses:0
active_defrag_scanned_keys:0
active_defrag_time_consumed:0
active_defrag_earliest_start_time:0

# Replication
role:master
connected_slaves:0
master_replid:{''.join(random.choices('0123456789abcdef', k=40))}
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:{random.uniform(0.5, 10.0):.2f}
used_cpu_user:{random.uniform(0.5, 10.0):.2f}
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Modules

# Errorstats
errorstats_total_errors:0
errorstats_get_errors:0
errorstats_set_errors:0

# Cluster
cluster_enabled:0

# Keyspace
db0:keys={len(self.databases[0])},expires=0,avg_ttl=0
"""
        return resp_encode(info_output.strip())

    async def handle_set(self, args, client_addr_tuple):
        """Handles the SET command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'set' command")
        key = args[0]
        value = args[1]
        self.get_current_db()[key] = value # Store as string by default
        return resp_encode("OK")

    async def handle_get(self, args, client_addr_tuple):
        """Handles the GET command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'get' command")
        key = args[0]
        value = self.get_current_db().get(key)
        # Redis GET returns nil if key is not a string or doesn't exist
        if value is None or not isinstance(value, str):
            return resp_encode(None)
        return resp_encode(value)

    async def handle_del(self, args, client_addr_tuple):
        """Handles the DEL command."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'del' command")
        deleted_count = 0
        for key in args:
            if key in self.get_current_db():
                del self.get_current_db()[key]
                deleted_count += 1
        return resp_encode(deleted_count)

    async def handle_exists(self, args, client_addr_tuple):
        """Handles the EXISTS command."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'exists' command")
        exists_count = 0
        for key in args:
            if key in self.get_current_db():
                exists_count += 1
        return resp_encode(exists_count)

    async def handle_keys(self, args, client_addr_tuple):
        """Handles the KEYS command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'keys' command")
        pattern = args[0]
        # Convert glob-style pattern to regex: replace '*' with '.*', '?' with '.', escape other regex chars
        regex_pattern = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
        
        matched_keys = [key for key in self.get_current_db().keys() if re.fullmatch(regex_pattern, key)]
        return resp_encode(matched_keys)

    async def handle_flushall(self, args, client_addr_tuple):
        """Handles the FLUSHALL command."""
        for db_index in self.databases:
            self.databases[db_index].clear()
        logger.warning("FLUSHALL executed. All databases cleared.", extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        self._populate_dummy_keys() # Re-populate dummy keys after flushall
        return resp_encode("OK")

    async def handle_flushdb(self, args, client_addr_tuple):
        """Handles the FLUSHDB command."""
        self.get_current_db().clear()
        logger.warning("FLUSHDB executed on DB %d. Current database cleared.", self.current_db_index, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        if self.current_db_index == 0:
            self._populate_dummy_keys() # Re-populate dummy keys if db0 is flushed
        return resp_encode("OK")

    async def handle_save(self, args, client_addr_tuple):
        """Handles the SAVE command."""
        # Simulate blocking behavior. Real Redis SAVE can be slow.
        logger.info("SAVE command received. Simulating blocking save operation...", extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        self._save_data_to_disk() # Force a save
        await asyncio.sleep(0.1) # Small delay to simulate work
        logger.info("SAVE simulation complete.", extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        return resp_encode("OK")

    async def handle_select(self, args, client_addr_tuple):
        """Handles the SELECT command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'select' command")
        try:
            db_index = int(args[0])
            if 0 <= db_index < 16: # Assuming 16 databases
                self.current_db_index = db_index
                return resp_encode("OK")
            else:
                raise RESPError("ERR DB index is out of range")
        except ValueError:
            raise RESPError("ERR invalid DB index")

    async def handle_dbsize(self, args, client_addr_tuple):
        """Handles the DBSIZE command."""
        size = len(self.get_current_db())
        return resp_encode(size)

    async def handle_config(self, args, client_addr_tuple):
        """Handles the CONFIG command (simplified but more realistic)."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'config' command")

        subcommand = args[0].upper()
        if subcommand == "GET":
            if len(args) != 2:
                raise RESPError("ERR wrong number of arguments for 'config get' command")
            param = args[1].lower()
            response_list = [param]
            # Emulate common config parameters with plausible values
            if param == "dir":
                response_list.append("/var/lib/redis") # Common Redis data directory
            elif param == "dbfilename":
                response_list.append("dump.rdb")
            elif param == "requirepass":
                response_list.append(EXPECTED_PASSWORD if AUTH_REQUIRED else "")
            elif param == "appendonly":
                response_list.append("no")
            elif param == "protected-mode":
                response_list.append("no")
            elif param == "daemonize":
                response_list.append("no")
            elif param == "loglevel":
                response_list.append("notice")
            elif param == "bind":
                response_list.append(HOST)
            elif param == "port":
                response_list.append(str(PORT))
            elif param == "save":
                # Typical Redis save points
                response_list.append("3600 1\n300 100\n60 10000")
            elif param == "*": # CONFIG GET *
                # Return a subset of common config parameters
                config_list = [
                    "dir", "/var/lib/redis",
                    "dbfilename", "dump.rdb",
                    "requirepass", (EXPECTED_PASSWORD if AUTH_REQUIRED else ""),
                    "port", str(PORT),
                    "loglevel", "notice",
                    "bind", HOST,
                    "protected-mode", "no",
                    "appendonly", "no"
                ]
                return resp_encode(config_list)
            else:
                # For unknown GET parameters, Redis returns an empty array
                return resp_encode([])
            return resp_encode(response_list)
        elif subcommand == "SET":
            if len(args) != 3:
                raise RESPError("ERR wrong number of arguments for 'config set' command")
            param = args[1].lower()
            value = args[2]
            logger.warning("CONFIG SET '%s' to '%s' captured.", param, value, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
            # Log the potential malicious config change, but always return OK
            if param in ["dir", "dbfilename", "appendfilename"]:
                logger.critical("Potential file write path change: CONFIG SET %s to '%s'", param, value, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
                # Simulate success
                return resp_encode("OK")
            return resp_encode("OK")
        elif subcommand == "REWRITE":
            return resp_encode("OK")
        elif subcommand == "RESETSTAT":
            return resp_encode("OK")
        else:
            raise RESPError(f"ERR unknown CONFIG subcommand '{subcommand}'")

    async def handle_eval(self, args, client_addr_tuple):
        """Handles EVAL/EVALSHA. Logs and returns a generic error/nil."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'eval' command")
        
        lua_script = args[0]
        try:
            num_keys = int(args[1])
            keys = args[2 : 2 + num_keys]
            eval_args = args[2 + num_keys :]
        except ValueError:
            raise RESPError("ERR invalid number of keys")

        logger.critical(
            "EVAL command with Lua script captured! Script: \n---\n%s\n---\nKeys: %s, Args: %s",
            lua_script, keys, eval_args, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"}
        )
        # Return a plausible successful response, e.g., nil or empty array, or simulated string
        # Do NOT actually execute the Lua script
        return resp_encode(None) # Or resp_encode(RESPError("ERR Error running script (user_script:1: ..."))

    async def handle_auth(self, args, client_addr_tuple):
        """Handles the AUTH command."""
        if not AUTH_REQUIRED:
            # If AUTH is not required, any AUTH command with 1 argument succeeds
            if len(args) == 1:
                self.authenticated = True
                return resp_encode("OK")
            else:
                raise RESPError("ERR wrong number of arguments for 'auth' command")

        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'auth' command")
        password = args[0]
        if password == EXPECTED_PASSWORD:
            self.authenticated = True
            return resp_encode("OK")
        else:
            raise RESPError("ERR invalid password")

    async def handle_multi(self, args, client_addr_tuple):
        """Handles the MULTI command."""
        if self.in_transaction:
            raise RESPError("ERR MULTI calls can not be nested")
        self.in_transaction = True
        self.transaction_queue = []
        return resp_encode("OK")

    async def handle_exec(self, args, client_addr_tuple):
        """Handles the EXEC command."""
        if not self.in_transaction:
            raise RESPError("ERR EXEC without MULTI")
        
        self.in_transaction = False
        results = []
        
        for command_parts in self.transaction_queue:
            cmd = command_parts[0].upper()
            cmd_args = command_parts[1:]
            
            try:
                # Call the handler for each queued command, without transaction/auth checks
                handler = getattr(self, f"handle_{cmd.lower()}", None)
                if handler:
                    # Execute the command and get its RESP encoded result
                    # Note: We pass a dummy client_addr_tuple as the context is for the transaction
                    result_bytes = await handler(cmd_args, ("127.0.0.1", 0)) # Use a dummy IP for logging
                    results.append(result_bytes)
                else:
                    results.append(resp_encode(RESPError(f"ERR unknown command in transaction: {cmd}")))
            except Exception as e:
                # If a command in transaction fails, Redis typically returns an error within the EXEC array
                results.append(resp_encode(RESPError(f"ERR transaction command failed: {e}")))

        self.transaction_queue = []
        return resp_encode(results) # Returns an array of results from each command

    async def handle_discard(self, args, client_addr_tuple):
        """Handles the DISCARD command."""
        if not self.in_transaction:
            raise RESPError("ERR DISCARD without MULTI")
        self.in_transaction = False
        self.transaction_queue = []
        return resp_encode("OK")

    async def handle_quit(self, args, client_addr_tuple):
        """Handles the QUIT command."""
        return resp_encode("OK")

    async def handle_slaveof(self, args, client_addr_tuple):
        """Handles the SLAVEOF command."""
        client_addr_str = f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"
        if len(args) != 2:
            raise RESPError("ERR wrong number of arguments for 'slaveof' command")
        
        master_host = args[0]
        master_port_str = args[1]
        
        try:
            master_port = int(master_port_str)
        except ValueError:
            raise RESPError("ERR invalid port number")

        if master_host.lower() == "no" and master_port_str.lower() == "one":
            self.master_info = None
            logger.warning("SLAVEOF NO ONE received from %s. Honeypot simulating transition to master.", client_addr_str, extra={'client_addr': client_addr_str})
            return resp_encode("OK")
        
        self.master_info = {"host": master_host, "port": master_port}
        logger.critical(
            "SLAVEOF command captured from %s! Attacker attempting replication from master: %s:%s. "
            "Attempting to connect and retrieve potential RDB/module transfer.",
            client_addr_str, master_host, master_port, extra={'client_addr': client_addr_str}
        )
        
        # Attempt to connect to the attacker's "master" to retrieve a payload
        payload_filename = os.path.join(PAYLOADS_DIR, f"slaveof_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{client_addr_tuple[0]}.bin")
        try:
            # Set a short timeout to avoid blocking the honeypot indefinitely
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(master_host, master_port), timeout=5
            )
            logger.info("Successfully connected to attacker's master %s:%s from %s.", master_host, master_port, client_addr_str, extra={'client_addr': client_addr_str})
            
            payload_data = b""
            # Read a chunk of data. Redis replication typically starts with a handshake
            # followed by the RDB or AOF file. We'll just grab what we can.
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=2) # Read in chunks with timeout
                    if not chunk:
                        break
                    payload_data += chunk
                    if len(payload_data) > 1024 * 1024 * 5: # Limit to 5MB to prevent OOM
                        logger.warning("Payload from %s:%s exceeded 5MB, truncating.", master_host, master_port, extra={'client_addr': client_addr_str})
                        break
            except asyncio.TimeoutError:
                logger.warning("Timeout while reading payload from %s:%s. Read %d bytes.", master_host, master_port, len(payload_data), extra={'client_addr': client_addr_str})
            except Exception as read_e:
                logger.error("Error reading payload from %s:%s: %s", master_host, master_port, read_e, exc_info=True, extra={'client_addr': client_addr_str})

            writer.close()
            await writer.wait_closed()

            if payload_data:
                with open(payload_filename, 'wb') as f:
                    f.write(payload_data)
                logger.critical("Captured %d bytes payload from SLAVEOF target %s:%s, saved to %s",
                                len(payload_data), master_host, master_port, payload_filename, extra={'client_addr': client_addr_str})
            else:
                logger.info("No payload data received from SLAVEOF target %s:%s", master_host, master_port, extra={'client_addr': client_addr_str})

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as conn_e:
            logger.warning("Failed to connect to SLAVEOF target %s:%s from %s: %s", master_host, master_port, client_addr_str, conn_e, extra={'client_addr': client_addr_str})
        except Exception as e:
            logger.error("Unexpected error during SLAVEOF payload retrieval from %s:%s from %s: %s", master_host, master_port, client_addr_str, e, exc_info=True, extra={'client_addr': client_addr_str})
        
        return resp_encode("OK")

    async def handle_replconf(self, args, client_addr_tuple):
        """Handles REPLCONF. Acknowledges, but doesn't implement replication."""
        # REPLCONF can have various arguments (e.g., listening-port, capa, ack)
        # For a honeypot, we mostly just need to acknowledge it.
        # If it's REPLCONF ACK, we should respond with an empty bulk string or specific format.
        if len(args) >= 2 and args[0].lower() == "ack":
            try:
                # Redis's REPLCONF ACK response is typically an empty string or +OK
                int(args[1]) # Just try to parse the offset
                return resp_encode("OK")
            except ValueError:
                # Malformed ACK, but still return OK for stealth
                return resp_encode("OK")
        elif len(args) >= 2 and args[0].lower() == "listening-port":
            try:
                int(args[1]) # Just try to parse the port
                return resp_encode("OK")
            except ValueError:
                return resp_encode("OK")
        elif len(args) >= 2 and args[0].lower() == "capa":
            # REPLCONF capa response is typically OK
            return resp_encode("OK")
        
        # Default for other REPLCONF forms
        return resp_encode("OK")

    async def handle_psync(self, args, client_addr_tuple):
        """Handles PSYNC. Logs and simulates full resync."""
        client_addr_str = f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"
        if len(args) != 2:
            raise RESPError("ERR wrong number of arguments for 'psync' command")
        
        replid = args[0]
        offset = args[1]

        logger.warning("PSYNC command detected from %s! Master ID: %s, Offset: %s. Initiating full resync simulation.", client_addr_str, replid, offset, extra={'client_addr': client_addr_str})

        # Format: +FULLRESYNC <replid> <offset>\r\n
        # Followed by a Redis RDB file (which we won't generate here).
        
        fake_replid = ''.join(random.choices('0123456789abcdef', k=40))
        fake_offset = random.randint(100000, 500000) # Simulate some arbitrary offset

        response_header = f"+FULLRESYNC {fake_replid} {fake_offset}\r\n".encode('utf-8')
        
        # Redis then sends an RDB file. We can simulate a small, empty RDB file
        # or just send the header and let the client time out or error.
        # A minimal RDB header (REDIS followed by 4-byte version and 8-byte checksum placeholder)
        # This is a very rough simulation.
        # Minimal RDB file: REDIS<version><checksum_placeholder><EOF_MARKER>
        # Version 6: REDIS0006
        minimal_rdb = b"REDIS0006" + b"\xFA" + b"\t" + b"\x00" + b"\x00" + b"\x00" + b"\x00" + b"\x00" + b"\x00" + b"\x00" + b"\x00" # DUMMY_DB_SIZE, EOF, CRC
        
        return response_header + b"$" + str(len(minimal_rdb)).encode() + b"\r\n" + minimal_rdb + b"\r\n" # Send as bulk string


    async def handle_publish(self, args, client_addr_tuple):
        """Handles the PUBLISH command (simplified)."""
        if len(args) != 2:
            raise RESPError("ERR wrong number of arguments for 'publish' command")
        channel = args[0]
        message = args[1]
        logger.info("PUBLISH command received (channel: %s, message: %s).", channel, message, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        # In a real Redis, this would broadcast the message. Here, we just log and return 0 (no subscribers).
        return resp_encode(0)

    async def handle_subscribe(self, args, client_addr_tuple):
        """Handles the SUBSCRIBE command (simplified)."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'subscribe' command")
        channels = args
        logger.info("SUBSCRIBE command received (channels: %s).", channels, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        # For a honeypot, we acknowledge the subscription.
        # Response format: Array of [message_type, channel, count_of_subscribed_channels] for each channel
        responses = []
        for i, channel in enumerate(channels):
            responses.append(["subscribe", channel, i + 1])
        return resp_encode(responses)

    async def handle_psubscribe(self, args, client_addr_tuple):
        """Handles the PSUBSCRIBE command (simplified)."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'psubscribe' command")
        patterns = args
        logger.info("PSUBSCRIBE command received (patterns: %s).", patterns, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        responses = []
        for i, pattern in enumerate(patterns):
            responses.append(["psubscribe", pattern, i + 1])
        return resp_encode(responses)

    async def handle_unsubscribe(self, args, client_addr_tuple):
        """Handles the UNSUBSCRIBE command (simplified)."""
        channels = args if args else [] # Unsubscribe from all if no args
        logger.info("UNSUBSCRIBE command received (channels: %s).", channels, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        responses = []
        # In a real Redis, the count would reflect currently subscribed channels.
        # Here, we just simulate decrementing.
        for i, channel in enumerate(channels):
            responses.append(["unsubscribe", channel, max(0, len(channels) - i -1)])
        if not channels: # If no channels specified, simulate unsubscribing from all
             responses.append(["unsubscribe", None, 0])
        return resp_encode(responses)

    async def handle_punsubscribe(self, args, client_addr_tuple):
        """Handles the PUNSUBSCRIBE command (simplified)."""
        patterns = args if args else [] # Unsubscribe from all if no args
        logger.info("PUNSUBSCRIBE command received (patterns: %s).", patterns, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
        responses = []
        for i, pattern in enumerate(patterns):
            responses.append(["punsubscribe", pattern, max(0, len(patterns) - i - 1)])
        if not patterns: # If no patterns specified, simulate unsubscribing from all
             responses.append(["punsubscribe", None, 0])
        return resp_encode(responses)
    
    async def handle_client_command(self, args, client_addr_tuple):
        """Handles the CLIENT command, returning realistic information."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'client' command")
        subcommand = args[0].upper()

        if subcommand == "GETNAME":
            return resp_encode(None) # Default Redis clients often have no name
        elif subcommand == "SETNAME":
            if len(args) != 2:
                raise RESPError("ERR wrong number of arguments for 'client setname' command")
            # client_name = args[1] # We could store this per client if needed
            return resp_encode("OK")
        elif subcommand == "LIST":
            # Simulate a list of connected clients, including the current one
            # Format: id=... addr=... fd=... name=... age=... idle=... flags=... db=... sub=... psub=... multi=... qbuf=... qbuf_free=... argvmem=... cmd=... user=...
            client_id = random.randint(100, 99999)
            age = int(time.time() - self.start_time)
            idle = random.randint(0, 60)
            
            # A more detailed client info string
            client_info_string = (
                f"id={client_id} addr={client_addr_tuple[0]}:{client_addr_tuple[1]} fd={random.randint(10, 100)} "
                f"name= age={age} idle={idle} flags=N db={self.current_db_index} "
                f"sub=0 psub=0 multi=0 qbuf=0 qbuf_free=32768 argvmem=0 cmd=client user=default"
            )
            return resp_encode(client_info_string)
        elif subcommand == "KILL":
            # CLIENT KILL [ip:port] [ID client-id] [TYPE normal|master|replica|pubsub] [SKIPNO]
            # For a honeypot, we just acknowledge or simulate kill
            if len(args) >= 2:
                # Log the attempted kill
                logger.warning("CLIENT KILL command received with args: %s", args, extra={'client_addr': f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"})
                return resp_encode(1) # Simulate one client killed
            else:
                raise RESPError("ERR wrong number of arguments for 'client kill' command")
        else:
            raise RESPError(f"ERR unknown CLIENT subcommand '{subcommand}'")

    async def handle_command_command(self, args, client_addr_tuple):
        """Handles the COMMAND command, returning a plausible list of commands."""
        # This needs to be a realistic subset of commands that Redis supports.
        # Nmap's Redis probe often uses COMMAND or COMMAND INFO to fingerprint.
        # The arguments are: name, arity, flags, first_key, last_key, step, categories
        
        # A plausible set of commands with correct arities and flags
        commands_info = [
            # Strings
            ["get", 2, ["readonly", "fast"], 1, 1, 1, ["read"]],
            ["set", -3, ["write", "denyoom"], 1, 1, 1, ["write"]],
            ["del", -2, ["write"], 1, -1, 1, ["write"]],
            ["exists", -2, ["readonly", "fast"], 1, -1, 1, ["read"]],
            ["incr", 2, ["write", "denyoom", "fast"], 1, 1, 1, ["write"]],
            ["decr", 2, ["write", "denyoom", "fast"], 1, 1, 1, ["write"]],
            ["echo", 2, ["fast"], 0, 0, 0, ["fast"]],
            ["ping", -1, ["fast"], 0, 0, 0, ["fast"]],
            ["keys", 2, ["readonly", "slow", "dangerous"], 0, 0, 0, ["read"]], # Dangerous is a flag
            ["ttl", 2, ["readonly", "fast"], 1, 1, 1, ["read"]],
            # Hashes
            ["hset", -4, ["write", "denyoom"], 1, 1, 1, ["write"]],
            ["hget", 3, ["readonly", "fast"], 1, 1, 1, ["read"]],
            ["hgetall", 2, ["readonly", "slow"], 1, 1, 1, ["read"]],
            ["hdel", -3, ["write", "fast"], 1, 1, 1, ["write"]],
            ["hexists", 3, ["readonly", "fast"], 1, 1, 1, ["read"]],
            # Lists
            ["lpush", -3, ["write", "denyoom", "fast"], 1, 1, 1, ["write"]],
            ["rpush", -3, ["write", "denyoom", "fast"], 1, 1, 1, ["write"]],
            ["lpop", 2, ["write", "fast"], 1, 1, 1, ["write"]],
            ["rpop", 2, ["write", "fast"], 1, 1, 1, ["write"]],
            ["lrange", 4, ["readonly"], 1, 1, 1, ["read"]],
            ["llen", 2, ["readonly", "fast"], 1, 1, 1, ["read"]],
            # Sets
            ["sadd", -3, ["write", "denyoom", "fast"], 1, 1, 1, ["write"]],
            ["smembers", 2, ["readonly", "slow"], 1, 1, 1, ["read"]],
            ["srem", -3, ["write", "fast"], 1, 1, 1, ["write"]],
            ["sismember", 3, ["readonly", "fast"], 1, 1, 1, ["read"]],
            ["scard", 2, ["readonly", "fast"], 1, 1, 1, ["read"]],
            # Sorted Sets
            ["zadd", -4, ["write", "denyoom", "fast"], 1, 1, 1, ["write"]],
            ["zrange", -4, ["readonly"], 1, 1, 1, ["read"]],
            ["zrem", -3, ["write", "fast"], 1, 1, 1, ["write"]],
            ["zcard", 2, ["readonly", "fast"], 1, 1, 1, ["read"]],
            # Admin/Connection/Pubsub
            ["auth", 2, ["noscript", "loading", "admin", "fast"], 0, 0, 0, ["connection"]],
            ["select", 2, ["loading", "fast"], 0, 0, 0, ["connection"]],
            ["info", -1, ["loading", "admin", "fast"], 0, 0, 0, ["server"]],
            ["flushall", -1, ["write", "dangerous"], 0, 0, 0, ["keyspace", "fast"]],
            ["flushdb", -1, ["write", "dangerous"], 0, 0, 0, ["keyspace", "fast"]],
            ["save", 1, ["admin", "blocking", "dangerous"], 0, 0, 0, ["server"]],
            ["config", -2, ["admin", "noscript", "loading"], 0, 0, 0, ["server"]],
            ["multi", 1, ["noscript", "fast"], 0, 0, 0, ["transactions"]],
            ["exec", 1, ["noscript", "slow"], 0, 0, 0, ["transactions"]],
            ["discard", 1, ["noscript", "fast"], 0, 0, 0, ["transactions"]],
            ["quit", 1, ["fast"], 0, 0, 0, ["connection"]],
            ["slaveof", 3, ["admin", "noscript"], 0, 0, 0, ["replication"]],
            ["replconf", -1, ["admin", "noscript", "fast"], 0, 0, 0, ["replication"]],
            ["psync", 3, ["admin", "noscript"], 0, 0, 0, ["replication"]],
            ["publish", 3, ["pubsub", "fast"], 0, 0, 0, ["pubsub"]],
            ["subscribe", -2, ["pubsub", "noscript"], 0, 0, 0, ["pubsub"]],
            ["psubscribe", -2, ["pubsub", "noscript"], 0, 0, 0, ["pubsub"]],
            ["unsubscribe", -1, ["pubsub", "noscript"], 0, 0, 0, ["pubsub"]],
            ["punsubscribe", -1, ["pubsub", "noscript"], 0, 0, 0, ["pubsub"]],
            ["client", -2, ["admin", "noscript", "fast"], 0, 0, 0, ["connection"]],
            ["command", -1, ["readonly", "noscript", "fast"], 0, 0, 0, ["server"]]
        ]

        if not args: # COMMAND
            # Return full list of supported commands for COMMAND
            return resp_encode(commands_info)
        elif args[0].upper() == "INFO":
            if len(args) == 2:
                cmd_name = args[1].lower()
                # Find info for a specific command
                for cmd in commands_info:
                    if cmd[0] == cmd_name:
                        return resp_encode([cmd])
                return resp_encode(None) # Return nil if command not found
            else:
                raise RESPError("ERR wrong number of arguments for 'command info' command")
        elif args[0].upper() == "COUNT":
            return resp_encode(len(commands_info))
        elif args[0].upper() == "GETKEYS":
            # This is complex to implement fully; return error or a mock
            raise RESPError("ERR COMMAND GETKEYS not supported by this honeypot")
        elif args[0].upper() == "GETKEYSANDFLAGS":
            # This is complex to implement fully; return error or a mock
            raise RESPError("ERR COMMAND GETKEYSANDFLAGS not supported by this honeypot")
        else:
            raise RESPError(f"ERR unknown COMMAND subcommand '{args[0]}'")

    async def handle_echo(self, args, client_addr_tuple):
        """Handles the ECHO command."""
        if not args:
            raise RESPError("ERR wrong number of arguments for 'echo' command")
        return resp_encode(args[0])
    
    async def handle_ttl(self, args, client_addr_tuple):
        """Handles the TTL command (simplified)."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'ttl' command")
        key = args[0]
        if key not in self.get_current_db():
            return resp_encode(-2) # Key does not exist
        # For simplicity, all keys in our in-memory store have no expiry
        return resp_encode(-1) # Key exists but has no associated expire

    async def handle_incr(self, args, client_addr_tuple):
        """Handles the INCR command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'incr' command")
        key = args[0]
        current_db = self.get_current_db()
        try:
            value = current_db.get(key)
            if value is None:
                new_value = 1
            else:
                new_value = int(value) + 1
            current_db[key] = str(new_value) # Store as string, as Redis does
            return resp_encode(new_value)
        except ValueError:
            raise RESPError("ERR value is not an integer or out of range")

    async def handle_decr(self, args, client_addr_tuple):
        """Handles the DECR command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'decr' command")
        key = args[0]
        current_db = self.get_current_db()
        try:
            value = current_db.get(key)
            if value is None:
                new_value = -1
            else:
                new_value = int(value) - 1
            current_db[key] = str(new_value) # Store as string, as Redis does
            return resp_encode(new_value)
        except ValueError:
            raise RESPError("ERR value is not an integer or out of range")
    
    # --- Hash Commands ---
    async def handle_hset(self, args, client_addr_tuple):
        """Handles the HSET command."""
        if len(args) < 3 or len(args) % 2 == 0: # HSET key field value [field value ...]
            raise RESPError("ERR wrong number of arguments for 'hset' command")
        key = args[0]
        current_db = self.get_current_db()
        
        # Initialize as dict if not exists or wrong type
        if key not in current_db or not isinstance(current_db[key], dict):
            current_db[key] = {}
            added_fields = 0
        else:
            added_fields = 0 # This will count newly added fields, not updates
        
        hash_obj = current_db[key]
        for i in range(1, len(args), 2):
            field = args[i]
            value = args[i+1]
            if field not in hash_obj:
                added_fields += 1
            hash_obj[field] = value
        return resp_encode(added_fields)

    async def handle_hget(self, args, client_addr_tuple):
        """Handles the HGET command."""
        if len(args) != 2:
            raise RESPError("ERR wrong number of arguments for 'hget' command")
        key = args[0]
        field = args[1]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        if isinstance(hash_obj, dict):
            return resp_encode(hash_obj.get(field))
        return resp_encode(None) # Return nil if key is not a hash or does not exist/field not found

    async def handle_hgetall(self, args, client_addr_tuple):
        """Handles the HGETALL command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'hgetall' command")
        key = args[0]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        if isinstance(hash_obj, dict):
            result = []
            for field, value in hash_obj.items():
                result.append(field)
                result.append(value)
            return resp_encode(result)
        return resp_encode([]) # Return empty array if key is not a hash or does not exist

    async def handle_hdel(self, args, client_addr_tuple):
        """Handles the HDEL command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'hdel' command")
        key = args[0]
        fields_to_delete = args[1:]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        deleted_count = 0
        if isinstance(hash_obj, dict):
            for field in fields_to_delete:
                if field in hash_obj:
                    del hash_obj[field]
                    deleted_count += 1
            if not hash_obj: # Remove key if hash becomes empty
                del current_db[key]
        return resp_encode(deleted_count)

    async def handle_hexists(self, args, client_addr_tuple):
        """Handles the HEXISTS command."""
        if len(args) != 2:
            raise RESPError("ERR wrong number of arguments for 'hexists' command")
        key = args[0]
        field = args[1]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        exists = 0
        if isinstance(hash_obj, dict) and field in hash_obj:
            exists = 1
        return resp_encode(exists)

    # --- List Commands ---
    async def handle_lpush(self, args, client_addr_tuple):
        """Handles the LPUSH command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'lpush' command")
        key = args[0]
        elements = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = []
        elif not isinstance(current_db[key], list):
            raise RESPError(f"ERR Operation against a key holding the wrong kind of value")
        
        current_db[key] = elements[::-1] + current_db[key] # Prepend elements
        return resp_encode(len(current_db[key]))

    async def handle_rpush(self, args, client_addr_tuple):
        """Handles the RPUSH command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'rpush' command")
        key = args[0]
        elements = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = []
        elif not isinstance(current_db[key], list):
            raise RESPError(f"ERR Operation against a key holding the wrong kind of value")
        
        current_db[key].extend(elements) # Append elements
        return resp_encode(len(current_db[key]))

    async def handle_lpop(self, args, client_addr_tuple):
        """Handles the LPOP command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'lpop' command")
        key = args[0]
        current_db = self.get_current_db()
        list_obj = current_db.get(key)

        if isinstance(list_obj, list) and list_obj:
            popped_item = list_obj.pop(0) # Pop from the left (beginning)
            if not list_obj: # Remove key if list becomes empty
                del current_db[key]
            return resp_encode(popped_item)
        return resp_encode(None) # List empty or not a list

    async def handle_rpop(self, args, client_addr_tuple):
        """Handles the RPOP command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'rpop' command")
        key = args[0]
        current_db = self.get_current_db()
        list_obj = current_db.get(key)

        if isinstance(list_obj, list) and list_obj:
            popped_item = list_obj.pop() # Pop from the right (end)
            if not list_obj: # Remove key if list becomes empty
                del current_db[key]
            return resp_encode(popped_item)
        return resp_encode(None) # List empty or not a list

    async def handle_lrange(self, args, client_addr_tuple):
        """Handles the LRANGE command."""
        if len(args) != 3:
            raise RESPError("ERR wrong number of arguments for 'lrange' command")
        key = args[0]
        try:
            start = int(args[1])
            end = int(args[2])
        except ValueError:
            raise RESPError("ERR value is not an integer or out of range")

        current_db = self.get_current_db()
        list_obj = current_db.get(key)

        if isinstance(list_obj, list):
            # Handle negative indices as per Redis
            if start < 0:
                start = len(list_obj) + start
            if end < 0:
                end = len(list_obj) + end
            
            # Adjust slicing for inclusive end and bounds
            if start > end: # Redis returns empty list if start > end
                result = []
            else:
                result = list_obj[start : end + 1]
            return resp_encode(result)
        return resp_encode([]) # Return empty array if not a list or doesn't exist

    async def handle_llen(self, args, client_addr_tuple):
        """Handles the LLEN command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'llen' command")
        key = args[0]
        current_db = self.get_current_db()
        list_obj = current_db.get(key)
        if isinstance(list_obj, list):
            length = len(list_obj)
            return resp_encode(length)
        return resp_encode(0) # Return 0 if not a list or doesn't exist

    # --- Set Commands ---
    async def handle_sadd(self, args, client_addr_tuple):
        """Handles the SADD command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'sadd' command")
        key = args[0]
        members = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = set()
        elif not isinstance(current_db[key], set):
            raise RESPError(f"ERR Operation against a key holding the wrong kind of value")
        
        added_count = 0
        for member in members:
            if member not in current_db[key]:
                current_db[key].add(member)
                added_count += 1
        return resp_encode(added_count)

    async def handle_smembers(self, args, client_addr_tuple):
        """Handles the SMEMBERS command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'smembers' command")
        key = args[0]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        if isinstance(set_obj, set):
            members_list = list(set_obj) # Convert to list for RESP encoding
            return resp_encode(members_list)
        return resp_encode([]) # Return empty array if not a set or doesn't exist

    async def handle_srem(self, args, client_addr_tuple):
        """Handles the SREM command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'srem' command")
        key = args[0]
        members_to_remove = args[1:]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        removed_count = 0
        if isinstance(set_obj, set):
            for member in members_to_remove:
                if member in set_obj:
                    set_obj.remove(member)
                    removed_count += 1
            if not set_obj: # Remove key if set becomes empty
                del current_db[key]
        return resp_encode(removed_count)

    async def handle_sismember(self, args, client_addr_tuple):
        """Handles the SISMEMBER command."""
        if len(args) != 2:
            raise RESPError("ERR wrong number of arguments for 'sismember' command")
        key = args[0]
        member = args[1]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        is_member = 0
        if isinstance(set_obj, set) and member in set_obj:
            is_member = 1
        return resp_encode(is_member)

    async def handle_scard(self, args, client_addr_tuple):
        """Handles the SCARD command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'scard' command")
        key = args[0]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        if isinstance(set_obj, set):
            cardinality = len(set_obj)
            return resp_encode(cardinality)
        return resp_encode(0) # Return 0 if not a set or doesn't exist

    # --- Sorted Set Commands (Simplified) ---
    async def handle_zadd(self, args, client_addr_tuple):
        """Handles the ZADD command."""
        if len(args) < 3 or len(args) % 2 != 1: # ZADD key score member [score member ...]
            raise RESPError("ERR wrong number of arguments for 'zadd' command")
        key = args[0]
        members_scores = args[1:]
        current_db = self.get_current_db()

        # Sorted sets are stored as a list of (member, score) tuples, kept sorted
        if key not in current_db:
            current_db[key] = []
        # Check if it's a list, and if elements are tuples of len 2 (member, score)
        elif not (isinstance(current_db[key], list) and all(isinstance(x, tuple) and len(x) == 2 for x in current_db[key])):
            raise RESPError(f"ERR Operation against a key holding the wrong kind of value")
        
        zset_obj = current_db[key]
        added_count = 0 # Count members that were truly added (not just updated)
        for i in range(0, len(members_scores), 2):
            try:
                score = float(members_scores[i])
                member = members_scores[i+1]
            except ValueError:
                raise RESPError("ERR value is not a valid float")

            # Check if member already exists to update score or add new
            found = False
            for j, (existing_member, _) in enumerate(zset_obj):
                if existing_member == member:
                    zset_obj[j] = (member, score) # Update score
                    found = True
                    break
            if not found:
                zset_obj.append((member, score))
                added_count += 1
        
        # Sort the zset by score (ascending) for realism
        zset_obj.sort(key=lambda x: x[1])
        current_db[key] = zset_obj # Update the stored list
        return resp_encode(added_count)


    async def handle_zrange(self, args, client_addr_tuple):
        """Handles the ZRANGE command."""
        if len(args) < 3: # ZRANGE key start stop [WITHSCORES]
            raise RESPError("ERR wrong number of arguments for 'zrange' command")
        key = args[0]
        try:
            start_idx = int(args[1])
            stop_idx = int(args[2])
        except ValueError:
            raise RESPError("ERR value is not an integer or out of range")
        
        with_scores = False
        if len(args) > 3 and args[3].upper() == "WITHSCORES":
            with_scores = True

        current_db = self.get_current_db()
        zset_obj = current_db.get(key)
        
        result = []
        if isinstance(zset_obj, list) and all(isinstance(x, tuple) and len(x) == 2 for x in zset_obj):
            # Handle negative indices
            list_len = len(zset_obj)
            if start_idx < 0:
                start_idx = list_len + start_idx
            if stop_idx < 0:
                stop_idx = list_len + stop_idx

            # Adjust slicing for inclusive stop and bounds
            # Redis ZRANGE includes both start and stop. Python slice is [start:end] (exclusive of end).
            # So, if stop_idx is positive, we need to add 1 to it for Python slice.
            if stop_idx >= 0:
                stop_idx += 1 
            
            # Clamp indices
            start_idx = max(0, start_idx)
            stop_idx = min(list_len, stop_idx)

            ranged_items = zset_obj[start_idx:stop_idx]

            for member, score in ranged_items:
                result.append(member)
                if with_scores:
                    result.append(str(score)) # Scores are returned as bulk strings
            
        return resp_encode(result)

    async def handle_zrem(self, args, client_addr_tuple):
        """Handles the ZREM command."""
        if len(args) < 2:
            raise RESPError("ERR wrong number of arguments for 'zrem' command")
        key = args[0]
        members_to_remove = args[1:]
        current_db = self.get_current_db()
        zset_obj = current_db.get(key)
        removed_count = 0
        if isinstance(zset_obj, list) and all(isinstance(x, tuple) and len(x) == 2 for x in zset_obj):
            original_len = len(zset_obj)
            zset_obj_updated = [(m, s) for m, s in zset_obj if m not in members_to_remove]
            removed_count = original_len - len(zset_obj_updated)
            if not zset_obj_updated: # Remove key if zset becomes empty
                del current_db[key]
            else:
                current_db[key] = zset_obj_updated # Update the stored list
        return resp_encode(removed_count)

    async def handle_zcard(self, args, client_addr_tuple):
        """Handles the ZCARD command."""
        if len(args) != 1:
            raise RESPError("ERR wrong number of arguments for 'zcard' command")
        key = args[0]
        current_db = self.get_current_db()
        zset_obj = current_db.get(key)
        if isinstance(zset_obj, list) and all(isinstance(x, tuple) and len(x) == 2 for x in zset_obj):
            cardinality = len(zset_obj)
            return resp_encode(cardinality)
        return resp_encode(0) # Return 0 if not a sorted set or doesn't exist


# --- Web Portal Functions ---
async def logs_page(request):
    """Serves an HTML page to view logs."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Redis Honeypot Logs</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }
            h1 { color: #333; }
            #log-container {
                background-color: #fff;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 15px;
                max-height: 80vh;
                overflow-y: scroll;
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 0.9em;
                white-space: pre-wrap; /* Preserve whitespace and wrap long lines */
                word-wrap: break-word; /* Break long words */
            }
            .log-entry { margin-bottom: 5px; border-bottom: 1px solid #eee; padding-bottom: 5px; }
            .log-entry:last-child { border-bottom: none; }
            .level-INFO { color: #28a745; }    /* Green */
            .level-WARNING { color: #ffc107; } /* Orange */
            .level-ERROR { color: #dc3545; }   /* Red */
            .level-CRITICAL { color: #a00; font-weight: bold; } /* Darker Red, Bold */
            .level-DEBUG { color: #6c757d; }   /* Grey */
            .timestamp { color: #666; font-size: 0.85em; margin-right: 10px; }
            .client-addr { color: #007bff; font-weight: bold; margin-right: 10px; }
            #live-updates-status {
                margin-top: 10px;
                font-size: 0.9em;
                color: #555;
            }
        </style>
    </head>
    <body>
        <h1>Redis Honeypot Live Logs</h1>
        <div id="log-container">Loading logs...</div>
        <div id="live-updates-status">Waiting for live updates...</div>

        <script>
            const logContainer = document.getElementById('log-container');
            const liveUpdatesStatus = document.getElementById('live-updates-status');

            async function fetchLogs() {
                try {
                    const response = await fetch('/api/logs');
                    const logs = await response.json();
                    logContainer.innerHTML = ''; // Clear existing logs
                    logs.forEach(log => {
                        const logEntryDiv = document.createElement('div');
                        logEntryDiv.classList.add('log-entry');
                        logEntryDiv.classList.add(`level-${log.levelname}`); // Add class for styling
                        logEntryDiv.innerHTML = `
                            <span class="timestamp">${new Date(log.timestamp * 1000).toLocaleString()}</span>
                            <span class="client-addr">${log.client_addr}</span>
                            <strong>${log.levelname}:</strong> ${log.message}
                        `;
                        logContainer.prepend(logEntryDiv); // Add to top for most recent logs
                    });
                    // Scroll to bottom after loading new logs
                    // logContainer.scrollTop = logContainer.scrollHeight;
                    liveUpdatesStatus.textContent = `Last updated: ${new Date().toLocaleTimeString()} (Polling)`;
                } catch (error) {
                    console.error('Error fetching logs:', error);
                    liveUpdatesStatus.textContent = `Error fetching logs: ${error.message}`;
                    logContainer.innerHTML = '<p style="color: red;">Failed to load logs.</p>';
                }
            }

            // Fetch logs immediately on page load
            fetchLogs();
            // Poll for new logs every 3 seconds
            setInterval(fetchLogs, 3000);
        </script>
    </body>
    </html>
    """
    return web.Response(text=html_content, content_type='text/html')

async def api_logs(request):
    """API endpoint to return recent logs as JSON."""
    # Convert deque to list and reverse to get newest first for API
    logs_list = list(recent_logs)[::-1]
    return web.json_response(logs_list)

async def start_web_server():
    """Starts the aiohttp web server for the log viewer."""
    app = web.Application()
    app.router.add_get('/', logs_page)
    app.router.add_get('/api/logs', api_logs)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, WEB_PORT)
    await site.start()
    logger.info(f"Web log viewer started on http://{HOST}:{WEB_PORT}", extra={'client_addr': 'SERVER'})

# --- Main Honeypot Server ---
async def handle_client(reader, writer):
    """
    Handles a single client connection. Reads commands, processes them, and sends responses.
    """
    client_addr_tuple = writer.get_extra_info('peername')
    client_addr_str = f"{client_addr_tuple[0]}:{client_addr_tuple[1]}"
    logger.info("New connection from %s", client_addr_str, extra={'client_addr': client_addr_str})

    # Each client gets its own honeypot state for isolation.
    # This prevents one client's actions from affecting another's view of the DB.
    honeypot_instance = RedisHoneypot() 

    try:
        # Loop to handle multiple commands from the same client
        while True:
            try:
                # Read and decode the RESP command
                command_parts = await resp_decode(reader)
                
                # If command_parts is None, it means a Null Array was received, or client disconnected cleanly after sending a final newline
                if command_parts is None:
                    logger.debug("Client %s sent a Null Array or empty command, disconnecting.", client_addr_str, extra={'client_addr': client_addr_str})
                    break 

                # If resp_decode returns a RESPError object, it indicates a protocol violation
                if isinstance(command_parts, RESPError):
                    logger.error("RESP Protocol Error for client %s: %s", client_addr_str, command_parts, extra={'client_addr': client_addr_str})
                    # Send a generic Redis protocol error message for malformed requests
                    writer.write(resp_encode(RESPError("ERR Protocol error: invalid multibulk length or malformed request")))
                    await writer.drain()
                    break # Close connection on severe protocol error
                
                # Ensure the top-level command is an array of bulk strings (standard Redis command format)
                if not isinstance(command_parts, list) or \
                   not all(isinstance(part, (str, type(None))) for part in command_parts):
                    logger.warning("Received malformed command (not an array of strings/nil) from %s: %s", client_addr_str, command_parts, extra={'client_addr': client_addr_str})
                    writer.write(resp_encode(RESPError("ERR Protocol error: expected bulk strings or nil in array")))
                    await writer.drain()
                    break # Close connection on malformed command

                # Execute the command using the honeypot instance's handler
                response = await honeypot_instance.handle_command(command_parts, client_addr_tuple)
                
                # Write the response back to the client
                writer.write(response)
                await writer.drain()

            except asyncio.IncompleteReadError:
                # This exception is raised when the connection is closed by the client gracefully (EOF)
                logger.info("Client %s disconnected gracefully (EOF).", client_addr_str, extra={'client_addr': client_addr_str})
                break
            except ConnectionResetError:
                # This exception is raised when the client forcibly closes the connection
                logger.info("Client %s forcibly disconnected.", client_addr_str, extra={'client_addr': client_addr_str})
                break
            except Exception as e:
                # Catch any other unexpected errors during command execution or response encoding
                logger.error("Unhandled error for client %s: %s", client_addr_str, e, exc_info=True, extra={'client_addr': client_addr_str})
                # Send a generic Redis internal error for any unexpected exception
                writer.write(resp_encode(RESPError("ERR internal server error")))
                await writer.drain()
                break # Close connection on unhandled error

    finally:
        logger.info("Connection with %s closed.", client_addr_str, extra={'client_addr': client_addr_str})
        writer.close()
        await writer.wait_closed()


async def main():
    """
    Main function to start the Redis honeypot and web server.
    """
    # Start the Redis honeypot server
    redis_server = await asyncio.start_server(
        handle_client, HOST, PORT, reuse_address=True, reuse_port=True
    )

    # Start the web server concurrently
    web_server_task = asyncio.create_task(start_web_server())

    # Log initial server start
    logger.info(f"\n--- Redis Honeypot Started ---", extra={'client_addr': 'SERVER'})
    logger.info(f"Listening on {HOST}:{PORT}", extra={'client_addr': 'SERVER'})
    logger.info(f"Web log viewer on http://{HOST}:{WEB_PORT}", extra={'client_addr': 'SERVER'})
    logger.info(f"Log file: {LOG_FILE}", extra={'client_addr': 'SERVER'})
    logger.info(f"Persistence file: {STORAGE_FILE}", extra={'client_addr': 'SERVER'})
    logger.info(f"Payloads directory: {PAYLOADS_DIR}", extra={'client_addr': 'SERVER'})
    logger.info(f"Authentication required: {AUTH_REQUIRED}", extra={'client_addr': 'SERVER'})
    if AUTH_REQUIRED:
        logger.info(f"Expected password: {EXPECTED_PASSWORD}", extra={'client_addr': 'SERVER'})
    logger.info(f"To test: redis-cli -p {PORT} (and optionally -a {EXPECTED_PASSWORD} if auth is enabled)", extra={'client_addr': 'SERVER'})
    logger.info(f"------------------------------\n", extra={'client_addr': 'SERVER'})

    # Keep the Redis server running forever
    async with redis_server:
        await redis_server.serve_forever()

    # The web server task will run in the background until the event loop stops
    # await web_server_task # Uncomment this if you want `main()` to wait for web server to finish

# Register the save function to run on program exit
def graceful_shutdown_save():
    """Function to save honeypot data to disk on graceful program exit."""
    # A temporary instance is created to call the save method.
    # In a more complex scenario with shared state, this might need a different approach.
    temp_honeypot = RedisHoneypot()
    temp_honeypot._save_data_to_disk()

atexit.register(graceful_shutdown_save)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Redis Honeypot stopped by user (KeyboardInterrupt).", extra={'client_addr': 'SERVER'})
    except Exception as e:
        logger.critical(f"An unexpected fatal error occurred in main: {e}", exc_info=True, extra={'client_addr': 'SERVER'})

