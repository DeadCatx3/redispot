import asyncio
import logging
import json
import time
import uuid
import re
import os
import atexit

# --- Configuration ---
HOST = '0.0.0.0'  # Bind to all available interfaces for external access
PORT = 6379       # Standard Redis port
LOG_FILE = 'redis_honeypot.log'  # File to log commands and connection attempts
STORAGE_FILE = 'redis_honeypot_data.json' # File for key-value store persistence
PAYLOADS_DIR = 'payloads' # Directory to store captured SLAVEOF payloads
AUTH_REQUIRED = False     # Set to True to require AUTH command
EXPECTED_PASSWORD = "my_secure_password" # Change this if AUTH_REQUIRED is True or use -a

# --- Default Dummy Keys for Honeypot Session ---
# Values should be stored in a way that allows easy reconstruction
DEFAULT_DUMMY_KEYS = {
    "web_cache:user_sessions": "a:1:{s:6:\"active\";b:1;}",
    "config:app_version": "1.0.5",
    "users:last_login:admin": "1718224800",
    "temp_data:processing_queue_size": "50",
    "app:status": "online",
    "service:metrics:requests_per_sec": "120",
    "secret:api_key": "89615-29901-27444-pl60",
    "backup:last_run": "2025-06-12_01:00:00",
    "online_users": {"Deadcatx3", "Guest1106", "Chapplin"},
    "leaderboard": [("Deadcatx3", 100), ("Guest1106", 90), ("Chapplin", 80)]
}


# --- Logging Setup ---
# Configure logging to console and file
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(client_addr)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('redis_honeypot')

# Add client_addr to the logger's extra dictionary for custom formatting
class ClientAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        if 'client_addr' not in kwargs:
            kwargs["extra"] = self.extra
        else:
            if "extra" not in kwargs:
                kwargs["extra"] = {}
            kwargs["extra"]["client_addr"] = kwargs["client_addr"]
        return msg, kwargs

logger = ClientAdapter(logger, {'client_addr': 'N/A'})

# Ensure payloads directory exists
os.makedirs(PAYLOADS_DIR, exist_ok=True)

# --- RESP (Redis Serialization Protocol) Parser and Serializer ---
# RESP documentation reference: https://redis.io/docs/latest/develop/reference/protocol-spec/

class RESPError(Exception):
    """Custom exception for RESP parsing errors."""
    pass

def resp_encode(data):
    """
    Encodes Python data types into RESP byte format.

    Args:
        data: The Python object to encode (str, int, list, None, bytes).

    Returns:
        bytes: The RESP encoded byte string.
    """
    if isinstance(data, str):
        # Simple String
        if '\n' in data or '\r' in data or ' ' in data: # Use Bulk String if it contains spaces or newlines
            return f"${len(data)}\r\n{data}\r\n".encode('utf-8')
        return f"+{data}\r\n".encode('utf-8')
    elif isinstance(data, int):
        # Integer
        return f":{data}\r\n".encode('utf-8')
    elif isinstance(data, bytes):
        # Bulk String (bytes)
        return f"${len(data)}\r\n".encode('utf-8') + data + b"\r\n"
    elif data is None:
        # Null Bulk String
        return b"$-1\r\n"
    elif isinstance(data, list):
        # Array
        encoded_elements = [resp_encode(item) for item in data]
        return f"*{len(data)}\r\n".encode('utf-8') + b"".join(encoded_elements)
    elif isinstance(data, Exception):
        # Error
        error_msg = str(data)
        return f"-ERR {error_msg}\r\n".encode('utf-8')
    else:
        # Attempt to convert other types to string for bulk string encoding
        try:
            str_data = str(data)
            return f"${len(str_data)}\r\n{str_data}\r\n".encode('utf-8')
        except Exception:
            raise ValueError(f"Unsupported data type for RESP encoding: {type(data)}")


async def _read_until_crlf(reader):
    """Reads bytes from the reader until a CRLF (\\r\\n) is encountered."""
    buffer = bytearray()
    while True:
        char = await reader.readexactly(1)
        if char == b'\r':
            next_char = await reader.readexactly(1)
            if next_char == b'\n':
                return buffer.decode('utf-8')
            else:
                buffer.extend(b'\r' + next_char)
        else:
            buffer.extend(char)

async def _parse_bulk_string(reader):
    """Parses a RESP Bulk String."""
    length_str = await _read_until_crlf(reader)
    length = int(length_str)
    if length == -1:
        return None  # Null Bulk String
    data = await reader.readexactly(length)
    crlf = await reader.readexactly(2) # Read the trailing CRLF
    if crlf != b'\r\n':
        raise RESPError("Malformed bulk string: missing CRLF")
    return data.decode('utf-8')

async def resp_decode(reader):
    """
    Decodes RESP bytes from an asyncio StreamReader into Python data types.

    Args:
        reader (asyncio.StreamReader): The stream reader to read from.

    Returns:
        The decoded Python object (str, int, list, None).
    """
    initial_byte = await reader.readexactly(1)

    if initial_byte == b'+':
        return await _read_until_crlf(reader)
    elif initial_byte == b'-':
        return RESPError(await _read_until_crlf(reader))
    elif initial_byte == b':':
        return int(await _read_until_crlf(reader))
    elif initial_byte == b'$':
        return await _parse_bulk_string(reader)
    elif initial_byte == b'*':
        length_str = await _read_until_crlf(reader)
        num_elements = int(length_str)
        if num_elements == -1:
            return None 
        elements = []
        for _ in range(num_elements):
            elements.append(await resp_decode(reader))
        return elements
    else:
        raise RESPError(f"Unknown RESP type prefix: {initial_byte}")

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
                    for db_idx, db_data in data.items():
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
                        self.databases[int(db_idx)] = current_db
                logger.info("Loaded data from %s", STORAGE_FILE, extra={'client_addr': 'SERVER'})
            except (json.JSONDecodeError, IOError) as e:
                logger.error("Failed to load data from %s: %s", STORAGE_FILE, e, extra={'client_addr': 'SERVER'})
        else:
            logger.info("No persistence file found at %s. Starting with empty databases.", STORAGE_FILE, extra={'client_addr': 'SERVER'})

    def _save_data_to_disk(self):
        """Saves the key-value store to the persistence file."""
        serializable_data = {}
        for db_idx, db_data in self.databases.items():
            serializable_db = {}
            for k, v in db_data.items():
                if isinstance(v, list):
                    serializable_db[k] = {'type': 'list', 'value': v}
                elif isinstance(v, dict):
                    serializable_db[k] = {'type': 'hash', 'value': v}
                elif isinstance(v, set):
                    serializable_db[k] = {'type': 'set', 'value': list(v)} # Sets are not JSON serializable directly
                elif isinstance(v, list) and all(isinstance(x, tuple) and len(x) == 2 for x in v): # Heuristic for zset
                    serializable_db[k] = {'type': 'zset', 'value': [[m, s] for m, s in v]} # Tuples are not JSON serializable directly
                else:
                    serializable_db[k] = v # Assume string for other types
            serializable_data[str(db_idx)] = serializable_db
        
        try:
            with open(STORAGE_FILE, 'w') as f:
                json.dump(serializable_data, f, indent=4)
            logger.info("Saved data to %s", STORAGE_FILE, extra={'client_addr': 'SERVER'})
        except IOError as e:
            logger.error("Failed to save data to %s: %s", STORAGE_FILE, e, exc_info=True, extra={'client_addr': 'SERVER'})

    def _populate_dummy_keys(self):
        """Populates db0 with default dummy keys."""
        for key, value in DEFAULT_DUMMY_KEYS.items():
            self.databases[0][key] = value
        logger.info("Populated DB0 with default dummy keys.", extra={'client_addr': 'SERVER'})

    def get_current_db(self):
        """Returns the currently selected database."""
        return self.databases[self.current_db_index]

    async def handle_command(self, command_parts, client_addr):
        """
        Dispatches incoming Redis commands to their respective handlers.

        Args:
            command_parts (list): List of strings representing the command and its arguments.
            client_addr (tuple): (IP address, port) of the client.

        Returns:
            The RESP encoded response bytes.
        """
        if not command_parts:
            return resp_encode(RESPError("ERR unknown command"))

        command = command_parts[0].upper()
        args = command_parts[1:]

        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}

        # Check authentication first (if enabled)
        if not self.authenticated and command != "AUTH":
            logger.warning("Attempted command '%s' before authentication", command, extra=log_extra)
            return resp_encode(RESPError("NOAUTH Authentication required."))

        # If in transaction mode, queue commands except EXEC, DISCARD, WATCH
        if self.in_transaction and command not in ("EXEC", "DISCARD", "WATCH"):
            self.transaction_queue.append(command_parts)
            logger.info("Command '%s' queued in transaction.", command, extra=log_extra)
            return resp_encode("QUEUED")

        # Command dispatch table
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
            "EVALSHA": self.handle_eval, # Treat EVALSHA same as EVAL for logging
            "MULTI": self.handle_multi,
            "EXEC": self.handle_exec,
            "DISCARD": self.handle_discard,
            "SLAVEOF": self.handle_slaveof,
            "AUTH": self.handle_auth,
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
            # Add other common commands for realism, even if just returning OK
            "CLIENT": self.handle_generic_ok,
            "COMMAND": self.handle_generic_ok,
            "ECHO": self.handle_echo,
            "TTL": self.handle_ttl,
            "INCR": self.handle_incr,
            "DECR": self.handle_decr,
        }

        handler = handlers.get(command)
        if handler:
            try:
                response = await handler(args, client_addr)
                logger.info("Handled command '%s' (args: %s)", command, args, extra=log_extra)
                # Automatically save data on successful modification commands
                if command in ["SET", "DEL", "FLUSHALL", "FLUSHDB", "HSET", "HDEL",
                               "LPUSH", "RPUSH", "LPOP", "RPOP", "SADD", "SREM", "ZADD", "ZREM"]:
                    self._save_data_to_disk()
                return response
            except Exception as e:
                logger.error("Error handling command '%s': %s", command, e, exc_info=True, extra=log_extra)
                return resp_encode(RESPError(f"ERR honeypot internal error: {e}"))
        else:
            logger.warning("Unknown or unimplemented command: '%s' (args: %s)", command, args, extra=log_extra)
            return resp_encode(RESPError(f"ERR unknown command '{command}'"))

    # --- Command Handlers ---
    async def handle_auth(self, args, client_addr):
        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}
        if not AUTH_REQUIRED:
            self.authenticated = True
            logger.info("AUTH received, but authentication is not required. Granting access.", extra=log_extra)
            return resp_encode("OK")

        if len(args) == 1:
            password = args[0]
            if password == EXPECTED_PASSWORD:
                self.authenticated = True
                logger.info("Client authenticated successfully.", extra=log_extra)
                return resp_encode("OK")
            else:
                logger.warning("Client authentication failed with incorrect password.", extra=log_extra)
                return resp_encode(RESPError("ERR invalid password"))
        else:
            logger.warning("AUTH command with incorrect number of arguments.", extra=log_extra)
            return resp_encode(RESPError("ERR wrong number of arguments for 'auth' command"))

    async def handle_ping(self, args, client_addr):
        return resp_encode("PONG")

    async def handle_info(self, args, client_addr):
        # Fabricated INFO output for realism and to trigger hits on masscanners
        info_output = f"""
# Server
redis_version:6.0.9
redis_git_sha1:00000000
redis_build_id:c0ffee
redis_mode:standalone
os:Linux 5.4.0-105-generic x86_64
arch_bits:64
multiplexing_api:epoll
gcc_version:9.3.0
process_id:12345
run_id:fedcba9876543210
tcp_port:6379
uptime_in_seconds:{int(time.time() - time.time() // 86400 * 86400)}
uptime_in_days:{int(time.time() // 86400)}
hz:10
lru_clock:12345678
executable:/usr/local/bin/redis-server
config_file:/etc/redis/redis.conf

# Clients
connected_clients:1
client_recent_max_input_buffer:2
client_recent_max_output_buffer:0
blocked_clients:0

# Memory
used_memory:1048576
used_memory_human:1.00M
used_memory_rss:2097152
used_memory_rss_human:2.00M
used_memory_peak:1048576
used_memory_peak_human:1.00M
total_system_memory:8589934592
total_system_memory_human:8.00G
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
mem_allocator:jemalloc-5.1.0

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1678886400
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_last_ok_seconds:0
rdb_last_cow_size:0
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:0
aof_current_size:0
aof_fsync_enabled:0

# Stats
total_connections_received:10
total_commands_processed:50
instantaneous_ops_per_sec:1
total_net_input_bytes:10000
total_net_output_bytes:20000
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0
migrate_cached_sockets:0
io_threaded_reads_processed:0
io_threaded_writes_processed:0

# Replication
role:master
connected_slaves:0
master_replid:95655383a54b38343e06cf0a581e18d6e7f72236
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.10
used_cpu_user:0.05
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
db0:keys={len(self.databases[0])},expires=0,avg_ttl=0
db1:keys={len(self.databases[1])},expires=0,avg_ttl=0
"""
        return resp_encode(info_output.strip())

    async def handle_set(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'set' command"))
        key = args[0]
        value = args[1]
        self.get_current_db()[key] = value # Store as string by default
        logger.info("SET key '%s' to value '%s'", key, value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_get(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'get' command"))
        key = args[0]
        value = self.get_current_db().get(key)
        # Redis GET returns nil if key is not a string or doesn't exist
        if value is None or not isinstance(value, str):
            value = None
        logger.info("GET key '%s' (value: %s)", key, value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(value)

    async def handle_del(self, args, client_addr):
        if not args:
            return resp_encode(RESPError("ERR wrong number of arguments for 'del' command"))
        deleted_count = 0
        for key in args:
            if key in self.get_current_db():
                del self.get_current_db()[key]
                deleted_count += 1
        logger.info("DEL keys %s (deleted: %d)", args, deleted_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(deleted_count)

    async def handle_exists(self, args, client_addr):
        if not args:
            return resp_encode(RESPError("ERR wrong number of arguments for 'exists' command"))
        exists_count = 0
        for key in args:
            if key in self.get_current_db():
                exists_count += 1
        logger.info("EXISTS keys %s (count: %d)", args, exists_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(exists_count)

    async def handle_keys(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'keys' command"))
        pattern = args[0]
        # Simple glob-like pattern matching (not full regex)
        regex_pattern = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
        
        matched_keys = [key for key in self.get_current_db() if re.fullmatch(regex_pattern, key)]
        logger.info("KEYS pattern '%s' (matched: %s)", pattern, matched_keys, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(matched_keys)

    async def handle_flushall(self, args, client_addr):
        for db_index in self.databases:
            self.databases[db_index].clear()
        logger.warning("FLUSHALL executed. All databases cleared.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        self._populate_dummy_keys() # Re-populate dummy keys after flushall
        return resp_encode("OK")

    async def handle_flushdb(self, args, client_addr):
        self.get_current_db().clear()
        logger.warning("FLUSHDB executed on DB %d. Current database cleared.", self.current_db_index, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        if self.current_db_index == 0:
            self._populate_dummy_keys() # Re-populate dummy keys if db0 is flushed
        return resp_encode("OK")

    async def handle_save(self, args, client_addr):
        # Simulate blocking behavior
        logger.info("SAVE command received. Simulating blocking save operation...", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        self._save_data_to_disk() # Force a save
        await asyncio.sleep(0.1) # Small delay to simulate work
        logger.info("SAVE simulation complete.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_select(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'select' command"))
        try:
            db_index = int(args[0])
            if 0 <= db_index < 16:
                self.current_db_index = db_index
                logger.info("SELECT database %d.", db_index, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                return resp_encode("OK")
            else:
                return resp_encode(RESPError("ERR DB index is out of range"))
        except ValueError:
            return resp_encode(RESPError("ERR invalid DB index"))

    async def handle_dbsize(self, args, client_addr):
        size = len(self.get_current_db())
        logger.info("DBSIZE command. Current DB size: %d", size, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(size)

    async def handle_config(self, args, client_addr):
        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}
        if not args:
            return resp_encode(RESPError("ERR wrong number of arguments for 'config' command"))

        subcommand = args[0].upper()
        if subcommand == "GET":
            if len(args) != 2:
                return resp_encode(RESPError("ERR wrong number of arguments for 'config get' command"))
            param = args[1].lower()
            # Emulate common config parameters, particularly those used in exploits
            if param == "dir":
                return resp_encode(["dir", "/var/www/html/"])
            elif param == "dbfilename":
                return resp_encode(["dbfilename", "dump.rdb"])
            elif param == "requirepass":
                return resp_encode(["requirepass", EXPECTED_PASSWORD if AUTH_REQUIRED else ""])
            elif param == "appendonly":
                return resp_encode(["appendonly", "no"])
            elif param == "protected-mode":
                return resp_encode(["protected-mode", "no"])
            elif param == "daemonize":
                return resp_encode(["daemonize", "yes"])
            elif param == "loglevel":
                return resp_encode(["loglevel", "notice"])
            elif param == "bind":
                return resp_encode(["bind", "0.0.0.0"])
            elif param == "port":
                return resp_encode(["port", str(PORT)])
            else:
                logger.info("CONFIG GET '%s' requested. Returning empty.", param, extra=log_extra)
                return resp_encode([]) # For other unknown params, return empty array
        elif subcommand == "SET":
            if len(args) != 3:
                return resp_encode(RESPError("ERR wrong number of arguments for 'config set' command"))
            param = args[1].lower()
            value = args[2]
            logger.warning("CONFIG SET '%s' to '%s' captured.", param, value, extra=log_extra)
            # Log the potential malicious config change, but don't actually change anything critical
            if param == "dir":
                logger.warning("Potential path traversal/arbitrary write attempt: CONFIG SET dir to '%s'", value, extra=log_extra)
            elif param == "dbfilename":
                logger.warning("Potential arbitrary file write attempt: CONFIG SET dbfilename to '%s'", value, extra=log_extra)
            elif param == "requirepass":
                logger.warning("Attempt to change requirepass to '%s'", value, extra=log_extra)
            return resp_encode("OK")
        elif subcommand == "REWRITE":
            logger.warning("CONFIG REWRITE captured. Simulating success.", extra=log_extra)
            return resp_encode("OK")
        elif subcommand == "RESETSTAT":
            logger.info("CONFIG RESETSTAT captured. Simulating success.", extra=log_extra)
            return resp_encode("OK")
        else:
            return resp_encode(RESPError(f"ERR unknown CONFIG subcommand '{subcommand}'"))

    async def handle_eval(self, args, client_addr):
        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'eval' command"))
        
        lua_script = args[0]
        try:
            num_keys = int(args[1])
            keys = args[2 : 2 + num_keys]
            eval_args = args[2 + num_keys :]
        except ValueError:
            return resp_encode(RESPError("ERR invalid number of keys"))

        logger.critical(
            "EVAL command with Lua script captured! Script: \n---\n%s\n---\nKeys: %s, Args: %s",
            lua_script, keys, eval_args, extra=log_extra
        )
        # Return a plausible successful response
        return resp_encode(None)

    async def handle_multi(self, args, client_addr):
        if self.in_transaction:
            return resp_encode(RESPError("ERR MULTI calls can not be nested"))
        self.in_transaction = True
        self.transaction_queue = []
        logger.info("MULTI command received. Entering transaction mode.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_exec(self, args, client_addr):
        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}
        if not self.in_transaction:
            return resp_encode(RESPError("ERR EXEC without MULTI"))
        
        self.in_transaction = False
        results = []
        logger.info("EXEC command received. Executing %d queued commands.", len(self.transaction_queue), extra=log_extra)
        
        for cmd_parts in self.transaction_queue:
            cmd = cmd_parts[0].upper()
            cmd_args = cmd_parts[1:]
            
            try:
                # Get the handler directly from the main handlers list (avoiding transaction recursion)
                handler = self._get_exec_handler(cmd)
                if handler:
                    result_bytes = await handler(cmd_args, client_addr)
                    # For EXEC, the response should be the actual result of the command
                    results.append(result_bytes)
                else:
                    results.append(resp_encode(RESPError(f"ERR unknown command in transaction: {cmd}")))
            except Exception as e:
                logger.error("Error executing queued command '%s': %s", cmd, e, exc_info=True, extra=log_extra)
                results.append(resp_encode(RESPError(f"ERR transaction error: {e}")))

        self.transaction_queue = []
        return resp_encode(results)

    def _get_exec_handler(self, command):
        # This returns the appropriate handler for EXEC'd commands.
        handlers = {
            "SET": self.handle_set, "GET": self.handle_get, "DEL": self.handle_del,
            "EXISTS": self.handle_exists, "KEYS": self.handle_keys, "FLUSHALL": self.handle_flushall,
            "FLUSHDB": self.handle_flushdb, "SAVE": self.handle_save, "SELECT": self.handle_select,
            "DBSIZE": self.handle_dbsize, "CONFIG": self.handle_config, "EVAL": self.handle_eval,
            "EVALSHA": self.handle_eval, "PING": self.handle_ping, "AUTH": self.handle_auth,
            "HSET": self.handle_hset, "HGET": self.handle_hget, "HGETALL": self.handle_hgetall, "HDEL": self.handle_hdel, "HEXISTS": self.handle_hexists,
            "LPUSH": self.handle_lpush, "RPUSH": self.handle_rpush, "LPOP": self.handle_lpop, "RPOP": self.handle_rpop, "LRANGE": self.handle_lrange, "LLEN": self.handle_llen,
            "SADD": self.handle_sadd, "SMEMBERS": self.handle_smembers, "SREM": self.handle_srem, "SISMEMBER": self.handle_sismember, "SCARD": self.handle_scard,
            "ZADD": self.handle_zadd, "ZRANGE": self.handle_zrange, "ZREM": self.handle_zrem, "ZCARD": self.handle_zcard,
            "CLIENT": self.handle_generic_ok, "COMMAND": self.handle_generic_ok, "ECHO": self.handle_echo,
            "TTL": self.handle_ttl, "INCR": self.handle_incr, "DECR": self.handle_decr,
        }
        return handlers.get(command)

    async def handle_discard(self, args, client_addr):
        if not self.in_transaction:
            return resp_encode(RESPError("ERR DISCARD without MULTI"))
        self.in_transaction = False
        self.transaction_queue = []
        logger.info("DISCARD command received. Transaction discarded.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_slaveof(self, args, client_addr):
        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}
        if len(args) != 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'slaveof' command"))
        
        master_host = args[0]
        master_port_str = args[1]
        
        try:
            master_port = int(master_port_str)
        except ValueError:
            return resp_encode(RESPError("ERR invalid port number"))

        if master_host.lower() == "no" and master_port_str.lower() == "one":
            self.master_info = None
            logger.warning("SLAVEOF NO ONE received. Honeypot simulating transition to master.", extra=log_extra)
            return resp_encode("OK")
        
        self.master_info = {"host": master_host, "port": master_port}
        logger.critical(
            "SLAVEOF command captured! Attacker attempting replication from master: %s:%s. "
            "Attempting to connect and retrieve potential RDB/module transfer.",
            master_host, master_port, extra=log_extra
        )
        
        # Attempt to connect to the attacker's "master" to retrieve a payload
        payload_filename = os.path.join(PAYLOADS_DIR, f"payload_{int(time.time())}_{master_host}_{master_port}.bin")
        try:
            # Set a short timeout to avoid blocking the honeypot indefinitely
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(master_host, master_port), timeout=5
            )
            logger.info("Successfully connected to attacker's master %s:%s", master_host, master_port, extra=log_extra)
            
            payload_data = b""
            # Read a chunk of data. Redis replication typically starts with a handshake
            # followed by the RDB or AOF file. We'll just grab what we can.
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=5) # Read in chunks with timeout
                    if not chunk:
                        break
                    payload_data += chunk
                    if len(payload_data) > 1024 * 1024 * 10: # Limit to 10MB to prevent OOM
                        logger.warning("Payload from %s:%s exceeded 5MB, truncating.", master_host, master_port, extra=log_extra)
                        break
            except asyncio.TimeoutError:
                logger.warning("Timeout while reading payload from %s:%s. Read %d bytes.", master_host, master_port, len(payload_data), extra=log_extra)
            except Exception as read_e:
                logger.error("Error reading payload from %s:%s: %s", master_host, master_port, read_e, exc_info=True, extra=log_extra)

            writer.close()
            await writer.wait_closed()

            if payload_data:
                with open(payload_filename, 'wb') as f:
                    f.write(payload_data)
                logger.critical("Captured %d bytes payload from SLAVEOF target %s:%s, saved to %s",
                                len(payload_data), master_host, master_port, payload_filename, extra=log_extra)
            else:
                logger.info("No payload data received from SLAVEOF target %s:%s", master_host, master_port, extra=log_extra)

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as conn_e:
            logger.warning("Failed to connect to SLAVEOF target %s:%s: %s", master_host, master_port, conn_e, extra=log_extra)
        except Exception as e:
            logger.error("Unexpected error during SLAVEOF payload retrieval from %s:%s: %s", master_host, master_port, e, exc_info=True, extra=log_extra)
        
        return resp_encode("OK")

    # --- Hash Commands ---
    async def handle_hset(self, args, client_addr):
        if len(args) < 3 or len(args) % 2 == 0:
            return resp_encode(RESPError("ERR wrong number of arguments for 'hset' command"))
        key = args[0]
        current_db = self.get_current_db()
        
        # Initialize as dict if not exists or wrong type
        if key not in current_db or not isinstance(current_db[key], dict):
            current_db[key] = {}
            added_fields = 0
        else:
            added_fields = 0
        
        hash_obj = current_db[key]
        for i in range(1, len(args), 2):
            field = args[i]
            value = args[i+1]
            if field not in hash_obj:
                added_fields += 1
            hash_obj[field] = value
        logger.info("HSET key '%s' added %d fields.", key, added_fields, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(added_fields)

    async def handle_hget(self, args, client_addr):
        if len(args) != 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'hget' command"))
        key = args[0]
        field = args[1]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        if isinstance(hash_obj, dict):
            value = hash_obj.get(field)
            logger.info("HGET key '%s' field '%s' (value: %s)", key, field, value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(value)
        logger.info("HGET key '%s' field '%s' (not a hash or does not exist)", key, field, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(None) # Return nil if key is not a hash or does not exist/field not found

    async def handle_hgetall(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'hgetall' command"))
        key = args[0]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        if isinstance(hash_obj, dict):
            result = []
            for field, value in hash_obj.items():
                result.append(field)
                result.append(value)
            logger.info("HGETALL key '%s' (result: %s)", key, result, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(result)
        logger.info("HGETALL key '%s' (not a hash or does not exist)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode([]) # Return empty array if key is not a hash or does not exist

    async def handle_hdel(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'hdel' command"))
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
        logger.info("HDEL key '%s' deleted %d fields.", key, deleted_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(deleted_count)

    async def handle_hexists(self, args, client_addr):
        if len(args) != 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'hexists' command"))
        key = args[0]
        field = args[1]
        current_db = self.get_current_db()
        hash_obj = current_db.get(key)
        exists = 0
        if isinstance(hash_obj, dict) and field in hash_obj:
            exists = 1
        logger.info("HEXISTS key '%s' field '%s' (exists: %d)", key, field, exists, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(exists)

    # --- List Commands ---
    async def handle_lpush(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'lpush' command"))
        key = args[0]
        elements = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = []
        elif not isinstance(current_db[key], list):
            return resp_encode(RESPError(f"ERR Operation against a key holding the wrong kind of value"))
        
        current_db[key] = elements[::-1] + current_db[key] # Prepend elements
        logger.info("LPUSH key '%s' added %d elements. New length: %d", key, len(elements), len(current_db[key]), extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(len(current_db[key]))

    async def handle_rpush(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'rpush' command"))
        key = args[0]
        elements = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = []
        elif not isinstance(current_db[key], list):
            return resp_encode(RESPError(f"ERR Operation against a key holding the wrong kind of value"))
        
        current_db[key].extend(elements) # Append elements
        logger.info("RPUSH key '%s' added %d elements. New length: %d", key, len(elements), len(current_db[key]), extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(len(current_db[key]))

    async def handle_lpop(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'lpop' command"))
        key = args[0]
        current_db = self.get_current_db()
        list_obj = current_db.get(key)

        if isinstance(list_obj, list) and list_obj:
            popped_item = list_obj.pop(0) # Pop from the left (beginning)
            if not list_obj: # Remove key if list becomes empty
                del current_db[key]
            logger.info("LPOP key '%s' popped '%s'. New length: %d", key, popped_item, len(list_obj), extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(popped_item)
        logger.info("LPOP key '%s' (list empty or not a list)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(None)

    async def handle_rpop(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'rpop' command"))
        key = args[0]
        current_db = self.get_current_db()
        list_obj = current_db.get(key)

        if isinstance(list_obj, list) and list_obj:
            popped_item = list_obj.pop() # Pop from the right (end)
            if not list_obj: # Remove key if list becomes empty
                del current_db[key]
            logger.info("RPOP key '%s' popped '%s'. New length: %d", key, popped_item, len(list_obj), extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(popped_item)
        logger.info("RPOP key '%s' (list empty or not a list)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(None)

    async def handle_lrange(self, args, client_addr):
        if len(args) != 3:
            return resp_encode(RESPError("ERR wrong number of arguments for 'lrange' command"))
        key = args[0]
        try:
            start = int(args[1])
            end = int(args[2])
        except ValueError:
            return resp_encode(RESPError("ERR value is not an integer or out of range"))

        current_db = self.get_current_db()
        list_obj = current_db.get(key)

        if isinstance(list_obj, list):
            # Handle negative indices
            if start < 0:
                start = len(list_obj) + start
            if end < 0:
                end = len(list_obj) + end
            
            if start > end: # Redis returns empty list if start > end
                result = []
            else:
                result = list_obj[start : end + 1]
            logger.info("LRANGE key '%s' from %d to %d. Result: %s", key, start, end, result, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(result)
        logger.info("LRANGE key '%s' (not a list or does not exist)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode([]) # Return empty array if not a list or doesn't exist

    async def handle_llen(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'llen' command"))
        key = args[0]
        current_db = self.get_current_db()
        list_obj = current_db.get(key)
        if isinstance(list_obj, list):
            length = len(list_obj)
            logger.info("LLEN key '%s'. Length: %d", key, length, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(length)
        logger.info("LLEN key '%s' (not a list or does not exist)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(0) # Return 0 if not a list or doesn't exist


    # --- Set Commands ---
    async def handle_sadd(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'sadd' command"))
        key = args[0]
        members = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = set()
        elif not isinstance(current_db[key], set):
            return resp_encode(RESPError(f"ERR Operation against a key holding the wrong kind of value"))
        
        added_count = 0
        for member in members:
            if member not in current_db[key]:
                current_db[key].add(member)
                added_count += 1
        logger.info("SADD key '%s' added %d members.", key, added_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(added_count)

    async def handle_smembers(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'smembers' command"))
        key = args[0]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        if isinstance(set_obj, set):
            members_list = list(set_obj) # Convert to list for RESP encoding
            logger.info("SMEMBERS key '%s'. Members: %s", key, members_list, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(members_list)
        logger.info("SMEMBERS key '%s' (not a set or does not exist)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode([]) # Return empty array if not a set or doesn't exist

    async def handle_srem(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'srem' command"))
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
        logger.info("SREM key '%s' removed %d members.", key, removed_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(removed_count)

    async def handle_sismember(self, args, client_addr):
        if len(args) != 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'sismember' command"))
        key = args[0]
        member = args[1]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        is_member = 0
        if isinstance(set_obj, set) and member in set_obj:
            is_member = 1
        logger.info("SISMEMBER key '%s' member '%s' (is_member: %d)", key, member, is_member, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(is_member)

    async def handle_scard(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'scard' command"))
        key = args[0]
        current_db = self.get_current_db()
        set_obj = current_db.get(key)
        if isinstance(set_obj, set):
            cardinality = len(set_obj)
            logger.info("SCARD key '%s'. Cardinality: %d", key, cardinality, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(cardinality)
        logger.info("SCARD key '%s' (not a set or does not exist)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(0)


    # --- Sorted Set Commands ---
    async def handle_zadd(self, args, client_addr):
        if len(args) < 3 or len(args) % 2 != 1: # ZADD key score member
            return resp_encode(RESPError("ERR wrong number of arguments for 'zadd' command"))
        key = args[0]
        members_scores = args[1:]
        current_db = self.get_current_db()

        if key not in current_db:
            current_db[key] = []
        elif not (isinstance(current_db[key], list) and all(isinstance(x, tuple) and len(x) == 2 for x in current_db[key])):
            return resp_encode(RESPError(f"ERR Operation against a key holding the wrong kind of value"))
        
        zset_obj = current_db[key]
        added_count = 0
        for i in range(0, len(members_scores), 2):
            try:
                score = float(members_scores[i])
                member = members_scores[i+1]
            except ValueError:
                return resp_encode(RESPError("ERR value is not a valid float"))

            # Remove existing member if it exists to update score
            zset_obj = [(m, s) for m, s in zset_obj if m != member]
            zset_obj.append((member, score))
            added_count += 1
        
        # Sort the zset by score (ascending) for realism
        zset_obj.sort(key=lambda x: x[1])
        current_db[key] = zset_obj # Update the stored list
        logger.info("ZADD key '%s' added/updated %d members.", key, added_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(added_count)


    async def handle_zrange(self, args, client_addr):
        if len(args) < 3: # ZRANGE key start stop [WITHSCORES]
            return resp_encode(RESPError("ERR wrong number of arguments for 'zrange' command"))
        key = args[0]
        try:
            start_idx = int(args[1])
            stop_idx = int(args[2])
        except ValueError:
            return resp_encode(RESPError("ERR value is not an integer or out of range"))
        
        with_scores = False
        if len(args) > 3 and args[3].upper() == "WITHSCORES":
            with_scores = True

        current_db = self.get_current_db()
        zset_obj = current_db.get(key)
        
        result = []
        if isinstance(zset_obj, list) and all(isinstance(x, tuple) and len(x) == 2 for x in zset_obj):
            # Handle negative indices
            if start_idx < 0:
                start_idx = len(zset_obj) + start_idx
            if stop_idx < 0:
                stop_idx = len(zset_obj) + stop_idx

            # Adjust slice end for inclusive behavior
            if stop_idx >= 0:
                stop_idx += 1 
            
            # Slice the sorted list
            ranged_items = zset_obj[start_idx:stop_idx]

            for member, score in ranged_items:
                result.append(member)
                if with_scores:
                    result.append(str(score)) # Scores are returned as bulk strings
            
        logger.info("ZRANGE key '%s' from %d to %d (with_scores: %s). Result: %s", key, start_idx, stop_idx, with_scores, result, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(result)

    async def handle_zrem(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'zrem' command"))
        key = args[0]
        members_to_remove = args[1:]
        current_db = self.get_current_db()
        zset_obj = current_db.get(key)
        removed_count = 0
        if isinstance(zset_obj, list) and all(isinstance(x, tuple) and len(x) == 2 for x in zset_obj):
            original_len = len(zset_obj)
            zset_obj = [(m, s) for m, s in zset_obj if m not in members_to_remove]
            removed_count = original_len - len(zset_obj)
            if not zset_obj: # Remove key if zset becomes empty
                del current_db[key]
            else:
                current_db[key] = zset_obj # Update the stored list
        logger.info("ZREM key '%s' removed %d members.", key, removed_count, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(removed_count)

    async def handle_zcard(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'zcard' command"))
        key = args[0]
        current_db = self.get_current_db()
        zset_obj = current_db.get(key)
        if isinstance(zset_obj, list) and all(isinstance(x, tuple) and len(x) == 2 for x in zset_obj):
            cardinality = len(zset_obj)
            logger.info("ZCARD key '%s'. Cardinality: %d", key, cardinality, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(cardinality)
        logger.info("ZCARD key '%s' (not a sorted set or does not exist)", key, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(0)


    # --- Generic Handlers for common commands that don't need complex logic ---
    async def handle_generic_ok(self, args, client_addr):
        # For commands like CLIENT, COMMAND, etc., just return OK
        return resp_encode("OK")

    async def handle_generic_nil(self, args, client_addr):
        # For commands that return nil (e.g., LPOP on empty list)
        return resp_encode(None)
    
    async def handle_generic_empty_array(self, args, client_addr):
        # For commands that return empty array (e.g., SMEMBERS on empty set)
        return resp_encode([])

    async def handle_echo(self, args, client_addr):
        if not args:
            return resp_encode(RESPError("ERR wrong number of arguments for 'echo' command"))
        return resp_encode(args[0])
    
    async def handle_ttl(self, args, client_addr):
        # Simulate TTL for keys. Return -2 for non-existent, -1 for no expiry, or a positive integer.
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'ttl' command"))
        key = args[0]
        if key not in self.get_current_db():
            return resp_encode(-2) # Key does not exist
        # All keys in our in-memory store have no expiry
        return resp_encode(-1)

    async def handle_incr(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'incr' command"))
        key = args[0]
        current_db = self.get_current_db()
        try:
            value = current_db.get(key)
            if value is None:
                new_value = 1
            else:
                new_value = int(value) + 1
            current_db[key] = str(new_value) # Store as string, as Redis does
            logger.info("INCR key '%s' to value '%s'", key, new_value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(new_value)
        except ValueError:
            return resp_encode(RESPError("ERR value is not an integer or out of range"))

    async def handle_decr(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'decr' command"))
        key = args[0]
        current_db = self.get_current_db()
        try:
            value = current_db.get(key)
            if value is None:
                new_value = -1
            else:
                new_value = int(value) - 1
            current_db[key] = str(new_value) # Store as string, as Redis does
            logger.info("DECR key '%s' to value '%s'", key, new_value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(new_value)
        except ValueError:
            return resp_encode(RESPError("ERR value is not an integer or out of range"))


# --- Asyncio TCP Server ---
async def handle_client(reader, writer):
    """
    Handles a single client connection. Reads commands, processes them, and sends responses.
    """
    client_addr = writer.get_extra_info('peername')
    logger.info("New connection from %s:%s", client_addr[0], client_addr[1], extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})

    honeypot = RedisHoneypot() # Each client gets its own honeypot state for isolation

    try:
        while True:
            try:
                command_parts = await resp_decode(reader)
                
                if command_parts is None: # Client sent a Null Array
                    logger.warning("Client sent a Null Array, disconnecting.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                    break

                if isinstance(command_parts, RESPError): # Error during decoding
                    logger.error("RESP Decoding Error: %s", command_parts, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                    writer.write(resp_encode(command_parts))
                    await writer.drain()
                    continue

                if not isinstance(command_parts, list):
                    # Malformed command, not an array of bulk strings
                    logger.warning("Received malformed command (not an array): %s", command_parts, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                    writer.write(resp_encode(RESPError("ERR Protocol error: expected '*' as first byte")))
                    await writer.drain()
                    continue
                
                # The _parse_bulk_string returns string, so elements of array should be strings/None
                if not all(isinstance(part, (str, type(None))) for part in command_parts):
                    logger.warning("Received malformed command (array contains non-strings/non-nil): %s", command_parts, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                    writer.write(resp_encode(RESPError("ERR Protocol error: expected bulk strings or nil in array")))
                    await writer.drain()
                    continue

                response = await honeypot.handle_command(command_parts, client_addr)
                writer.write(response)
                await writer.drain()

            except asyncio.IncompleteReadError:
                logger.info("Client %s:%s disconnected gracefully (EOF).", client_addr[0], client_addr[1], extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                break
            except ConnectionResetError:
                logger.info("Client %s:%s forcibly disconnected.", client_addr[0], client_addr[1], extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                break
            except Exception as e:
                logger.error("Unhandled error for client %s:%s: %s", client_addr[0], client_addr[1], e, exc_info=True, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                writer.write(resp_encode(RESPError("ERR honeypot internal error")))
                await writer.drain()
                break # Close connection on unhandled error

    finally:
        logger.info("Closing connection for %s:%s", client_addr[0], client_addr[1], extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        writer.close()
        await writer.wait_closed()


async def main():
    """
    Main function to start the Redis honeypot server.
    """
    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
        reuse_address=True,
        reuse_port=True # Allows multiple processes to bind to the same port on some OS
    )

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logger.info("Redis Honeypot listening on %s", addrs, extra={'client_addr': 'SERVER'})
    
    # Message box for initial server start
    print(f"\n--- Redis Honeypot Started ---")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Log file: {LOG_FILE}")
    print(f"Persistence file: {STORAGE_FILE}")
    print(f"Payloads directory: {PAYLOADS_DIR}")
    print(f"Authentication required: {AUTH_REQUIRED}")
    if AUTH_REQUIRED:
        print(f"Expected password: {EXPECTED_PASSWORD}")
    print(f"To test: redis-cli -p {PORT} (and optionally -a {EXPECTED_PASSWORD} if auth is enabled)")
    print("------------------------------\n")

    async with server:
        await server.serve_forever()

def graceful_shutdown_save():
    temp_honeypot = RedisHoneypot()
    temp_honeypot._save_data_to_disk()

atexit.register(graceful_shutdown_save)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Redis Honeypot stopped by user (KeyboardInterrupt).", extra={'client_addr': 'SERVER'})
    except Exception as e:
        logger.critical("Fatal error in main server loop: %s", e, exc_info=True, extra={'client_addr': 'SERVER'})

