import asyncio
import logging
import json
import time
import uuid
import re

# --- Configuration ---
HOST = '0.0.0.0'  # Bind to all available interfaces for external access
PORT = 6379       # Standard Redis port
LOG_FILE = 'redis_honeypot.log'
AUTH_REQUIRED = False # Set to True to require AUTH command
EXPECTED_PASSWORD = "my_secure_password" # Change this if AUTH_REQUIRED is True

# --- Default Dummy Keys for Honeypot Session ---
# This dictionary defines a set of default keys and values that will be present
# in the emulated Redis database for each new client session.
# These keys are designed to make the honeypot appear more realistic and
# provide a starting point for attackers to interact with.
DEFAULT_DUMMY_KEYS = {
    "web_cache:user_sessions": "a:1:{s:6:\"active\";b:1;}",
    "config:app_version": "1.0.5",
    "users:last_login:admin": "1718224800", # Example timestamp
    "temp_data:processing_queue_size": "50",
    "app:status": "online",
    "cache:item:12345": "{\"name\":\"productX\",\"price\":99.99}",
    "inventory:productA": "250",
    "service:metrics:requests_per_sec": "120",
    "secret:api_key": "78tN4-8y7nx-9u23p", # A key to attract attention
    "backup:last_run": "2025-06-12_01:00:00"
}


# --- Logging Setup ---
# Configure logging to console and a file.
# The console logger is for immediate feedback during development/debugging.
# The file logger is for capturing all honeypot interactions as threat intelligence.
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

# --- RESP (Redis Serialization Protocol) Parser and Serializer ---

# RESP documentation reference: https://redis.io/docs/latest/develop/reference/protocol-spec/

class RESPError(Exception):
    """Custom exception for RESP parsing errors."""
    pass

def resp_encode(data):
    """
    Encodes Python data types into RESP byte format.

    Args:
        data: The Python object to encode (str, int, list, None).

    Returns:
        bytes: The RESP encoded byte string.
    """
    if isinstance(data, str):
        # Simple String
        if '\n' in data or '\r' in data:
            # If the string contains newlines, it should be a Bulk String
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

    Raises:
        RESPError: If the RESP message is malformed or invalid.
        asyncio.IncompleteReadError: If the connection closes prematurely.
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
            return None # Null Array
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

        # Populate the default database (db0) with dummy keys for each new session
        self.databases[0].update(DEFAULT_DUMMY_KEYS)

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
        # Add 'async' prefix to handler methods to indicate they are coroutines
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
            # Add other common commands for realism, even if just returning OK
            "CLIENT": self.handle_generic_ok,
            "COMMAND": self.handle_generic_ok,
            "ECHO": self.handle_echo,
            "TTL": self.handle_ttl,
            "INCR": self.handle_incr,
            "DECR": self.handle_decr,
            "LPUSH": self.handle_generic_ok,
            "RPUSH": self.handle_generic_ok,
            "LPOP": self.handle_generic_nil,
            "RPOP": self.handle_generic_nil,
            "LRANGE": self.handle_generic_empty_array,
            "SADD": self.handle_generic_ok,
            "SMEMBERS": self.handle_generic_empty_array,
            "SREM": self.handle_generic_ok,
        }

        handler = handlers.get(command)
        if handler:
            try:
                response = await handler(args, client_addr)
                logger.info("Handled command '%s' (args: %s)", command, args, extra=log_extra)
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
        # Fabricated INFO output for realism and to guide attackers
        info_output = """
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
uptime_in_seconds:3600
uptime_in_days:0
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
db0:keys=10,expires=0,avg_ttl=0
db1:keys=0,expires=0,avg_ttl=0
"""
        return resp_encode(info_output.strip())

    async def handle_set(self, args, client_addr):
        if len(args) < 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'set' command"))
        key = args[0]
        value = args[1]
        self.get_current_db()[key] = value
        logger.info("SET key '%s' to value '%s'", key, value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_get(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'get' command"))
        key = args[0]
        value = self.get_current_db().get(key)
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
        # Convert glob to regex: replace '*' with '.*', '?' with '.', escape other regex chars
        regex_pattern = re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.')
        
        matched_keys = [key for key in self.get_current_db() if re.fullmatch(regex_pattern, key)]
        logger.info("KEYS pattern '%s' (matched: %s)", pattern, matched_keys, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode(matched_keys)

    async def handle_flushall(self, args, client_addr):
        for db_index in self.databases:
            self.databases[db_index].clear()
        logger.warning("FLUSHALL executed. All databases cleared.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_flushdb(self, args, client_addr):
        self.get_current_db().clear()
        logger.warning("FLUSHDB executed on DB %d. Current database cleared.", self.current_db_index, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    async def handle_save(self, args, client_addr):
        # Simulate blocking behavior
        logger.info("SAVE command received. Simulating blocking save operation...", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
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
                return resp_encode(["dir", "/var/www/html/"]) # Common web root
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
        num_keys = int(args[1])
        keys = args[2 : 2 + num_keys]
        eval_args = args[2 + num_keys :]

        logger.critical(
            "EVAL command with Lua script captured! Script: \n---\n%s\n---\nKeys: %s, Args: %s",
            lua_script, keys, eval_args, extra=log_extra
        )
        # Return a plausible successful response, e.g., nil or empty array, or simulated string
        # Do NOT actually execute the Lua script
        return resp_encode(None) # Or resp_encode("Simulated Eval Output")

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
            
            # Re-dispatch the queued command using a simplified handler (no transaction check)
            # This is a simplified approach. A full implementation would need to
            # carefully handle error accumulation and atomicity.
            try:
                # Get the original handler from the dispatch table (ensure it's awaitable)
                handler = self.handlers_for_exec.get(cmd)
                if handler:
                    result = await handler(cmd_args, client_addr)
                    # For EXEC, the response should be the actual result of the command
                    # or an error. We simulate this by directly encoding the result.
                    results.append(result)
                else:
                    results.append(resp_encode(RESPError(f"ERR unknown command in transaction: {cmd}")))
            except Exception as e:
                logger.error("Error executing queued command '%s': %s", cmd, e, exc_info=True, extra=log_extra)
                results.append(resp_encode(RESPError(f"ERR transaction error: {e}")))

        self.transaction_queue = []
        return resp_encode(results)

    async def handle_discard(self, args, client_addr):
        if not self.in_transaction:
            return resp_encode(RESPError("ERR DISCARD without MULTI"))
        self.in_transaction = False
        self.transaction_queue = []
        logger.info("DISCARD command received. Transaction discarded.", extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
        return resp_encode("OK")

    # Helper for EXEC to avoid re-entering transaction mode
    @property
    def handlers_for_exec(self):
        # This is a simplified way to get handlers without transaction check
        # In a real system, you'd design `handle_command` to have an internal flag
        # or a different dispatch for transaction execution.
        return {
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
            "EVALSHA": self.handle_eval,
            "PING": self.handle_ping,
            "AUTH": self.handle_auth,
            "CLIENT": self.handle_generic_ok,
            "COMMAND": self.handle_generic_ok,
            "ECHO": self.handle_echo,
            "TTL": self.handle_ttl,
            "INCR": self.handle_incr,
            "DECR": self.handle_decr,
            "LPUSH": self.handle_generic_ok,
            "RPUSH": self.handle_generic_ok,
            "LPOP": self.handle_generic_nil,
            "RPOP": self.handle_generic_nil,
            "LRANGE": self.handle_generic_empty_array,
            "SADD": self.handle_generic_ok,
            "SMEMBERS": self.handle_generic_empty_array,
            "SREM": self.handle_generic_ok,
        }

    async def handle_slaveof(self, args, client_addr):
        log_extra = {'client_addr': f"{client_addr[0]}:{client_addr[1]}"}
        if len(args) != 2:
            return resp_encode(RESPError("ERR wrong number of arguments for 'slaveof' command"))
        
        master_host = args[0]
        master_port = args[1]
        
        if master_host.lower() == "no" and master_port.lower() == "one":
            self.master_info = None
            logger.warning("SLAVEOF NO ONE received. Honeypot simulating transition to master.", extra=log_extra)
            return resp_encode("OK")
        
        self.master_info = {"host": master_host, "port": master_port}
        logger.critical(
            "SLAVEOF command captured! Attacker attempting replication from master: %s:%s. "
            "Simulating connection and potential RDB/module transfer.",
            master_host, master_port, extra=log_extra
        )
        
        # Simulate connection to attacker's master (without actually connecting)
        # In a real honeypot, you might try to connect or at least log the attempt
        # and expect an incoming RDB or module push.
        # For this high-interaction honeypot, we only log the attempt.
        await asyncio.sleep(0.5) # Simulate some network delay
        
        # This is where you would ideally have a mechanism to either:
        # 1. Attempt to connect to the attacker's master to pull a malicious RDB/module.
        # 2. Set up a listener to receive an RDB/module if the attacker pushes it.
        # For now, we only log and acknowledge.
        
        return resp_encode("OK")

    # --- Generic Handlers for common commands that don't need complex logic ---
    async def handle_generic_ok(self, args, client_addr):
        # For commands like CLIENT, COMMAND, etc., just return OK
        return resp_encode("OK")

    async def handle_generic_nil(self, args, client_addr):
        # For commands like LPOP, RPOP when list is empty
        return resp_encode(None)
    
    async def handle_generic_empty_array(self, args, client_addr):
        # For commands like LRANGE, SMEMBERS when empty
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
        # For simplicity, all keys in our in-memory store have no expiry
        return resp_encode(-1) # Key exists but has no associated expire

    async def handle_incr(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'incr' command"))
        key = args[0]
        current_db = self.get_current_db()
        try:
            value = int(current_db.get(key, 0)) + 1
            current_db[key] = str(value) # Store as string, as Redis does
            logger.info("INCR key '%s' to value '%s'", key, value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(value)
        except ValueError:
            return resp_encode(RESPError("ERR value is not an integer or out of range"))

    async def handle_decr(self, args, client_addr):
        if len(args) != 1:
            return resp_encode(RESPError("ERR wrong number of arguments for 'decr' command"))
        key = args[0]
        current_db = self.get_current_db()
        try:
            value = int(current_db.get(key, 0)) - 1
            current_db[key] = str(value) # Store as string, as Redis does
            logger.info("DECR key '%s' to value '%s'", key, value, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
            return resp_encode(value)
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
                
                # Check if all elements in command_parts are strings
                if not all(isinstance(part, str) for part in command_parts):
                    logger.warning("Received malformed command (array contains non-strings): %s", command_parts, extra={'client_addr': f"{client_addr[0]}:{client_addr[1]}"})
                    writer.write(resp_encode(RESPError("ERR Protocol error: expected bulk strings in array")))
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
    
    # Message box simulation for initial server start
    print(f"\n--- Redis Honeypot Started ---")
    print(f"Listening on {HOST}:{PORT}")
    print(f"Log file: {LOG_FILE}")
    print(f"Authentication required: {AUTH_REQUIRED}")
    if AUTH_REQUIRED:
        print(f"Expected password: {EXPECTED_PASSWORD}")
    print(f"To test: redis-cli -p {PORT} (and optionally -a {EXPECTED_PASSWORD} if auth is enabled)")
    print("------------------------------\n")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Redis Honeypot stopped by user (KeyboardInterrupt).", extra={'client_addr': 'SERVER'})
    except Exception as e:
        logger.critical("Fatal error in main server loop: %s", e, exc_info=True, extra={'client_addr': 'SERVER'})

