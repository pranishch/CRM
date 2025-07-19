import os
import psutil

# Get current process ID
pid = os.getpid()

# Get process memory usage
process = psutil.Process(pid)
memory_in_bytes = process.memory_info().rss
memory_in_mb = memory_in_bytes / (1024 * 1024)

print(f"Current Django RAM usage: {memory_in_mb:.2f} MB")
