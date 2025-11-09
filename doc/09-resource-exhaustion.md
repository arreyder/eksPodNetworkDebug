# Resource Exhaustion

## What We Check

The toolkit monitors system resources that can cause network connectivity issues when exhausted.

**Checks performed:**
- **File descriptors**: Tracks allocated vs maximum file descriptors
- **Memory pressure**: Monitors memory usage and availability
- Reports when resources are approaching limits

## Why It Matters

**Resource exhaustion** can cause:
- **File descriptor exhaustion**: New connections cannot be established
- **Memory pressure**: Network buffers cannot be allocated
- **OOM kills**: Pods/processes killed due to memory pressure
- **Connection failures**: Unable to create new sockets
- **Performance degradation**: System thrashing under resource pressure

**Common causes:**
- Too many open connections (file descriptors)
- Memory leaks in applications or CNI
- Insufficient node resources
- Resource limits too restrictive

## How We Check It

1. **File Descriptors**: Reads `/proc/sys/fs/file-nr`:
   - Allocated file descriptors
   - Maximum file descriptors
   - Calculates usage percentage

2. **Memory**: Reads `/proc/meminfo`:
   - Total memory
   - Available memory
   - Calculates usage percentage

**Output examples:**
- `[OK] File descriptor usage: 2656 / 1472008 (~0%)`
- `[OK] Memory usage: ~3%`
- `[WARN] File descriptor usage high: 85%`
- `[WARN] Memory usage high: 92%`

## Recommended Actions

### If File Descriptors Exhausted

1. **Check current usage**:
   ```bash
   # On node, check file descriptor usage
   cat /proc/sys/fs/file-nr
   # Format: allocated unused maximum
   ```

2. **Identify processes using many FDs**:
   ```bash
   # Find processes with most open files
   lsof | awk '{print $2}' | sort | uniq -c | sort -rn | head -10
   ```

3. **Increase file descriptor limit**:
   ```bash
   # Temporary increase
   ulimit -n 65536
   
   # Permanent increase (in /etc/security/limits.conf)
   * soft nofile 65536
   * hard nofile 65536
   ```

4. **Review connection patterns**:
   - Check for connection leaks
   - Review connection pooling
   - Consider connection reuse

### If Memory Pressure

1. **Check memory usage**:
   ```bash
   # On node, check memory
   free -h
   cat /proc/meminfo | grep -E "MemTotal|MemAvailable|MemFree"
   ```

2. **Identify memory consumers**:
   ```bash
   # Top memory consumers
   ps aux --sort=-%mem | head -10
   ```

3. **Check for memory leaks**:
   - Review application logs
   - Check CNI plugin memory usage
   - Monitor memory over time

4. **Adjust resource limits**:
   ```bash
   # Increase node memory (if possible)
   # Or reduce pod memory requests/limits
   ```

### Preventing Resource Exhaustion

1. **Set appropriate resource limits**:
   - Configure pod resource requests/limits
   - Set node resource limits

2. **Monitor resource usage**:
   - Set up alerts for high resource usage
   - Monitor trends over time

3. **Review connection patterns**:
   - Implement connection pooling
   - Close connections properly
   - Use connection timeouts

## Related Files

- `node_file_descriptors.txt` - File descriptor usage
- `node_memory_info.txt` - Memory information

## References

- [Linux File Descriptors](https://www.kernel.org/doc/Documentation/sysctl/fs.txt)
- [Kubernetes Resource Management](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

