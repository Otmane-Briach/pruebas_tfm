#!/usr/bin/env python3
"""
collector_fixed.py - Collector con syscalls expandidas DEFINITIVO
FIX: unlinkat usa 'flag' no 'flags'
"""

from bcc import BPF
import json
import time
import argparse
import sys
import signal
import os

# Importar hash detection
try:
    from hash_detection_collector import HashDetectionEngine
    HASH_DETECTION_AVAILABLE = True
except ImportError:
    print("WARNING: hash_detection_collector.py not found. Hash detection disabled.", file=sys.stderr)
    HASH_DETECTION_AVAILABLE = False

b = None
hash_engine = None

def signal_handler(sig, frame):
    """Manejo de señales"""
    print("\nRecibida señal de parada, limpiando...", file=sys.stderr)
    if b:
        try:
            b.cleanup()
        except:
            pass
    if hash_engine:
        stats = hash_engine.get_statistics()
        print("\nHASH DETECTION STATISTICS:", file=sys.stderr)
        print(f"   Files scanned: {stats['files_scanned']}", file=sys.stderr)
        print(f"   Malware detected: {stats['malware_detected']}", file=sys.stderr)
        print(f"   Detection rate: {stats['detection_rate']:.2f}%", file=sys.stderr)
        print(f"   Database size: {stats['hash_database_size']}", file=sys.stderr)
    sys.exit(0)

# PROGRAMA eBPF CORREGIDO - unlinkat usa 'flag' no 'flags'
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 type;  // 0=EXEC, 1=OPEN, 2=WRITE, 3=UNLINK, 4=CHMOD, 5=CONNECT, 6=PTRACE, 7=MMAP, 8=CHOWN
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 flags;
};

BPF_PERF_OUTPUT(events);

static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (!parent) return 0;
    u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

// SYSCALL: execve
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 0;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// SYSCALL: openat
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 1;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->flags;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// SYSCALL: write
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // filtro >1KB
    if (args->count < 1024) return 0;
    data.type = 2;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->count;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.filename[0] = '\0';
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: unlink
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 3;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = 0;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: unlinkat - CORREGIDO: usa 'flag' no 'flags'
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 3;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->flag;  // FIX: es 'flag' no 'flags'
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: chmod
TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 4;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->mode;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: fchmodat
TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 4;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->mode;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: connect con IP:Puerto
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 5;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    
    // Capturar IP y puerto (IPv4) - FORMA CORREGIDA
    // En lugar de usar struct sockaddr, leer bytes directamente
    void *addr = (void *)args->uservaddr;
    if (addr) {
        u16 family = 0;
        bpf_probe_read(&family, sizeof(family), addr);
        
        if (family == 2) {  // AF_INET
            // Para IPv4: family(2) + port(2) + ip(4)
            // Leer IP (offset 4 bytes desde inicio)
            bpf_probe_read(&data.flags, 4, (char*)addr + 4);
            // Leer puerto (offset 2 bytes desde inicio)  
            u16 port = 0;
            bpf_probe_read(&port, 2, (char*)addr + 2);
            // Guardar puerto en los primeros bytes del filename
            *(u16*)data.filename = ntohs(port);
        }
    }
    
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: ptrace
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 6;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->request;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.filename[0] = '\0';
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: mmap
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 7;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->prot;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.filename[0] = '\0';
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: chown
TRACEPOINT_PROBE(syscalls, sys_enter_fchownat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 8;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->user;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

# Mapeo de tipos
TYPE_STR = {
    0: "EXEC", 
    1: "OPEN", 
    2: "WRITE",
    3: "UNLINK",
    4: "CHMOD",
    5: "CONNECT",
    6: "PTRACE", 
    7: "MMAP",
    8: "CHOWN"
}

# Contadores
write_event_count = 0
total_write_bytes = 0
unlink_event_count = 0
chmod_event_count = 0
connect_event_count = 0
ptrace_event_count = 0
mmap_event_count = 0
chown_event_count = 0

def terminate_malicious_process(pid, malware_info):
    """Terminar proceso malicioso"""
    try:
        proc_stat = f"/proc/{pid}/status"
        if os.path.exists(proc_stat):
            with open(proc_stat) as f:
                if "Uid:\t0\t" in f.read():
                    print(f"SEGURIDAD: NO terminando proceso root PID {pid}", file=sys.stderr)
                    return
        print(f"TERMINANDO PROCESO MALICIOSO PID {pid}", file=sys.stderr)
        os.kill(pid, 9)
    except Exception as e:
        print(f"Error terminando proceso {pid}: {e}", file=sys.stderr)

def decode_open_flags(flags):
    """Decodificar flags de open()"""
    if flags == 0: return "RDONLY"
    O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL = 0x1, 0x2, 0x40, 0x200, 0x400, 0x80
    modes = []
    m = flags & 0x3
    modes.append({0: "RDONLY", O_WRONLY: "WRONLY", O_RDWR: "RDWR"}.get(m, "RDONLY"))
    for bit, name in ((O_CREAT, "CREAT"), (O_TRUNC, "TRUNC"), (O_APPEND, "APPEND"), (O_EXCL, "EXCL")):
        if flags & bit: 
            modes.append(name)
    return "|".join(modes)

def decode_chmod_mode(mode):
    """Decodificar permisos chmod"""
    octal = oct(mode & 0o777)
    
    perms = []
    if mode & 0o4000: perms.append("SETUID")
    if mode & 0o2000: perms.append("SETGID")
    if mode & 0o1000: perms.append("STICKY")
    
    symbolic = ""
    for shift in [6, 3, 0]:
        p = (mode >> shift) & 0o7
        symbolic += "r" if p & 0o4 else "-"
        symbolic += "w" if p & 0o2 else "-"
        symbolic += "x" if p & 0o1 else "-"
    
    result = f"{octal} ({symbolic})"
    if perms:
        result += f" [{','.join(perms)}]"
    
    return result

def decode_ptrace_request(request):
    """Decodificar request de ptrace"""
    PTRACE_REQUESTS = {
        0: "TRACEME", 1: "PEEKTEXT", 2: "PEEKDATA", 3: "PEEKUSER",
        4: "POKETEXT", 5: "POKEDATA", 6: "POKEUSER", 7: "CONT",
        8: "KILL", 9: "SINGLESTEP", 12: "GETREGS", 13: "SETREGS",
        16: "ATTACH", 17: "DETACH", 24: "SYSCALL"
    }
    return PTRACE_REQUESTS.get(request, f"UNKNOWN({request})")

def decode_mmap_prot(prot):
    """Decodificar protección de mmap"""
    flags = []
    if prot & 0x1: flags.append("READ")
    if prot & 0x2: flags.append("WRITE") 
    if prot & 0x4: flags.append("EXEC")
    if not flags: flags.append("NONE")
    return "|".join(flags)

def handle_event(cpu, data, size):
    """Procesar eventos"""
    global hash_engine, write_event_count, total_write_bytes
    global unlink_event_count, chmod_event_count
    global connect_event_count, ptrace_event_count, mmap_event_count, chown_event_count
    
    try:
        event = b["events"].event(data)
        comm = event.comm.decode(errors='ignore').rstrip('\x00')
        filename = event.filename.decode(errors='ignore').rstrip('\x00')
        
        output = {
            "timestamp": time.time(),
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "type": TYPE_STR.get(event.type, "UNKNOWN"),
            "comm": comm
        }

        if event.type == 0:  # EXEC
            output["path"] = filename
            if hash_engine and HASH_DETECTION_AVAILABLE:
                res = hash_engine.scan_process_binary(event.pid, comm, filename)
                if res.get("malicious"):
                    output.update({
                        "MALWARE_DETECTED": True,
                        "hash": res["hash"],
                        "malware_info": res["malware_info"],
                        "scan_method": res.get("scan_method")
                    })
                    terminate_malicious_process(event.pid, res["malware_info"])
                elif res.get("scanned"):
                    output.update({
                        "hash": res["hash"], 
                        "scan_clean": True, 
                        "scan_method": res.get("scan_method")
                    })

        elif event.type == 1:  # OPEN
            output["path"] = filename
            output["flags"] = event.flags
            output["flags_decoded"] = decode_open_flags(event.flags)

        elif event.type == 2:  # WRITE
            bytes_written = event.flags
            output["bytes_written"] = bytes_written
            write_event_count += 1
            total_write_bytes += bytes_written
            if write_event_count % 100 == 0:
                print(f"DEBUG: {write_event_count} WRITE events, {total_write_bytes} bytes", file=sys.stderr)

        elif event.type == 3:  # UNLINK
            output["path"] = filename
            output["operation"] = "DELETE"
            unlink_event_count += 1
            
            if any(filename.endswith(ext) for ext in ['.doc', '.pdf', '.jpg', '.png', '.xlsx']):
                output["suspicious_deletion"] = True
                output["reason"] = "User file deleted"
            
            if unlink_event_count % 50 == 0:
                print(f"DEBUG: {unlink_event_count} files deleted", file=sys.stderr)

        elif event.type == 4:  # CHMOD
            output["path"] = filename
            output["mode"] = event.flags
            output["mode_decoded"] = decode_chmod_mode(event.flags)
            chmod_event_count += 1
            
            suspicious_perms = []
            if event.flags & 0o4000:
                suspicious_perms.append("SETUID")
            if event.flags & 0o2000:
                suspicious_perms.append("SETGID")
            if (event.flags & 0o777) == 0o777:
                suspicious_perms.append("WORLD_ALL")
            
            if suspicious_perms:
                output["suspicious_chmod"] = True
                output["suspicious_reasons"] = suspicious_perms
            
            if chmod_event_count % 20 == 0:
                print(f"DEBUG: {chmod_event_count} permission changes", file=sys.stderr)
        
        elif event.type == 5:  # CONNECT
            output["operation"] = "NETWORK_CONNECT"
            connect_event_count += 1
            
            # Decodificar IP:Puerto si está disponible
            if event.flags != 0:  # flags contiene la IP
                import socket
                import struct
                try:
                    ip = socket.inet_ntoa(struct.pack('<I', event.flags))
                    port = struct.unpack('<H', event.filename[:2])[0] if event.filename else 0
                    output["dest_ip"] = ip
                    output["dest_port"] = port
                    output["connection"] = f"{ip}:{port}"
                    
                    # Detectar C2 conocidos
                    KNOWN_C2 = ['192.168.1.100', '10.0.0.50']  # Ejemplos
                    if ip in KNOWN_C2:
                        output["suspicious_c2"] = True
                        output["alert"] = f"C2 connection to {ip}:{port}"
                except:
                    pass
            
            # Detectar conexiones sospechosas
            if event.uid != 0:  # Procesos no-root haciendo conexiones
                output["suspicious_connect"] = True
                output["reason"] = "Non-root network connection"
            
            if connect_event_count % 30 == 0:
                print(f"DEBUG: {connect_event_count} network connections", file=sys.stderr)

        elif event.type == 6:  # PTRACE
            output["ptrace_request"] = event.flags
            output["ptrace_decoded"] = decode_ptrace_request(event.flags)
            ptrace_event_count += 1
            
            # Todos los ptrace son sospechosos
            output["suspicious_ptrace"] = True
            output["reason"] = f"Process debugging/injection: {output['ptrace_decoded']}"
            
            if ptrace_event_count % 10 == 0:
                print(f"DEBUG: {ptrace_event_count} ptrace calls", file=sys.stderr)

        elif event.type == 7:  # MMAP
            output["mmap_prot"] = event.flags
            output["mmap_decoded"] = decode_mmap_prot(event.flags)
            mmap_event_count += 1
            
            # Detectar WRITE+EXEC (code injection)
            if (event.flags & 0x2) and (event.flags & 0x4):  # WRITE + EXEC
                output["suspicious_mmap"] = True
                output["reason"] = "Executable memory mapping"
            
            if mmap_event_count % 50 == 0:
                print(f"DEBUG: {mmap_event_count} memory mappings", file=sys.stderr)

        elif event.type == 8:  # CHOWN
            output["path"] = filename
            output["new_owner"] = event.flags
            chown_event_count += 1
            
            # Detectar cambios de ownership sospechosos
            if event.uid != 0 and event.flags == 0:  # No-root cambiando a root
                output["suspicious_chown"] = True
                output["reason"] = "Ownership change to root"
            
            if chown_event_count % 20 == 0:
                print(f"DEBUG: {chown_event_count} ownership changes", file=sys.stderr)

        # Filtro de ruido
        if event.type == 2 and comm in ("tee", "cat"):
            return

        # Output JSON
        try:
            j = json.dumps(output, separators=(",", ":"))
            print(j, flush=True)
            
            if event.type in [3, 4]:
                print(f"DEBUG: {TYPE_STR[event.type]} - {filename[:50]}...", file=sys.stderr)
                
        except BrokenPipeError:
            sys.exit(0)
        except Exception as e:
            print(f"ERROR JSON output: {e}", file=sys.stderr)
            
    except Exception as e:
        print(f"ERROR procesando evento: {e}", file=sys.stderr)

def main():
    global b, hash_engine
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    p = argparse.ArgumentParser()
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--no-hash", action="store_true")
    p.add_argument("--download-hashes", action="store_true")
    p.add_argument("--hash-only-samples", action="store_true")
    p.add_argument("--dry-kill", action="store_true")
    args = p.parse_args()

    if args.verbose:
        print("🚀 EDR Collector EXPANDIDO iniciando...", file=sys.stderr)
        print("   SYSCALLS MONITORIZADAS:", file=sys.stderr)
        print("     • execve - Ejecución de procesos", file=sys.stderr)
        print("     • openat - Apertura de archivos", file=sys.stderr)
        print("     • write - Escritura (>1KB)", file=sys.stderr)
        print("     • unlink/unlinkat - Borrado de archivos", file=sys.stderr)
        print("     • chmod/fchmodat - Cambios de permisos", file=sys.stderr)
        print("     • connect - Conexiones de red", file=sys.stderr)
        print("     • ptrace - Debugging/inyección", file=sys.stderr)
        print("     • mmap - Mapeo de memoria", file=sys.stderr)
        print("     • chown - Cambio de propietario", file=sys.stderr)

    if not args.no_hash and HASH_DETECTION_AVAILABLE:
        hash_engine = HashDetectionEngine()
        hash_engine.setup_database(download_real=(args.download_hashes and not args.hash_only_samples))

    try:
        if args.verbose:
            print("Compilando eBPF...", file=sys.stderr)
        
        b = BPF(text=BPF_PROGRAM)
        b["events"].open_perf_buffer(handle_event)

        if args.verbose:
            print("✓ eBPF compilado exitosamente", file=sys.stderr)
            print("Monitorizando syscalls (9 tipos activos)...", file=sys.stderr)
            
        while True:
            b.perf_buffer_poll()
            
    except Exception as e:
        print(f"Error fatal: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if b:
            try: 
                b.cleanup()
            except: 
                pass
        if args.verbose:
            print(f"   WRITE: {write_event_count} eventos, {total_write_bytes} bytes", file=sys.stderr)
            print(f"   UNLINK: {unlink_event_count} archivos borrados", file=sys.stderr)
            print(f"   CHMOD: {chmod_event_count} cambios de permisos", file=sys.stderr)
            print(f"   CONNECT: {connect_event_count} conexiones de red", file=sys.stderr)
            print(f"   PTRACE: {ptrace_event_count} llamadas debug", file=sys.stderr)
            print(f"   MMAP: {mmap_event_count} mapeos memoria", file=sys.stderr)
            print(f"   CHOWN: {chown_event_count} cambios propietario", file=sys.stderr)

if __name__ == "__main__":
    main()
