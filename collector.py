#!/usr/bin/env python3
"""
collector.py -  
 
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

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 type;
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
    bpf_get_current_comm(&data.comm, sizeof(data.comm)); nombre del proceso que esta ejecutando la syscall
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);#ruta del archivo que se le pasa como argumento a la syscall
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

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
    bpf_get_current_comm(&data.comm, sizeof(data.comm)); #capturamos nombre del proceso
    data.filename[0] = '\0';
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
// NUEVA SYSCALL: unlink (borrado de archivos)
TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 3;  // UNLINK
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = 0;  // No hay flags en unlink
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: unlinkat (borrado de archivos con dirfd)
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 3;  // UNLINK (mismo tipo que unlink)
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->flags;  // AT_REMOVEDIR flag
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->pathname);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: chmod (cambio de permisos)
TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 4;  // CHMOD
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->mode;  // Nuevo modo/permisos
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// NUEVA SYSCALL: fchmodat (cambio de permisos con dirfd)
TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 4;  // CHMOD (mismo tipo)
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->mode;  // Nuevo modo/permisos
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

"""

# Mapeo de tipos actualizado
TYPE_STR = {
    0: "EXEC", 
    1: "OPEN", 
    2: "WRITE",
    3: "UNLINK",  # NUEVO
    4: "CHMOD"    # NUEVO
}
write_event_count = 0
total_write_bytes = 0
unlink_event_count = 0  # NUEVO
chmod_event_count = 0   # NUEVO

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
    O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL = 0x1,0x2,0x40,0x200,0x400,0x80
    modes = []
    m = flags & 0x3
    modes.append({0:"RDONLY",O_WRONLY:"WRONLY",O_RDWR:"RDWR"}.get(m,"RDONLY"))
    for bit, name in ((O_CREAT,"CREAT"),(O_TRUNC,"TRUNC"),(O_APPEND,"APPEND"),(O_EXCL,"EXCL")):
        if flags & bit: modes.append(name)
    return "|".join(modes)

def decode_chmod_mode(mode):
    """Decodificar permisos chmod en formato octal y simbólico"""
    # Convertir a octal
    octal = oct(mode & 0o777)
    
    # Decodificar permisos simbólicos
    perms = []
    
    # Permisos especiales
    if mode & 0o4000: perms.append("SETUID")
    if mode & 0o2000: perms.append("SETGID")
    if mode & 0o1000: perms.append("STICKY")
    
    # Permisos estándar (owner-group-others)
    symbolic = ""
    for shift in [6, 3, 0]:  # owner, group, others
        p = (mode >> shift) & 0o7
        symbolic += "r" if p & 0o4 else "-"
        symbolic += "w" if p & 0o2 else "-"
        symbolic += "x" if p & 0o1 else "-"
    
    result = f"{octal} ({symbolic})"
    if perms:
        result += f" [{','.join(perms)}]"
    
    return result

def handle_event(cpu, data, size):
    """Procesar eventos + JSON compacto y filtro de ruido"""
    global hash_engine, write_event_count, total_write_bytes
    global unlink_event_count, chmod_event_count  # NUEVO
    try:
        #Convierte los bytes recibidos desde eBPF en una estructura Python equivalente a event_t.
        event = b["events"].event(data) #Usa el layout del struct event_t que he definido en el código C ebpf
                                        #y devuelve un objeto python (event) con esos atributos.
        comm = event.comm.decode(errors='ignore').rstrip('\x00')
        filename = event.filename.decode(errors='ignore').rstrip('\x00')
        output = {
            "timestamp": time.time(),
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "type": TYPE_STR.get(event.type,"UNKNOWN"),
            "comm": comm
        }

        if event.type == 0:  # EXEC 
            output["path"] = filename #Se guarda el nombre del ejecutable
            if hash_engine and HASH_DETECTION_AVAILABLE: 
                res = hash_engine.scan_process_binary(event.pid, comm, filename) #ESTO ESTA EN EL HASH_DETECTION_COLLECTOR
                #Se compara con la base de datos. Si es malware, se mata el proceso:
                if res.get("malicious"):
                    output.update({
                        "MALWARE_DETECTED": True,
                        "hash": res["hash"],
                        "malware_info": res["malware_info"],
                        "scan_method": res.get("scan_method")
                    })
                    terminate_malicious_process(event.pid, res["malware_info"])
                elif res.get("scanned"):
                    output.update({"hash": res["hash"], "scan_clean": True, "scan_method": res.get("scan_method")})

        elif event.type == 1:  # OPEN
            output["path"] = filename
            output["flags"] = event.flags  #usamos los flags para saber en qué modo se abre (lectura, escritura, creación etc)
            output["flags_decoded"] = decode_open_flags(event.flags)

        elif event.type == 2:  # WRITE
            bytes_written = event.flags
            output["bytes_written"] = bytes_written
            write_event_count += 1
            total_write_bytes += bytes_written
            if write_event_count % 100 == 0:
                print(f"DEBUG COLLECTOR: {write_event_count} events, {total_write_bytes} bytes", file=sys.stderr)

        elif event.type == 3:  # UNLINK - NUEVO
            output["path"] = filename
            output["operation"] = "DELETE"
            unlink_event_count += 1
            
            # Análisis adicional para ransomware
            if any(filename.endswith(ext) for ext in ['.doc', '.pdf', '.jpg', '.png', '.xlsx']):
                output["suspicious_deletion"] = True
                output["reason"] = "User file deleted"
            
            # Debug cada 50 deletes
            if unlink_event_count % 50 == 0:
                print(f"DEBUG: {unlink_event_count} files deleted", file=sys.stderr)

        elif event.type == 4:  # CHMOD - NUEVO
            output["path"] = filename
            output["mode"] = event.flags
            output["mode_decoded"] = decode_chmod_mode(event.flags)
            chmod_event_count += 1
            
            # Detectar permisos sospechosos
            suspicious_perms = []
            if event.flags & 0o4000:  # SETUID
                suspicious_perms.append("SETUID")
            if event.flags & 0o2000:  # SETGID
                suspicious_perms.append("SETGID")
            if (event.flags & 0o777) == 0o777:  # World writable/executable
                suspicious_perms.append("WORLD_ALL")
            
            if suspicious_perms:
                output["suspicious_chmod"] = True
                output["suspicious_reasons"] = suspicious_perms
            
            # Debug cada 20 chmods
            if chmod_event_count % 20 == 0:
                print(f"DEBUG: {chmod_event_count} permission changes", file=sys.stderr)

        # 1) filtro ruido de pipeline
        if event.type == 2 and comm in ("tee","cat"):
            return

        # 2) JSON compacto
        try:
            j = json.dumps(output, separators=(",",":"))
            print(j, flush=True)
            
             # Debug adicional para nuevos eventos
            if event.type in [3, 4]:  # UNLINK o CHMOD
                print(f"DEBUG NEW EVENT: {TYPE_STR[event.type]} - {filename[:50]}...", file=sys.stderr)
                
        except BrokenPipeError:
            sys.exit(0)
        except Exception as e:
            print(f"ERROR JSON output: {e}", file=sys.stderr)

    except Exception as e:
        if "WRITE" in str(e):
            print(f"ERROR procesando WRITE: {e}", file=sys.stderr)

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
        print("   NUEVAS SYSCALLS:", file=sys.stderr)
        print("     • unlink/unlinkat - Detección de borrado", file=sys.stderr)
        print("     • chmod/fchmodat - Cambios de permisos", file=sys.stderr)

    if not args.no_hash and HASH_DETECTION_AVAILABLE:
        hash_engine = HashDetectionEngine()
        hash_engine.setup_database(download_real=(args.download_hashes and not args.hash_only_samples))

    try:
        if args.verbose:
            print("Compilando eBPF expandido...", file=sys.stderr)
        b = BPF(text=BPF_PROGRAM)
        b["events"].open_perf_buffer(handle_event)

        if args.verbose:
            print("Monitorizando syscalls (5 tipos activos)...", file=sys.stderr)
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
            print(f"\nEstadísticas finales:", file=sys.stderr)
            print(f"   WRITE: {write_event_count} eventos, {total_write_bytes} bytes", file=sys.stderr)
            print(f"   UNLINK: {unlink_event_count} archivos borrados", file=sys.stderr)
            print(f"   CHMOD: {chmod_event_count} cambios de permisos", file=sys.stderr)

if __name__ == "__main__":
    main()
