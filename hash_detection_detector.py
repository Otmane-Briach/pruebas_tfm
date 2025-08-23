#!/usr/bin/env python3
"""
hash_detection_detector.py 
Umbrales realistas + debug mejorado + anti-spam 
ARREGLADO: Error de sintaxis en stats
"""

import sys
import json
import time
import sqlite3
import signal
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional
import subprocess

@dataclass
class Event:
    """Estructura para eventos con soporte hash detection"""
    timestamp: float
    pid: int
    event_type: str
    comm: str
    path: Optional[str] = None
    flags: Optional[int] = None
    flags_decoded: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    ppid: Optional[int] = None
    # Campos para hash detection
    malware_detected: Optional[bool] = None
    file_hash: Optional[str] = None
    malware_info: Optional[Dict] = None
    scan_clean: Optional[bool] = None
    scan_method: Optional[str] = None
    # Campo para eventos WRITE
    bytes_written: Optional[int] = None
    # NUEVOS CAMPOS para unlink/chmod
    operation: Optional[str] = None  # Para UNLINK: "DELETE"
    mode: Optional[int] = None  # Para CHMOD: permisos nuevos
    mode_decoded: Optional[str] = None  # Permisos decodificados
    suspicious_deletion: Optional[bool] = None  # Borrado sospechoso
    suspicious_chmod: Optional[bool] = None  # Permisos peligrosos
    suspicious_reasons: Optional[List[str]] = None  # Razones de sospecha
    # Campos para nuevas syscalls
    ptrace_request: Optional[int] = None
    ptrace_decoded: Optional[str] = None
    mmap_prot: Optional[int] = None
    mmap_decoded: Optional[str] = None
    new_owner: Optional[int] = None
    suspicious_connect: Optional[bool] = None
    suspicious_ptrace: Optional[bool] = None
    suspicious_mmap: Optional[bool] = None
    suspicious_chown: Optional[bool] = None

class ProcessTree:
    def __init__(self):
        self.tree = {}
    
    def add_process(self, pid: int, ppid: int, exe: str):
        if pid not in self.tree:
            self.tree[pid] = {'ppid': ppid, 'children': [], 'exe': exe, 'score': 0, 'events': []}
        if ppid in self.tree:
            self.tree[ppid]['children'].append(pid)
    
    def update_score(self, pid: int, score: int):
        if pid in self.tree:
            self.tree[pid]['score'] = score
    
    def get_family_score(self, pid: int) -> int:
        if pid not in self.tree:
            return 0
        total = self.tree[pid]['score']
        for child in self.tree[pid]['children']:
            total += self.get_family_score(child)
        return total

class ProcessScoreTracker:
    """Sistema de scoring unificado basado en ESCAPADE/LeARN"""
    
    def __init__(self, detector=None):  
        self.detector = detector   
        self.process_scores = defaultdict(lambda: {
            'score': 0,
            'indicators': [],
            'last_update': 0,
            'window_events': deque()
        })
        
        # Scoring EXACTO según tu documento a Florina
        self.scoring_rules = {
            # +3 PUNTOS: Alta prevalencia (>80%) y especificidad (<2% FP)
            'locked_files_burst': 3,      # >5 archivos .locked en 10s
            'massive_write': 3,            # >20MB o >50 ops
            'unlink_burst': 3,             # >5 deletes en 10s
            'ransom_note': 3,              # Drop HTML/RTF
             
            'directory_scan': 3,        # NUEVO: >100 OPEN en 10s = escaneo masivo
            'recursive_scan': 2,        # NUEVO: Escaneo de /proc /sys /dev
            
            # +2 PUNTOS: Prevalencia media (50-80%) y especificidad media (2-5% FP)
            'tmp_execution': 2,            # Ejecución desde /tmp
            'kill_process': 2,             # pkill/kill
            'persistence_cron': 3,          # Modificación de crontab
            'persistence_systemd': 3,       # Nuevo servicio systemd
            'persistence_bashrc': 2,        # Modificación .bashrc/.profile
            'persistence_ldpreload': 3,     # LD_PRELOAD hijacking
            'setuid_chmod': 2,             # chmod SETUID/SETGID
            
            # +1 PUNTO: Baja prevalencia (<50%) y especificidad (>5% FP)
            'chmod_regular': 1,            # chmod normal
            'mmap_exec': 1,                # mmap WRITE+EXEC
            'ptrace_use': 1,               # ptrace
            'o_trunc': 1,                  # O_TRUNC flag
            
            'chmod_burst': 3,              # NUEVO: múltiples chmod del mismo parent
            'multi_arch_payload': 4,       # NUEVO: mismo archivo, diferentes arquitecturas
            'botnet_multiarch_download': 5,  # Patrón específico Mirai: 3+ arch consecutivas

            # +1 BONUS: Co-ocurrencia
            'cooccurrence': 1,              # Múltiples indicadores juntos

            
            'download_execute_chain': 5,    # Download + chmod +x
             
            'multi_arch_payload': 4,         # Descarga para múltiples arquitecturas
            'rapid_fork': 2,                # Fork bombing
            
            
        }
        
        self.alert_threshold = 8  # Umbral según tu documento
        self.time_window = 10      # Ventana de 10 segundos
        self.decay_window = 30 
        self.alerted_pids = set()  # Anti-spam
        # Tracking familiar para detectar fork-and-run
        self.family_scores = defaultdict(lambda: {
            'pids': set(),
            'indicators': defaultdict(int),
            'last_update': 0,
            'window_start': 0
        })

        # NUEVO: Para detección de botnet Mirai
        self.download_attempts = defaultdict(lambda: {
            'architectures': set(),
            'first_seen': 0,
            'failed_count': 0,
            'commands': set()
        })
        self.pid_to_family = {}
        self.alerted_families = set()
        # MITRE ATT&CK Mapping
        self.mitre_mapping = {
            'locked_files_burst': ['T1486'],      # Data Encrypted for Impact
            'massive_write': ['T1486', 'T1565.001'],  # Data Encrypted + Data Manipulation
            'unlink_burst': ['T1485'],            # Data Destruction
            'ransom_note': ['T1486'],              # Data Encrypted for Impact
            'tmp_execution': ['T1036.005'],        # Masquerading: Match Legitimate Name/Location
            'kill_process': ['T1489'],             # Service Stop
            'setuid_chmod': ['T1548.001'],         # Setuid and Setgid
            'chmod_regular': ['T1222.002'],        # File/Directory Permissions Modification
            'mmap_exec': ['T1055.001'],            # Dynamic-link Library Injection
            'ptrace_use': ['T1055.008'],           # Process Injection: Ptrace
            'o_trunc': ['T1565.001'],              # Data Manipulation
            'persistence_cron': ['T1053.003'],       # Scheduled Task/Job: Cron
            'persistence_systemd': ['T1543.002'],    # Create or Modify System Process: Systemd
            'persistence_bashrc': ['T1546.004'],     # Event Triggered Execution: .bash_profile
            'persistence_ldpreload': ['T1574.006'],  # Hijack Execution Flow: LD_PRELOAD
            'botnet_multiarch_download': ['T1105', 'T1608.001'],  # Ingress Tool Transfer + Stage Capabilities
            'cooccurrence': []                     # No MITRE específico
            
        }
    
    def add_indicator(self, pid: int, indicator: str, event_time: float, verbose: bool = False) -> Optional[str]:
        """Actualizar score con sistema de decay"""
        proc = self.process_scores[pid]
        
        # Aplicar decay y limpiar eventos antiguos
        new_window = deque()
        for e in proc['window_events']:
            age = event_time - e[0]
            if age <= self.decay_window:  # Mantener hasta 30s con decay
                # e = (timestamp, indicator, points_originales, weight_actual)
                if len(e) == 3:  # Formato antiguo, añadir weight
                    new_window.append((e[0], e[1], e[2], 1.0))
                else:
                    new_window.append(e)
        proc['window_events'] = new_window
        
        # Anti-spam para o_trunc
        if indicator == 'o_trunc':
            o_trunc_count = sum(1 for e in proc['window_events'] if e[1] == 'o_trunc' and event_time - e[0] <= self.time_window)
            if o_trunc_count >= 3:
                return None
        
        # Anti-spam: no duplicar mismo indicador en ventana de 10s (excepto o_trunc)
        if indicator != 'o_trunc':
            recent_indicators = [e[1] for e in proc['window_events'] if event_time - e[0] <= self.time_window]
            if indicator in recent_indicators:
                return None
        
        # Añadir nuevo evento
        points = self.scoring_rules.get(indicator, 0)
        if points > 0:
            proc['window_events'].append((event_time, indicator, points, 1.0))  # Weight inicial 1.0
            proc['last_update'] = event_time
            
            # TRACKING FAMILIAR (mantener como está)
            if hasattr(self.detector, 'process_tree') and self.detector.process_tree.tree:
                ppid = None
                if pid in self.detector.process_tree.tree:
                    ppid = self.detector.process_tree.tree[pid].get('ppid')
                
                if ppid:
                    family_id = f"family_{ppid}"
                    family = self.family_scores[family_id]
                    
                    # Usar ventana más larga para familias (30s)
                    if event_time - family['window_start'] > self.decay_window:
                        family['indicators'].clear()
                        family['pids'].clear()
                        family['window_start'] = event_time
                    
                    family['indicators'][indicator] += 1
                    family['pids'].add(pid)
                    family['last_update'] = event_time
                    
                    # Calcular score familiar CON DECAY
                    family_score = 0
                    for ind, count in family['indicators'].items():
                        base_points = self.scoring_rules.get(ind, 0)
                        if count >= 5 and ind == 'chmod_regular':
                            family_score += 6
                        elif count >= 5:
                            family_score += base_points * 2
                        elif count >= 3:
                            family_score += base_points * 1.5
                        else:
                            family_score += base_points * count
                    
                    if family_score >= self.alert_threshold and family_id not in self.alerted_families:
                        self.alerted_families.add(family_id)
                        indicators_str = ', '.join([f"{ind}(x{cnt})" for ind, cnt in family['indicators'].items()])
                        mitre_techniques = set()
                        for ind in family['indicators'].keys():
                            mitre_techniques.update(self.mitre_mapping.get(ind, []))
                        mitre_str = f" [MITRE: {', '.join(sorted(mitre_techniques))}]" if mitre_techniques else ""
                        
                        alert_msg = f"RANSOMWARE FAMILIAR [SCORE {int(family_score)}]: {indicators_str} ({len(family['pids'])} procesos, parent PID {ppid}){mitre_str}"
                        
                        if self.detector and hasattr(self.detector, '_execute_response'):
                            self.detector._execute_response(ppid, int(family_score), "family_parent", alert_msg)
                        
                        for fpid in family['pids']:
                            self.alerted_pids.add(fpid)
                        
                        return alert_msg
            
            # DEBUG
            if verbose:
                print(f"DEBUG INDICATOR: {indicator} para PID {pid}", file=sys.stderr)
            
            # Response inmediato para indicadores críticos (mantener como está)
            CRITICAL_INDICATORS = {'locked_files_burst', 'unlink_burst', 'massive_write'}
            if indicator in CRITICAL_INDICATORS:
                if False:  # Mantener tu lógica actual
                    pass
            
            # CALCULAR SCORE CON DECAY
            current_score = 0
            indicators_with_decay = []
            
            for e in proc['window_events']:
                age = event_time - e[0]
                
                # Calcular weight según edad
                if age <= self.time_window:  # 0-10s: 100%
                    weight = 1.0
                elif age <= self.time_window * 2:  # 10-20s: 70%
                    weight = 0.7
                elif age <= self.decay_window:  # 20-30s: 40%
                    weight = 0.4
                else:
                    continue  # No debería pasar si limpiamos bien
                
                weighted_points = e[2] * weight
                current_score += weighted_points
                
                if weight > 0:
                    indicators_with_decay.append(f"{e[1]}(+{e[2]}*{weight:.1f})")
            
            # Log de trazabilidad con decay
            if verbose or current_score >= 4:
                print(f"SCORING PID {pid}: {current_score:.1f}/{self.alert_threshold} pts [decay: {', '.join(indicators_with_decay[:5])}]", file=sys.stderr)
            
            # Bonus co-ocurrencia
            unique_indicators = set(e[1] for e in proc['window_events'])
            if len(unique_indicators) >= 3:
                current_score += self.scoring_rules['cooccurrence']
                if verbose:
                    print(f"  +1 bonus co-ocurrencia → {current_score:.1f}/{self.alert_threshold}", file=sys.stderr)
            
            # Verificar umbral
            if current_score >= self.alert_threshold and pid not in self.alerted_pids:
                self.alerted_pids.add(pid)
                
                # Para el mensaje, mostrar solo indicadores recientes (sin decay)
                recent_indicators = [(e[1], e[2]) for e in proc['window_events'] if event_time - e[0] <= self.time_window]
                all_indicators = [(e[1], e[2]) for e in proc['window_events']]
                
                indicators_str = ', '.join([f"{ind}(+{pts})" for ind, pts in recent_indicators])
                if len(all_indicators) > len(recent_indicators):
                    indicators_str += f" [+{len(all_indicators)-len(recent_indicators)} eventos con decay]"
                
                mitre_techniques = set()
                for e in proc['window_events']:
                    techniques = self.mitre_mapping.get(e[1], [])
                    mitre_techniques.update(techniques)
                
                mitre_str = f" [MITRE: {', '.join(sorted(mitre_techniques))}]" if mitre_techniques else ""
                
                proc['window_events'].clear()
                alert_msg = f"RANSOMWARE [SCORE {current_score:.1f}]: {indicators_str} (PID {pid}){mitre_str}"
                
                proc['last_score'] = current_score
                
                return alert_msg
        
        return None

class ThreatDetectorFixed:
    """Detector WRITE CORREGIDO con umbrales realistas"""
    
    def __init__(self):
        self.running = True
        
        # Ventanas de tiempo (existentes)
        self.file_windows = defaultdict(deque)
        self.exec_windows = defaultdict(deque)

        # Sistema de scoring unificado
        self.score_tracker = ProcessScoreTracker(self)  # <-- AÑADIR self aquí
        self.verbose_scoring = os.environ.get('EDR_VERBOSE_SCORING', '0') == '1'

        # Response Engine Configuration
        self.response_mode = os.environ.get('EDR_RESPONSE_MODE', 'monitor').lower()
        self.response_thresholds = {
            'block': 4,   # SIGSTOP para score >= 6
            'kill': 6     # SIGKILL para score >= 8
        }
        self.blocked_pids = set()  # PIDs bloqueados con SIGSTOP
        self.killed_pids = set()   # PIDs terminados con SIGKILL

        self.process_tree = ProcessTree()
        self.emergency_stopped = set()  # PIDs detenidos de emergencia
        
        # Ventanas para nuevas syscalls
        self.deletion_windows = defaultdict(deque)  # Ventana para UNLINK
        self.chmod_windows = defaultdict(deque)     # Ventana para CHMOD
        # NUEVA: Ventana para detectar escaneos
        self.scan_windows = defaultdict(deque)

        # Tracking para detección de botnets
        self.failed_connections = defaultdict(list)
        self.download_targets = defaultdict(set)
        self.fork_patterns = defaultdict(list)

        # Tracking temporal para arquitecturas con timestamp
        self.arch_timestamps = defaultdict(list)
        # NUEVO: Para detección de chmod burst por parent
        self.parent_chmod_windows = defaultdict(deque)
        # NUEVO: Para detección multi-arquitectura mejorada
        self.arch_files_by_base = defaultdict(lambda: defaultdict(set))
       

        # Ventanas para detección de persistencia
        self.persistence_windows = defaultdict(deque)
        self.persistence_alerted = set()

        # Contadores específicos
        self.deletion_patterns = {
            'user_files': defaultdict(int),  # Archivos de usuario borrados
            'last_reset': time.time()
        }
    
        # Estados de alerta para anti-spam
        self.mass_deletion_alerted = set()  # PIDs alertados por borrado masivo
        self.privilege_escalation_alerted = set()  # PIDs alertados por chmod sospechoso

        # CORREGIDO: Contadores WRITE con reset menos agresivo
        self.write_counters = {
            'ops': defaultdict(int),     # Número de operaciones write
            'bytes': defaultdict(int),   # Total bytes escritos
            'last_reset': time.time()    # Para reset periódico
        }
        self.write_alerted = set()  # PIDs que ya han generado alerta WRITE
        self.write_last_alert = {}  # Último timestamp de alerta por PID
        
        # ANTI-SPAM: Estados de alerta por PID + COOLDOWN por directorio
        self.ransomware_alerted = set()
        self.suspicious_location_alerted = set()
        self.ransomware_dir_alerted = {}  # directorio -> timestamp
        self.ransomware_cooldown = 60  # segundos

        # Whitelist de procesos de sistema que no vamos a contar porque son seguros
        self.whitelist_procs = {
            "tracker-extract", "tracker-miner-f", "tracker-miner-fs", 
            "systemd", "kworker", "ksoftirqd", "migration", "rcu_gp", "rcu_par_gp",
            "Web Content", "WebExtensions", "Isolated Web"

        }
        
        # ahora sii: Umbrales WRITE REALISTAS para testing
        self.config = {
            "file_burst_threshold": 5,# >5 archivos .locked según documento ESCAPADE/LeARN
            "exec_burst_threshold": 3,
            "time_window": 10,
            # UMBRALES WRITE AJUSTADOS PARA TESTING
            "write_ops_threshold": 50,            # 50 operaciones (era 500)
            "write_bytes_threshold": 20*1024*1024,  # 20MB (era 100MB)
            "write_reset_interval": 60,           # Reset cada 60s (era 30s)
            "write_alert_cooldown": 30,           # 30s entre alertas del mismo PID
            # Configuración existente
            "suspicious_paths": {
                "/tmp", "/var/tmp", "/dev/shm"
            },
            "critical_files": {
                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/etc/hosts", "/boot/grub/grub.cfg", "/etc/crontab"
            },
            "suspicious_processes": {
                "nc", "ncat", "netcat", "curl", "wget", "nmap", 
                "masscan", "nikto", "sqlmap", "metasploit"
            },
            "suspicious_extensions": {
                ".locked", ".enc", ".crypt", ".encrypt", ".encrypted",
                ".vault", ".crypto", ".secure", ".ransomed", ".sougolock"  # <-- AÑADIR
            },

            # Umbrales para UNLINK
            "deletion_burst_threshold": 10,  # 10 archivos en ventana
            "deletion_time_window": 30,      # 30 segundos
            "critical_deletion_threshold": 5, # 5 archivos críticos
            
            # Umbrales para CHMOD  
            "chmod_suspicious_threshold": 3,  # 3 cambios sospechosos
            "chmod_time_window": 60,          # 60 segundos
            
            # Extensiones críticas para ransomware
            "critical_extensions": {
                ".doc", ".docx", ".pdf", ".jpg", ".jpeg", ".png",
                ".xlsx", ".xls", ".ppt", ".pptx", ".zip", ".rar",
                ".txt", ".csv", ".sql", ".db", ".bak"
            },
            
            # Permisos peligrosos
            "dangerous_permissions": {
                0o4000: "SETUID",  # Privilege escalation
                0o2000: "SETGID",  # Group privilege
                0o777:  "WORLD_ALL",  # World writable/executable
                0o666:  "WORLD_RW"    # World readable/writable
            },
            # NUEVO: Archivos de persistencia
            "persistence_files": {
                "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/",
                "/etc/systemd/system/", "/lib/systemd/system/", 
                "/etc/init.d/", "/etc/rc.local",
                "/.bashrc", "/.profile", "/.bash_profile",
                "/etc/ld.so.preload", "/etc/ld.so.conf",
                "/etc/passwd", "/etc/shadow", "/etc/sudoers"
            },
            "persistence_extensions": {
                ".service", ".timer", ".sh"
            }

        }
        
        # Estadísticas MEJORADAS con soporte WRITE - ARREGLADO
        self.stats = {
            "total_events": 0,
            "alerts_by_type": defaultdict(int),
            "hash_scans": 0,
            "malware_detected": 0,
            "clean_files": 0,
            "top_processes": defaultdict(int),
            "family_counts": defaultdict(int),
            "start_time": time.time(),
            "errors": 0,
            "max_events_per_second": 0,
            "events_this_second": 0,
            "last_second": int(time.time()),
            # Estadísticas WRITE
            "write_events": 0,
            "total_bytes_written": 0,
            "write_alerts": 0,
            "write_processes": set(),  # PIDs únicos que han hecho WRITE
            "write_burst_checks": 0,   # DEBUG: cuántas veces se llamó _check_write_burst
            "write_resets": 0,         # DEBUG: cuántas veces se resetearon contadores - ARREGLADO
             # Estadísticas para nuevos eventos
            "unlink_events": 0,
            "chmod_events": 0,
            "mass_deletions_detected": 0,
            "privilege_escalations_detected": 0,
            "ransomware_deletion_patterns": 0,
            "connect_events": 0,
            "ptrace_events": 0,
            "mmap_events": 0,
            "chown_events": 0,
            "network_alerts": 0,
            "injection_alerts": 0,
            "memory_alerts": 0,
            "ownership_alerts": 0,
            "botnet_indicators": 0,
            "download_execute_detected": 0,
            "scanning_detected": 0,
            "multi_arch_detected": 0,
            # Estadísticas de persistencia
            "persistence_attempts": 0,
            "persistence_cron": 0,
            "persistence_systemd": 0,
            "persistence_bashrc": 0,
            "persistence_ldpreload": 0,
            # Response Engine stats
            "response_blocks": 0,
            "response_kills": 0,
            "response_failures": 0


        }
        
        

        # PERSISTENCIA SQLite con esquema corregido
        self.setup_database()
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGPIPE, self._signal_handler)


    def setup_database(self):
        """Configurar base de datos de eventos con esquema expandido para nuevas syscalls"""
        try:
            self.db_conn = sqlite3.connect("edr_events.db")
            
            # Verificar si la tabla existe
            cursor = self.db_conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
            table_exists = cursor.fetchone() is not None
            
            if not table_exists:
                # Crear tabla completa con TODAS las columnas incluyendo las nuevas syscalls
                self.db_conn.execute("""
                    CREATE TABLE events(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL,
                        pid INTEGER,
                        ppid INTEGER,
                        comm TEXT,
                        event_type TEXT,
                        path TEXT,
                        flags INTEGER,
                        flags_decoded TEXT,
                        alert_level TEXT,
                        alert_message TEXT,
                        file_hash TEXT,
                        malware_family TEXT,
                        malware_source TEXT,
                        scan_method TEXT,
                        uid INTEGER,
                        gid INTEGER,
                        bytes_written INTEGER,
                        operation TEXT,
                        mode INTEGER,
                        mode_decoded TEXT,
                        suspicious_deletion INTEGER,
                        suspicious_chmod INTEGER,
                        suspicious_reasons TEXT,
                        ptrace_request INTEGER,
                        ptrace_decoded TEXT,
                        mmap_prot INTEGER,
                        mmap_decoded TEXT,
                        new_owner INTEGER,
                        suspicious_connect INTEGER,
                        suspicious_ptrace INTEGER,
                        suspicious_mmap INTEGER,
                        suspicious_chown INTEGER
                    )
                """)
                print("Tabla events creada con esquema expandido (incluye UNLINK/CHMOD)", file=sys.stderr)
            else:
                # Tabla existe - verificar y añadir columnas faltantes
                cursor = self.db_conn.execute("PRAGMA table_info(events)")
                existing_columns = [row[1] for row in cursor.fetchall()]
                
                # Lista de columnas que deben existir (nombre, tipo)
                required_columns = [
                    ("bytes_written", "INTEGER"),
                    ("operation", "TEXT"),
                    ("mode", "INTEGER"),
                    ("mode_decoded", "TEXT"),
                    ("suspicious_deletion", "INTEGER"),
                    ("suspicious_chmod", "INTEGER"),
                    ("suspicious_reasons", "TEXT"),
                    ("ptrace_request", "INTEGER"),
                    ("ptrace_decoded", "TEXT"),
                    ("mmap_prot", "INTEGER"),
                    ("mmap_decoded", "TEXT"),
                    ("new_owner", "INTEGER"),
                    ("suspicious_connect", "INTEGER"),
                    ("suspicious_ptrace", "INTEGER"),
                    ("suspicious_mmap", "INTEGER"),
                    ("suspicious_chown", "INTEGER")
                ]
                
                columns_added = []
                for column_name, column_type in required_columns:
                    if column_name not in existing_columns:
                        try:
                            self.db_conn.execute(f"ALTER TABLE events ADD COLUMN {column_name} {column_type}")
                            columns_added.append(column_name)
                        except sqlite3.OperationalError as e:
                            # La columna ya existe o hay otro error
                            if "duplicate column name" not in str(e).lower():
                                print(f"Error añadiendo columna {column_name}: {e}", file=sys.stderr)
                
                if columns_added:
                    print(f"Columnas añadidas a tabla existente: {', '.join(columns_added)}", file=sys.stderr)
                else:
                    print("Esquema de base de datos ya completo", file=sys.stderr)
            
            # Crear índices (incluir nuevos para optimización)
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_pid ON events(pid)",
                "CREATE INDEX IF NOT EXISTS idx_alert_level ON events(alert_level)",
                "CREATE INDEX IF NOT EXISTS idx_malware ON events(malware_family)",
                "CREATE INDEX IF NOT EXISTS idx_event_type ON events(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_operation ON events(operation)",  # NUEVO
                "CREATE INDEX IF NOT EXISTS idx_suspicious ON events(suspicious_deletion, suspicious_chmod)"  # NUEVO
            ]
            
            for idx in indexes:
                try:
                    self.db_conn.execute(idx)
                except sqlite3.OperationalError:
                    pass  # Índice ya existe
            
            self.db_conn.commit()
            print("Base de datos SQLite configurada: edr_events.db", file=sys.stderr)
            
            # Debug: mostrar esquema final
            cursor = self.db_conn.execute("PRAGMA table_info(events)")
            total_columns = len(cursor.fetchall())
            print(f"Esquema final: {total_columns} columnas en tabla events", file=sys.stderr)
            
        except Exception as e:
            print(f"Error configurando base de datos: {e}", file=sys.stderr)
            self.db_conn = None
        
    def _signal_handler(self, signum, frame):
        """Manejo de señales"""
        self.running = False
        # Desbloquear procesos suspendidos antes de salir
        if self.blocked_pids:
            print(f"Desbloqueando {len(self.blocked_pids)} procesos...", file=sys.stderr)
            for pid in list(self.blocked_pids):
                self._unblock_process(pid)
        self.print_final_stats()
        self._cleanup_database()
        sys.exit(0)
        
    def _cleanup_database(self):
        """Limpiar conexión de base de datos"""
        if self.db_conn:
            try:
                self.db_conn.commit()
                self.db_conn.close()
                print("Base de datos guardada y cerrada", file=sys.stderr)
            except:
                pass
        
    def analyze_event(self, event_data: dict) -> Optional[str]:
        """Análisis de eventos COMPLETO + WRITE CORREGIDO"""
        if not self.running:
            return None
            
        try:
            # AÑADIR: Ignorar eventos del propio detector
            my_pid = os.getpid()
            event_pid = event_data.get("pid", 0)
            
            if event_pid == my_pid:
                # Es el propio detector, ignorar
                return None
            # También ignorar el collector (proceso padre)
            if event_pid == os.getppid():
                return None
            #vamos a Crear un objeto Event desde el JSON recibido por stdin
            # Event ahora incluye también el campo bytes_written para eventos de tipo WRITE
            event = Event(
                timestamp=event_data.get("timestamp", time.time()),
                pid=event_data.get("pid", 0),
                ppid=event_data.get("ppid", 0),
                event_type=event_data.get("type", "UNKNOWN"),
                comm=event_data.get("comm", "unknown"),
                path=event_data.get("path", ""),
                flags=event_data.get("flags", 0),
                flags_decoded=event_data.get("flags_decoded", ""),
                uid=event_data.get("uid", 0),
                gid=event_data.get("gid", 0),
                malware_detected=event_data.get("MALWARE_DETECTED", False),
                file_hash=event_data.get("hash"),
                malware_info=event_data.get("malware_info"),
                scan_clean=event_data.get("scan_clean", False),
                scan_method=event_data.get("scan_method", ""),
                bytes_written=event_data.get("bytes_written", 0)
            )

            # Tracking de process tree
            if event.event_type == "EXEC":
                self.process_tree.add_process(event.pid, event.ppid, event.comm)
            
            # NUEVO: Pasar PPID al score tracker para todos los eventos
            if hasattr(event, 'ppid') and event.ppid:
                # Asegurar que el árbol conoce esta relación
                if event.pid not in self.process_tree.tree:
                    self.process_tree.tree[event.pid] = {
                        'ppid': event.ppid,
                        'exe': event.comm,
                        'score': 0,
                        'children': [],
                        'events': []
                    }

            # DEBUG: Si el evento es WRITE, imprime un mensaje de debug mostrando el PID y los bytes escritos
            if event.event_type == "WRITE":
                print(f"DEBUG WRITE: PID {event.pid}, bytes: {event.bytes_written}", file=sys.stderr)

            # PROCESO WRITE: Actualizar contadores antes de whitelist
            if event.event_type == "WRITE":
                self._process_write_event(event.pid, event.bytes_written or 0)

            # WHITELIST: ignorar eventos de procesos ruidosos DESPUÉS de procesar WRITE
            if event.comm in self.whitelist_procs:
                self._update_stats_complete(event)
                self._persist_event(event, None, None)
                return None
            
            # Procesar campos específicos de UNLINK
            if event_data.get("type") == "UNLINK":
                event.operation = event_data.get("operation", "DELETE")
                event.suspicious_deletion = event_data.get("suspicious_deletion", False)
                self.stats["unlink_events"] += 1
            
            # Procesar campos específicos de CHMOD
            elif event_data.get("type") == "CHMOD":
                event.mode = event_data.get("mode")
                event.mode_decoded = event_data.get("mode_decoded")
                event.suspicious_chmod = event_data.get("suspicious_chmod", False)
                event.suspicious_reasons = event_data.get("suspicious_reasons", [])
                self.stats["chmod_events"] += 1
            # Procesar campos específicos de las nuevas syscalls
            elif event_data.get("type") == "CONNECT":
                event.suspicious_connect = event_data.get("suspicious_connect", False)
                self.stats["connect_events"] += 1
                
                # Network attribution
                if "dest_ip" in event_data:
                    # Tracking de conexiones por proceso
                    if event.pid in self.process_tree.tree:
                        if 'connections' not in self.process_tree.tree[event.pid]:
                            self.process_tree.tree[event.pid]['connections'] = []
                        self.process_tree.tree[event.pid]['connections'].append({
                            'ip': event_data.get("dest_ip"),
                            'port': event_data.get("dest_port"),
                            'time': event.timestamp
                        })
                    
                    # Alerta si es C2
                    if event_data.get("suspicious_c2"):
                        alert_message = f"C2 DETECTED: {event.comm} connecting to {event_data['connection']}"
                        self.stats["alerts_by_type"]["c2_connection"] += 1
            
            elif event_data.get("type") == "PTRACE":
                event.ptrace_request = event_data.get("ptrace_request")
                event.ptrace_decoded = event_data.get("ptrace_decoded")
                event.suspicious_ptrace = event_data.get("suspicious_ptrace", False)
                self.stats["ptrace_events"] += 1
                
            elif event_data.get("type") == "MMAP":
                event.mmap_prot = event_data.get("mmap_prot")
                event.mmap_decoded = event_data.get("mmap_decoded")
                event.suspicious_mmap = event_data.get("suspicious_mmap", False)
                self.stats["mmap_events"] += 1
                
            elif event_data.get("type") == "CHOWN":
                event.new_owner = event_data.get("new_owner")
                event.suspicious_chown = event_data.get("suspicious_chown", False)
                self.stats["chown_events"] += 1

            # Actualizar estadísticas mejoradas
            self._update_stats_complete(event)
            
            # PRIORIDAD MÁXIMA: Hash detection de malware
            alert_level = None
            alert_message = None
            
            if event.malware_detected and event.malware_info:
                #Aquí no se usan heurísticas, porque el hash match es determinista 
                #y debe tener prioridad sobre cualquier sospecha
                family = event.malware_info.get("family", "Unknown")
                source = event.malware_info.get("source", "Unknown")
                method = event.scan_method or "unknown"
                
                alert_level = "CRITICAL"
                alert_message = f"MALWARE DETECTADO POR HASH: {event.comm} (PID {event.pid}) - Familia: {family} - Fuente: {source} - Método: {method}"
                
                self.stats["alerts_by_type"]["malware_hash"] += 1
                self.stats["family_counts"][family] += 1
                
            else:#Si no hay hash positivo → pasar a heurísticas
                # Análisis heurístico CON WRITE CORREGIDO
                heuristic_alert = self._run_detection_rules_complete(event)
                if heuristic_alert:
                    if "RANSOMWARE" in heuristic_alert or "CRITICO" in heuristic_alert:
                        alert_level = "ALERT"
                    else:
                        alert_level = "INFO"
                    alert_message = heuristic_alert
            
            # Persistir evento en base de datos
            self._persist_event(event, alert_level, alert_message)
            
            # Retornar alerta si existe
            if alert_message:
                # Ejecutar Response Engine si hay score alto
                # REEMPLAZAR (línea ~450-460 en analyze_event):
                if "RANSOMWARE" in alert_message and "[SCORE" in alert_message:
                    import re
                    score_match = re.search(r'\[SCORE (\d+)\]', alert_message)
                    pid_match = re.search(r'\(PID (\d+)\)', alert_message)  # AÑADIR ESTO
                    
                    if score_match and pid_match:
                        score = int(score_match.group(1))
                        alert_pid = int(pid_match.group(1))  # USAR EL PID DE LA ALERTA
                        
                        # Obtener comm del proceso correcto
                        try:
                            with open(f"/proc/{alert_pid}/comm", 'r') as f:
                                alert_comm = f.read().strip()
                        except:
                            alert_comm = "unknown"
                        
                        # Debug
                        print(f"DEBUG: Alerta PID {alert_pid} ({alert_comm}), Score {score}", file=sys.stderr)
                        
                        if alert_comm not in ['bash', 'sh', 'testing_sistema', 'sudo']:
                            response_executed = self._execute_response(alert_pid, score, alert_comm, alert_message)
                            if response_executed:
                                print(f"RESPONSE: Acción tomada contra {alert_comm} (PID {alert_pid})", file=sys.stderr)

                    return alert_message
                
            return None
            
        except Exception as e:
            self.stats["errors"] += 1
            print(f"DEBUG ERROR: {e}", file=sys.stderr)
            return None

    def _process_write_event(self, pid: int, bytes_written: int):
        """procesar evento WRITE con ANTI-SPAM integrado y DEBUG"""
        current_time = time.time()
        
        # reset periódico de contadores MENOS AGRESIVO
        #Si ha pasado más tiempo que write_reset_interval (configurable, por ejemplo, 60s), se resetean los contadores.
        if current_time - self.write_counters['last_reset'] > self.config['write_reset_interval']:
            # Log de reset para debug
            old_ops = len(self.write_counters['ops'])
            old_bytes = sum(self.write_counters['bytes'].values())
            old_pids = set(self.write_counters['ops'].keys())
            
            self.write_counters['ops'].clear()
            self.write_counters['bytes'].clear()
            self.write_counters['last_reset'] = current_time
            self.stats["write_resets"] += 1
            
            # NO limpiar anti-spam tan agresivamente
            # self.write_alerted.clear()  # permite que anti-spam persista
            
            print(f"DEBUG: Reset write counters #{self.stats['write_resets']}, había {old_ops} PIDs activos, {old_bytes:,} bytes", file=sys.stderr)
            if old_ops > 0:
                top_pids = sorted([(pid, self.write_counters['ops'].get(pid, 0)) for pid in list(old_pids)[:3]], key=lambda x: x[1], reverse=True)
                print(f"  Top PIDs reseteados: {top_pids}", file=sys.stderr)
        
        # aactualizar contadores
        self.write_counters['ops'][pid] += 1
        self.write_counters['bytes'][pid] += bytes_written
        
        # actualizar estadísticas globales
        self.stats["write_events"] += 1
        self.stats["total_bytes_written"] += bytes_written
        self.stats["write_processes"].add(pid)

    def _check_write_burst(self, pid: int) -> Optional[str]:
        """Detectar ráfaga de escrituras"""
        self.stats["write_burst_checks"] += 1
        
        #Recuperar datos acumulados del PID
        ops = self.write_counters['ops'][pid]
        bytes_total = self.write_counters['bytes'][pid]
        current_time = time.time()
        
        # DEBUG: Log cada check significativo
        if ops > 10 or bytes_total > 5*1024*1024:  # >10 ops o >5MB
            print(f"DEBUG: _check_write_burst PID {pid}: {ops} ops, {bytes_total:,} bytes (umbral: {self.config['write_ops_threshold']} ops, {self.config['write_bytes_threshold']/1024/1024:.0f}MB)", file=sys.stderr)
        
        # Anti-spam por PID: verificar cooldown
        if pid in self.write_alerted:
            if self.stats["write_burst_checks"] % 100 == 0:  # Debug ocasional
                print(f"DEBUG: PID {pid} ya alertado anteriormente (anti-spam)", file=sys.stderr)
            return None  # Ya alertamos este PID, ignorar
            
        last_alert = self.write_last_alert.get(pid, 0)
        if current_time - last_alert < self.config['write_alert_cooldown']:
            return None  # En cooldown
        
        alert_triggered = False
        alert_msg = None
        
        # Verificar umbrales y añadir al scoring
        if ops >= 50 or bytes_total >= 20*1024*1024:  # Umbrales según tu doc
            alert = self.score_tracker.add_indicator(pid, 'massive_write', current_time, verbose=self.verbose_scoring)
            if alert:
                self.write_alerted.add(pid)
                self.write_last_alert[pid] = current_time
                self.stats["write_alerts"] += 1
                print(f"DEBUG: ALERTA SCORING WRITE - PID {pid}", file=sys.stderr)
                return alert

        return None

    def _update_stats_complete(self, event: Event):
        """Actualizar estadísticas COMPLETAS"""
        self.stats["total_events"] += 1
        self.stats["top_processes"][event.comm] += 1
        
        # Estadísticas de hash
        if event.file_hash:
            self.stats["hash_scans"] += 1
        if event.malware_detected:
            self.stats["malware_detected"] += 1
        if event.scan_clean:
            self.stats["clean_files"] += 1
            
        # Calcular eventos por segundo (máximo)
        current_second = int(time.time())
        if current_second == self.stats["last_second"]:
            self.stats["events_this_second"] += 1
        else:
            if self.stats["events_this_second"] > self.stats["max_events_per_second"]:
                self.stats["max_events_per_second"] = self.stats["events_this_second"]
            self.stats["events_this_second"] = 1
            self.stats["last_second"] = current_second
    
    def _persist_event(self, event: Event, alert_level: str, alert_message: str):
        """Persistir evento en base de datos - VERSIÓN EXPANDIDA"""
        if not self.db_conn:
            return
            
        try:
            # Extraer información de malware
            malware_family = None
            malware_source = None
            if event.malware_info:
                malware_family = event.malware_info.get('family')
                malware_source = event.malware_info.get('source')
            
            # Convertir suspicious_reasons a JSON string si existe
            suspicious_reasons_json = None
            if hasattr(event, 'suspicious_reasons') and event.suspicious_reasons:
                suspicious_reasons_json = json.dumps(event.suspicious_reasons)
            
            # Preparar valores con los NUEVOS campos
            values = (
                event.timestamp, 
                event.pid, 
                event.ppid, 
                event.comm, 
                event.event_type, 
                event.path, 
                event.flags, 
                event.flags_decoded,
                alert_level, 
                alert_message, 
                event.file_hash, 
                malware_family, 
                malware_source, 
                event.scan_method,
                event.uid, 
                event.gid, 
                event.bytes_written,
                # NUEVOS CAMPOS
                getattr(event, 'operation', None),  # Para UNLINK
                getattr(event, 'mode', None),  # Para CHMOD
                getattr(event, 'mode_decoded', None),  # Permisos decodificados
                1 if getattr(event, 'suspicious_deletion', False) else 0,  # Boolean as int
                1 if getattr(event, 'suspicious_chmod', False) else 0,  # Boolean as int
                suspicious_reasons_json,  # JSON array de razones
                # NUEVOS CAMPOS
                getattr(event, 'ptrace_request', None),
                getattr(event, 'ptrace_decoded', None),
                getattr(event, 'mmap_prot', None),
                getattr(event, 'mmap_decoded', None),
                getattr(event, 'new_owner', None),
                1 if getattr(event, 'suspicious_connect', False) else 0,
                1 if getattr(event, 'suspicious_ptrace', False) else 0,
                1 if getattr(event, 'suspicious_mmap', False) else 0,
                1 if getattr(event, 'suspicious_chown', False) else 0
            )
            
            # SQL con TODOS los campos
            self.db_conn.execute("""
                INSERT INTO events(
                    timestamp, pid, ppid, comm, event_type, path, 
                    flags, flags_decoded, alert_level, alert_message,
                    file_hash, malware_family, malware_source, scan_method,
                    uid, gid, bytes_written,
                    operation, mode, mode_decoded, 
                    suspicious_deletion, suspicious_chmod, suspicious_reasons,
                    ptrace_request, ptrace_decoded, mmap_prot, mmap_decoded,
                    new_owner, suspicious_connect, suspicious_ptrace,
                    suspicious_mmap, suspicious_chown
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, values)
            
            # Commit cada 50 eventos para performance
            if self.stats["total_events"] % 50 == 0:
                self.db_conn.commit()
                
            # Debug para nuevos tipos de eventos
            if event.event_type in ["UNLINK", "CHMOD"]:
                if self.stats["total_events"] % 100 == 0:
                    print(f"DB: Guardados {self.stats['unlink_events']} UNLINK, {self.stats['chmod_events']} CHMOD", file=sys.stderr)
                    
        except Exception as e:
            print(f"DB Error al guardar evento {event.event_type}: {e}", file=sys.stderr)
            # En caso de error, intentar commit parcial
            try:
                self.db_conn.rollback()
            except:
                pass
        
    def _run_detection_rules_complete(self, event: Event) -> Optional[str]:
        """Reglas de detección COMPLETAS + WRITE CORREGIDO"""
        
        # PRIORIDAD: Check write burst para eventos WRITE
        if event.event_type == "WRITE":
            write_alert = self._check_write_burst(event.pid) #miramos si es 5mb o + de 50 writes 
            if write_alert:
                self.stats["alerts_by_type"]["write_burst"] += 1
                return write_alert
        
        # EXEC procesos que no deberían correr en el sistema
        if self._check_suspicious_process(event):
            self.stats["alerts_by_type"]["suspicious_process"] += 1
            return f"Proceso sospechoso: {event.comm} (PID {event.pid})"
        
        # OPEN rchiovos criticos a los que no se deberia accder
        alert = self._check_critical_files(event)
        if alert:
            self.stats["alerts_by_type"]["critical_file"] += 1
            return alert
            
        alert = self._check_file_burst_antispam(event)
        if alert:
            self.stats["alerts_by_type"]["file_burst"] += 1
            return alert
        
        # AÑADIR DESPUÉS:
        #alert = self._check_directory_scan(event)  # NUEVO
        #if alert:
        #    self.stats["alerts_by_type"]["directory_scan"] += 1
        #    return alert
            
        alert = self._check_exec_burst(event)
        if alert:
            self.stats["alerts_by_type"]["exec_burst"] += 1
            return alert
            
        alert = self._check_suspicious_locations_improved(event)
        if alert:
            self.stats["alerts_by_type"]["suspicious_location"] += 1
            return alert
        
        # NUEVAS DETECCIONES
        alert = self._check_mass_deletion(event)
        if alert:
            self.stats["alerts_by_type"]["mass_deletion"] += 1
            return alert
        
        alert = self._check_privilege_escalation(event)
        if alert:
            self.stats["alerts_by_type"]["privilege_escalation"] += 1
            return alert
        #NUEVO: Detección de chmod burst
        alert = self._check_chmod_burst_by_parent(event)
        if alert:
            self.stats["alerts_by_type"]["chmod_burst"] += 1
            return alert

        # NUEVO: Detección multi-arquitectura
        alert = self._check_multi_arch_files(event)
        if alert:
            self.stats["alerts_by_type"]["multi_arch"] += 1
            return alert
        
        # NUEVAS DETECCIONES
        alert = self._check_network_suspicious(event)
        if alert:
            self.stats["alerts_by_type"]["network_suspicious"] += 1
            return alert
            
        alert = self._check_process_injection(event)
        if alert:
            self.stats["alerts_by_type"]["process_injection"] += 1
            return alert
            
        alert = self._check_memory_execution(event)
        if alert:
            self.stats["alerts_by_type"]["memory_execution"] += 1
            return alert
            
        alert = self._check_ownership_manipulation(event)
        if alert:
            self.stats["alerts_by_type"]["ownership_manipulation"] += 1
            return alert
        
        alert = self._check_persistence_attempt(event)
        if alert:
            self.stats["alerts_by_type"]["persistence"] += 1
            return alert
        
        # DETECCIÓN DE BOTNETS
        alert = self._check_download_execute_chain(event)
        if alert:
            self.stats["alerts_by_type"]["download_execute"] += 1
            return alert

        alert = self._check_rapid_forks(event)
        if alert:
            self.stats["alerts_by_type"]["rapid_fork"] += 1
            return alert

        # NUEVO: Detección específica de botnets
        alert = self._check_mirai_download_pattern(event)
        if alert:
            self.stats["alerts_by_type"]["botnet_pattern"] += 1
            return alert
        

        return None
    
    def _check_download_execute_chain(self, event: Event) -> Optional[str]:
        """Detectar patrón download + chmod +x"""
        if event.event_type == "CHMOD":
            if event.mode and (event.mode & 0o111):  # Permisos de ejecución
                # Verificar si el parent es wget/curl
                if event.ppid in self.process_tree.tree:
                    parent = self.process_tree.tree[event.ppid]
                    if parent.get('exe') in ['wget', 'curl']:
                        alert = self.score_tracker.add_indicator(
                            event.pid, 'download_execute_chain', event.timestamp, verbose=self.verbose_scoring
                        )
                        if alert:
                            return alert
        return None

    def _check_rapid_forks(self, event: Event) -> Optional[str]:
        """Detectar fork bombing"""
        if event.event_type == "EXEC":
            self.fork_patterns[event.ppid].append(event.timestamp)
            
            # Limpiar ventana de 5 segundos
            recent = [t for t in self.fork_patterns[event.ppid] 
                    if event.timestamp - t < 5]
            self.fork_patterns[event.ppid] = recent
            
            if len(recent) >= 5:  # 5+ forks en 5s
                parent = self.process_tree.tree.get(event.ppid, {})
                # Ignorar compiladores conocidos
                if parent.get('exe') not in ['make', 'gcc', 'g++', 'cargo', 'npm', 'python']:
                    alert = self.score_tracker.add_indicator(
                        event.ppid, 'rapid_fork', event.timestamp, verbose=self.verbose_scoring
                    )
                    if alert:
                        return alert
        return None

    
    
     
        
    # MANTENER TODAS LAS FUNCIONES EXISTENTES SIN CAMBIOS
    def _check_suspicious_process(self, event: Event) -> bool:
        """Detección de procesos sospechosos"""
        if event.event_type != "EXEC":
            return False
            
        comm_lower = event.comm.lower()
        return comm_lower in self.config["suspicious_processes"]
    
    def _check_critical_files(self, event: Event) -> Optional[str]:
        """Detección de acceso a archivos críticos"""
        if event.event_type != "OPEN" or not event.path:
            return None
            
        if event.path in self.config["critical_files"]:
            if event.flags and (event.flags & 0x1 or event.flags & 0x2):  # WRITE flags
                return f"CRITICO: Modificación archivo sistema: {event.path}"
            else:
                return f"Acceso archivo crítico: {event.path}"
                
        return None
    
    def _check_file_burst_antispam(self, event: Event) -> Optional[str]:
        """Detección de archivos .locked con SCORING CORRECTO"""
        if event.event_type != "OPEN":
            return None
            
        if not event.flags or not (event.flags & 0x40):  # O_CREAT
            return None
        
        # Verificar extensión ransomware
        if not (event.path and any(event.path.endswith(ext) for ext in self.config["suspicious_extensions"])):
            return None
        
        current_time = event.timestamp
        pid = event.pid
        
        # Actualizar ventana para contar burst
        window = self.file_windows[pid]
        while window and current_time - window[0] > 10:  # Ventana de 10s según tu doc
            window.popleft()
        window.append(current_time)
        
        # Si hay >5 archivos .locked en 10s → +3 puntos
        if len(window) >= self.config["file_burst_threshold"]:
            alert = self.score_tracker.add_indicator(pid, 'locked_files_burst', current_time, verbose=self.verbose_scoring)
            if alert:
                return alert  # Ya incluye MITRE desde add_indicator
        
        return None
    
    def _check_exec_burst(self, event: Event) -> Optional[str]:
        """Detección de ráfagas de ejecución"""
        if event.event_type != "EXEC":
            return None
            
        current_time = event.timestamp
        pid = event.pid
        
        window = self.exec_windows[pid]
        while window and current_time - window[0] > self.config["time_window"]:
            window.popleft()
            
        window.append(current_time)
        
        if len(window) >= self.config["exec_burst_threshold"]:
            return f"Ráfaga ejecuciones: {len(window)} procesos en {self.config['time_window']}s (PID {pid})"
            
        return None
    
    def _check_suspicious_locations_improved(self, event: Event) -> Optional[str]:
        """Detección /tmp con SCORING CORRECTO"""
        if event.event_type not in ["OPEN", "EXEC"]:
            return None
            
        if not event.path:
            return None
            
        # Verificar si es /tmp o similar
        for suspicious_path in self.config["suspicious_paths"]:
            if event.path.startswith(suspicious_path):
                # Ejecución desde /tmp → +2 puntos
                if event.event_type == "EXEC":
                    alert = self.score_tracker.add_indicator(
                        event.pid, 'tmp_execution', event.timestamp, verbose=self.verbose_scoring
                    )
                    if alert:
                        return alert
                
                # O_TRUNC → +1 punto
                if event.flags and event.flags & 0x200:
                    alert = self.score_tracker.add_indicator(
                        event.pid, 'o_trunc', event.timestamp, verbose=self.verbose_scoring
                    )
                    if alert:
                        return alert
                        
        return None
    

    def _check_mass_deletion(self, event: Event) -> Optional[str]:
        """
        Detectar borrado masivo de archivos (ransomware pattern)
        Basado en paper: "Unveiling the Landscape of Ransomware" (2023)
        """
        if event.event_type != "UNLINK":
            return None
            
        current_time = event.timestamp
        pid = event.pid
        
        # Anti-spam: ya alertado?
        if pid in self.mass_deletion_alerted:
            return None
        
        #mantener esto?
        if current_time - self.deletion_patterns['last_reset'] > self.config["deletion_time_window"] * 2:  # e.g., doble ventana
            self.deletion_patterns['user_files'].clear()
            self.deletion_patterns['last_reset'] = current_time

        # Actualizar ventana temporal
        window = self.deletion_windows[pid]
        while window and current_time - window[0] > self.config["deletion_time_window"]:
            window.popleft()
        
        # Añadir evento actual
        window.append(current_time)
        
        # Análisis de archivos críticos borrados
        critical_count = 0
        if event.path:
            # Verificar extensión crítica
            for ext in self.config["critical_extensions"]:
                if event.path.endswith(ext):
                    critical_count = 1
                    self.deletion_patterns['user_files'][pid] += 1
                    break
        
        # DETECCIÓN 1: Ráfaga de borrados
        if len(window) >= 5:  # >5 en 10s según tu documento
            alert = self.score_tracker.add_indicator(pid, 'unlink_burst', current_time, verbose=self.verbose_scoring)
            if alert:
                self.mass_deletion_alerted.add(pid)
                self.stats["mass_deletions_detected"] += 1
                return alert
        
        # DETECCIÓN 2: Borrado de archivos críticos
        user_files_deleted = self.deletion_patterns['user_files'][pid]
        if user_files_deleted >= self.config["critical_deletion_threshold"]:
            self.mass_deletion_alerted.add(pid)
            self.stats["ransomware_deletion_patterns"] += 1
            return f"PATRÓN RANSOMWARE: {user_files_deleted} archivos de usuario borrados (PID {pid}) [MITRE: T1485, T1486]"
        
        return None

    def _check_directory_scan(self, event: Event) -> Optional[str]:
        """
        Detectar escaneo masivo del filesystem (pre-cifrado)
        El ransomware escanea TODO antes de cifrar
        """
        if event.event_type != "OPEN":
            return None
        
        current_time = event.timestamp
        pid = event.pid
        
        # Actualizar ventana
        window = self.scan_windows[pid]
        while window and current_time - window[0] > 10:  # Ventana 10s
            window.popleft()
        window.append(current_time)
        
        # Si >100 OPEN en 10s = escaneo masivo
        if len(window) >= 100:
            alert = self.score_tracker.add_indicator(
                pid, 'directory_scan', current_time, verbose=self.verbose_scoring
            )
            if alert:
                self.scan_windows[pid].clear()
                return alert
        
        # Detectar escaneo de directorios del sistema
        if event.path and len(window) >= 50:
            if any(sys_dir in event.path for sys_dir in ['/proc/', '/sys/', '/dev/']):
                # Contar cuántos son de sistema
                system_count = sum(1 for _ in range(min(50, len(window))))
                if system_count > 30:
                    alert = self.score_tracker.add_indicator(
                        pid, 'recursive_scan', current_time, verbose=self.verbose_scoring
                    )
                    if alert:
                        return alert
        
        return None

    def _check_privilege_escalation(self, event: Event) -> Optional[str]:
        """
        Detectar cambios de permisos sospechosos (privilege escalation)
        Basado en MITRE ATT&CK T1548 - Abuse Elevation Control Mechanism
        """
        if event.event_type != "CHMOD":
            return None
        
        pid = event.pid
        
        # Anti-spam
        if pid in self.privilege_escalation_alerted:
            return None
        
        # Analizar permisos
        if not hasattr(event, 'mode') or event.mode is None:
            return None
            
        mode = event.mode
        suspicious_perms = []
        
        # Verificar cada permiso peligroso
        for dangerous_mode, description in self.config["dangerous_permissions"].items():
            if dangerous_mode == 0o777 or dangerous_mode == 0o666:
                # Verificar permisos exactos
                if (mode & 0o777) == dangerous_mode:
                    suspicious_perms.append(description)
            else:
                # Verificar bits especiales
                if mode & dangerous_mode:
                    suspicious_perms.append(description)
        
        if not suspicious_perms:
            return None
        
        # Actualizar ventana temporal
        current_time = event.timestamp
        window = self.chmod_windows[pid]
        
        while window and current_time - window[0] > self.config["chmod_time_window"]:
            window.popleft()
        
        window.append(current_time)
        
        # DETECCIÓN: Múltiples cambios sospechosos
        if "SETUID" in suspicious_perms or "SETGID" in suspicious_perms:
            # SETUID/SETGID → +2 puntos
            alert = self.score_tracker.add_indicator(pid, 'setuid_chmod', current_time, verbose=self.verbose_scoring)
        else:
            # chmod regular → +1 punto
            alert = self.score_tracker.add_indicator(pid, 'chmod_regular', current_time, verbose=self.verbose_scoring)

        if alert:
            self.privilege_escalation_alerted.add(pid)
            self.stats["privilege_escalations_detected"] += 1
            return alert
        
        # Alerta individual para SETUID/SETGID
        if "SETUID" in suspicious_perms or "SETGID" in suspicious_perms:
            if event.path and any(critical in event.path for critical in ["/tmp", "/dev/shm", "/var/tmp"]):
                return f"ALERTA CRÍTICA: {suspicious_perms[0]} en ubicación sospechosa: {event.path} [MITRE: T1548.001]"
        
        return None

    def _check_chmod_burst_by_parent(self, event: Event) -> Optional[str]:
        """Detectar múltiples chmod del mismo proceso PADRE"""
        
        if event.event_type != "CHMOD":
            return None
        
        ppid = event.ppid
        current_time = event.timestamp
        
        window = self.parent_chmod_windows[ppid]
        
        # Limpiar ventana de 10 segundos
        while window and current_time - window[0] > 10:
            window.popleft()
        
        window.append(current_time)
        
        # Si el PADRE genera 5+ chmod en 10s = burst
        if len(window) >= 5:  # 5 chmod para ser más sensible
            alert = self.score_tracker.add_indicator(
                ppid, 'chmod_burst', current_time, verbose=self.verbose_scoring
            )
            if alert:
                self.parent_chmod_windows[ppid].clear()
                return alert
        
        return None
    """cuidado,check_multi_arch_files() busca archivos creados localmente, pero el Mirai falló al descargar (Network unreachable). 
    Solo se detectaría si los archivos se hubieran descargado exitosamente. """   
    
    def _check_multi_arch_files(self, event: Event) -> Optional[str]:
        """Detectar creación de archivos con mismo nombre y diferentes arquitecturas"""
        
        # Solo archivos creados/abiertos para escritura
        if event.event_type != "OPEN":
            return None
        if not event.flags or not (event.flags & (0x40 | 0x1 | 0x2)):  # CREAT, WRONLY, RDWR
            return None
        if not event.path:
            return None
        
        # Buscar patrón nombre.arquitectura
        import re
        match = re.match(r'^(.+)\.(x86|i[3-6]86|amd64|mips|mipsel|mpsl|arm[4-7]?|armv[67]l|ppc|powerpc|sh4|sparc|m68k|arc)$', 
                        event.path.lower().split('/')[-1])  # Solo el nombre del archivo
        
        if not match:
            return None
        
        base_name = match.group(1)
        arch = match.group(2)
        ppid = event.ppid
        
        # Registrar arquitectura para este base_name
        self.arch_files_by_base[ppid][base_name].add(arch)
        
        # Si detectamos 3+ arquitecturas del MISMO archivo = BOTNET
        if len(self.arch_files_by_base[ppid][base_name]) >= 3:
            alert = self.score_tracker.add_indicator(
                ppid, 'multi_arch_payload', event.timestamp, verbose=self.verbose_scoring
            )
            if alert:
                del self.arch_files_by_base[ppid][base_name]  # Limpiar para no re-alertar
                return alert
        
        return None
    
    def _check_mirai_download_pattern(self, event: Event) -> Optional[str]:
        """
        Detectar patrón ESPECÍFICO de Mirai: wget/curl de múltiples arquitecturas
        consecutivas con mismo prefijo
        """
        if event.event_type != "EXEC":
            return None
            
        # Solo wget y curl
        if event.comm not in ['wget', 'curl']:
            return None
            
        # Buscar patrón de arquitectura en la línea de comando
        if not event.path:
            return None
        
        # Extraer el comando completo si es posible
        try:
            with open(f"/proc/{event.pid}/cmdline", 'r') as f:
                cmdline = f.read().replace('\0', ' ')
        except:
            return None
        
        # Patrón Mirai: descarga archivos con sufijos de arquitectura
        import re
        arch_pattern = r'fetch\.(x86|i[3-6]86|amd64|mips|mipsel|mpsl|arm[4-7]?|armv[67]l|ppc|powerpc|sh4|sparc|m68k|arc)'
        match = re.search(arch_pattern, cmdline.lower())
        
        if not match:
            return None
        
        current_time = event.timestamp
        ppid = event.ppid
        arch = match.group(1)
        
        # Tracking por proceso padre (el script malicioso)
        tracker = self.download_attempts[ppid]
        
        # Inicializar o resetear si pasó mucho tiempo
        if current_time - tracker['first_seen'] > 30:  # Ventana de 30 segundos
            tracker['architectures'].clear()
            tracker['first_seen'] = current_time
            tracker['failed_count'] = 0
            tracker['commands'].clear()
        
        tracker['architectures'].add(arch)
        tracker['commands'].add(event.comm)
        
        # DETECCIÓN: 3+ arquitecturas diferentes en 30s = Mirai/Botnet
        if len(tracker['architectures']) >= 3:
            alert = self.score_tracker.add_indicator(
                ppid, 'botnet_multiarch_download', current_time, verbose=self.verbose_scoring
            )
            if alert:
                # Limpiar para no re-alertar
                self.download_attempts[ppid]['architectures'].clear()
                return alert
                
        return None

    def _check_network_suspicious(self, event: Event) -> Optional[str]:
        """Detectar conexiones de red sospechosas"""
        if event.event_type != "CONNECT":
            return None
            
        if event.suspicious_connect:
            self.stats["network_alerts"] += 1
            return f"CONEXIÓN SOSPECHOSA: Proceso no-root {event.comm} (PID {event.pid}) [MITRE: T1071]"
        
        return None
    
    def _check_process_injection(self, event: Event) -> Optional[str]:
        """Detectar inyección con scoring"""
        if event.event_type != "PTRACE":
            return None
        
        # ptrace → +1 punto
        alert = self.score_tracker.add_indicator(
            event.pid, 'ptrace_use', event.timestamp, verbose=self.verbose_scoring
        )
        if alert:
            self.stats["injection_alerts"] += 1
            return alert
        return None
    
    def _check_memory_execution(self, event: Event) -> Optional[str]:
        """Detectar ejecución en memoria con scoring"""
        if event.event_type != "MMAP":
            return None
            
        if event.suspicious_mmap:
            # mmap WRITE+EXEC → +1 punto
            alert = self.score_tracker.add_indicator(
                event.pid, 'mmap_exec', event.timestamp, verbose=self.verbose_scoring
            )
            if alert:
                self.stats["memory_alerts"] += 1
                return alert
        return None
    
    def _check_ownership_manipulation(self, event: Event) -> Optional[str]:
        """Detectar manipulación de propietarios"""
        if event.event_type != "CHOWN":
            return None
            
        if event.suspicious_chown:
            self.stats["ownership_alerts"] += 1
            return f"CAMBIO PROPIETARIO SOSPECHOSO: a UID {event.new_owner} por {event.comm} (PID {event.pid}) [MITRE: T1222.002]"
        
        return None
    
    def _check_persistence_attempt(self, event: Event) -> Optional[str]:
        """
        Detectar intentos de establecer persistencia
        MITRE: T1053, T1543, T1546, T1574
        """
        if event.event_type not in ["OPEN", "WRITE", "EXEC"]:
            return None
            
        if not event.path:
            return None
            
        pid = event.pid
        current_time = event.timestamp
        
        # Anti-spam
        if pid in self.persistence_alerted:
            return None
        
        # Verificar si es archivo de persistencia
        persistence_type = None
        mitre_technique = None
        
        # Crontab
        if any(cron in event.path for cron in ["/etc/crontab", "/cron.d/", "/var/spool/cron/"]):
            if event.event_type == "OPEN" and event.flags and (event.flags & 0x1 or event.flags & 0x2):  # WRITE
                persistence_type = "persistence_cron"
                mitre_technique = "T1053.003"
                self.stats["persistence_cron"] += 1
                
        # Systemd
        elif any(systemd in event.path for systemd in ["/systemd/system/", "/init.d/"]):
            if event.path.endswith(".service") or event.path.endswith(".timer"):
                persistence_type = "persistence_systemd"
                mitre_technique = "T1543.002"
                self.stats["persistence_systemd"] += 1
                
        # Bashrc/Profile
        elif any(profile in event.path for profile in [".bashrc", ".profile", ".bash_profile"]):
            if event.event_type == "OPEN" and event.flags and (event.flags & 0x1 or event.flags & 0x2):
                persistence_type = "persistence_bashrc"
                mitre_technique = "T1546.004"
                self.stats["persistence_bashrc"] += 1
                
        # LD_PRELOAD
        elif "ld.so.preload" in event.path or "ld.so.conf" in event.path:
            persistence_type = "persistence_ldpreload"
            mitre_technique = "T1574.006"
            self.stats["persistence_ldpreload"] += 1
        
        if persistence_type:
            self.stats["persistence_attempts"] += 1
            
            # Añadir al scoring
            alert = self.score_tracker.add_indicator(pid, persistence_type, current_time, verbose=self.verbose_scoring)
            if alert:
                self.persistence_alerted.add(pid)
                return alert
            
            # Alerta directa para LD_PRELOAD (muy sospechoso)
            if persistence_type == "persistence_ldpreload":
                self.persistence_alerted.add(pid)
                return f"⚠️ PERSISTENCIA CRÍTICA: LD_PRELOAD hijacking por {event.comm} (PID {pid}) [MITRE: {mitre_technique}]"
            
            # Alerta informativa para otros tipos
            if event.uid != 0:  # Usuario no-root modificando archivos de sistema
                return f"PERSISTENCIA SOSPECHOSA: {event.comm} modificando {event.path} [MITRE: {mitre_technique}]"
        
        return None
    
    def _execute_response(self, pid: int, score: int, comm: str, reason: str) -> bool:
        """
        Ejecutar respuesta según modo configurado y score
        Retorna True si se ejecutó alguna acción
        """
        # CASO ESPECIAL: Si el PID es 1 y viene de detección familiar
        if pid == 1 and "FAMILIAR" in reason:
            print(f"RESPONSE: Familia huérfana detectada (parent PID 1)", file=sys.stderr)
            # Extraer PIDs de la familia del mensaje de alerta
            import re
            match = re.search(r'\((\d+) procesos', reason)
            if match and self.score_tracker.family_scores.get('family_1'):
                family = self.score_tracker.family_scores['family_1']
                killed_count = 0
                for child_pid in family['pids']:
                    if child_pid != os.getpid() and child_pid != os.getppid():
                        try:
                            # Verificar que el proceso existe antes de matar
                            if os.path.exists(f"/proc/{child_pid}"):
                                os.kill(child_pid, 9)
                                killed_count += 1
                                print(f"RESPONSE: Matado hijo huérfano PID {child_pid}", file=sys.stderr)
                        except Exception as e:
                            print(f"RESPONSE: Error matando PID {child_pid}: {e}", file=sys.stderr)
                
                if killed_count > 0:
                    self.stats["response_kills"] += killed_count
                    print(f"RESPONSE: {killed_count} procesos huérfanos eliminados", file=sys.stderr)
                    return True
            return False
        
        # Protección contra PID <= 1 (pero ya manejamos PID 1 arriba)
        if pid <= 0:
            print(f"RESPONSE: Ignorando PID inválido {pid}", file=sys.stderr)
            return False
            
        # Revisar si fue detenido de emergencia
        if pid in self.emergency_stopped:
            family_score = self.process_tree.get_family_score(pid)
            if family_score < 6:
                # Falsa alarma, reanudar
                try:
                    os.kill(pid, 18)  # SIGCONT
                    self.emergency_stopped.discard(pid)
                    print(f"✓ Reanudando {comm} (PID {pid}) - Score familiar: {family_score}", file=sys.stderr)
                except:
                    pass
                return False

        if self.response_mode == 'monitor':
            return False
            
        # No responder a procesos del sistema o al script de testing
        protected_procs = ['systemd', 'init', 'kernel', 'bash', 'sh', 'testing_sistema', 'python', 'python3']
        if comm in protected_procs or 'testing' in comm.lower():
            print(f"RESPONSE: Ignorando proceso protegido {comm} (PID {pid})", file=sys.stderr)
            return False
            
        # No actuar sobre el PID del pipeline principal
        if pid == os.getppid():  # Parent PID
            print(f"RESPONSE: Ignorando proceso padre {comm} (PID {pid})", file=sys.stderr)
            return False
            
        # Verificar si ya fue procesado
        if pid in self.killed_pids:
            return False
            
        action_taken = False
        
        # KILL MODE: Terminar si score >= umbral kill
        print(f"DEBUG RESPONSE: mode={self.response_mode}, score={score}, threshold={self.response_thresholds['kill']}", file=sys.stderr)
        if self.response_mode == 'kill' and score >= self.response_thresholds['kill']:
            if self._kill_process_family(pid, comm, reason):
                self.killed_pids.add(pid)
                self.stats["response_kills"] += 1
                action_taken = True
                print(f"🔴 RESPONSE KILL: Proceso {comm} (PID {pid}) terminado - Score: {score}", file=sys.stderr)
                
        # BLOCK MODE: Suspender si score >= umbral block
        elif self.response_mode in ['block', 'kill'] and score >= self.response_thresholds['block']:
            if pid not in self.blocked_pids:
                if self._block_process(pid, comm, reason):
                    self.blocked_pids.add(pid)
                    self.stats["response_blocks"] += 1
                    action_taken = True
                    print(f"🟡 RESPONSE BLOCK: Proceso {comm} (PID {pid}) suspendido - Score: {score}", file=sys.stderr)
                    
        return action_taken
    
    def _kill_process_family(self, pid: int, comm: str, reason: str) -> bool:
        """Matar proceso Y todos sus hijos"""
        try:
            # Obtener lista de PIDs: padre + hijos
            import subprocess
            result = subprocess.run(
                f"pgrep -P {pid}", 
                shell=True, 
                capture_output=True, 
                text=True
            )
            
            child_pids = []
            if result.stdout:
                child_pids = [int(p) for p in result.stdout.strip().split('\n') if p]
            
            all_pids = [pid] + child_pids
            killed_count = 0
            
            # Matar todos: hijos primero, padre después
            for target_pid in reversed(all_pids):
                try:
                    # Usar sudo kill en lugar de os.kill
                    kill_result = subprocess.run(
                        ['sudo', 'kill', '-9', str(target_pid)],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    if kill_result.returncode == 0:
                        killed_count += 1
                        print(f"RESPONSE: Matado PID {target_pid}", file=sys.stderr)
                except Exception as e:
                    print(f"RESPONSE: Error matando PID {target_pid}: {e}", file=sys.stderr)
                    
            if killed_count > 0:
                print(f"RESPONSE: Familia de {comm} eliminada: {killed_count} procesos", file=sys.stderr)
                return True
                
        except Exception as e:
            print(f"RESPONSE ERROR killing family: {e}", file=sys.stderr)
        
        return self._kill_process(pid, comm, reason)  # Fallback

    def _kill_process(self, pid: int, comm: str, reason: str) -> bool:
        """Terminar proceso con SIGKILL usando sudo"""
        try:
            if not os.path.exists(f"/proc/{pid}"):
                return False
            
            # Usar sudo kill en lugar de os.kill
            import subprocess
            result = subprocess.run(
                ['sudo', 'kill', '-9', str(pid)], 
                capture_output=True, 
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                print(f"RESPONSE: Proceso {pid} ({comm}) terminado: {reason}", file=sys.stderr)
                return True
            else:
                print(f"RESPONSE ERROR: {result.stderr}", file=sys.stderr)
                return False
                
        except Exception as e:
            self.stats["response_failures"] += 1
            print(f"RESPONSE ERROR: {e}", file=sys.stderr)
            return False
    
    def _block_process(self, pid: int, comm: str, reason: str) -> bool:
        """Suspender proceso con SIGSTOP"""
        try:
            if not os.path.exists(f"/proc/{pid}"):
                return False
                
            os.kill(pid, 19)  # SIGSTOP
            print(f"RESPONSE: Proceso {pid} ({comm}) suspendido: {reason}", file=sys.stderr)
            return True
            
        except (ProcessLookupError, FileNotFoundError):
            return False
        except PermissionError:
            self.stats["response_failures"] += 1
            print(f"RESPONSE ERROR: Sin permisos para suspender {pid}", file=sys.stderr)
            return False
        except Exception as e:
            self.stats["response_failures"] += 1
            print(f"RESPONSE ERROR: {e}", file=sys.stderr)
            return False
    
    def _unblock_process(self, pid: int) -> bool:
        """Reanudar proceso con SIGCONT"""
        try:
            os.kill(pid, 18)  # SIGCONT
            self.blocked_pids.discard(pid)
            return True
        except:
            return False
        
    def print_stats(self):
        """Mostrar estadísticas en tiempo real con DEBUG WRITE"""
        try:
            uptime = time.time() - self.stats["start_time"]
            rate = self.stats["total_events"] / uptime if uptime > 0 else 0
            total_alerts = sum(self.stats["alerts_by_type"].values())
            active_write_pids = len(self.write_counters['ops'])
            
            print(f"Eventos: {self.stats['total_events']} | "
                f"Alertas: {total_alerts} | "
                f"WRITE: {self.stats['write_events']}({self.stats['write_alerts']} alertas) | "
                f"PIDs activos: {active_write_pids} | "
                f"Rate: {rate:.1f}/s", file=sys.stderr)
        except Exception:
            pass
    
    def print_final_stats(self):
        """Estadísticas finales COMPLETAS CON DEBUG WRITE"""
        print("\n" + "="*60, file=sys.stderr)
        print("ESTADISTICAS FINALES - DETECTOR WRITE CORREGIDO", file=sys.stderr)
        
        uptime = time.time() - self.stats["start_time"]
        rate = self.stats["total_events"] / uptime if uptime > 0 else 0
        total_alerts = sum(self.stats["alerts_by_type"].values())
        
        print(f"Tiempo ejecución: {uptime:.1f} segundos", file=sys.stderr)
        print(f"Total eventos: {self.stats['total_events']}", file=sys.stderr)
        print(f"Rate promedio: {rate:.1f} eventos/segundo", file=sys.stderr)
        print(f"Rate máximo: {self.stats['max_events_per_second']} eventos/segundo", file=sys.stderr)
        print(f"Total alertas: {total_alerts}", file=sys.stderr)
        
        # Estadísticas WRITE detalladas CON DEBUG
        print(f"\n EVENTOS WRITE CORREGIDOS:", file=sys.stderr)
        print(f"   Eventos WRITE: {self.stats['write_events']}", file=sys.stderr)
        print(f"   Bytes escritos totales: {self.stats['total_bytes_written']:,}", file=sys.stderr)
        print(f"   Alertas por escritura: {self.stats['write_alerts']}", file=sys.stderr)
        print(f"   Procesos únicos con WRITE: {len(self.stats['write_processes'])}", file=sys.stderr)
        print(f"   Checks de burst realizados: {self.stats['write_burst_checks']}", file=sys.stderr)
        print(f"   Resets de contadores: {self.stats['write_resets']}", file=sys.stderr)
        
        # Configuración actual
        print(f"\n  CONFIGURACIÓN WRITE:", file=sys.stderr)
        print(f"   Umbral operaciones: {self.config['write_ops_threshold']}", file=sys.stderr)
        print(f"   Umbral bytes: {self.config['write_bytes_threshold']:,} ({self.config['write_bytes_threshold']/1024/1024:.0f}MB)", file=sys.stderr)
        print(f"   Reset interval: {self.config['write_reset_interval']}s", file=sys.stderr)
        print(f"   Alert cooldown: {self.config['write_alert_cooldown']}s", file=sys.stderr)
        
        # Estado de contadores activos
        active_pids = len(self.write_counters['ops'])
        if active_pids > 0:
            print(f"\n CONTADORES ACTIVOS AL FINAL:", file=sys.stderr)
            print(f"   PIDs activos WRITE: {active_pids}", file=sys.stderr)
            # Top PIDs más activos
            sorted_pids = sorted(self.write_counters['ops'].items(), key=lambda x: x[1], reverse=True)[:5]
            for pid, ops in sorted_pids:
                bytes_total = self.write_counters['bytes'][pid]
                print(f"      PID {pid}: {ops} ops, {bytes_total:,} bytes", file=sys.stderr)
        
        # Análisis de eficiencia WRITE
        if self.stats['write_events'] > 0:
            avg_bytes = self.stats['total_bytes_written'] / self.stats['write_events']
            alert_rate = (self.stats['write_alerts'] / self.stats['write_events']) * 100
            print(f"\n ANÁLISIS WRITE:", file=sys.stderr)
            print(f"   Promedio bytes/write: {avg_bytes:.1f}", file=sys.stderr)
            print(f"   Tasa de alerta WRITE: {alert_rate:.4f}%", file=sys.stderr)
            
            if self.stats['write_alerts'] == 0 and self.stats['write_events'] > 100:
                print(f"    SIN ALERTAS: Umbrales muy altos o anti-spam muy agresivo", file=sys.stderr)
            elif self.stats['write_alerts'] > 0:
                print(f"   ALERTAS GENERADAS: Sistema funcionando", file=sys.stderr)
        
        # Resto de estadísticas 
        print(f"\n OTRAS MÉTRICAS:", file=sys.stderr)
        print(f"   Hash scans realizados: {self.stats['hash_scans']}", file=sys.stderr)
        print(f"   Malware detectado: {self.stats['malware_detected']}", file=sys.stderr)
        print(f"   Archivos limpios: {self.stats['clean_files']}", file=sys.stderr)
        print(f"   Errores: {self.stats['errors']}", file=sys.stderr)
        
        if self.stats["alerts_by_type"]:
            print("\n Alertas por tipo:", file=sys.stderr)
            for alert_type, count in self.stats["alerts_by_type"].items():
                print(f"   {alert_type}: {count}", file=sys.stderr)
                
        # Diagnóstico automático mejorado
        print(f"\n DIAGNÓSTICO AUTOMÁTICO:", file=sys.stderr)
        if self.stats['write_alerts'] > 50:
            print(f"     Muchas alertas WRITE ({self.stats['write_alerts']})", file=sys.stderr)
            print(f"     Considera subir umbrales", file=sys.stderr)
        elif self.stats['write_alerts'] == 0 and self.stats['write_events'] > 100:
            print(f"     Sin alertas WRITE con {self.stats['write_events']} eventos", file=sys.stderr)
            if self.stats['write_burst_checks'] == 0:
                print(f"   PROBLEMA: _check_write_burst nunca se ejecutó", file=sys.stderr)
            elif self.stats['write_burst_checks'] < self.stats['write_events'] / 10:
                print(f"     Pocos checks de burst ({self.stats['write_burst_checks']})", file=sys.stderr)
            else:
                print(f"   Umbrales conservadores funcionando ({self.stats['write_burst_checks']} checks)", file=sys.stderr)
        elif self.stats['write_alerts'] > 0:
            print(f"    Alertas WRITE controladas ({self.stats['write_alerts']})", file=sys.stderr)
        else:
            print(f"    Pocos eventos WRITE para evaluar ({self.stats['write_events']})", file=sys.stderr)
        
        
        print(f"\n NUEVAS SYSCALLS:", file=sys.stderr)
        print(f"   Eventos UNLINK: {self.stats['unlink_events']}", file=sys.stderr)
        print(f"   Eventos CHMOD: {self.stats['chmod_events']}", file=sys.stderr)
        print(f"   Borrados masivos detectados: {self.stats['mass_deletions_detected']}", file=sys.stderr)
        print(f"   Escalaciones de privilegios: {self.stats['privilege_escalations_detected']}", file=sys.stderr)
        print(f"   Patrones ransomware: {self.stats['ransomware_deletion_patterns']}", file=sys.stderr)
        print(f"   Eventos CONNECT: {self.stats['connect_events']}", file=sys.stderr)
        print(f"   Eventos PTRACE: {self.stats['ptrace_events']}", file=sys.stderr)
        print(f"   Eventos MMAP: {self.stats['mmap_events']}", file=sys.stderr)
        print(f"   Eventos CHOWN: {self.stats['chown_events']}", file=sys.stderr)
        print(f"   Alertas de red: {self.stats['network_alerts']}", file=sys.stderr)
        print(f"   Alertas de inyección: {self.stats['injection_alerts']}", file=sys.stderr)
        print(f"   Alertas de memoria: {self.stats['memory_alerts']}", file=sys.stderr)
        print(f"   Alertas de ownership: {self.stats['ownership_alerts']}", file=sys.stderr)
        
        print(f"\n SISTEMA DE SCORING UNIFICADO:", file=sys.stderr)
        print(f"   Umbral configurado: >{self.score_tracker.alert_threshold} puntos", file=sys.stderr)
        print(f"   Ventana temporal: {self.score_tracker.time_window}s", file=sys.stderr)
        print(f"   PIDs que alcanzaron umbral: {len(self.score_tracker.alerted_pids)}", file=sys.stderr)
        print(f"   Familias que alcanzaron umbral: {len(self.score_tracker.alerted_families)}", file=sys.stderr)

        if self.verbose_scoring:
            print(f"   Modo verbose: ACTIVO", file=sys.stderr)
        
        # Estadísticas MITRE ATT&CK
        print(f"\n COBERTURA MITRE ATT&CK:", file=sys.stderr)
        mitre_covered = set()
        for techniques in self.score_tracker.mitre_mapping.values():
            mitre_covered.update(techniques)
        mitre_covered.discard('')  # Quitar vacíos
        
        print(f"   Técnicas MITRE cubiertas: {len(mitre_covered)}", file=sys.stderr)
        print(f"   Técnicas: {', '.join(sorted(mitre_covered))}", file=sys.stderr)
        print(f"   Cobertura táctica:", file=sys.stderr)
        print(f"     - Persistence: T1548", file=sys.stderr)
        print(f"     - Defense Evasion: T1036, T1055", file=sys.stderr)
        print(f"     - Impact: T1485, T1486, T1489", file=sys.stderr)

        print(f"\n DETECCIÓN DE PERSISTENCIA:", file=sys.stderr)
        print(f"   Intentos de persistencia: {self.stats['persistence_attempts']}", file=sys.stderr)
        print(f"   Modificaciones crontab: {self.stats['persistence_cron']}", file=sys.stderr)
        print(f"   Servicios systemd: {self.stats['persistence_systemd']}", file=sys.stderr)
        print(f"   Modificaciones .bashrc: {self.stats['persistence_bashrc']}", file=sys.stderr)
        print(f"   LD_PRELOAD hijacking: {self.stats['persistence_ldpreload']}", file=sys.stderr)
        
        print(f"\n RESPONSE ENGINE:", file=sys.stderr)
        print(f"   Modo configurado: {self.response_mode.upper()}", file=sys.stderr)
        if self.response_mode != 'monitor':
            print(f"   Procesos bloqueados (SIGSTOP): {self.stats['response_blocks']}", file=sys.stderr)
            print(f"   Procesos terminados (SIGKILL): {self.stats['response_kills']}", file=sys.stderr)
            print(f"   Fallos de respuesta: {self.stats['response_failures']}", file=sys.stderr)
            print(f"   Umbrales: Block={self.response_thresholds['block']}, Kill={self.response_thresholds['kill']}", file=sys.stderr)
            if self.blocked_pids:
                print(f"   PIDs bloqueados activos: {list(self.blocked_pids)}", file=sys.stderr)

        print(f"\n🌳 PROCESS TREE:", file=sys.stderr)
        suspicious_families = [(pid, info) for pid, info in self.process_tree.tree.items() 
                              if info['score'] > 0 or len(info.get('connections', [])) > 0]
        if suspicious_families:
            for pid, info in suspicious_families[:5]:  # Top 5
                print(f"   PID {pid} ({info['exe']}): Score={info['score']}", file=sys.stderr)
                if 'connections' in info:
                    for conn in info['connections'][:3]:
                        print(f"      → {conn['ip']}:{conn['port']}", file=sys.stderr)


        print("="*60, file=sys.stderr)
         


def main():
    """Función principal CORREGIDA"""
    detector = ThreatDetectorFixed()
    
    print("EDR Threat Detector WRITE CORREGIDO iniciado", file=sys.stderr)
    print("Mejoras implementadas:", file=sys.stderr)
    print("   • UMBRALES REALISTAS: 50 ops, 20MB", file=sys.stderr)
    print("   • Debug mejorado para WRITE", file=sys.stderr)
    print("   • Anti-spam menos agresivo", file=sys.stderr)
    print("   • Reset cada 60s (menos frecuente)", file=sys.stderr)
    print("   • Esquema DB corregido automáticamente", file=sys.stderr)
    print("   • ERROR SINTAXIS ARREGLADO", file=sys.stderr)
    print("Configuración:", file=sys.stderr)
    print(f"   WRITE umbral: >{detector.config['write_ops_threshold']} ops o >{detector.config['write_bytes_threshold']//1024//1024}MB", file=sys.stderr)
    print(f"   Reset interval: {detector.config['write_reset_interval']}s", file=sys.stderr)
    
    line_count = 0
    
    try:
        for line in sys.stdin:
            if not detector.running:
                break
            #leemos línea a línea de sys.stdin (la tubería desde collector.py, que imprime cada evento como JSON).
            #Cada línea → event = json.loads(line) → detector.analyze_event(event)
            try:
                line = line.strip()
                if not line:
                    continue
                    
                event = json.loads(line)
                alert = detector.analyze_event(event)
                
                if alert:
                    print(f"ALERTA: {alert}", flush=True)
                    sys.stdout.flush()
                
                line_count += 1
                
                # Stats cada 200 eventos (menos spam)
                if line_count % 200 == 0:
                    detector.print_stats()
                    
            except json.JSONDecodeError:
                detector.stats["errors"] += 1
                continue
            except BrokenPipeError:
                break
            except Exception as e:
                detector.stats["errors"] += 1
                print(f"Error procesando evento: {e}", file=sys.stderr)
                continue
    
    except KeyboardInterrupt:
        pass
    except BrokenPipeError:
        pass
    finally:
        detector.running = False
        detector._cleanup_database()
    
    detector.print_final_stats()

if __name__ == "__main__":
    main()
