#!/usr/bin/env python3
"""
hash_detection_detector.py 
Umbrales realistas + debug mejorado + anti-spam 
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

class ThreatDetectorFixed:
    """Detector WRITE CORREGIDO con umbrales realistas"""
    
    def __init__(self):
        self.running = True
        
        # Ventanas de tiempo (existentes)
        self.file_windows = defaultdict(deque)
        self.exec_windows = defaultdict(deque)
        
        # Ventanas para nuevas syscalls
        self.deletion_windows = defaultdict(deque)  # Ventana para UNLINK
        self.chmod_windows = defaultdict(deque)     # Ventana para CHMOD

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
            "systemd", "kworker", "ksoftirqd", "migration", "rcu_gp", "rcu_par_gp"
        }
        
        # ahora sii: Umbrales WRITE REALISTAS para testing
        self.config = {
            "file_burst_threshold": 5,
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
                ".vault", ".crypto", ".secure", ".ransomed"
            }

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
            }
        }
        
        # Estadísticas MEJORADAS con soporte WRITE
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
            "write_resets": 0          # DEBUG: cuántas veces se resetearon contadores
             # Estadísticas para nuevos eventos
            "unlink_events": 0,
            "chmod_events": 0,
            "mass_deletions_detected": 0,
            "privilege_escalations_detected": 0,
            "ransomware_deletion_patterns": 0
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
                # Crear tabla completa con TODAS las columnas incluyendo las nuevas
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
                        suspicious_reasons TEXT
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
                    ("suspicious_reasons", "TEXT")
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
        
        # Umbral de operaciones (REALISTA)
        if ops >= self.config['write_ops_threshold']:
            alert_msg = f"ESCRITURA INTENSIVA: {ops} operaciones, {bytes_total:,} bytes (PID {pid})"
            alert_triggered = True
            print(f"DEBUG: Alerta por OPERACIONES - PID {pid}: {ops} >= {self.config['write_ops_threshold']}", file=sys.stderr)
        
        # Umbral de bytes (REALISTA)
        elif bytes_total >= self.config['write_bytes_threshold']:
            alert_msg = f"ESCRITURA MASIVA: {bytes_total:,} bytes en {ops} operaciones (PID {pid})"
            alert_triggered = True
            print(f"DEBUG: Alerta por BYTES - PID {pid}: {bytes_total:,} >= {self.config['write_bytes_threshold']:,}", file=sys.stderr)
        
        if alert_triggered:
            # Marcar PID como alertado
            self.write_alerted.add(pid)
            self.write_last_alert[pid] = current_time
            self.stats["write_alerts"] += 1
            print(f"DEBUG: ALERTA WRITE GENERADA - PID {pid}, total alertas: {self.stats['write_alerts']}", file=sys.stderr)
            return alert_msg
        
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
                suspicious_reasons_json  # JSON array de razones
            )
            
            # SQL con TODOS los campos
            self.db_conn.execute("""
                INSERT INTO events(
                    timestamp, pid, ppid, comm, event_type, path, 
                    flags, flags_decoded, alert_level, alert_message,
                    file_hash, malware_family, malware_source, scan_method,
                    uid, gid, bytes_written,
                    operation, mode, mode_decoded, 
                    suspicious_deletion, suspicious_chmod, suspicious_reasons
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
        
        alert = self._check_ransomware_pattern_composite(event)
        if alert:
            self.stats["alerts_by_type"]["ransomware_composite"] += 1
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
        """Detección de ráfagas de archivos CON ANTI-SPAM GLOBAL, Solo cuenta si el OPEN tiene 
        O_CREAT y la extensión es sospechosa (.locked, .encrypted, etc.) en una ventana de tiempo"""
        if event.event_type != "OPEN":
            return None
            
        if not event.flags or not (event.flags & 0x40):  # O_CREAT
            return None
        
        # Requerir extensión de ransomware para reducir falsos positivos
        if not (event.path and any(event.path.endswith(ext) for ext in self.config["suspicious_extensions"])):
            return None

        current_time = event.timestamp
        pid = event.pid
        
        # Limpiar ventana
        window = self.file_windows[pid]
        while window and current_time - window[0] > self.config["time_window"]:
            window.popleft()

        #Así, al terminar el bucle, window contiene solo los eventos de los últimos N segundos
        # (N = time_window). Luego comparas len(window) con el umbral (file_burst_threshold) para
        # decidir si hay ráfag    
            
        # Añadir evento
        window.append(current_time)
        
        # Verificar umbral
        if len(window) >= self.config["file_burst_threshold"]:
            # Anti-spam por PID
            if pid not in self.ransomware_alerted:
                # Anti-spam por directorio (cooldown global)
                dirpath = os.path.dirname(event.path) if event.path else "/tmp"
                last_alert = self.ransomware_dir_alerted.get(dirpath, 0)
                
                if current_time - last_alert > self.ransomware_cooldown:
                    self.ransomware_alerted.add(pid)
                    self.ransomware_dir_alerted[dirpath] = current_time
                    return f"RANSOMWARE DETECTADO: {len(window)} archivos creados en {self.config['time_window']}s (PID {pid}, DIR {dirpath})"
                else:
                    self.ransomware_alerted.add(pid)
            
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
        """Detección de ubicaciones sospechosas MEJORADA con scoring"""
        if event.event_type != "OPEN" or not event.path:
            return None
            
        # Verificar ubicación sospechosa
        is_suspicious_location = False
        for suspicious_path in self.config["suspicious_paths"]:
            if event.path.startswith(suspicious_path):
                is_suspicious_location = True
                break
                
        if not is_suspicious_location:
            return None
            
        # Scoring system
        score = 0
        reasons = []
        
        # +2 puntos: Archivo en ubicación sospechosa
        score += 2
        reasons.append("ubicación sospechosa")
        
        # +3 puntos: Flag CREATE
        if event.flags and event.flags & 0x40:  # O_CREAT
            score += 3
            reasons.append("creación de archivo")
            
        # +2 puntos: Extensión sospechosa
        if any(event.path.endswith(ext) for ext in self.config["suspicious_extensions"]):
            score += 2
            reasons.append("extensión de ransomware")
            
        # +1 punto: Flag TRUNC (sobreescritura)
        if event.flags and event.flags & 0x200:  # O_TRUNC
            score += 1
            reasons.append("sobreescritura")
            
        # Alertar solo si score >= 4 y no hemos alertado ya este PID
        if score >= 4:
            pid = event.pid
            if pid not in self.suspicious_location_alerted:
                self.suspicious_location_alerted.add(pid)
                reason_str = ", ".join(reasons)
                return f"Archivo en ubicación sospechosa: {event.path} (Score: {score} - {reason_str})"
            
        # Score bajo: alerta simple
        elif score >= 2:
            return f"Archivo en ubicación sospechosa: {event.path}"
            
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
        if len(window) >= self.config["deletion_burst_threshold"]:
            self.mass_deletion_alerted.add(pid)
            self.stats["mass_deletions_detected"] += 1
            return f"BORRADO MASIVO: {len(window)} archivos eliminados en {self.config['deletion_time_window']}s (PID {pid})"
        
        # DETECCIÓN 2: Borrado de archivos críticos
        user_files_deleted = self.deletion_patterns['user_files'][pid]
        if user_files_deleted >= self.config["critical_deletion_threshold"]:
            self.mass_deletion_alerted.add(pid)
            self.stats["ransomware_deletion_patterns"] += 1
            return f"PATRÓN RANSOMWARE: {user_files_deleted} archivos de usuario borrados (PID {pid})"
        
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
        if len(window) >= self.config["chmod_suspicious_threshold"]:
            self.privilege_escalation_alerted.add(pid)
            self.stats["privilege_escalations_detected"] += 1
            perms_str = ", ".join(suspicious_perms)
            return f"ESCALACIÓN PRIVILEGIOS: {len(window)} cambios sospechosos [{perms_str}] (PID {pid})"
        
        # Alerta individual para SETUID/SETGID
        if "SETUID" in suspicious_perms or "SETGID" in suspicious_perms:
            if event.path and any(critical in event.path for critical in ["/tmp", "/dev/shm", "/var/tmp"]):
                return f"ALERTA CRÍTICA: {suspicious_perms[0]} en ubicación sospechosa: {event.path}"
        
        return None

    def _check_ransomware_pattern_composite(self, event: Event) -> Optional[str]:
        """
        Detección compuesta: CREATE + WRITE + DELETE pattern
        Score-based detection inspirado en ESCAPADe paper
        """
        pid = event.pid
        current_time = event.timestamp
        
        # Calcular score compuesto
        score = 0
        indicators = []
        
        # Score por tipo de evento
        if event.event_type == "UNLINK":
            # Verificar si es archivo de usuario
            if event.path and any(event.path.endswith(ext) for ext in self.config["critical_extensions"]):
                score += 3
                indicators.append("user_file_deletion")
                
        elif event.event_type == "OPEN":
            # Verificar creación con extensión sospechosa
            if event.flags and (event.flags & 0x40):  # O_CREAT
                if event.path and any(event.path.endswith(ext) for ext in self.config["suspicious_extensions"]):
                    score += 4
                    indicators.append("ransomware_extension")
                    
        elif event.event_type == "WRITE":
            # Escritura intensiva
            if event.bytes_written and event.bytes_written > 10*1024*1024:  # >10MB
                score += 2
                indicators.append("large_write")
                
        elif event.event_type == "CHMOD":
            # Cambio a read-only (típico post-cifrado)
            if hasattr(event, 'mode') and event.mode == 0o400:
                score += 2
                indicators.append("readonly_chmod")
        
        # Bonus por co-ocurrencia temporal
        # Verificar eventos recientes del mismo PID
        recent_deletions = len(self.deletion_windows.get(pid, []))
        recent_chmods = len(self.chmod_windows.get(pid, []))
        
        if recent_deletions > 3 and event.event_type in ["OPEN", "WRITE"]:
            score += 2
            indicators.append("deletion_cooccurrence")
            
        if recent_chmods > 2 and event.event_type == "UNLINK":
            score += 1
            indicators.append("chmod_cooccurrence")
        
        # Umbral de detección
        if score >= 7:  # Umbral alto para reducir falsos positivos
            indicators_str = ", ".join(indicators)
            return f"RANSOMWARE COMPUESTO: Score {score} [{indicators_str}] (PID {pid})"
        
        return None    
        
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
    print("Configuración:", file=sys.stderr)
    print(f"   WRITE umbral: >{detector.config['write_ops_threshold']} ops o >{detector.config['write_bytes_threshold']//1024//1024}MB", file=sys.stderr)
    print(f"   Reset interval: {detector.config['write_reset_interval']}s", file=sys.stderr)
    print("-" * 60, file=sys.stderr)
    print(f"\NUEVAS SYSCALLS:", file=sys.stderr)
    print(f"   Eventos UNLINK: {self.stats['unlink_events']}", file=sys.stderr)
    print(f"   Eventos CHMOD: {self.stats['chmod_events']}", file=sys.stderr)
    print(f"   Borrados masivos detectados: {self.stats['mass_deletions_detected']}", file=sys.stderr)
    print(f"   Escalaciones de privilegios: {self.stats['privilege_escalations_detected']}", file=sys.stderr)
    print(f"   Patrones ransomware (deletion): {self.stats['ransomware_deletion_patterns']}", file=sys.stderr)
    
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
                    print(f"ALERTA: {alert}")
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