#!/usr/bin/env python3
"""
hash_detection_collector.py  
LeARN Fase Estática
"""

import os
import hashlib
import csv
import sqlite3
import requests
import time
import zipfile
import io
from typing import Set, Dict, Optional
from pathlib import Path

class MalwareHashDatabase:
    """Base de datos simplificada de hashes de malware"""
    
    def __init__(self, db_path: str = "malware_hashes.db"):
        self.db_path = db_path
        self.hash_cache = set()  # Cache en memoria
        self.init_database()
        
    def init_database(self):
        """Inicializar base de datos"""
        conn = sqlite3.connect(self.db_path)
        
        # Crear tabla
        conn.execute("""
            CREATE TABLE IF NOT EXISTS malware_hashes (
                sha256 TEXT PRIMARY KEY,
                family TEXT,
                source TEXT
            )
        """)
        
        # Crear índice
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON malware_hashes(sha256)")
        
        conn.commit()
        conn.close()
        
        # Cargar cache
        self._load_hashes_to_memory()
        
    def _load_hashes_to_memory(self):
        """Cargar hashes a memoria"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT sha256 FROM malware_hashes")
        self.hash_cache = set(row[0].lower() for row in cursor.fetchall())
        conn.close()
        
        print(f"Loaded {len(self.hash_cache)} malware hashes to memory")
        
    def add_sample_hashes(self):
        """Añadir hashes de ejemplo para testing"""
        sample_hashes = {
            # EICAR test file (real hash)
            '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f': 'EICAR-Test',
            # Algunos hashes de ejemplo (FALSOS para testing)
            'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef': 'TestMalware-1',
            'cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe': 'TestMalware-2',
            'feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface': 'TestMalware-3'
        }
        
        conn = sqlite3.connect(self.db_path)
        
        for sha256, family in sample_hashes.items():
            sha256 = sha256.lower()
            conn.execute("""
                INSERT OR IGNORE INTO malware_hashes 
                (sha256, family, source)
                VALUES (?, ?, ?)
            """, (sha256, family, 'Sample'))
            
        conn.commit()
        conn.close()
        
        # Recargar cache
        self._load_hashes_to_memory()
        print(f"Added {len(sample_hashes)} sample hashes")
        
    def download_real_hashes(self):
        """Descargar hashes reales de MalwareBazaar (CSV DIRECTO)"""
        print("Downloading MalwareBazaar CSV dataset...")
        
        try:
            url = "https://bazaar.abuse.ch/export/csv/recent/"
            
            print(f"Fetching CSV from {url}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            print(f"Downloaded {len(response.text)} characters (CSV file)")
            
            # Procesar CSV directamente
            reader = csv.reader(io.StringIO(response.text))
            
            imported = 0
            conn = sqlite3.connect(self.db_path)
            
            for row_num, row in enumerate(reader):
                # Saltar líneas vacías o de comentarios
                if not row or (len(row) > 0 and row[0].startswith('#')):
                    continue
                    
                try:
                    # Verificar que tenemos suficientes columnas
                    if len(row) < 9:  # Necesitamos al menos 9 columnas
                        continue
                        
                    # Columna 1: SHA256 (limpiar comillas y espacios)
                    sha256_raw = row[1].strip().strip('"').strip()
                    sha256 = sha256_raw.lower()
                    
                    # Debug para las primeras líneas
                    if imported < 5:
                        print(f"Debug row {imported}: SHA256='{sha256}' (len={len(sha256)})")
                        print(f"  Family raw: '{row[8]}'")
                    
                    # Validar SHA256 (64 caracteres hex)
                    if len(sha256) != 64 or not all(c in '0123456789abcdef' for c in sha256):
                        if imported < 10:
                            print(f"Invalid SHA256: '{sha256}' (len={len(sha256)})")
                        continue
                    
                    # Columna 8: Family (limpiar comillas y espacios)
                    family_raw = row[8].strip().strip('"').strip()
                    family = family_raw if family_raw and family_raw != 'n/a' else 'Unknown'
                    
                    # Insertar en base de datos
                    conn.execute("""
                        INSERT OR IGNORE INTO malware_hashes 
                        (sha256, family, source)
                        VALUES (?, ?, ?)
                    """, (sha256, family, 'MalwareBazaar'))
                    
                    imported += 1
                    
                    # Progress update
                    if imported % 1000 == 0:
                        conn.commit()
                        print(f"Imported {imported} hashes...")
                        
                    # Optional: Limit for demo (remove for full download)
                    if imported >= 5000:  # Limit to 5k for demo
                        print("Reached demo limit of 5,000 hashes")
                        break
                        
                except (IndexError, ValueError) as e:
                    if imported < 10:  # Only show first few errors
                        print(f"Error parsing row {row_num}: {e}")
                    continue
                
            conn.commit()
            conn.close()
                    
            print(f"Successfully imported {imported} hashes from MalwareBazaar")
            
            # Recargar cache
            self._load_hashes_to_memory()
            return imported > 0
            
        except Exception as e:
            print(f"Error downloading/processing MalwareBazaar CSV: {e}")
            return False
        
    def is_malicious(self, sha256: str) -> bool:
        """Verificar si un hash es malicioso"""
        return sha256.lower() in self.hash_cache
        
    def get_malware_info(self, sha256: str) -> Optional[Dict]:
        """Obtener información de un hash malicioso"""
        if not self.is_malicious(sha256):
            return None
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("""
            SELECT family, source 
            FROM malware_hashes 
            WHERE sha256 = ?
        """, (sha256.lower(),))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'family': row[0],
                'source': row[1]
            }
        return None

class FileHasher:
    """Calculador de hashes"""
    
    @staticmethod
    def calculate_sha256(file_path: str) -> Optional[str]:
        """Calcular SHA-256 de un archivo"""
        try:
            with open(file_path, 'rb') as f:
                sha256_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
                return sha256_hash.hexdigest()
                
        except (IOError, OSError, PermissionError):
            return None
            
    @staticmethod
    def get_file_info(file_path: str) -> Dict:
        """Información básica del archivo"""
        try:
            stat = os.stat(file_path)
            return {
                'size': stat.st_size,
                'exists': True
            }
        except (IOError, OSError):
            return {'exists': False}

class HashDetectionEngine:
    """Motor de detección por hash"""
    
    def __init__(self):
        self.hash_db = MalwareHashDatabase()
        self.hasher = FileHasher()
        self.stats = {
            'files_scanned': 0,
            'malware_detected': 0,
            'scan_errors': 0
        }
        
    def setup_database(self, download_real: bool = False):
        """Configurar base de datos"""
        print("Setting up malware hash database...")
        
        # Siempre añadir samples para testing
        self.hash_db.add_sample_hashes()
        
        # Opcionalmente descargar hashes reales
        if download_real:
            success = self.hash_db.download_real_hashes()
            if not success:
                print("Failed to download real hashes, using samples only")
        
        print("Hash database setup complete")
        
    def scan_file(self, file_path: str) -> Dict:
        """Escanear un archivo específico"""
        result = {
            'file_path': file_path,
            'scanned': False,
            'malicious': False,
            'hash': None,
            'malware_info': None,
            'error': None
        }
        
        try:
            # Verificar que existe
            file_info = self.hasher.get_file_info(file_path)
            if not file_info['exists']:
                result['error'] = 'File not found'
                return result
                
            # Calcular hash
            file_hash = self.hasher.calculate_sha256(file_path)
            if not file_hash:
                result['error'] = 'Unable to calculate hash'
                self.stats['scan_errors'] += 1
                return result
                
            result['hash'] = file_hash
            result['scanned'] = True
            self.stats['files_scanned'] += 1
            
            # Verificar contra base de datos
            if self.hash_db.is_malicious(file_hash):
                result['malicious'] = True
                result['malware_info'] = self.hash_db.get_malware_info(file_hash)
                self.stats['malware_detected'] += 1
                
        except Exception as e:
            result['error'] = str(e)
            self.stats['scan_errors'] += 1
            
        return result
        
    def scan_process_binary(self, pid: int, comm: str, original_filename: str = None) -> Dict:
        """
        Escanear binario del proceso con estrategia dual REAL:
        1) Recorrer candidatos (/proc/pid/exe y rutas estándar)
           - Retornar de inmediato SOLO si se detecta malware.
        2) Escanear el filename original si no hubo detección previa,
           incluso si ya escaneamos el intérprete.
        """
        possible_paths = [
            f"/proc/{pid}/exe",
            f"/usr/bin/{comm}",
            f"/bin/{comm}",
            f"/usr/local/bin/{comm}",
            f"/sbin/{comm}",
            f"/usr/sbin/{comm}"
        ]
        
        best_clean = None
        for path in possible_paths:
            try:
                cand = path
                if os.path.islink(cand):
                    real_path = os.readlink(cand)
                    if not os.path.isabs(real_path):
                        real_path = os.path.join(os.path.dirname(cand), real_path)
                    cand = real_path
                if os.path.exists(cand):
                    r = self.scan_file(cand)
                    if r.get('scanned'):
                        r['scan_method'] = 'process_binary'
                        if r['malicious']:
                            return r         # ← sólo retorno inmediato si MALICIOSO
                        if best_clean is None:
                            best_clean = r
            except (OSError, IOError):
                continue

        # Intento 2: original_filename aunque ya haya habido scan limpio del intérprete
        if original_filename and os.path.exists(original_filename) and os.path.isfile(original_filename):
            try:
                r2 = self.scan_file(original_filename)
                if r2.get('scanned'):
                    r2['scan_method'] = 'original_file'
                    if r2['malicious']:
                        return r2
                    if best_clean is None:
                        best_clean = r2
            except (OSError, IOError):
                pass

        # Ningún scan efectivo
        return best_clean or {
            'file_path': f'Unknown (PID: {pid}, Command: {comm})',
            'scanned': False,
            'malicious': False,
            'scan_method': 'failed',
            'error': 'Executable path not found'
        }
        
    def get_statistics(self) -> Dict:
        """Estadísticas del motor"""
        return {
            'files_scanned': self.stats['files_scanned'],
            'malware_detected': self.stats['malware_detected'],
            'scan_errors': self.stats['scan_errors'],
            'detection_rate': (
                self.stats['malware_detected'] / max(1, self.stats['files_scanned'])
            ) * 100,
            'hash_database_size': len(self.hash_db.hash_cache)
        }

def test_hash_detection():
    """Test del sistema de hash detection"""
    print("=== TESTING HASH DETECTION ===")
    
    engine = HashDetectionEngine()
    engine.setup_database(download_real=False)
    
    # Test 1: Crear archivo EICAR
    eicar_content = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    test_file = "/tmp/eicar_test.txt"
    
    with open(test_file, 'w') as f:
        f.write(eicar_content)
        
    print("\n1. Testing EICAR detection...")
    result = engine.scan_file(test_file)
    
    print(f"File: {test_file}")
    print(f"Hash: {result['hash']}")
    print(f"Malicious: {result['malicious']}")
    
    if result['malicious']:
        print(f"Malware info: {result['malware_info']}")
    else:
        print("NOT DETECTED - This is expected if EICAR hash changed")
        
    # Test 2: Archivo benigno
    print("\n2. Testing benign file...")
    benign_file = "/tmp/benign_test.txt"
    with open(benign_file, 'w') as f:
        f.write("This is a harmless file")
        
    result = engine.scan_file(benign_file)
    print(f"File: {benign_file}")
    print(f"Hash: {result['hash']}")
    print(f"Malicious: {result['malicious']}")
    
    # Test 3: Proceso inexistente
    print("\n3. Testing process scan...")
    result = engine.scan_process_binary(99999, "nonexistent")
    print(f"Process scan result: {result['error']}")
    
    # Limpiar
    os.remove(test_file)
    os.remove(benign_file)
    
    # Estadísticas
    stats = engine.get_statistics()
    print(f"\n4. Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
        
    print("\n=== HASH DETECTION TEST COMPLETE ===")

def create_test_malware():
    """Crear archivo de prueba con hash conocido"""
    # Crear un archivo que coincida con uno de nuestros hashes de ejemplo
    test_content = "This is test malware content for hash detection"
    test_file = "/tmp/test_malware_sample.txt"
    
    with open(test_file, 'w') as f:
        f.write(test_content)
        
    # Calcular su hash
    hash_val = FileHasher.calculate_sha256(test_file)
    print(f"Created test file: {test_file}")
    print(f"Hash: {hash_val}")
    
    # Añadir a la base de datos como malware
    engine = HashDetectionEngine()
    engine.setup_database()
    
    conn = sqlite3.connect("malware_hashes.db")
    conn.execute("""
        INSERT OR REPLACE INTO malware_hashes 
        (sha256, family, source)
        VALUES (?, ?, ?)
    """, (hash_val.lower(), 'TestMalware-Custom', 'Manual'))
    conn.commit()
    conn.close()
    
    print(f"Added {hash_val} to malware database")
    
    # Test detection
    engine = HashDetectionEngine()
    engine.setup_database()
    
    result = engine.scan_file(test_file)
    print(f"Detection result: {result['malicious']}")
    print(f"Malware info: {result['malware_info']}")
    
    return test_file, hash_val

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "create-test":
        create_test_malware()
    else:
        test_hash_detection()