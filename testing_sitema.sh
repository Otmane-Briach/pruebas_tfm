#!/bin/bash
# test_full_system.sh - Test completo del sistema EDR con TODAS las syscalls expandidas

echo "================================================"
echo "    TEST COMPLETO EDR - TODAS LAS SYSCALLS     "
echo "================================================"
echo

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Directorio de pruebas
TEST_DIR="/tmp/edr_full_test_$(date +%s)"
mkdir -p "$TEST_DIR"

# Función para obtener conteos sin problemas de newlines
get_count() {
    local file="$1"
    local pattern="$2"
    local count=0
    
    if [ -f "$file" ] && [ -s "$file" ]; then
        count=$(grep -c "$pattern" "$file" 2>/dev/null | head -1 | tr -d '\n\r' || echo "0")
        # Verificar que es un número válido
        if ! [[ "$count" =~ ^[0-9]+$ ]]; then
            count=0
        fi
    fi
    echo "$count"
}

# Limpiar
echo "🧹 Limpiando estado previo..."
pkill -f collector 2>/dev/null
pkill -f detector 2>/dev/null
pkill -f nc 2>/dev/null
pkill -f gdb 2>/dev/null
rm -f /tmp/edr_full.log /tmp/edr_alerts.log
rm -f edr_events.db
sleep 2

# Iniciar pipeline completo
echo "🚀 Iniciando pipeline EDR completo..."
echo "   Collector → Detector → Alertas"
echo

# Iniciar collector + detector
sudo python3 collector.py --verbose --no-hash 2>/tmp/edr.err | \
    tee /tmp/edr_full.log | \
    python3 hash_detection_detector.py > /tmp/edr_alerts.log 2>&1 &
PIPELINE_PID=$!

echo "   Pipeline iniciado (PID: $PIPELINE_PID)"
echo "   Esperando inicialización..."

# Esperar que todo esté listo
for i in {1..10}; do
    if grep -q "Monitorizando" /tmp/edr.err 2>/dev/null; then
        echo -e "${GREEN}✓ Sistema EDR activo${NC}"
        break
    fi
    sleep 1
    echo -n "."
done
echo
sleep 3

# =========================================
# TEST 1: DETECCIÓN DE BORRADO MASIVO
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 1: DETECCIÓN DE BORRADO MASIVO${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando borrado de múltiples archivos críticos..."

# Crear archivos críticos
for i in {1..12}; do
    touch "$TEST_DIR/document_$i.pdf"
    touch "$TEST_DIR/photo_$i.jpg"
done
echo "✓ Creados 24 archivos críticos"

# Borrar rápidamente (patrón ransomware)
echo "Borrando archivos rápidamente..."
for file in "$TEST_DIR"/*.pdf "$TEST_DIR"/*.jpg; do
    rm "$file" 2>/dev/null
done
echo "✓ Archivos borrados"

sleep 3

# Verificar detección
echo "Verificando alertas generadas..."
if grep -q "BORRADO MASIVO\|PATRÓN RANSOMWARE" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Borrado masivo detectado${NC}"
    grep "BORRADO MASIVO\|PATRÓN RANSOMWARE" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectó borrado masivo (revisar umbrales)${NC}"
fi

# =========================================
# TEST 2: DETECCIÓN DE ESCALACIÓN DE PRIVILEGIOS
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 2: ESCALACIÓN DE PRIVILEGIOS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Creando binario y aplicando SETUID..."

# Crear script ejecutable
cat > "$TEST_DIR/backdoor.sh" << 'EOF'
#!/bin/bash
echo "Backdoor simulada"
EOF
chmod +x "$TEST_DIR/backdoor.sh"
echo "✓ Script creado"

# Aplicar SETUID (privilege escalation)
chmod u+s "$TEST_DIR/backdoor.sh"
echo "✓ SETUID aplicado"

# Múltiples cambios sospechosos
chmod 777 "$TEST_DIR/backdoor.sh"
chmod g+s "$TEST_DIR/backdoor.sh"
echo "✓ Permisos sospechosos aplicados"

sleep 3

# Verificar detección
echo "Verificando alertas de privilegios..."
if grep -q "ESCALACIÓN PRIVILEGIOS\|SETUID\|ALERTA CRÍTICA" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Escalación de privilegios detectada${NC}"
    grep "ESCALACIÓN\|SETUID\|ALERTA CRÍTICA" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectó escalación de privilegios${NC}"
fi

# =========================================
# TEST 3: DETECCIÓN DE CONEXIONES DE RED
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 3: DETECCIÓN DE CONEXIONES DE RED${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando conexiones de red sospechosas..."

# Test CONNECT - netcat listener y cliente
echo "Iniciando servidor netcat..."
nc -l 8888 > /dev/null 2>&1 &
NC_PID=$!
sleep 1

echo "Conectando como cliente..."
echo "test connection" | timeout 3 nc localhost 8888 &
sleep 2

# Cleanup netcat
kill $NC_PID 2>/dev/null
echo "✓ Conexiones de red simuladas"

sleep 3

# Verificar detección
echo "Verificando alertas de red..."
if grep -q "CONEXIÓN SOSPECHOSA\|NETWORK" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Conexiones sospechosas detectadas${NC}"
    grep "CONEXIÓN\|NETWORK" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectaron conexiones sospechosas${NC}"
fi

# =========================================
# TEST 4: DETECCIÓN DE INYECCIÓN DE PROCESOS
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 4: DETECCIÓN DE INYECCIÓN DE PROCESOS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando inyección via ptrace..."

# Test PTRACE - usar gdb para hacer ptrace
echo "Creando proceso objetivo..."
sleep 300 &
TARGET_PID=$!

echo "Ejecutando ptrace con gdb..."
timeout 5 gdb -p $TARGET_PID -batch -ex "info registers" -ex "detach" > /dev/null 2>&1 &
sleep 3

# Cleanup
kill $TARGET_PID 2>/dev/null
echo "✓ Operaciones ptrace simuladas"

sleep 3

# Verificar detección
echo "Verificando alertas de inyección..."
if grep -q "INYECCIÓN PROCESO\|PTRACE" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Inyección de procesos detectada${NC}"
    grep "INYECCIÓN\|PTRACE" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectó inyección de procesos${NC}"
fi

# =========================================
# TEST 5: DETECCIÓN DE EJECUCIÓN EN MEMORIA
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 5: DETECCIÓN DE EJECUCIÓN EN MEMORIA${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando mapeo de memoria ejecutable..."

# Test MMAP - crear script que use mmap con WRITE+EXEC
cat > "$TEST_DIR/mmap_test.py" << 'EOF'
import mmap
import os
# Crear archivo temporal y mapearlo con permisos WRITE+EXEC
with open('/tmp/test_mmap', 'w+b') as f:
    f.write(b'test' * 1024)
    f.flush()
    # Mapear con WRITE+EXEC (sospechoso)
    mm = mmap.mmap(f.fileno(), 4096, prot=mmap.PROT_WRITE|mmap.PROT_EXEC)
    mm.close()
os.remove('/tmp/test_mmap')
EOF

python3 "$TEST_DIR/mmap_test.py" 2>/dev/null &
sleep 2
echo "✓ Mapeo de memoria ejecutable simulado"

sleep 3

# Verificar detección
echo "Verificando alertas de memoria..."
if grep -q "EJECUCIÓN MEMORIA\|MMAP" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Ejecución en memoria detectada${NC}"
    grep "EJECUCIÓN\|MMAP" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectó ejecución en memoria${NC}"
fi

# =========================================
# TEST 6: DETECCIÓN DE CAMBIO DE PROPIETARIO
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 6: DETECCIÓN DE CAMBIO DE PROPIETARIO${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando cambios de propietario sospechosos..."

# Crear archivo como usuario normal y intentar cambiarlo a root
touch "$TEST_DIR/testfile"
echo "✓ Archivo creado"

# Simular chown (esto normalmente fallaría, pero genera el evento)
chown root "$TEST_DIR/testfile" 2>/dev/null || echo "   (Cambio de owner esperado que falle)"
chown 1000 "$TEST_DIR/testfile" 2>/dev/null
echo "✓ Cambios de propietario simulados"

sleep 3

# Verificar detección
echo "Verificando alertas de ownership..."
if grep -q "CAMBIO PROPIETARIO\|CHOWN" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Cambios de propietario detectados${NC}"
    grep "PROPIETARIO\|CHOWN" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectaron cambios de propietario${NC}"
fi

# =========================================
# TEST 7: PATRÓN RANSOMWARE COMPLETO
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 7: PATRÓN RANSOMWARE COMPLETO${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando: crear → cifrar → borrar → cambiar permisos"

RANSOM_DIR="$TEST_DIR/ransomware"
mkdir -p "$RANSOM_DIR"

# Fase 1: Crear archivos víctima
echo "Fase 1: Creando archivos víctima..."
for i in {1..8}; do
    echo "Important data $i" > "$RANSOM_DIR/file_$i.doc"
done

# Fase 2: Simular cifrado (crear .locked, borrar originales)
echo "Fase 2: Cifrando y borrando originales..."
for file in "$RANSOM_DIR"/*.doc; do
    base=$(basename "$file" .doc)
    # Crear versión "cifrada"
    dd if=/dev/urandom of="$RANSOM_DIR/$base.locked" bs=2K count=1 2>/dev/null
    # Cambiar permisos para evitar modificación
    chmod 400 "$RANSOM_DIR/$base.locked"
    # Borrar original
    rm "$file"
done

echo "✓ Patrón ransomware ejecutado"
sleep 3

# Verificar detección
echo "Verificando detección de ransomware..."
RANSOMWARE_ALERTS=$(get_count "/tmp/edr_alerts.log" "RANSOMWARE")
if [ "$RANSOMWARE_ALERTS" -gt "0" ]; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Ransomware detectado ($RANSOMWARE_ALERTS alertas)${NC}"
    grep "RANSOMWARE" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectó patrón ransomware${NC}"
fi

# =========================================
# ANÁLISIS DE RESULTADOS
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}ANÁLISIS DE RESULTADOS - TODAS LAS SYSCALLS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Contar eventos capturados para TODAS las syscalls
TOTAL_EVENTS=0
if [ -f "/tmp/edr_full.log" ]; then
    TOTAL_EVENTS=$(wc -l < /tmp/edr_full.log 2>/dev/null | tr -d '\n\r' || echo "0")
    if ! [[ "$TOTAL_EVENTS" =~ ^[0-9]+$ ]]; then
        TOTAL_EVENTS=0
    fi
fi

# Contar cada tipo de syscall
EXEC_COUNT=$(get_count "/tmp/edr_full.log" '"type":"EXEC"')
OPEN_COUNT=$(get_count "/tmp/edr_full.log" '"type":"OPEN"')
WRITE_COUNT=$(get_count "/tmp/edr_full.log" '"type":"WRITE"')
UNLINK_COUNT=$(get_count "/tmp/edr_full.log" '"type":"UNLINK"')
CHMOD_COUNT=$(get_count "/tmp/edr_full.log" '"type":"CHMOD"')
CONNECT_COUNT=$(get_count "/tmp/edr_full.log" '"type":"CONNECT"')
PTRACE_COUNT=$(get_count "/tmp/edr_full.log" '"type":"PTRACE"')
MMAP_COUNT=$(get_count "/tmp/edr_full.log" '"type":"MMAP"')
CHOWN_COUNT=$(get_count "/tmp/edr_full.log" '"type":"CHOWN"')

echo "📊 Eventos capturados por syscall (9 tipos):"
echo "   Total eventos: $TOTAL_EVENTS"
echo "   ├─ EXEC: $EXEC_COUNT"
echo "   ├─ OPEN: $OPEN_COUNT"
echo "   ├─ WRITE: $WRITE_COUNT"
echo "   ├─ UNLINK: $UNLINK_COUNT"
echo "   ├─ CHMOD: $CHMOD_COUNT"
echo "   ├─ CONNECT: $CONNECT_COUNT"
echo "   ├─ PTRACE: $PTRACE_COUNT"
echo "   ├─ MMAP: $MMAP_COUNT"
echo "   └─ CHOWN: $CHOWN_COUNT"

# Contar alertas generadas
echo
echo "🚨 Alertas generadas:"
TOTAL_ALERTS=$(get_count "/tmp/edr_alerts.log" "ALERTA:")
echo "   Total alertas: $TOTAL_ALERTS"

if [ -f /tmp/edr_alerts.log ] && [ -s /tmp/edr_alerts.log ]; then
    echo "   Tipos de alertas:"
    grep "ALERTA:" /tmp/edr_alerts.log 2>/dev/null | cut -d: -f2 | cut -d' ' -f2-4 | sort | uniq -c | head -8
fi

# Verificar base de datos
echo
echo "💾 Base de datos:"
DB_EVENTS=""
DB_ALERTS=""
if [ -f "edr_events.db" ]; then
    DB_EVENTS=$(sqlite3 edr_events.db "SELECT COUNT(*) FROM events;" 2>/dev/null | tr -d '\n\r' || echo "0")
    DB_ALERTS=$(sqlite3 edr_events.db "SELECT COUNT(*) FROM events WHERE alert_level IS NOT NULL;" 2>/dev/null | tr -d '\n\r' || echo "0")
    
    # Verificar que son números válidos
    if ! [[ "$DB_EVENTS" =~ ^[0-9]+$ ]]; then
        DB_EVENTS="0"
    fi
    if ! [[ "$DB_ALERTS" =~ ^[0-9]+$ ]]; then
        DB_ALERTS="0"
    fi
    
    echo "   Eventos guardados: $DB_EVENTS"
    echo "   Eventos con alerta: $DB_ALERTS"
    
    # Mostrar distribución por tipo en BD
    if [ "$DB_EVENTS" -gt "0" ]; then
        echo "   Distribución en BD:"
        sqlite3 edr_events.db "SELECT event_type, COUNT(*) FROM events GROUP BY event_type ORDER BY COUNT(*) DESC;" 2>/dev/null | head -9 | while read line; do
            echo "      $line"
        done
    fi
else
    echo "   Base de datos no encontrada"
    DB_EVENTS="0"
    DB_ALERTS="0"
fi

# =========================================
# VALIDACIÓN FINAL
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}VALIDACIÓN DEL SISTEMA COMPLETO${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TESTS_PASSED=0
TESTS_TOTAL=8

# Test 1: Captura de syscalls básicas
if [ "$UNLINK_COUNT" -gt "10" ] && [ "$CHMOD_COUNT" -gt "3" ]; then
    echo -e "   ${GREEN}✓ Syscalls básicas funcionando (UNLINK/CHMOD)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ Captura insuficiente syscalls básicas (UNLINK: $UNLINK_COUNT, CHMOD: $CHMOD_COUNT)${NC}"
fi

# Test 2: Captura de nuevas syscalls
NUEVA_SYSCALLS_OK=0
if [ "$CONNECT_COUNT" -gt "0" ]; then ((NUEVA_SYSCALLS_OK++)); fi
if [ "$PTRACE_COUNT" -gt "0" ]; then ((NUEVA_SYSCALLS_OK++)); fi
if [ "$MMAP_COUNT" -gt "0" ]; then ((NUEVA_SYSCALLS_OK++)); fi

if [ "$NUEVA_SYSCALLS_OK" -ge "2" ]; then
    echo -e "   ${GREEN}✓ Nuevas syscalls funcionando ($NUEVA_SYSCALLS_OK/3 activas)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠ Pocas nuevas syscalls activas ($NUEVA_SYSCALLS_OK/3) (CONNECT: $CONNECT_COUNT, PTRACE: $PTRACE_COUNT, MMAP: $MMAP_COUNT)${NC}"
fi

# Test 3: Diversidad de eventos
TIPOS_ACTIVOS=0
for count in "$EXEC_COUNT" "$OPEN_COUNT" "$WRITE_COUNT" "$UNLINK_COUNT" "$CHMOD_COUNT" "$CONNECT_COUNT" "$PTRACE_COUNT" "$MMAP_COUNT" "$CHOWN_COUNT"; do
    if [ "$count" -gt "0" ]; then ((TIPOS_ACTIVOS++)); fi
done

if [ "$TIPOS_ACTIVOS" -ge "6" ]; then
    echo -e "   ${GREEN}✓ Diversidad de syscalls ($TIPOS_ACTIVOS/9 tipos activos)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠ Poca diversidad de eventos ($TIPOS_ACTIVOS/9 tipos)${NC}"
fi

# Test 4: Generación de alertas
if [ "$TOTAL_ALERTS" -gt "5" ]; then
    echo -e "   ${GREEN}✓ Sistema de alertas muy activo ($TOTAL_ALERTS alertas)${NC}"
    ((TESTS_PASSED++))
elif [ "$TOTAL_ALERTS" -gt "0" ]; then
    echo -e "   ${YELLOW}⚠ Pocas alertas generadas ($TOTAL_ALERTS)${NC}"
else
    echo -e "   ${RED}✗ No se generaron alertas${NC}"
fi

# Test 5: Persistencia en BD
if [ "$DB_EVENTS" -gt "0" ]; then
    echo -e "   ${GREEN}✓ Persistencia en BD funcionando ($DB_EVENTS eventos)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ BD no está guardando eventos${NC}"
fi

# Test 6: Detección de amenazas específicas
THREAT_TYPES=0
if grep -q "RANSOMWARE\|BORRADO MASIVO" /tmp/edr_alerts.log 2>/dev/null; then ((THREAT_TYPES++)); fi
if grep -q "ESCALACIÓN\|SETUID" /tmp/edr_alerts.log 2>/dev/null; then ((THREAT_TYPES++)); fi
if grep -q "CONEXIÓN\|INYECCIÓN\|EJECUCIÓN MEMORIA" /tmp/edr_alerts.log 2>/dev/null; then ((THREAT_TYPES++)); fi

if [ "$THREAT_TYPES" -ge "2" ]; then
    echo -e "   ${GREEN}✓ Detección multi-amenaza activa ($THREAT_TYPES tipos)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠ Detección limitada de amenazas ($THREAT_TYPES tipos)${NC}"
fi

# Test 7: Volumen de datos
if [ "$TOTAL_EVENTS" -gt "100" ]; then
    echo -e "   ${GREEN}✓ Volumen alto de eventos ($TOTAL_EVENTS)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠ Bajo volumen de eventos ($TOTAL_EVENTS)${NC}"
fi

# Test 8: Sistema estable
if kill -0 $PIPELINE_PID 2>/dev/null; then
    echo -e "   ${GREEN}✓ Sistema estable y ejecutándose${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ Sistema crasheó${NC}"
fi

# Resultado final
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TESTS_PASSED" -eq "$TESTS_TOTAL" ]; then
    echo -e "${GREEN}🚀 SISTEMA EDR COMPLETAMENTE FUNCIONAL ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo "Todas las syscalls están integradas y funcionando perfectamente"
elif [ "$TESTS_PASSED" -ge 6 ]; then
    echo -e "${GREEN}✅ SISTEMA EDR ALTAMENTE FUNCIONAL ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo "La mayoría de funcionalidades están operativas"
elif [ "$TESTS_PASSED" -ge 4 ]; then
    echo -e "${YELLOW}⚠️ SISTEMA PARCIALMENTE FUNCIONAL ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo "Revisar configuración y umbrales de detección"
else
    echo -e "${RED}❌ SISTEMA REQUIERE REVISIÓN MAYOR ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Cleanup
echo
echo "🧹 Limpiando..."
kill $PIPELINE_PID 2>/dev/null
pkill -f nc 2>/dev/null
pkill -f gdb 2>/dev/null
pkill -f sleep 2>/dev/null
rm -rf "$TEST_DIR"

echo
echo "📝 Logs y datos guardados en:"
echo "   - /tmp/edr_full.log (eventos JSON de todas las syscalls)"
echo "   - /tmp/edr_alerts.log (alertas del detector)"
echo "   - /tmp/edr.err (errores/debug del collector)"
echo "   - edr_events.db (base de datos completa)"

echo
echo "📊 RESUMEN FINAL:"
echo "   • $TIPOS_ACTIVOS/9 tipos de syscalls capturadas"
echo "   • $TOTAL_EVENTS eventos totales procesados"
echo "   • $TOTAL_ALERTS alertas de seguridad generadas"
echo "   • $DB_EVENTS eventos persistidos en base de datos"

echo
echo "✨ Test completo de todas las syscalls terminado"
