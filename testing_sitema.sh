#!/bin/bash
# test_new_syscalls.sh - Validación de nuevas syscalls (unlink/chmod)

set -u

echo "================================================"
echo "    TEST DE NUEVAS SYSCALLS - UNLINK & CHMOD   "
echo "================================================"
echo

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directorio de pruebas
TEST_DIR="/tmp/edr_syscall_test_$(date +%s)"
mkdir -p "$TEST_DIR"

# Limpiar procesos previos
echo "🧹 Limpiando estado previo..."
pkill -f collector.py 2>/dev/null || true
rm -f /tmp/syscall_test.log /tmp/syscall_test.err
sleep 2

# Iniciar collector expandido
echo "🚀 Iniciando EDR con syscalls expandidas..."
echo "   Monitorizando: EXEC, OPEN, WRITE, UNLINK, CHMOD"
echo

sudo python3 collector.py --verbose 2>/tmp/syscall_test.err | tee /tmp/syscall_test.log &
EDR_PID=$!

# Esperar compilación eBPF
echo "⏳ Esperando compilación eBPF..."
sleep 5

if ! kill -0 $EDR_PID 2>/dev/null; then
    echo -e "${RED}❌ Error: EDR no pudo iniciar${NC}"
    cat /tmp/syscall_test.err
    exit 1
fi

echo -e "${GREEN}✓ EDR iniciado correctamente (PID: $EDR_PID)${NC}"
echo

# ======================
# TEST 1: UNLINK BÁSICO
# ======================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: DETECCIÓN DE BORRADO (unlink)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "1.1 Creando archivos de prueba..."
for ext in txt doc pdf jpg xlsx; do
    touch "$TEST_DIR/important_file.$ext"
    echo "    Created: important_file.$ext"
done

echo
echo "1.2 Simulando borrado tipo ransomware..."
for file in "$TEST_DIR"/*.{txt,doc,pdf}; do
    if [ -f "$file" ]; then
        echo -e "    ${YELLOW}Deleting: $(basename $file)${NC}"
        rm "$file"
        sleep 0.2  # Pequeña pausa para captura
    fi
done

echo
echo "1.3 Verificando captura de eventos UNLINK..."
sleep 2

UNLINK_COUNT=$(grep -c '"type":"UNLINK"' /tmp/syscall_test.log 2>/dev/null || echo 0)
if [ "$UNLINK_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Capturados $UNLINK_COUNT eventos UNLINK${NC}"
    echo "   Muestra de eventos:"
    grep '"type":"UNLINK"' /tmp/syscall_test.log | head -3 | while read line; do
        echo "   $line" | jq -c '{type, path, operation}' 2>/dev/null || echo "   $line"
    done
else
    echo -e "${RED}❌ No se capturaron eventos UNLINK${NC}"
fi

# ======================
# TEST 2: CHMOD BÁSICO
# ======================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: DETECCIÓN DE CAMBIOS DE PERMISOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo

echo "2.1 Creando archivo para pruebas de permisos..."
TEST_FILE="$TEST_DIR/sensitive_file.sh"
echo "#!/bin/bash" > "$TEST_FILE"
echo "echo 'test'" >> "$TEST_FILE"

echo
echo "2.2 Aplicando cambios de permisos normales..."
chmod 755 "$TEST_FILE"
echo -e "    ${GREEN}chmod 755 (normal)${NC}"
sleep 0.5

chmod 644 "$TEST_FILE"
echo -e "    ${GREEN}chmod 644 (read-only)${NC}"
sleep 0.5

echo
echo "2.3 Aplicando permisos SOSPECHOSOS..."

# SETUID (privilege escalation)
chmod u+s "$TEST_FILE"
echo -e "    ${YELLOW}chmod u+s (SETUID) - SUSPICIOUS${NC}"
sleep 0.5

# World writable
chmod 777 "$TEST_FILE"
echo -e "    ${YELLOW}chmod 777 (WORLD ALL) - SUSPICIOUS${NC}"
sleep 0.5

# SETGID
chmod g+s "$TEST_FILE"
echo -e "    ${YELLOW}chmod g+s (SETGID) - SUSPICIOUS${NC}"
sleep 0.5

echo
echo "2.4 Verificando captura de eventos CHMOD..."
sleep 2

CHMOD_COUNT=$(grep -c '"type":"CHMOD"' /tmp/syscall_test.log 2>/dev/null || echo 0)
if [ "$CHMOD_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Capturados $CHMOD_COUNT eventos CHMOD${NC}"
    echo "   Eventos con permisos sospechosos:"
    grep '"type":"CHMOD"' /tmp/syscall_test.log | grep -i "suspicious" | head -3 | while read line; do
        echo "   $line" | jq -c '{type, path, mode_decoded, suspicious_reasons}' 2>/dev/null || echo "   $line"
    done
else
    echo -e "${RED}❌ No se capturaron eventos CHMOD${NC}"
fi

# ================================
# TEST 3: PATRÓN RANSOMWARE COMPLETO
# ================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: SIMULACIÓN RANSOMWARE COMPLETA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Patrón: crear → cifrar (write) → borrar original → cambiar permisos"
echo

RANSOM_DIR="$TEST_DIR/ransomware_test"
mkdir -p "$RANSOM_DIR"

echo "3.1 Fase 1: Creando archivos víctima..."
for i in {1..5}; do
    echo "Important data $i" > "$RANSOM_DIR/document_$i.txt"
done

echo "3.2 Fase 2: Simulando cifrado..."
for file in "$RANSOM_DIR"/*.txt; do
    if [ -f "$file" ]; then
        base=$(basename "$file" .txt)
        # Simular write intensivo (cifrado)
        dd if=/dev/urandom of="$RANSOM_DIR/$base.locked" bs=10K count=1 2>/dev/null
        echo -e "    Encrypted: $base.txt → $base.locked"
        
        # Cambiar permisos del archivo cifrado
        chmod 400 "$RANSOM_DIR/$base.locked"
        
        # Borrar original
        rm "$file"
        echo -e "    ${RED}Deleted original: $base.txt${NC}"
        
        sleep 0.1
    fi
done

echo
echo "3.3 Analizando patrón completo..."
sleep 3

# Análisis del patrón
echo "📊 Resumen de eventos capturados:"
echo -n "   WRITE (cifrado): "
grep -c '"type":"WRITE"' /tmp/syscall_test.log 2>/dev/null || echo 0

echo -n "   UNLINK (borrado): "
grep -c '"type":"UNLINK"' /tmp/syscall_test.log 2>/dev/null || echo 0

echo -n "   CHMOD (permisos): "
grep -c '"type":"CHMOD"' /tmp/syscall_test.log 2>/dev/null || echo 0

echo -n "   OPEN con .locked: "
grep '"type":"OPEN"' /tmp/syscall_test.log | grep -c '\.locked' 2>/dev/null || echo 0

# =====================
# TEST 4: STRESS TEST
# =====================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 4: STRESS TEST (100 operaciones)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

STRESS_DIR="$TEST_DIR/stress"
mkdir -p "$STRESS_DIR"

echo "Ejecutando ráfaga de operaciones..."
START_TIME=$(date +%s)

for i in {1..100}; do
    # Crear archivo
    touch "$STRESS_DIR/file_$i.tmp"
    
    # Cambiar permisos
    chmod 644 "$STRESS_DIR/file_$i.tmp"
    
    # Borrar si es múltiplo de 3
    if [ $((i % 3)) -eq 0 ]; then
        rm "$STRESS_DIR/file_$i.tmp"
    fi
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "Completado en $DURATION segundos"
echo "Rate: $((100 / DURATION)) ops/segundo"

# =====================
# ANÁLISIS FINAL
# =====================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "ANÁLISIS FINAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Contar eventos totales
TOTAL_EVENTS=$(wc -l < /tmp/syscall_test.log 2>/dev/null || echo 0)
EXEC_COUNT=$(grep -c '"type":"EXEC"' /tmp/syscall_test.log 2>/dev/null || echo 0)
OPEN_COUNT=$(grep -c '"type":"OPEN"' /tmp/syscall_test.log 2>/dev/null || echo 0)
WRITE_COUNT=$(grep -c '"type":"WRITE"' /tmp/syscall_test.log 2>/dev/null || echo 0)
UNLINK_FINAL=$(grep -c '"type":"UNLINK"' /tmp/syscall_test.log 2>/dev/null || echo 0)
CHMOD_FINAL=$(grep -c '"type":"CHMOD"' /tmp/syscall_test.log 2>/dev/null || echo 0)

echo "📈 Estadísticas de captura:"
echo "   Total eventos: $TOTAL_EVENTS"
echo "   ├─ EXEC:   $EXEC_COUNT"
echo "   ├─ OPEN:   $OPEN_COUNT"
echo "   ├─ WRITE:  $WRITE_COUNT"
echo -e "   ├─ ${GREEN}UNLINK: $UNLINK_FINAL (NUEVO)${NC}"
echo -e "   └─ ${GREEN}CHMOD:  $CHMOD_FINAL (NUEVO)${NC}"

echo
echo "🔍 Detecciones sospechosas:"
SUSPICIOUS_UNLINKS=$(grep '"type":"UNLINK"' /tmp/syscall_test.log | grep -c "suspicious_deletion" 2>/dev/null || echo 0)
SUSPICIOUS_CHMODS=$(grep '"type":"CHMOD"' /tmp/syscall_test.log | grep -c "suspicious_chmod" 2>/dev/null || echo 0)

echo "   Borrados sospechosos: $SUSPICIOUS_UNLINKS"
echo "   Permisos peligrosos:  $SUSPICIOUS_CHMODS"

# Validación de funcionalidad
echo
echo "🎯 Validación de funcionalidad:"

TESTS_PASSED=0
TESTS_TOTAL=4

# Test 1: Captura UNLINK
if [ "$UNLINK_FINAL" -gt 0 ]; then
    echo -e "   ${GREEN}✓ UNLINK funcional${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ UNLINK no capturado${NC}"
fi

# Test 2: Captura CHMOD
if [ "$CHMOD_FINAL" -gt 0 ]; then
    echo -e "   ${GREEN}✓ CHMOD funcional${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ CHMOD no capturado${NC}"
fi

# Test 3: Detección de patrones sospechosos
if [ "$SUSPICIOUS_UNLINKS" -gt 0 ] || [ "$SUSPICIOUS_CHMODS" -gt 0 ]; then
    echo -e "   ${GREEN}✓ Detección de patrones sospechosos${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠ Sin detección de patrones (revisar umbrales)${NC}"
fi

# Test 4: Sistema estable
if kill -0 $EDR_PID 2>/dev/null; then
    echo -e "   ${GREEN}✓ Sistema estable tras stress test${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ Sistema crasheó durante las pruebas${NC}"
fi

# Resultado final
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TESTS_PASSED" -eq "$TESTS_TOTAL" ]; then
    echo -e "${GREEN}✅ TODAS LAS PRUEBAS PASADAS ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo "Las nuevas syscalls están funcionando correctamente"
else
    echo -e "${YELLOW}⚠️  PRUEBAS PARCIALES: $TESTS_PASSED/$TESTS_TOTAL pasadas${NC}"
    echo "Revisar logs para más detalles"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Cleanup
echo
echo "🧹 Limpiando..."
kill $EDR_PID 2>/dev/null || true
rm -rf "$TEST_DIR"

echo "✨ Test completado"
echo
echo "📝 Logs guardados en:"
echo "   - /tmp/syscall_test.log (eventos JSON)"
echo "   - /tmp/syscall_test.err (errores/debug)"
