#!/bin/bash
# test_full_system.sh - Test completo del sistema EDR con nuevas syscalls - ARREGLADO

echo "================================================"
echo "    TEST COMPLETO EDR - COLLECTOR + DETECTOR   "
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
sleep 2

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
echo
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
echo
echo "Verificando alertas de privilegios..."
if grep -q "ESCALACIÓN PRIVILEGIOS\|SETUID\|CHMOD SOSPECHOSOS" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Escalación de privilegios detectada${NC}"
    grep "ESCALACIÓN\|SETUID\|CHMOD" /tmp/edr_alerts.log | head -2
else
    echo -e "${YELLOW}⚠ No se detectó escalación de privilegios${NC}"
fi

# =========================================
# TEST 3: PATRÓN RANSOMWARE COMPLETO
# =========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 3: PATRÓN RANSOMWARE COMPLETO${NC}"
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
echo
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
echo -e "${BLUE}ANÁLISIS DE RESULTADOS${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Contar eventos capturados usando función segura
TOTAL_EVENTS=0
if [ -f "/tmp/edr_full.log" ]; then
    TOTAL_EVENTS=$(wc -l < /tmp/edr_full.log 2>/dev/null | tr -d '\n\r' || echo "0")
    if ! [[ "$TOTAL_EVENTS" =~ ^[0-9]+$ ]]; then
        TOTAL_EVENTS=0
    fi
fi

UNLINK_COUNT=$(get_count "/tmp/edr_full.log" '"type":"UNLINK"')
CHMOD_COUNT=$(get_count "/tmp/edr_full.log" '"type":"CHMOD"')
WRITE_COUNT=$(get_count "/tmp/edr_full.log" '"type":"WRITE"')

echo "📊 Eventos capturados:"
echo "   Total eventos: $TOTAL_EVENTS"
echo "   ├─ UNLINK: $UNLINK_COUNT"
echo "   ├─ CHMOD: $CHMOD_COUNT"
echo "   └─ WRITE: $WRITE_COUNT"

# Contar alertas generadas
echo
echo "🚨 Alertas generadas:"
TOTAL_ALERTS=$(get_count "/tmp/edr_alerts.log" "ALERTA:")
echo "   Total alertas: $TOTAL_ALERTS"

if [ -f /tmp/edr_alerts.log ] && [ -s /tmp/edr_alerts.log ]; then
    echo "   Tipos de alertas:"
    grep "ALERTA:" /tmp/edr_alerts.log 2>/dev/null | cut -d: -f2 | cut -d' ' -f2-4 | sort | uniq -c | head -5
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
echo -e "${BLUE}VALIDACIÓN DEL SISTEMA${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TESTS_PASSED=0
TESTS_TOTAL=5

# Test 1: Captura de nuevas syscalls
if [ "$UNLINK_COUNT" -gt "10" ] && [ "$CHMOD_COUNT" -gt "3" ]; then
    echo -e "   ${GREEN}✓ Nuevas syscalls funcionando${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ Captura insuficiente de syscalls (UNLINK: $UNLINK_COUNT, CHMOD: $CHMOD_COUNT)${NC}"
fi

# Test 2: Generación de alertas
if [ "$TOTAL_ALERTS" -gt "0" ]; then
    echo -e "   ${GREEN}✓ Sistema de alertas activo${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ No se generaron alertas${NC}"
fi

# Test 3: Persistencia en BD
if [ "$DB_EVENTS" -gt "0" ]; then
    echo -e "   ${GREEN}✓ Persistencia en BD funcionando${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ BD no está guardando eventos${NC}"
fi

# Test 4: Detección de amenazas
if grep -q "RANSOMWARE\|ESCALACIÓN\|BORRADO MASIVO" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "   ${GREEN}✓ Detección de amenazas activa${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${YELLOW}⚠ Detección limitada de amenazas${NC}"
fi

# Test 5: Sistema estable
if kill -0 $PIPELINE_PID 2>/dev/null; then
    echo -e "   ${GREEN}✓ Sistema estable${NC}"
    ((TESTS_PASSED++))
else
    echo -e "   ${RED}✗ Sistema crasheó${NC}"
fi

# Resultado final
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$TESTS_PASSED" -eq "$TESTS_TOTAL" ]; then
    echo -e "${GREEN}✅ SISTEMA EDR COMPLETAMENTE FUNCIONAL ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo "Las nuevas syscalls están integradas y detectando amenazas"
elif [ "$TESTS_PASSED" -ge 3 ]; then
    echo -e "${YELLOW}⚠️ SISTEMA PARCIALMENTE FUNCIONAL ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
    echo "Revisar configuración y umbrales de detección"
else
    echo -e "${RED}❌ SISTEMA REQUIERE REVISIÓN ($TESTS_PASSED/$TESTS_TOTAL)${NC}"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Debug adicional si hay problemas
if [ "$TOTAL_EVENTS" -eq "0" ]; then
    echo
    echo "🔍 DIAGNÓSTICO DETALLADO:"
    echo "   No se capturaron eventos. Verificando:"
    
    # Verificar si el collector está corriendo
    if ps aux | grep -q "[c]ollector.py"; then
        echo "   ✓ Collector está ejecutándose"
    else
        echo "   ✗ Collector no está ejecutándose"
    fi
    
    # Verificar logs de error
    if [ -f "/tmp/edr.err" ]; then
        echo "   📋 Últimas líneas del log de error:"
        tail -5 /tmp/edr.err | sed 's/^/      /'
    fi
    
    # Verificar si hay permisos de eBPF
    if [ "$EUID" -ne 0 ]; then
        echo "   ⚠ Script no se ejecutó como root, collector puede fallar"
    fi
fi

# Cleanup
echo
echo "🧹 Limpiando..."
kill $PIPELINE_PID 2>/dev/null
rm -rf "$TEST_DIR"

echo
echo "📝 Logs guardados en:"
echo "   - /tmp/edr_full.log (eventos JSON)"
echo "   - /tmp/edr_alerts.log (alertas del detector)"
echo "   - /tmp/edr.err (errores/debug)"
echo "   - edr_events.db (base de datos)"

echo
echo "✨ Test completado"
