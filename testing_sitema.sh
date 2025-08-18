#!/bin/bash
# testing_sistema_scoring.sh - Test específico del sistema de scoring ESCAPADE/LeARN

echo "================================================"
echo "  TEST SISTEMA SCORING COMPUESTO EDR - v2.0   "
echo "================================================"
echo

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Directorio de pruebas
TEST_DIR="/tmp/edr_scoring_test_$(date +%s)"
mkdir -p "$TEST_DIR"

# Función para obtener conteos
get_count() {
    local file="$1"
    local pattern="$2"
    local count=0
    
    if [ -f "$file" ] && [ -s "$file" ]; then
        count=$(grep -c "$pattern" "$file" 2>/dev/null | head -1 | tr -d '\n\r' || echo "0")
        if ! [[ "$count" =~ ^[0-9]+$ ]]; then
            count=0
        fi
    fi
    echo "$count"
}

# Limpiar estado previo
echo "🧹 Limpiando estado previo..."
pkill -f collector 2>/dev/null
pkill -f detector 2>/dev/null
rm -f /tmp/edr_scoring.log /tmp/edr_alerts.log /tmp/edr.err
rm -f edr_events.db
sleep 2

# ==========================================
# INICIAR SISTEMA CON VERBOSE SCORING
# ==========================================
echo "🚀 Iniciando EDR con VERBOSE SCORING..."
echo "   Modo: Trazabilidad completa del scoring"

# Activar modo verbose para el scoring
export EDR_VERBOSE_SCORING=1

# Configurar Response Engine (por defecto monitor)
if [ "$1" = "--block" ]; then
    export EDR_RESPONSE_MODE=block
    echo "   Response Engine: BLOCK MODE"
elif [ "$1" = "--kill" ]; then
    export EDR_RESPONSE_MODE=kill
    echo "   Response Engine: KILL MODE"
else
    export EDR_RESPONSE_MODE=monitor
    echo "   Response Engine: MONITOR MODE (solo alertas)"
fi

# Iniciar pipeline con verbose scoring
sudo python3 collector.py --verbose --no-hash 2>/tmp/edr.err | \
    tee /tmp/edr_scoring.log | \
    python3 hash_detection_detector.py > /tmp/edr_alerts.log 2>&1 &
PIPELINE_PID=$!

echo "   Pipeline iniciado (PID: $PIPELINE_PID)"
echo "   Variable EDR_VERBOSE_SCORING=$EDR_VERBOSE_SCORING"

# Esperar inicialización
for i in {1..10}; do
    if grep -q "Monitorizando" /tmp/edr.err 2>/dev/null; then
        echo -e "${GREEN}✓ Sistema EDR activo con verbose scoring${NC}"
        break
    fi
    sleep 1
    echo -n "."
done
echo
sleep 3

# ==========================================
# TEST 1: SCORING INDIVIDUAL (NO DEBE ALERTAR)
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 1: INDICADORES INDIVIDUALES${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Generando indicadores individuales que NO deben superar umbral..."

# Indicador 1: Escritura masiva (+3 puntos, no debe alertar solo)
echo "Generando escritura masiva (50MB)..."
dd if=/dev/zero of="$TEST_DIR/big_file.dat" bs=1M count=50 2>/dev/null
echo "✓ Escritura de 50MB completada (+3 puntos esperados)"

sleep 2

# Indicador 2: Ejecución desde /tmp (+2 puntos, no debe alertar solo)
echo "Creando script en /tmp..."
cat > /tmp/test_script.sh << 'EOF'
#!/bin/bash
echo "Script ejecutado desde /tmp"
sleep 1
EOF
chmod +x /tmp/test_script.sh
/tmp/test_script.sh
echo "✓ Ejecución desde /tmp completada (+2 puntos esperados)"

sleep 2

# Verificar que NO hay alertas RANSOMWARE
RANSOMWARE_ALERTS=$(get_count "/tmp/edr_alerts.log" "RANSOMWARE")
if [ "$RANSOMWARE_ALERTS" -eq "0" ]; then
    echo -e "${GREEN}✅ CORRECTO: Indicadores individuales no generan alertas${NC}"
    echo "   Scoring compuesto funcionando según diseño"
else
    echo -e "${RED}❌ ERROR: Indicadores individuales generaron alertas${NC}"
fi

# Verificar logs de scoring verbose
if grep -q "SCORING PID" /tmp/edr_alerts.log 2>/dev/null; then
    echo -e "${GREEN}✓ Verbose scoring activo${NC}"
    echo "   Últimos logs de scoring:"
    grep "SCORING PID" /tmp/edr_alerts.log | tail -3 | sed 's/^/      /'
else
    echo -e "${YELLOW}⚠ Verbose scoring no detectado${NC}"
fi

# ==========================================
# TEST 2: COMBINACIÓN QUE ALCANZA UMBRAL
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 2: COMBINACIÓN MULTI-INDICADOR${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Combinando indicadores para superar umbral de 6 puntos..."

COMBO_DIR="$TEST_DIR/combo_attack"
mkdir -p "$COMBO_DIR"

# Indicador 1: Crear archivos .locked masivamente (+3 puntos)
echo "Fase 1: Creando archivos .locked (+3 puntos esperados)..."
for i in {1..6}; do
    touch "$COMBO_DIR/victim_$i.locked"
done
echo "✓ 6 archivos .locked creados"

sleep 2

# Indicador 2: Borrado masivo (+3 puntos)
echo "Fase 2: Borrando archivos masivamente (+3 puntos esperados)..."
for i in {1..6}; do
    echo "data" > "$COMBO_DIR/delete_me_$i.doc"
done
# Borrar rápidamente
for file in "$COMBO_DIR"/delete_me_*.doc; do
    rm "$file" 2>/dev/null
done
echo "✓ Borrado masivo completado"

sleep 2

# Indicador 3: CHMOD sospechoso (+2 puntos)
echo "Fase 3: Cambio de permisos SETUID (+2 puntos esperados)..."
touch "$COMBO_DIR/backdoor"
chmod u+s "$COMBO_DIR/backdoor" 2>/dev/null
echo "✓ SETUID aplicado"

sleep 3

# Verificar que SÍ hay alertas RANSOMWARE
echo "Verificando detección combinada..."
COMBO_ALERTS=$(get_count "/tmp/edr_alerts.log" "RANSOMWARE.*SCORE")
if [ "$COMBO_ALERTS" -gt "0" ]; then
    echo -e "${GREEN}✅ DETECCIÓN EXITOSA: Combinación detectada${NC}"
    echo "   Alertas de scoring encontradas:"
    grep "RANSOMWARE.*SCORE" /tmp/edr_alerts.log | tail -2 | sed 's/^/      /'
else
    echo -e "${RED}❌ ERROR: Combinación no detectada${NC}"
    echo "   Revisando logs de scoring..."
    grep "SCORING PID" /tmp/edr_alerts.log | tail -5 | sed 's/^/      /'
fi

# ==========================================
# TEST 3: PATRÓN RANSOMWARE REAL
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 3: SIMULACIÓN RANSOMWARE REAL${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando ataque ransomware completo..."

RANSOM_DIR="$TEST_DIR/realistic_ransomware"
mkdir -p "$RANSOM_DIR"

# Paso 1: Escritura masiva (cifrado simulado) +3
echo "Simulando cifrado masivo..."
dd if=/dev/urandom of="$RANSOM_DIR/encryption_data" bs=1M count=25 2>/dev/null

# Paso 2: Crear archivos cifrados +3
echo "Creando archivos .encrypted..."
for i in {1..7}; do
    echo "encrypted_data_$i" > "$RANSOM_DIR/document_$i.encrypted"
done

# Paso 3: Borrar originales +3
echo "Borrando archivos originales..."
for i in {1..8}; do
    echo "original_data_$i" > "$RANSOM_DIR/original_$i.doc"
done
sleep 1
for file in "$RANSOM_DIR"/original_*.doc; do
    rm "$file" 2>/dev/null
done

# Paso 4: Ejecución desde /tmp +2
echo "Ejecutando desde /tmp..."
cat > /tmp/ransom_script.sh << 'EOF'
#!/bin/bash
echo "Ransomware simulation"
sleep 1
EOF
chmod +x /tmp/ransom_script.sh
/tmp/ransom_script.sh

sleep 3

# Verificar detección de patrón real
echo "Verificando detección de ransomware real..."
REAL_ALERTS=$(get_count "/tmp/edr_alerts.log" "RANSOMWARE")
if [ "$REAL_ALERTS" -gt "0" ]; then
    echo -e "${GREEN}✅ RANSOMWARE REAL DETECTADO${NC}"
    echo "   Total alertas: $REAL_ALERTS"
    
    # Mostrar desglose del scoring
    echo "   Desglose de scoring detectado:"
    grep "RANSOMWARE.*SCORE" /tmp/edr_alerts.log | tail -1 | sed 's/^/      /'
else
    echo -e "${RED}❌ RANSOMWARE REAL NO DETECTADO${NC}"
fi


# ==========================================
# TEST 3.5: DETECCIÓN DE PERSISTENCIA
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 3.5: DETECCIÓN DE PERSISTENCIA${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Simulando intentos de persistencia..."

# Test crontab
echo "Intentando modificar crontab (simulado)..."
echo "* * * * * /tmp/backdoor.sh" > "$TEST_DIR/fake_crontab"
cat "$TEST_DIR/fake_crontab" > /dev/null

# Test bashrc
echo "Creando .bashrc malicioso..."
echo "alias sudo='echo pwned && sudo'" > "$TEST_DIR/.bashrc"

# Test systemd (simulado)
echo "Creando servicio systemd falso..."
cat > "$TEST_DIR/backdoor.service" << EOF
[Unit]
Description=Backdoor

[Service]
ExecStart=/tmp/backdoor

[Install]
WantedBy=multi-user.target
EOF

sleep 2

# Verificar detección
PERSISTENCE_ALERTS=$(grep -c "PERSISTENCIA" /tmp/edr_alerts.log 2>/dev/null || echo "0")
if [ "$PERSISTENCE_ALERTS" -gt "0" ]; then
    echo -e "${GREEN}✅ PERSISTENCIA DETECTADA${NC}"
    echo "   Alertas de persistencia:"
    grep "PERSISTENCIA" /tmp/edr_alerts.log | tail -3 | sed 's/^/      /'
else
    echo -e "${YELLOW}⚠ Persistencia no detectada (puede requerir permisos root)${NC}"
fi

# ==========================================
# TEST 3.6: RESPONSE ENGINE
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 3.6: RESPONSE ENGINE${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Verificar modo actual
RESPONSE_MODE=${EDR_RESPONSE_MODE:-monitor}
echo "Modo Response Engine: $RESPONSE_MODE"

if [ "$RESPONSE_MODE" = "monitor" ]; then
    echo -e "${YELLOW}⚠ Response Engine en modo MONITOR (solo alertas)${NC}"
    echo "   Para probar respuestas activas, ejecutar con:"
    echo "   EDR_RESPONSE_MODE=block ./testing_sistema.sh"
else
    echo -e "${GREEN}✓ Response Engine en modo $RESPONSE_MODE${NC}"
    
    # Contar respuestas en logs
    BLOCKS=$(grep -c "RESPONSE BLOCK" /tmp/edr_alerts.log 2>/dev/null || echo "0")
    KILLS=$(grep -c "RESPONSE KILL" /tmp/edr_alerts.log 2>/dev/null || echo "0")
    
    echo "   Acciones ejecutadas:"
    echo "     Procesos bloqueados: $BLOCKS"
    echo "     Procesos terminados: $KILLS"
    
    if [ "$BLOCKS" -gt "0" ] || [ "$KILLS" -gt "0" ]; then
        echo -e "${GREEN}✅ RESPONSE ENGINE ACTIVO Y FUNCIONANDO${NC}"
    fi
fi

# ==========================================
# TEST 4: ANÁLISIS DE LOGS VERBOSE
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${BLUE}TEST 4: ANÁLISIS DE SCORING VERBOSE${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Contar progresión de scoring
SCORING_LINES=$(get_count "/tmp/edr_alerts.log" "SCORING PID")
if [ "$SCORING_LINES" -gt "0" ]; then
    echo "📊 Análisis de progresión de scoring:"
    echo "   Total logs de scoring: $SCORING_LINES"
    
    # Mostrar ejemplos de progresión
    echo "   Ejemplos de progresión de puntos:"
    grep "SCORING PID" /tmp/edr_alerts.log | grep -v "0/6" | tail -5 | sed 's/^/      /'
    
    # Verificar diferentes tipos de indicadores
    echo "   Tipos de indicadores detectados:"
    grep "SCORING PID" /tmp/edr_alerts.log | grep -o '\[[^]]*\]' | sort | uniq -c | sed 's/^/      /'
else
    echo -e "${YELLOW}⚠ No se encontraron logs de scoring verbose${NC}"
fi

# ==========================================
# ANÁLISIS FINAL DEL SISTEMA
# ==========================================
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${PURPLE}ANÁLISIS FINAL - SISTEMA DE SCORING${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Contar eventos y alertas
TOTAL_EVENTS=$(get_count "/tmp/edr_scoring.log" '"type"')
TOTAL_ALERTS=$(get_count "/tmp/edr_alerts.log" "ALERTA:")
SCORING_ALERTS=$(get_count "/tmp/edr_alerts.log" "RANSOMWARE.*SCORE")
INDIVIDUAL_ALERTS=$(get_count "/tmp/edr_alerts.log" "ALERTA:" | awk -v sa="$SCORING_ALERTS" '{print $1-sa}')

echo "📈 Métricas del sistema:"
echo "   Total eventos procesados: $TOTAL_EVENTS"
echo "   Total alertas generadas: $TOTAL_ALERTS"
echo "   Alertas por scoring compuesto: $SCORING_ALERTS"
echo "   Alertas individuales: $INDIVIDUAL_ALERTS"

# Calcular eficacia del scoring
if [ "$SCORING_ALERTS" -gt "0" ]; then
    echo -e "   ${GREEN}✓ Sistema de scoring compuesto: FUNCIONAL${NC}"
else
    echo -e "   ${RED}✗ Sistema de scoring compuesto: NO FUNCIONAL${NC}"
fi

# Verificar configuración
echo
echo "⚙️ Configuración del scoring:"
if grep -q "Umbral configurado: >6 puntos" /tmp/edr_alerts.log 2>/dev/null; then
    grep "Umbral configurado\|Ventana temporal\|PIDs que alcanzaron" /tmp/edr_alerts.log | sed 's/^/   /'
fi

# ==========================================
# VALIDACIÓN ACADÉMICA
# ==========================================
echo
echo "🎓 Validación académica (ESCAPADE/LeARN):"

VALIDATION_SCORE=0
VALIDATION_TOTAL=5

# Test 1: Scoring compuesto funcionando
if [ "$SCORING_ALERTS" -gt "0" ]; then
    echo -e "   ${GREEN}✓ Detección compuesta funcional${NC}"
    ((VALIDATION_SCORE++))
else
    echo -e "   ${RED}✗ Detección compuesta no funcional${NC}"
fi

# Test 2: Verbose logging activo
if [ "$SCORING_LINES" -gt "10" ]; then
    echo -e "   ${GREEN}✓ Trazabilidad de scoring activa${NC}"
    ((VALIDATION_SCORE++))
else
    echo -e "   ${RED}✗ Trazabilidad insuficiente${NC}"
fi

# Test 3: Indicadores individuales no alertan
if [ "$SCORING_ALERTS" -gt "$INDIVIDUAL_ALERTS" ]; then
    echo -e "   ${GREEN}✓ Reducción de falsos positivos${NC}"
    ((VALIDATION_SCORE++))
else
    echo -e "   ${YELLOW}⚠ Revisar balance individual vs compuesto${NC}"
fi




# Test 4: Múltiples tipos de indicadores
INDICATOR_TYPES=$(grep "SCORING PID" /tmp/edr_alerts.log | grep -o '\[[^]]*\]' | sort | uniq | wc -l)
if [ "$INDICATOR_TYPES" -ge "3" ]; then
    echo -e "   ${GREEN}✓ Diversidad de indicadores ($INDICATOR_TYPES tipos)${NC}"
    ((VALIDATION_SCORE++))
else
    echo -e "   ${YELLOW}⚠ Poca diversidad de indicadores ($INDICATOR_TYPES tipos)${NC}"
fi

# Test 5: Ransomware real detectado
if [ "$REAL_ALERTS" -gt "0" ]; then
    echo -e "   ${GREEN}✓ Detección de patrones realistas${NC}"
    ((VALIDATION_SCORE++))
else
    echo -e "   ${RED}✗ Patrones realistas no detectados${NC}"
fi

# Resultado final de validación
echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$VALIDATION_SCORE" -eq "$VALIDATION_TOTAL" ]; then
    echo -e "${GREEN}🏆 SISTEMA ACADÉMICAMENTE VALIDADO ($VALIDATION_SCORE/$VALIDATION_TOTAL)${NC}"
    echo "   Implementación de ESCAPADE/LeARN correcta"
elif [ "$VALIDATION_SCORE" -ge 3 ]; then
    echo -e "${GREEN}✅ SISTEMA MAYORMENTE VALIDADO ($VALIDATION_SCORE/$VALIDATION_TOTAL)${NC}"
    echo "   Scoring compuesto funcionando adecuadamente"
else
    echo -e "${RED}❌ SISTEMA REQUIERE REVISIÓN ($VALIDATION_SCORE/$VALIDATION_TOTAL)${NC}"
    echo "   Implementación de scoring necesita ajustes"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"






# Cleanup
echo
echo "🧹 Limpiando..."
kill $PIPELINE_PID 2>/dev/null
rm -rf "$TEST_DIR"
unset EDR_VERBOSE_SCORING

echo
echo "📋 Archivos de análisis:"
echo "   - /tmp/edr_scoring.log (eventos JSON)"
echo "   - /tmp/edr_alerts.log (alertas y scoring verbose)"
echo "   - /tmp/edr.err (debug del collector)"
echo "   - edr_events.db (base de datos)"

echo
echo "🎯 Para análisis detallado:"
echo "   grep 'SCORING PID' /tmp/edr_alerts.log"
echo "   grep 'RANSOMWARE.*SCORE' /tmp/edr_alerts.log"

echo
echo "✨ Test de sistema de scoring completado"
