# IDS/IPS Project — Snort + Azure Monitor

Sistema de detección/prevención de intrusiones basado en Snort 2.9.20 sobre Ubuntu 22.04, integrado con Azure Monitor para visualización centralizada de alertas. El entorno de pruebas en GNS3 ubica el servidor en modo inline entre un router Cisco 3725 y un switch para interceptar todo el tráfico de la red.

---

## Arquitectura

### Modo IDS (pasivo — una interfaz)

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────────┐
│ PC1 (VPCS)      │     │  Cisco 3725 R1   │     │  Ubuntu 22.04 Server   │
│ 192.168.1.25    │────▶│  192.168.1.1     │────▶│  Snort IDS             │
│ (nmap / ataque) │     │  GNS3            │     │  enp0s3 (sin IP inline)│
└─────────────────┘     └──────────────────┘     └───────────┬────────────┘
                                                              │ enp0s9: 192.168.1.202
                                                    Azure Monitor Agent
                                                              │
                                                 ┌────────────▼────────────┐
                                                 │  Azure Log Analytics    │
                                                 │  Workspace: snortlogs   │
                                                 │  Tabla: SnortAlerts_CL  │
                                                 └─────────────────────────┘
```

### Modo IPS inline (GNS3 — topología de laboratorio)

```
┌─────────────┐      ┌──────────┐  enp0s8        enp0s3  ┌────────────────────┐
│ PC1 (VPCS)  │──────│ Switch1  │────────────────────────│  linux02 (Ubuntu)  │
│192.168.1.25 │      └──────────┘       Snort IPS        │  Snort 2.9.x       │
└─────────────┘                         (inline)         │  enp0s3: sin IP    │
                                                          │  enp0s8: sin IP    │
                                                          │  enp0s9: 192.168.1.202 │
                                                          └───────┬──────┬─────┘
                                                         enp0s9  │      │ enp0s3
                                                                  │      │
                                                       ┌──────────┘      │
                                                       │              fa0/1
                                                  ┌────▼─────┐  ┌────────────────┐
                                                  │  Cloud1  │  │ R1 Cisco 3725  │
                                                  │(internet)│  │  192.168.1.1   │
                                                  └──────────┘  └────────────────┘
```

**Flujo de datos (IPS):** todo el tráfico de PC1 cruza el servidor (`enp0s8 ↔ enp0s3`) antes de llegar al router. Snort inspecciona cada paquete en tiempo real y puede bloquearlos.

**Flujo de gestión:** `enp0s9` (192.168.1.202) tiene IP fija con acceso a internet para Azure Arc SSH y envío de logs a Azure Monitor.

---

## Prerrequisitos

| Componente | Versión / Detalle |
|---|---|
| Ubuntu Server | 22.04 LTS (VM en VirtualBox) |
| Snort | 2.9.15.1 (paquete `apt`) |
| GNS3 Desktop | Última versión estable (local, sin GNS3 VM) |
| Imagen Cisco IOS | `c3725-adventerprisek9-mz.124-15.T14.image` |
| Azure | Suscripción activa + Log Analytics Workspace creado |
| VirtualBox | Para alojar la VM Ubuntu |

---

## 1. Servidor (Ubuntu 22.04) — Configuración completa

Esta sección cubre todos los pasos necesarios para que el servidor funcione tanto en modo IDS como IPS. El orden importa: red → kernel → interfaces → Snort → validación.

### 1.1 Adaptadores de red en VirtualBox

Con la VM **apagada**, configurar en **Settings → Network**:

| Adapter | Tipo | Red | Interfaz Linux | Rol |
|---|---|---|---|---|
| Adapter 1 | (gestionado por GNS3) | — | `enp0s3` | Inline IPS — lado del router |
| Adapter 2 | (gestionado por GNS3) | — | `enp0s8` | Inline IPS — lado del switch |
| Adapter 3 | Bridged Adapter | (NIC física) | `enp0s9` | Gestión / Internet / Azure Arc |

Los Adapters 1 y 2 son controlados directamente por GNS3 mediante UDP tunnels (Generic Driver). No se configuran manualmente en VirtualBox — GNS3 los toma cuando se inicia la VM desde el canvas. Solo el Adapter 3 se configura en VirtualBox como **Bridged** para tener IP fija con acceso a internet.

> **Importante:** el número de adaptadores también debe configurarse en GNS3 (ver sección 4.2). Si GNS3 está configurado con menos adaptadores de los que tiene VirtualBox, elimina los sobrantes al arrancar la VM desde el canvas.

### 1.2 Configuración de red (netplan)

Deshabilitar cloud-init para que no sobreescriba la configuración:
```bash
sudo touch /etc/cloud/cloud-init.disabled
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bak
```

Reemplazar `/etc/netplan/50-cloud-init.yaml` con la siguiente configuración. Las interfaces inline no necesitan IP — actúan como bridge L2 transparente. `enp0s9` lleva la IP fija de gestión:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      dhcp6: false
      optional: true
    enp0s8:
      dhcp4: false
      dhcp6: false
      optional: true
    enp0s9:
      dhcp4: false
      dhcp6: false
      addresses:
        - 192.168.1.202/24
      nameservers:
        addresses:
          - 8.8.8.8
      routes:
        - to: default
          via: 192.168.1.1
```

Aplicar:
```bash
sudo netplan apply
```

### 1.3 Instalar OpenSSH

```bash
sudo apt install openssh-server
sudo systemctl enable ssh
```

### 1.4 Deshabilitar IPv6

IPv6 genera tráfico Neighbor Discovery (NDP) que dispara falsos positivos masivos en Snort (`sid:527`). Se deshabilita a nivel de kernel:

```bash
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
```

Persistente tras reinicio:
```bash
echo "net.ipv6.conf.all.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6=1" | sudo tee -a /etc/sysctl.conf
```

### 1.5 Habilitar IP forwarding

Necesario para que el kernel reenvíe paquetes entre `enp0s3` y `enp0s8` en modo IPS:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Persistente tras reinicio:
```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

Aplicar todos los cambios de sysctl a la vez:
```bash
sudo sysctl -p
```

### 1.6 Modo promiscuo persistente (ambas interfaces)

Crear el servicio systemd para que el modo promiscuo se active automáticamente al arrancar:

```bash
sudo nano /etc/systemd/system/promisc.service
```

```ini
[Unit]
Description=Enable promiscuous mode on Snort inline interfaces
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip link set enp0s3 promisc on
ExecStart=/sbin/ip link set enp0s8 promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable promisc.service
sudo systemctl start promisc.service
```

### 1.7 Validación del servidor

Ejecutar estos comandos y verificar que cada salida coincide con lo esperado:

**Interfaces activas con PROMISC:**
```bash
ip link show
```
Salida esperada para cada interfaz inline:
```
enp0s3: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> ...
enp0s8: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> ...
```

**IP forwarding activo:**
```bash
cat /proc/sys/net/ipv4/ip_forward
# Debe mostrar: 1
```

**IPv6 deshabilitado:**
```bash
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
# Debe mostrar: 1
```

---

## 2. Snort IDS/IPS

### 2.1 Instalación

```bash
sudo apt update
sudo apt install snort
```

Verificar versión y DAQ disponibles:
```bash
snort --version 2>&1 | head -3
snort --daq-list 2>/dev/null | grep -E "afpacket|pcap"
```

`afpacket` debe aparecer en la lista — es el DAQ requerido para modo IPS inline.

### 2.2 Estructura de directorios

```
/etc/snort/
├── snort.conf                # Configuración principal (Debian default)
├── snort.debian.conf         # Variables HOME_NET e interfaz (prioridad sobre snort.conf)
├── classification.config     # Clasificaciones de alertas
├── reference.config          # Referencias CVE/Bugtraq
├── threshold.conf            # Supresión y umbral de eventos
├── rules/
│   ├── local.rules           # Reglas personalizadas del proyecto
│   ├── white_list.rules      # Lista blanca
│   ├── black_list.rules      # Lista negra
│   └── *.rules               # Reglas Debian/VRT habilitadas
├── so_rules/                 # Reglas de objetos compartidos
└── preproc_rules/            # Reglas de preprocesadores

/var/log/snort/
└── snort.alert.fast          # Alertas en texto plano (leído por Azure Monitor Agent)
```

### 2.3 Configuración de Snort

**`/etc/snort/snort.debian.conf`** — variables de entorno del servicio:

```bash
sudo nano /etc/snort/snort.debian.conf
```

```
DEBIAN_SNORT_STARTUP="boot"
DEBIAN_SNORT_HOME_NET="192.168.1.0/24"
DEBIAN_SNORT_INTERFACE="enp0s3"
DEBIAN_SNORT_OPTIONS=""
DEBIAN_SNORT_SEND_STATS="false"
```

> `HOME_NET` se define como la subred `/24` completa (no solo el IP del servidor) porque en modo IPS el servidor protege a todos los hosts de la LAN.

**`EXTERNAL_NET`** — verificar que esté como `any` en `snort.conf`. Como la IP del atacante puede ser dinámica (DHCP), no se define una IP fija:

```bash
grep "EXTERNAL_NET" /etc/snort/snort.conf | head -2
# Debe mostrar: ipvar EXTERNAL_NET any
```

**Deshabilitar el servicio automático** — se controla Snort manualmente:
```bash
sudo systemctl stop snort
sudo systemctl disable snort
```

### 2.4 Suprimir falsos positivos (threshold.conf)

```bash
sudo nano /etc/snort/threshold.conf
```

Agregar al final:
```
# Falso positivo: IPv6 NDP multicast (se complementa con disable_ipv6)
suppress gen_id 1, sig_id 527
```

### 2.5 Reglas personalizadas (local.rules)

```bash
sudo nano /etc/snort/rules/local.rules
```

```
# Detecta intentos de conexión SSH
alert tcp any any -> $HOME_NET 22 (msg:"[Snort IDS] SSH Access Attempt"; sid:1000010; rev:1;)

# Detecta escaneo de puertos TCP (15+ SYN en 2 segundos)
alert tcp any any -> $HOME_NET any (msg:"[Snort IDS] TCP Port Scan"; flags:S; threshold: type both, track by_src, count 15, seconds 2; sid:1000011; rev:1;)
```

Nuevas reglas propias: usar SIDs `1000012`, `1000013`, etc. No reutilizar SIDs existentes.

Preprocesadores activos relevantes:

| Preprocesador | Función |
|---|---|
| `frag3` | Reensamblado de fragmentos IP |
| `stream5` | Seguimiento de sesiones TCP/UDP |
| `http_inspect` | Normalización y anomalías HTTP |
| `ftp_telnet` | Inspección FTP y Telnet |
| `smtp` | Normalización SMTP |
| `ssh` | Detección de anomalías SSH (puerto 22) |
| `dcerpc2` | Inspección SMB/RPC |
| `dns` | Anomalías DNS (puerto 53) |
| `ssl` | Bypass de tráfico SSL cifrado |

### 2.6 Validación de configuración

**Modo IDS (una interfaz):**
```bash
sudo snort -T -i enp0s3 -c /etc/snort/snort.conf
```

**Modo IPS (dos interfaces):**
```bash
sudo snort -T -i enp0s3:enp0s8 -c /etc/snort/snort.conf
```

Ambos comandos deben terminar con:
```
Snort successfully validated the configuration!
Snort exiting
```

### 2.7 Ejecutar Snort

**Modo IDS — monitoreo pasivo, alertas en consola:**
```bash
sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf -k none
```

**Modo IDS — escribir alertas a archivo (para Azure Monitor Agent):**
```bash
sudo snort -A fast -i enp0s3 -c /etc/snort/snort.conf -k none -l /var/log/snort/
```

**Modo IPS inline — inspección y bloqueo entre router y switch:**
```bash
sudo snort -Q --daq afpacket -i enp0s3:enp0s8 -c /etc/snort/snort.conf -A console
```

Verificar que las alertas se están escribiendo al archivo:
```bash
tail -f /var/log/snort/snort.alert.fast
```

---

## 3. Integración con Azure

### 3.1 Conectar el servidor a Azure Arc

1. Ir al portal Azure → **Azure Arc** → **Machines** → **Add a single machine**
2. Seleccionar sistema operativo Linux y generar el script de onboarding
3. Descargar el script y transferirlo al servidor
4. Ejecutar en el servidor:
```bash
sudo chmod +x OnboardingScript.sh
sudo ./OnboardingScript.sh
```
El servidor aparece como recurso administrado en Azure Arc una vez completado.

> **Seguridad:** el script contiene `subscriptionId` y `tenantId`. Generar uno nuevo desde el portal si es necesario; nunca subir el script a repositorios públicos.

### 3.2 Instalar Azure Monitor Agent (AMA)

Desde el portal Azure:

1. Ir a **Azure Arc** → **Machines** → seleccionar el servidor → **Settings** → **Extensions**
2. Instalar la extensión **Azure Monitor Agent**
3. Verificar que el servicio esté activo en el servidor:
```bash
sudo systemctl status azuremonitoragent
```

### 3.3 Crear el workspace de Log Analytics

1. Ir a **Log Analytics Workspaces** → **Create**
2. Nombre del workspace: `snortlogs`
3. Seleccionar suscripción y grupo de recursos
4. Crear y esperar el aprovisionamiento

### 3.4 Crear Data Collection Endpoint (DCE)

1. Ir a **Monitor** → **Settings** → **Data collection endpoints** → **Create**
2. Nombre: `DCE-Snort`
3. Seleccionar la misma región que el workspace
4. Una vez creado: **DCE-Snort** → **Configuration** → **Resources** → agregar el servidor

### 3.5 Crear la tabla personalizada y la DCR

1. Ir a **Log Analytics Workspace** → `snortlogs` → **Settings** → **Tables**
2. **Create** → **New custom log (MMA-based)**
3. Subir el archivo `logsample.json` (muestra del formato de `snort.alert.fast`)
4. Nombre de la tabla: `SnortAlerts_CL`
5. En la sección de transformación KQL, editar para agregar `TimeGenerated`:
   ```kql
   source | extend TimeGenerated = now()
   ```
6. Al crear la tabla se genera automáticamente una **Data Collection Rule (DCR)**; nombrarla `DCR-Snort` y seleccionar el DCE-Snort

### 3.6 Asociar servidor a la DCR

1. Ir a **Monitor** → **Settings** → **Data collection rules** → `DCR-Snort`
2. **Configuration** → **Resources** → **Add** → seleccionar el servidor

### 3.7 Agregar Data Source a la DCR

1. Dentro de `DCR-Snort` → **Configuration** → **Data sources** → **Add**
2. Tipo: **Custom Text Logs**
3. Ruta del archivo en el servidor: `/var/log/snort/snort.alert.fast`
4. Tabla de destino: `SnortAlerts_CL`
5. Guardar

### 3.8 Generar logs y validar en Azure

Ejecutar Snort en el servidor para comenzar a generar alertas:
```bash
sudo snort -A fast -i enp0s3 -c /etc/snort/snort.conf -k none -l /var/log/snort/
```

En el portal Azure → **Log Analytics Workspace** → `snortlogs` → **Logs** → cambiar a **KQL mode** y ejecutar:
```kql
SnortAlerts_CL
| take 10
```

Los datos pueden demorar 5-10 minutos en aparecer por primera vez.

### 3.9 Consulta KQL para parsear alertas de Snort

```kql
SnortAlerts_CL
| extend
    timestamp      = extract(@"^(\d+/\d+-\d+:\d+:\d+\.\d+)", 1, RawData),
    sid            = extract(@"\[(\d+):(\d+):(\d+)\]", 0, RawData),
    msg            = extract(@"\]\s*(.*?)\s*\[\*\*\]", 1, RawData),
    classification = extract(@"\[Classification:\s*(.*?)\]", 1, RawData),
    priority       = extract(@"\[Priority:\s*(\d+)\]", 1, RawData),
    protocol       = extract(@"\{(\w+)\}", 1, RawData),
    src_ip         = extract(@"\}\s*([a-fA-F0-9:\.]+):(\d+)", 1, RawData),
    src_port       = extract(@"\}\s*([a-fA-F0-9:\.]+):(\d+)", 2, RawData),
    dst_ip         = extract(@"->\s*([a-fA-F0-9:\.]+):(\d+)", 1, RawData),
    dst_port       = extract(@"->\s*([a-fA-F0-9:\.]+):(\d+)", 2, RawData)
| project timestamp, msg, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port
| order by timestamp desc
```

> **Problema conocido:** si aparece error de espacio insuficiente al instalar el AMA, cambiar el disco virtual a **capacidad fija** en la configuración de la VM en VirtualBox/VMware.

---

## 4. Entorno de pruebas en GNS3 (IPS inline)

### 4.1 Instalación de GNS3

Se usa **GNS3 Desktop local** (sin GNS3 VM). Dynamips corre directamente en Windows y virtualiza el Cisco 3725. No se requiere GNS3 VM ni VT-x anidado.

1. Descargar e instalar GNS3 Desktop desde [gns3.com](https://www.gns3.com/)
2. Descargar la imagen IOS: `c3725-adventerprisek9-mz.124-15.T14.image`
3. En GNS3: **Edit → Preferences → Dynamips → IOS Routers → New → Run locally**
   - Seleccionar la imagen descargada
   - RAM: 256 MB
   - Agregar módulo en slot 1: `NM-1FE-TX` (activa `fa0/1`)
4. Ejecutar **Idle-PC finder** y aplicar el valor recomendado (reduce uso de CPU)

**Switch:** usar el **Ethernet Switch** integrado de GNS3 (sin imagen adicional).

**VPCS:** el Virtual PC Simulator de GNS3 simula PC1. Su configuración **no persiste** entre reinicios de GNS3 — debe reconfigurarse cada sesión.

### 4.2 Agregar la VM Ubuntu a GNS3

La VM Ubuntu debe incorporarse como nodo VirtualBox en GNS3 (no como Cloud node). Esta integración usa **UDP tunnels via Generic Driver**, lo que permite tráfico bidireccional completo. Los Cloud nodes con adaptadores Host-Only de VirtualBox no funcionan para IPS inline (ver nota al final de esta sección).

1. En GNS3: **Edit → Preferences → VirtualBox → VirtualBox VMs → New**
2. Seleccionar la VM (ej. `linux02`)
3. En la configuración del template: **Edit → Network → Adapters: 3**
4. Guardar

> **Importante:** configurar el número de adaptadores en GNS3 **antes de iniciar la VM desde el canvas**. Si se reduce el número, GNS3 elimina los adaptadores correspondientes en VirtualBox. Adapter 3 (enp0s9) debe estar configurado como **Bridged** en VirtualBox y no debe ser eliminado.

### 4.3 Topología GNS3

```
                                   enp0s8         enp0s3
┌─────────────┐    ┌──────────┐  Adapter 1     Adapter 0   ┌───────────────┐
│  PC1 (VPCS) │────│ Switch1  │────────────────────────────│ linux02       │
│192.168.1.25 │    └──────────┘       Snort IPS inline     │ Ubuntu/Snort  │
└─────────────┘                                             └───────┬───────┘
                                                      Adapter 2     │     Adapter 0
                                                       (enp0s9)     │     (enp0s3)
                                                           │         │
                                                    ┌──────┘         └─────────┐
                                                    │                          │
                                               ┌────▼────┐              ┌──────▼──────┐
                                               │ Cloud1  │              │  R1         │
                                               │(internet│              │ Cisco 3725  │
                                               │/Azure)  │              │ 192.168.1.1 │
                                               └─────────┘              └─────────────┘
```

**Conexiones en el canvas de GNS3:**

| Nodo origen | Puerto | Nodo destino | Puerto | Función |
|---|---|---|---|---|
| PC1 | e0 | Switch1 | puerto 1 | Cliente → LAN |
| Switch1 | puerto 2 | linux02 | Adapter 1 (enp0s8) | LAN → entrada Snort |
| linux02 | Adapter 0 (enp0s3) | R1 | fa0/1 | Salida Snort → router |
| linux02 | Adapter 2 (enp0s9) | Cloud1 | — | Gestión / internet / Azure Arc |

Cloud1 debe estar mapeado a la NIC física de Windows con salida a internet (misma que usa el Bridged Adapter de VirtualBox).

### 4.4 Configurar el router R1 (Cisco 3725)

Abrir la consola del router (doble clic en GNS3 → **Console**). Si GNS3 usa Solar-PuTTY, la consola abre automáticamente.

Pegar la siguiente configuración completa:

```
enable
configure terminal
hostname R1
no service config
no service tcp-small-servers
no service udp-small-servers
no ip domain-lookup

interface FastEthernet0/0
 no ip address
 shutdown

interface FastEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown

no ip http server
line con 0
 logging synchronous
line vty 0 4
 no login
end
write memory
```

Verificar:
```
R1# show interfaces fa0/1
! FastEthernet0/1 debe estar "up/up" con IP 192.168.1.1
R1# show arp
```

### 4.5 Configurar PC1 (VPCS)

Doble clic en PC1 para abrir su consola:

```
ip 192.168.1.25/24 192.168.1.1
```

> **La configuración de VPCS no persiste entre reinicios de GNS3.** Ejecutar este comando al inicio de cada sesión. Para intentar guardar: escribir `save` en la consola de PC1 antes de cerrar GNS3, aunque no siempre se restaura.

### 4.6 Ejecutar Snort en modo IPS inline

Antes de iniciar Snort, eliminar cualquier bridge temporal creado durante diagnósticos:

```bash
# Si existe br0 de sesiones anteriores:
sudo ip link show br0 2>/dev/null && sudo ip link delete br0
```

Verificar que ambas interfaces inline están activas con PROMISC:

```bash
ip link show enp0s3
ip link show enp0s8
# Ambas deben mostrar: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP>
```

Si alguna está DOWN, levantarla manualmente:

```bash
sudo ip link set enp0s3 up
sudo ip link set enp0s8 up
```

Iniciar Snort en modo IPS:

```bash
sudo snort -Q --daq afpacket -i enp0s3:enp0s8 -c /etc/snort/snort.conf -A console
```

Snort debe mostrar `Commencing packet processing` sin errores FATAL.

### 4.7 Verificación del flujo inline

Con Snort corriendo, desde la consola de PC1 en GNS3:

```
PC1> ping 192.168.1.1
```

El ping debe responder correctamente (R1 en 192.168.1.1). El tráfico ICMP cruza: `PC1 → Switch1 → enp0s8 → Snort → enp0s3 → R1 fa0/1`.

Para confirmar que el tráfico pasa por Snort (en otra terminal del servidor):

```bash
# Ver tráfico en la interfaz LAN (desde Switch1):
sudo tcpdump -i enp0s8 -n icmp

# Ver tráfico en la interfaz WAN (hacia R1):
sudo tcpdump -i enp0s3 -n icmp
```

Ambas interfaces deben mostrar los paquetes ICMP. Si aparecen en enp0s8 pero no en enp0s3, Snort no está reenviando (verificar DAQ afpacket y modo promiscuo).

Para ver alertas en tiempo real mientras hay tráfico:

```bash
tail -f /var/log/snort/snort.alert.fast
```

### 4.8 Acceso SSH al servidor desde Azure

Con el servidor registrado en Azure Arc y `enp0s9` con IP 192.168.1.202 e internet activo:

```bash
az ssh arc --resource-group snortids --name linux02 --local-user sysadmin
```

Esto abre un túnel SSH a través de Azure Arc sin necesidad de exponer el servidor directamente a internet.

---

> **Nota: por qué Cloud nodes no funcionan para IPS inline**
>
> Durante la configuración se intentó usar nodos Cloud de GNS3 mapeados a los adaptadores Host-Only de VirtualBox (vboxnet0, vboxnet1). Esta topología **no funciona** para IPS inline bidireccional.
>
> El problema: Npcap/WinPcap en Windows puede capturar frames que la VM envía al adaptador Host-Only (dirección VM→GNS3), pero **no puede inyectar frames unicast hacia la VM** (dirección GNS3→VM) en ese mismo adaptador. El resultado es tráfico unidireccional — los ARP y pings del router llegaban a `enp0s8` pero nunca salían por `enp0s3` de regreso.
>
> **Solución:** agregar la VM Ubuntu directamente como nodo VirtualBox en GNS3 (Edit → Preferences → VirtualBox VMs). GNS3 usa UDP tunnels via Generic Driver, que bypasea completamente el Host-Only networking y provee comunicación bidireccional completa.

---

## 5. Cliente Windows (generación de tráfico de prueba)

Instalar [nmap](https://nmap.org/) para simular ataques y reconocimiento.

**Escaneo TCP (detectable por Snort):**
```powershell
nmap -sT -Pn 192.168.1.201
```

**Escaneo SYN (más rápido, detectable por la regla de port scan):**
```powershell
nmap -sS -Pn 192.168.1.201
```

**Intento de conexión SSH (activa la regla `sid:1000010`):**
```powershell
ssh administrator@192.168.1.201
```

**Descargar log de Snort desde el servidor:**
```powershell
scp administrator@192.168.1.201:/var/log/snort/snort.alert.fast C:\Users\TuUsuario\Descargas\
```

---

## 6. Verificación end-to-end

1. **Verificar tráfico en la interfaz:**
   ```bash
   sudo tcpdump -i enp0s3 -n | head -20
   ```

2. **Iniciar Snort y generar tráfico:**
   ```bash
   # Servidor
   sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf -k none
   ```
   ```powershell
   # Cliente Windows
   nmap -sT -Pn 192.168.1.201
   ```
   Las alertas deben aparecer en la consola del servidor en tiempo real.

3. **Verificar escritura de logs:**
   ```bash
   tail -f /var/log/snort/snort.alert.fast
   ```

4. **Verificar que Azure Monitor Agent envía datos:**
   ```bash
   sudo systemctl status azuremonitoragent
   ```

5. **Validar datos en Azure (Log Analytics):**
   ```kql
   SnortAlerts_CL
   | take 10
   ```
   Los datos pueden demorar hasta 10 minutos en la primera ingesta.

---

## 7. Troubleshooting

| Problema | Causa probable | Solución |
|---|---|---|
| Snort no detecta tráfico | Interfaz no está en modo promiscuo | `sudo ip link set enp0s3 promisc on` |
| Error `FATAL` al validar con `-T` | Falta la flag `-i <interfaz>` | `sudo snort -T -i enp0s3:enp0s8 -c /etc/snort/snort.conf` |
| Modo IPS no pasa tráfico | `enp0s8` DOWN o sin PROMISC | `sudo ip link set enp0s8 up && sudo ip link set enp0s8 promisc on` |
| Flood de alertas `sid:527` | IPv6 NDP multicast | Agregar `suppress gen_id 1, sig_id 527` en `threshold.conf` y deshabilitar IPv6 en sysctl |
| PC1 no puede hacer ping a R1 | VPCS perdió su IP tras reinicio | Reconfiguraar: `ip 192.168.1.25/24 192.168.1.1` en consola de PC1 |
| Ping falla solo en una dirección | Bridge `br0` interferiendo con Snort | `sudo ip link delete br0` antes de iniciar Snort |
| Cloud nodes no funcionan para IPS | Npcap no puede inyectar unicast en Host-Only | Usar GNS3 VirtualBox VM integration (Edit → Preferences → VirtualBox VMs), no Cloud nodes |
| GNS3 elimina Adapter 3 al arrancar | Adaptadores en GNS3 configurados a menos de 3 | Ir a GNS3 → Preferences → VirtualBox VMs → Edit → Network → Adapters: 3 |
| `enp0s8` no aparece tras agregar Adapter 2 | VirtualBox no notifica en caliente a la VM | `sudo ip link set enp0s8 up` dentro de la VM |
| Azure Monitor Agent no instala | Espacio insuficiente en disco | Cambiar el disco virtual a capacidad fija en VirtualBox |
| Logs no aparecen en Azure | DCR no asociada o ruta incorrecta | Verificar Resources y Data Source en `DCR-Snort`; ruta: `/var/log/snort/snort.alert.fast` |
| Router GNS3 consume 100% CPU | Falta valor Idle-PC | Ejecutar Idle-PC finder en GNS3 y aplicar el valor recomendado |
| Snort termina inmediatamente en IPS | DAQ afpacket no disponible | `sudo apt install snort-rules-default libdumbnet1` |
| `community-*.rules not found` | Archivos de reglas no instalados | `sudo apt install snort-rules-default` |
