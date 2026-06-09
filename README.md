# IDS Project — Snort + Azure Monitor

Sistema de detección de intrusiones (IDS) basado en Snort sobre Ubuntu 22.04, integrado con Azure Monitor para visualización centralizada de alertas. Incluye un entorno de pruebas controlado con GNS3 y un router Cisco 3725.

## Arquitectura

```
┌─────────────────┐        ┌──────────────────┐        ┌──────────────────────┐
│ Windows (Client)│        │   GNS3 / Router  │        │  Ubuntu 22.04 Server │
│                 │        │   Cisco 3725      │        │                      │
│  nmap (ataque)  │──────▶ │  192.168.1.202   │──────▶ │  Snort IDS           │
│  192.168.1.25   │        │                  │        │  192.168.1.201       │
└─────────────────┘        └──────────────────┘        └──────────┬───────────┘
                                                                   │
                                                         Azure Monitor Agent
                                                                   │
                                                      ┌────────────▼────────────┐
                                                      │   Azure Log Analytics   │
                                                      │   Workspace             │
                                                      │   SnortAlerts_CL        │
                                                      └─────────────────────────┘
```

**Flujo de datos:** tráfico generado desde el cliente → capturado por Snort en `enp0s3` → alertas en `/var/log/snort/snort.alert.fast` → recolectadas por Azure Monitor Agent → tabla `SnortAlerts_CL` en Log Analytics.

---

## Prerrequisitos

| Componente | Versión / Detalle |
|---|---|
| Ubuntu Server | 22.04 LTS |
| Snort | 2.9.x (paquete `apt`) |
| GNS3 Desktop + GNS3 VM | Última versión estable |
| Imagen Cisco IOS | `c3725-adventerprisek9-mz.124-15.T14.image` |
| Azure | Suscripción activa, Log Analytics Workspace creado |
| Windows Client | nmap instalado |

---

## 1. Servidor (Ubuntu 22.04)

### 1.1 Configurar red

Se recomienda desconectar la interfaz de internet durante la instalación y activar DHCP para conectarse por SSH en el primer arranque.

Verificar la interfaz principal:
```bash
ip addr show enp0s3
```

Realizar una copia de seguridad del archivo de netplan antes de modificarlo:
```bash
sudo cp /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bak
```

Deshabilitar cloud-init para que no sobreescriba la configuración:
```bash
sudo touch /etc/cloud/cloud-init.disabled
```

Reemplazar el contenido de `/etc/netplan/50-cloud-init.yaml` con la siguiente configuración de IP estática:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      addresses:
        - 192.168.1.201/24
      nameservers:
        addresses:
          - 192.168.1.1
      routes:
      - to: default
        via: 192.168.1.1
```

Probar y aplicar:
```bash
sudo netplan try
sudo netplan apply
```

### 1.2 Instalar OpenSSH

```bash
sudo apt install openssh-server
```

### 1.3 Conectar a Azure Arc

1. Ingresar al portal Azure → **Azure Arc** → **Machines** → **Add a single machine**
2. Generar y descargar el script de onboarding
3. Transferir el script al servidor y darle permisos de ejecución:
```bash
sudo chmod +x OnboardingScript.sh
sudo ./OnboardingScript.sh
```
El servidor aparecerá como recurso en Azure Arc una vez completado.

> **Nota de seguridad:** el script contiene `subscriptionId` y `tenantId`. Generar uno nuevo desde el portal si es necesario y no subirlo a repositorios públicos.

### 1.4 Instalar Azure Monitor Agent

Desde el portal Azure:
1. Azure Arc → seleccionar el servidor → **Extensions** → **Add**
2. Buscar y seleccionar **Azure Monitor Agent for Linux**

Verificar que el servicio esté activo:
```bash
sudo systemctl status azuremonitoragent
```

> **Problema conocido:** si aparece error de espacio insuficiente durante la instalación, cambiar el disco virtual a capacidad fija en la configuración de la VM.

---

## 2. IDS — Snort

### 2.1 Instalación

```bash
sudo apt update
sudo apt install snort
```

Habilitar modo promiscuo en la interfaz para capturar todo el tráfico de la red:
```bash
sudo ip link set enp0s3 promisc on
```

Verificar que el modo esté activo (debe mostrar `PROMISC` en los flags):
```bash
ip link show enp0s3
```

### 2.2 Configuración (ids.conf)

El archivo de configuración del proyecto se encuentra en `/etc/snort/ids.conf`. Las variables clave son:

```
# Red protegida (servidor víctima)
ipvar HOME_NET [192.168.1.201]

# Origen del tráfico externo a monitorear
ipvar EXTERNAL_NET [192.168.1.25]
```

Validar que la configuración no tenga errores antes de ejecutar:
```bash
sudo snort -T -c /etc/snort/ids.conf
```

### 2.3 Reglas (local.rules)

Las reglas personalizadas se definen en `/etc/snort/rules/local.rules`. Regla actual:

```
# Detecta intentos de conexión SSH al servidor
alert tcp any any -> $HOME_NET 22 (msg:"[Snort IDS] SSH Access Attempt"; sid:1000010; rev:1;)
```

Para agregar nuevas reglas, respetar el formato `sid` único (usar `1000011`, `1000012`, etc. para reglas propias).

### 2.4 Ejecutar Snort

**Modo IDS (pasivo) — monitoreo en consola:**
```bash
sudo snort -A console -i enp0s3 -c /etc/snort/ids.conf -k none
```

**Modo IPS (inline) — inspección entre dos interfaces:**
```bash
sudo snort -Q --daq afpacket -i enp0s8:enp0s3 -c /etc/snort/ids.conf -A console
```
Este modo requiere agregar una segunda interfaz `enp0s8` a la VM en modo bridged (ver sección 4).

Las alertas se almacenan en:
```
/var/log/snort/snort.alert.fast
```

---

## 3. Cliente (Windows)

Instalar [nmap](https://nmap.org/) para la generación de tráfico de prueba.

**Escaneo de puertos (simula reconocimiento):**
```powershell
nmap -sT -Pn 192.168.1.201
```

**Transferencia de archivos con el servidor:**

Descargar log de Snort desde el servidor:
```powershell
scp administrator@192.168.1.201:/var/log/snort/snort.alert.fast C:\Users\TuUsuario\Descargas\
```

Subir archivo al servidor:
```powershell
scp archivo.txt administrator@192.168.1.201:/home/administrator/
```

---

## 4. Entorno controlado (GNS3)

### 4.1 Instalación

1. Descargar GNS3 Desktop y GNS3 VM desde [gns3.com](https://www.gns3.com/)
2. Descargar la imagen del router Cisco 3725: `c3725-adventerprisek9-mz.124-15.T14.image`
3. En GNS3: **Edit → Preferences → Dynamips → IOS Routers → New → GNS3 VM**
   - Seleccionar la imagen descargada
   - RAM: 256 MB
   - Adaptadores adicionales: `NM-1FE-TX` y `NM-4T`
   - Slot WIC: `WIC-1T`
4. Ejecutar **Idle-PC finder** y usar el valor recomendado (reduce el uso de CPU)

**Switch:** usar el switch Ethernet integrado de GNS3 (Ethernet Switch) para topologías simples. Para funcionalidades avanzadas de Capa 2 se puede usar una imagen IOU L2.

### 4.2 Topología y configuración del router

En el canvas de GNS3, agregar:
- Un nodo **Cloud** (conectado a la interfaz física del equipo host)
- El router **Cisco 3725**

Hacer doble clic en el nodo Cloud → seleccionar únicamente la interfaz de red principal del equipo host.

Configurar el router (acceder con doble clic o consola):
```
enable
configure terminal
no service config
no service tcp-small-servers
no service udp-small-servers
interface FastEthernet0/0
 ip address 192.168.1.202 255.255.255.0
 no shutdown
 exit
ip route 0.0.0.0 0.0.0.0 192.168.1.1
write memory
```

### 4.3 Configurar segunda interfaz para modo inline (IPS)

Agregar un segundo adaptador de red bridged a la VM Ubuntu en VirtualBox/VMware.

Actualizar `/etc/netplan/50-cloud-init.yaml` para incluir la segunda interfaz:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: false
      addresses:
        - 192.168.1.201/24
      nameservers:
        addresses:
          - 192.168.1.1
      routes:
      - to: default
        via: 192.168.1.1
    enp0s8:
      dhcp4: false
      dhcp6: false
      optional: true
```

Aplicar cambios:
```bash
sudo netplan apply
```

---

## 5. Integración con Azure

### 5.1 Crear tabla de logs personalizada

En el portal Azure → Log Analytics Workspace:
1. **Tables → Create → New custom log (MMA-based)**
2. Nombre de la tabla: `SnortAlerts_CL`
3. Ruta del log en el servidor: `/var/log/snort/snort.alert.fast`

Los registros comenzarán a aparecer como texto plano en la tabla después de algunos minutos.

### 5.2 Consulta KQL para parsear alertas

En **Logs** del workspace, activar el modo KQL e introducir:

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

---

## 6. Verificación end-to-end

1. **Verificar tráfico en la interfaz del servidor:**
   ```bash
   sudo tcpdump -i enp0s3 | grep IP
   ```

2. **Ejecutar Snort y generar tráfico desde el cliente:**
   ```bash
   # En el servidor
   sudo snort -A console -i enp0s3 -c /etc/snort/ids.conf -k none
   ```
   ```powershell
   # En el cliente Windows
   nmap -sT -Pn 192.168.1.201
   ```
   Deben aparecer alertas en la consola del servidor.

3. **Verificar que los logs se escriben:**
   ```bash
   tail -f /var/log/snort/snort.alert.fast
   ```

4. **Verificar que Azure Monitor Agent está enviando datos:**
   ```bash
   sudo systemctl status azuremonitoragent
   ```
   En el portal, ejecutar la query KQL — los datos pueden demorar 5-10 minutos en aparecer por primera vez.

---

## 7. Troubleshooting

| Problema | Causa probable | Solución |
|---|---|---|
| Snort no detecta tráfico | Interfaz no está en modo promiscuo | `sudo ip link set enp0s3 promisc on` |
| Error `FATAL` al validar con `-T` | Falta la flag `-i <interfaz>` en modo test | `sudo snort -T -i enp0s3 -c /etc/snort/ids.conf` |
| Azure Monitor Agent no instala | Espacio insuficiente en disco | Cambiar el disco virtual a capacidad fija en la VM |
| Logs no aparecen en Azure | Data Collection Rule no configurada | Verificar DCR asociada al workspace en Azure Monitor |
| Router GNS3 consume 100% CPU | Falta valor Idle-PC | Ejecutar Idle-PC finder y aplicar el valor recomendado |
| Modo inline no funciona | Segunda interfaz no disponible | Verificar que `enp0s8` aparece con `ip link show` |
