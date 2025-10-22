# Despliegue

## Servidor (Linux)

### Configurar conectividad del servidor

Se debe usar UBUNTU 22.04 para evitar problemas de compatibilidad.

Verificar IP, interfaz enp0s3
```bash
ip addr show enp0s3
```
Para onfigurar ip estatica directorio /etc/netplan, 

* Realizar una copia del archivo 50-cloud-init.yaml

* Asegurarse que se tengan permisos -rw- para root en el archivo .yaml.

* Desactivar el servicio cloud.init.

```bash
sudo touch /etc/cloud/cloud-init.disabled
```

* Configurar IP fija reemplazando todo el contenido por esto
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
Probar config
```bash
sudo netplan try
```
Aplicar cambios directamente
```bash
sudo netplan apply
```
### Instalar OpenSSH para poder transferir archivos al servirdor
```bash
sudo apt install openssh-server
```
### Configurar Azure Arc para visualizar el servidor on-premise como un recurso mas de azure

Pasos a seguir:
* Ingresamos a Azure portal Azure Arc 
* Machines 
* Add a single machine 
* Generamos y descargamos el script
* Ejecutamos el script en el servidor y deberia figurar ya en azure.

* Validar que se tengan permisos de ejecucion.

```bash
sudo chmod +x OnboardingScript.sh
```

* Ejecutar el script

```bash
sudo ./OnboardingScript.sh
```

---
### Instalar la extension Azure Monitor Agent en el servidor, desde el portal Azure

* Ingresar al portal azure.
* Buscar e ingrear a azure arc.
* Seleccionar el servidor.
* Ingresar a extensiones y dar clic en agregar.
* Buscar y seleccionar Azure Monitor Agent for Linux.
* En este caso nos topamos con el error de espacio insuficiente en el servidor, se tuvo que cambiar el disco a capacidad fija.
* Validamos que el servicio este en activo.

```bash
sudo systemctl status azuremonitoragent
```
---
### Instalar y probar snort

Instalar
```bash
sudo apt update 
sudo apt install snort
```
Verificar si la interfaz de red esta en modo promiscuo
```bash
ip link show enp0s3
```
Habilitar el modo promiscuo en la interfaz deseada
```bash
sudo ip link set enp0s3 promisc on
```
Ejecutar Snort con la interfaz enp0s en modo promiscuo
```bash
sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf -k none
```
Verificar si la vm recibe tráfico
```bash
sudo tcpdump -i enp0s3
```
Verificar las ip de donde proviene el tráfico
```bash
sudo tcpdump -i enp0s3 | grep IP
```
---
## Cliente (Windows)

Instalar nmap para el escaneo de puertos.
https://nmap.org/

Generar tráfico malicioso con nmap
```powershell
nmap -sT -Pn 192.168.1.201
```
Algunos comandos para subir y descargar archivos de nuestro server donde esta el IDS.

* Descargar archivo del server linux

  ```powershell
  scp administrator@192.168.1.201:/home/usuario/snort.log 
  C:\Users\TuUsuario\Descargas\
  ```

* Subir archivo al server linux
  ```powershell
  scp archivo.txt uadministrator@192.168.1.201:/home/usuario/
  ```

## Configurar IDS

Configurar Snort para ignorar ciertas IPs usando pass rules o HOME_NET en el archivo /etc/snort/snort.conf, todo esto se configurara en otro archivo llamado, ids.conf:

Ip victima (linea 65)
```
ipvar HOME_NET [192.168.1.201]
```
IP de donde proviene el trafico (linea 75)
```
ipvar EXTERNAL_NET [192.168.1.25]
```
Verificar la configuracion del archivo .conf
```bash
sudo snort -T -c /etc/snort/ids.conf
```
Se agrega una regla al archivo /etc/snort/rules/local.rules, para detectar intentos de conexión SSH
```
alert tcp any any -> $HOME_NET 22 (msg:"[Snort IDS] SSH Access Attempt"; sid:1000010; rev:1;)
```
Ejecutar SNORT con la configuración ids.conf
```bash
sudo snort -A console -i enp0s3 -c /etc/snort/ids.conf -k none
```
Las alertas son almacenadas en /var/log/snort/snort.alert.fast

* El siguiente paso es enviar las alertas a azure
---
## Crear un custom log en Azure para ver los registros de snort
* Crear una tabla en el workspace, MMA-based, llamada SnortAlerts_CL, especificar ruta de logs de snort /var/log/snort/snort.alert.fast
* Ahora podemos ver los logs la tabla en el workspace como texto plano en el portal azure.

### Uso de Kusto Query Language para mostrar los logs de forma mas ordenada
* En el apartado logs habilitamos la vista KQL mode e introducimos el siguiente query.
  ```
  SnortAlerts_CL
  | extend
      timestamp = extract(@"^(\d+/\d+-\d+:\d+:\d+\.\d+)", 1, RawData),
      sid = extract(@"\[(\d+):(\d+):(\d+)\]", 0, RawData),
      msg = extract(@"\]\s*(.*?)\s*\[\*\*\]", 1, RawData),
      classification = extract(@"\[Classification:\s*(.*?)\]", 1, RawData),
      priority = extract(@"\[Priority:\s*(\d+)\]", 1, RawData),
      protocol = extract(@"\{(\w+)\}", 1, RawData),
      src = extract(@"\}\s*([a-fA-F0-9:\.]+):(\d+)", 0, RawData),
      src_ip = extract(@"\}\s*([a-fA-F0-9:\.]+):(\d+)", 1, RawData),
      src_port = extract(@"\}\s*([a-fA-F0-9:\.]+):(\d+)", 2, RawData),
      dst_ip = extract(@"->\s*([a-fA-F0-9:\.]+):(\d+)", 1, RawData),
      dst_port = extract(@"->\s*([a-fA-F0-9:\.]+):(\d+)", 2, RawData)
  | project timestamp, msg, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port
  | order by timestamp desc
  ```

# Montaje de un entorno controlado para pruebas del IDS/IPS
* Descargar GNS3 y GNS3 VM.
* Descargar la imagen del router cisco 3725 https://upw.io/8RU/c3725-adventerprisek9-mz.124-15.T14.image
* Cargar la imagen en GNS3 Edit > Preferences > Dynamips > IOS Routers > New > GNS3 VM > Seleccionar la imagen > Ram 256MB
* Seleccionamos dos adaptadores de red adicionales, NM-1FE-TX y NM-4T.
* Seleccionamos WIC-1T en el siguiente slot.
* Seleccionar Idle-PC finder, y usar el valor recomendado.
* Descargar la imagen del switch ////

## Configurar router
* En dispositivos colocar un cloud y el router cisco previamente configurado.
* Hacer doble clic en el nodo cloud y seleccionar la interfaz principal de nuestro equipo y retirar las demas.
* Realizar la siguiente config en el router.
  ```bash
  enable
  configure terminal
  no service config
  no service tcp-small-servers
  no service udp-small-servers
  exit
  write memory
  interface FastEthernet0/0
  ip address 192.168.1.202 255.255.255.0
  no shutdown
  exit
  ip route 0.0.0.0 0.0.0.0 192.168.1.1
  ```
* Nueva configuracion ip en el servidor, agregar un bridged adapter adicional y modificar archivo yaml netplan.
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
  #habilitacion de una seguda interfaz en modo sniffer.
      enp0s8:
        dhcp4: false
        dhcp6: false
        optional: true
  ```
* Prueba con --daq afpacket en modo inlne, esto crea un puente de inspeccion entre ambas interfaces.
  
```bash
  sudo snort -Q --daq afpacket -i enp0s8:enp0s3 -c /etc/snort/ids.conf -A console
```
# Comandos usados en Git