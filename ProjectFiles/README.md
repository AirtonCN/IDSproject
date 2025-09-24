# Despliegue

## Servidor (Linux)

### Configurar servidor y conectividad
Verificar IP, interfaz enp0s3
```bash
ip addr show enp0s3
```
Desactivar servicio que impide iniciar rápido el servidor
```bash
systemctl disable systemd-networkd-wait-online.service
```

```bash
systemctl mask systemd-networkd-wait-online.service
```

Para onfigurar ip estatica directorio /etc/netplan, 

* Realizar una copia del archivo 50-cloud-init.yaml

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
### Configurar Azure Arc para visualizar el servidor on-premise como un recurso mas de azure

Pasos a seguir:
* Ingresamos a Azure portal Azure Arc 
* Machines 
* Add a single machine 
* Generamos y descargamos el script
```bash
export subscriptionId="a8cbb876-3c0b-41e0-914a-8b378aa251a1";
export resourceGroup="testenvironment02";
export tenantId="97ddd0b5-4ba0-4f0f-9887-6cc62ff2e6f6";
export location="eastus";
export authType="token";
export correlationId="d651ce4a-6c03-4870-b798-6f7357156657";
export cloud="AzureCloud";


# Download the installation package
LINUX_INSTALL_SCRIPT="/tmp/install_linux_azcmagent.sh"
if [ -f "$LINUX_INSTALL_SCRIPT" ]; then rm -f "$LINUX_INSTALL_SCRIPT"; fi;
output=$(wget https://gbl.his.arc.azure.com/azcmagent-linux -O "$LINUX_INSTALL_SCRIPT" 2>&1);
if [ $? != 0 ]; then wget -qO- --method=PUT --body-data="{\"subscriptionId\":\"$subscriptionId\",\"resourceGroup\":\"$resourceGroup\",\"tenantId\":\"$tenantId\",\"location\":\"$location\",\"correlationId\":\"$correlationId\",\"authType\":\"$authType\",\"operation\":\"onboarding\",\"messageType\":\"DownloadScriptFailed\",\"message\":\"$output\"}" "https://gbl.his.arc.azure.com/log" &> /dev/null || true; fi;
echo "$output";

# Install the hybrid agent
bash "$LINUX_INSTALL_SCRIPT";
sleep 5;

# Run connect command
sudo azcmagent connect --resource-group "$resourceGroup" --tenant-id "$tenantId" --location "$location" --subscription-id "$subscriptionId" --cloud "$cloud" --correlation-id "$correlationId";
```
   
* Ejecutamos el script en el servidor y deberia figurar ya en el apartado machines.
```
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
```
sudo systemctl status azuremonitoragent
```
---
### Instalar y probar snort 3

Requiere muchas dependencias, se instalara como un contenedor docker. Se realizara un ajuste de modo que el archivo de configuracion lua y las reglas sean legibles desde el server, para ello se deben crear unas cuantas carpetas, se detalla en el archivo filestructure.txt.
* Instalar docker.
  ```bash
  sudo apt install docker.io
  ```
* Descargar la imagen oficial de snort 3.
  ```bash
  docker pull ciscotalos/snort3
  ```
* Iniciar el contenedor snort ejecutar start.sh.
  ```bash
  docker run --name snort3 -h snort3 -u snorty -w /home/snorty -d -it ciscotalos/snort3 bash
  ```
* Copiar el archivo de configuracion .lua para que sea legible desde el server.
  ```bash
  docker cp snort3:/home/snorty/snort3/etc/snort/snort.lua /home/administrator/snort/snortconfig/snort.lua
  ``` 
* Copiar el archivo de reglas para que sea legible desde el server.
  ```bash
  docker cp snort3:/home/snorty/snort3/etc/rules/snort3-community.rules /home/administrator/snort/snortconfig/rules/
  ```





* Interactuar con el contenedor ejecutar interact.sh.
  ```
  docker exec -it snort3 bash
  ```

* Ejecutar el IDS.
  ```bash
  ```
* Salir de la interaccion con snort 3.
  ```bash
  exit
  ```
* Detener el contenedor de snort 3.
  ```bash
  docker kill snort3
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
Instalar nmap.
https://nmap.org/

Generar tráfico malicioso con nmap
```powershell
nmap -sT -Pn 192.168.1.201
```
Descargar archivo del server linux

```powershell
scp administrator@192.168.1.201:/home/usuario/snort.log 
C:\Users\TuUsuario\Descargas\
```

Subir archivo al server linux
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

## Envio de logs a Azure portal
* Crear un log analytics workspace llamado Snort-Alerts.
* Crear un data collection endpoint llamado snort-dce.
  ```bash
  az monitor data-collection endpoint create \
    --name snort-dce \
    --resource-group testenvironment02 \
    --location eastus \
    --public-network-access "Enabled"
  ```

* Crear una tabla donde subiremos una muestra del log, la tabla se llama SnortAlerts_CL
* Ingresamos a log analytics workspace en azure.
* En apartado Agents > Linux.
  * Creamos una DCR (Data collection rule) llamada SnortAlerts.
  * Rellenamos los datos con nuestra tabla previamente creada y el data collection endpoing.
  * En el apartado resources agregamos nuestro servidor previamente configurado con azure arc.
  * En el siguiente apartado de dta collection rule, seleccionamos como source custom text log, como destino nuestro loganalytics workspace previamente creado.
* En collect and deliver seleccionamos custom text log, ingresamos la ruta del log: /var/log/snort/snort.alert.fast
  * 
* 



