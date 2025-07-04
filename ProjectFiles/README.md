# Despliegue

## Servidor (Linux)

### Configurar conectividad del servidor
Verificar IP, interfaz enp0s3
```bash
ip addr show enp0s3
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
Instalar nmap.
https://nmap.org/

Generar tráfico malicioso con nmap
```powershell
nmap -sS [IP de la VM Snort]
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
Configurar Snort para ignorar ciertas IPs usando pass rules o HOME_NEEn el archivo /etc/snort/snort.conf:

```
ipvar HOME_NET [192.168.1.x]  # solo tu host
```
o
```
ipvar EXTERNAL_NET !$HOME_NET
```
Agrega la regla ejemplo deteccion de intetno SSHH en el acrhivo /etc/snort/rules/local.rules
```
alert tcp any any -> $HOME_NET 22 (msg:"[Snort IDS] SSH Access Attempt"; sid:1000010; rev:1;)
``` 





