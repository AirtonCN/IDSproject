# Configurar Servidor
## Instalar snort

```bash
sudo apt update 
sudo apt install snort
```

## Ejecutar Snort con la interfaz enp0s en modo promiscuo
sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf -k none
## Verificar si la vm recibe tráfico
sudo tcpdump -i eth0
## verificar las ip de donde proviene el tráfico
sudo tcpdump -i eth0 | grep IP
