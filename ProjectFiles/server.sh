#Instalar snort
sudo apt update
sudo apt install snort
#Ejecutar Snort con la interfaz enp0s en modo promiscuo
sudo snort -A console -i enp0s3 -c /etc/snort/snort.conf -k none
#Verificar si la vm recibe tráfico
sudo tcpdump -i eth0
#verificar las ip de donde proviene el tráfico
sudo tcpdump -i eth0 | grep IP


#Configurar Snort para ignorar ciertas IPs usando pass rules o HOME_NEEn el archivo /etc/snort/snort.conf:
ipvar HOME_NET [192.168.0.105]  # solo tu host
#O
ipvar EXTERNAL_NET !$HOME_NET



#Instalar OpenSSH para descargar o subir archivos a un server linux
sudo apt install openssh-server
#Por tema de permisos copiar primero los archivos a un 
