::Enviar tráfico sospechoso a la vm con snort
nmap -sS [IP de la VM Snort]

::Descargar archivo del server linux
scp usuario@192.168.x.x:/home/usuario/snort.log C:\Users\TuUsuario\Descargas\

::Subir archivo al server linux
scp archivo.txt usuario@192.168.x.x:/home/usuario/
