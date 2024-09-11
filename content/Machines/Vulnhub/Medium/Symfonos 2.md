#ctf-machine #vulnhub #medium-machine #linux  [VulnbubLink](https://www.vulnhub.com/entry/symfonos-2,331/)

## Enumeración inicial
Como no sabemos la dirección IP de la máquina víctima, realizamos un escaneo ARP con `arp-scan`:
![[Pasted image 20240901175131.png]]

Como podemos ver la IPv4 de la máquina es "192.168.159.150" ya que el OUI de la dirección MAC es "00:0c" correspondiente a las máquinas que se importan en VMWare.

Lanzamos una traza ICMP con `ping` para ver su valor de TTL.:
![[Pasted image 20240901175157.png]]

Como el TTL=64 podemos decir que probablemente se trate de una máquina Linux, ya que suelen tener ese valor.

### Nmap
Realizamos un primer escaneo con `nmap` para detectar los puertos TCP abiertos:
![[Pasted image 20240901175306.png]]

Como vemos hay 5 puertos abiertos, el puerto 21,22,80,139 y 445.

Realizamos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240901175454.png]]

Como vemos corren los servicios "ProFTPD" por el puerto 21, "OpenSSH 7.4p1" por el puerto 22, "WebFS" por el puerto 80 y "Samba smbd" por el puerto 445.


## Enumeración SMB
Si utilizamos `smbclient` para listar los recursos disponibles, vemos un recurso "anonymous":
![[Pasted image 20240901175915.png]]

El cual si intentamos acceder sin contraseña obtenemos acceso. Por lo que si listamos el contenido, vemos un directorio "backups":
![[Pasted image 20240901180000.png]]

Dicho directorio contiene un archivo llamado "log.txt", por lo que nos lo descargamos con "get".
![[Pasted image 20240901180107.png]]

Si analizamos el archivo vemos que el usuario *root*, guarda el archivo `/etc/shadows` en el directorio `/var/backups/shadow.bak`:
![[Pasted image 20240901180619.png]]

Además, podemos ver listados el contenido del archivo de configuración de "smb" y del "proftpd".

Si nos fijamos en el archivo de configuración de smb podemos ver una credencial de la base de datos:
![[Pasted image 20240901181028.png]]

## Enumeración web
Si accedemos a la página principal de la web vemos una imagen:
![[Pasted image 20240901181535.png]]

Como no hay nada interesante, hacemos un escaneo de directorios y archivos con `gobuster`, pero no encontramos nada.

## RCE
Si buscamos con `searchsploit` vulnerabilidades de "ProFTPd 1.3.5" vemos que existe una que permite RCE:
![[Pasted image 20240901182724.png]]

Por lo que si analizamos la vulnerabilidad, nos permite copiar un archivo, y pegarlo en otra ubicación del sistema. Por lo que podemos intentar copiar el archivo `/var/backups/shadow.bak` en el directorio `/home/aeolus/share` que es donde está el servicio SMB expuesto con el recurso "anonymous":
> [!NOTE] No lo copiamos en el directorio web porque no tenemos permisos de escritura.

Como vemos en el documento "smb.conf" el recurso "anonymoys" se encuentra en la ruta indicada:
![[Pasted image 20240901184052.png]]

Por lo que nos conectamos con `nc` al puerto 21 de la máquina víctima y copiamos el archivo a este directorio:
![[Pasted image 20240901184326.png]]

Por lo que si nos conectamos mediante `smbclient`, accedemos al recurso "anonymous" y nos podemos descargar el recurso con "get":
![[Pasted image 20240901184506.png]]

Si mostramos el contenido del archivo vemos 3 *hashes*:
![[Pasted image 20240901184634.png]]

Por lo que podemos utilizar `unshadow` después de descargarnos también el archivo `/etc/passwd` de la máquina víctima para generar *hashes* útiles para `john`:
![[Pasted image 20240901190601.png]]

Si lo intentamos *crackear* con `john`, extraemos la contraseña del usuario "aeolus".
![[Pasted image 20240901190847.png]]

Por lo que nos conectamos por SSH a la máquina:
![[Pasted image 20240901191002.png]]

## Escalada de privilegios
Si mostramos los servicios internos, vemos que el puerto 8080 esta abierto:
![[Pasted image 20240901195040.png]]

Por lo que nos descargamos `chisel` y hacemos que el puerto 8080 de la máquina víctima se convierta en nuestro puerto 8080 y así lograr tener acceso a ese puerto desde nuestra máquina.
![[Pasted image 20240901195621.png]]

Así que lo ejecutamos como servidor en nuestra máquina:
![[Pasted image 20240901195644.png]]

Y nos conectamos como clientes en la máquina víctima para que el puerto 8080 de la máquina víctima se convierta en nuestro puerto 8080:
![[Pasted image 20240901195734.png]]

Por lo que si ahora accedemos al *localhost* por el puerto 8080, vemos lo siguiente:
![[Pasted image 20240901195844.png]]

Si reutilizamos las credenciales que tenemos de "aeolus", accedemos dentro:
![[Pasted image 20240901200053.png]]

Si buscamos por vulnerabilidades de LibreNMS con `searchsploit`, vemos lo siguiente:
![[Pasted image 20240901200237.png]]

Parece ser que tenemos inyección de comandos.

Por lo que nos aprovechamos de la vulnerabilidad seleccionando "Add Device":
![[Pasted image 20240901200513.png]]

Y añadimos un *device* con el comando inyectado:
![[Pasted image 20240901210703.png]]

Y si ahora accedemos al siguiente enlace, se ejecuta el comando:
http://127.0.0.1:8080/ajax_output.php?id=capture&format=text&type=snmpwalk&hostname=pwned

Por lo que obtenemos una *reverse shell* por el puerto 443 como el usuario "cronus":
![[Pasted image 20240901210907.png]]

Así que hacemos el tratamiento de la TTY:
![[Pasted image 20240901211146.png]]
![[Pasted image 20240901211212.png]]

Si mostramos los permisos a nivel de *sudoers* vemos que tenemos capacidad de ejecutar *mysql* como  el usuario *root*:
![[Pasted image 20240901211626.png]]

Por lo que podemos ejecutar el siguiente comando para obtener una "bash" como *root*:
![[Pasted image 20240901211704.png]]

Así que si nos dirigimos al directorio `/root` podemos visualizar la *flag*:
![[Pasted image 20240901211739.png]]

___
#command-injection #abusing-sudoers #abusing-internal-services #abusing-sudoers #information-leakage #hash-cracking 
___




