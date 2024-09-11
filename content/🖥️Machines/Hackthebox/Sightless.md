#ctf-machine #hackthebox #easy-machine #linux 

![[Sightless.png]]

## Enumeración inicial
Primeramente lanzamos una traza ICMP con `ping` a la máquina víctima:
![[Pasted image 20240908104735.png]]

Como el TTL es muy cercano a 64, probablemente se trate de una máquina Linux.


### Nmap
Lanzamos un primer escaneo con `nmap` para identificar los puertos TCP abiertos:
![[Pasted image 20240908105028.png]]

Como vemos, hay tres puertos abiertos, los puertos 21, 22 y 80.

Lanzamos un segundo escaneo con `nmap` para determinar la versión y servicio que corren para estos puertos:
![[Pasted image 20240908105324.png]]

Como vemos, se está ejecutando el servicio FTP, SSH y HTTP. También hay un subdominio llamado "sightless.htb" por lo que lo añadimos al `/etc/hosts` de nuestra máquina:
![[Pasted image 20240908105530.png]]

## Enumeración web
Si lanzamos un análisis con `whatweb`, vemos que es un Ubuntu, además de un correo:
![[Pasted image 20240908105911.png]]


Si accedemos a la web vemos lo siguiente:
![[Pasted image 20240908110005.png]]

Si navegamos por la web podemos ver que se trata de una web bastante estática, pero vemos un link a un subdominio:
![[Pasted image 20240908110136.png]]

Por lo que lo añadimos en nuestro `/etc/hosts`:
![[Pasted image 20240908110226.png]]

Si accedemos vemos que se trata de un aplicativo llamado SQLPad de esta versón:
![[Pasted image 20240908111952.png]]

Si buscamos vulnerabilidades, vemos que tenemos un *template injection* en la sección de probar la conexión:
https://nvd.nist.gov/vuln/detail/CVE-2022-0944
![[Pasted image 20240908112046.png]]

Si seguimos el siguiente POC vemos que podemos obtener RCE:
https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb

Por lo que creamos una nueva conexión inyectando el siguiente comando:
![[Pasted image 20240908115426.png]]

Y si nos ponemos una escucha con `nc` por el puerto 443, obtenemos acceso:
![[Pasted image 20240908115452.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240908115712.png]]
![[Pasted image 20240908115742.png]]


## Escalada de privilegios
Si nos fijamos no estamos en la máquina víctima, sino que en un contenedor:
![[Pasted image 20240908115819.png]]


Si listamos el `/etc/shadow` del contenedor vemos lo siguiente:
![[Pasted image 20240908123100.png]]

Por lo que podemos intentar *crackear* estas dos contraseñas con `john` utilizando primeramente la herramienta `unshadow`:
![[Pasted image 20240908123139.png]]

Por lo que intentamos *crackear* con `john` y obtenemos 2 contraseñas:
![[Pasted image 20240908123206.png]]

Por lo que podemos intentar conectarnos mediante SSH a la máquina víctima con la contraseña y el usuario "michael":
![[Pasted image 20240908123523.png]]

En su directorio `/home` podemos visualizar la primera *flag*:
![[Pasted image 20240908123611.png]]

Si listamos los puertos internos abiertos, vemos lo siguiente:
![[Pasted image 20240908130222.png]]

