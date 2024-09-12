#ctf-machine #hackthebox #easy-machine #linux 

![[Cap.png]]

## Enumeración inicial
Primeramente lanzamos una traza ICMP con `ping` a la máquina víctima para ver si está activa:
![[Pasted image 20240912152054.png]]

Como vemos el valor de TTL es cercano a 64 por lo que podemos decir que probablemente se trata de una máquina Linux.

### Nmap
Realizamos un primer escaneo con `nmap` para identificar los puertos TCP abiertos:
![[Pasted image 20240912152259.png]]

Como vemos, hay 3 puertos abiertos, los puertos 21, 22 y 80.

Realizamos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240912152758.png]]
![[Pasted image 20240912152835.png]]

Como vemos se está ejecutando "OpenSSH" en el puerto 22, "vsFTPd" en el puerto 21 y el servidor "gunicorn" por el puerto 80.

## Enumeración web
Si accedemos a la web vemos lo siguiente:
![[Pasted image 20240912153237.png]]

Parece ser que por defecto somos el usuario "Nathan". Si accedemos al panel "Security Snapshot", vemos lo siguiente:
![[Pasted image 20240912153420.png]]

Como vemos, parece ser que se hace una captura de paquetes que si nos lo descargamos podemos visualizarlos con `wireshark`:
![[Pasted image 20240912153556.png]]

Si lo analizamos con detalle no vemos nada interesante. Pero si probamos de modificar el valor de la URL, a 0 por ejemplo, vemos un paquete de otra persona:
![[Pasted image 20240912153652.png]]

Por lo que nos lo descargamos y lo analizamos con `wireshark`. Si nos fijamos hay unos paquetes de FTP donde se ve el login de un usuario:
![[Pasted image 20240912153824.png]]

Así que podemos utilizar estas credenciales para conectarnos por FTP:
![[Pasted image 20240912154627.png]]

Una vez conectados vemos que hay un archivo llamado "user.txt" por lo que utilizamos "get" para traerlo a nuestra máquina y visualizarlo:
![[Pasted image 20240912154722.png]]

Como vemos se trata de la primera *flag*.

Podemos intentar conectarnos con estas credenciales por SSH:
![[Pasted image 20240912154849.png]]

Como vemos, obtenemos acceso.


## Escalada de privilegios
Si listamos los archivos con *capabilities*, podemos ver que Python tiene la *capability* "cap_setuid" por lo que podemos elevar nuestro privilegio usando:
![[Pasted image 20240912155228.png]]

Así que si accedemos al directorio `/root` podemos visualizar la última *flag*:
![[Pasted image 20240912155333.png]]

___
#abusing-capabilities #information-leakage #idors 
___


