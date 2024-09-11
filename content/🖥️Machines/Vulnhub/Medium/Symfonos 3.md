#ctf-machine #vulnhub #medium-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/symfonos-31,332/)

## Enumeración inicial
Como no conocemos la IPv4 de nuestra máquina víctima hacemos un escaneo ARP con `arp-scan`:
![[Pasted image 20240825184555.png]]

Como el OUI de la MAC de las máquinas importadas con VMWare es "00:0c" podemos decir que la máquina objetiva es la "192.168.159.143".

Si lanzamos una traza ICMP a la máquina objetiva podemos decir que probablemente sea una máquina Linux dado que el TTL=64:
![[Pasted image 20240825184732.png]]

### Nmap
Si hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos, podemos ver los siguientes:
![[Pasted image 20240825184923.png]]

Como podemos ver solo hay 3 puertos abiertos, el puerto 21 el puerto 22 y el puerto 80. Por lo que hacemos un segundo escaneo para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240825185139.png]]

Como podemos ver en el puerto 21 está el servicio "ProFPTD", en el puerto 22 "OpenSSH 7.4p1" de Debian por lo que podemos asegurar que estamos ante una máquina Linux y finalmente el puerto 80 donde corre "Apache httpd 2.4.25".


## Enumeración web
Si accedemos a la web podemos ver la siguiente imagen:
![[Pasted image 20240825185817.png]]

Por lo que si mostramos el contenido del código de la web podemos ver el siguiente mensaje:
![[Pasted image 20240825185846.png]]

Como no vemos nada interesante realizamos un escaneo de directorios y archivos PHP con `gobuster`:
![[Pasted image 20240825190902.png]]

Como vemos, solo hay un directorio interesante: `/gate/` por lo que si accedemos a él vemos lo siguiente:
![[Pasted image 20240825190057.png]]

Y en el código fuente:
![[Pasted image 20240825190157.png]]

Como no hay nada interesante hacemos un segundo escaneo de directorios con `gobuster` bajo el directorio `/gate/`.
![[Pasted image 20240825191600.png]]

Como vemos solo hay un directorio `/gate/cerberus/` por lo que si accedemos vemos lo siguiente:
![[Pasted image 20240825191038.png]]

Y su código fuente:
![[Pasted image 20240825191051.png]]

Como no hay nada interesante procedemos nuevamente a hacer otro escaneo con `gobuster` bajo el directorio `/gate/cerberus/`:
![[Pasted image 20240825193439.png]]

Pero no encontramos nada. Si hacemos uso de otro diccionario llamado "common.txt" vemos lo siguiente:
![[Pasted image 20240825193602.png]]

Por lo que sí accedemos al directorio `/gate/cerberus/tartarus` vemos la siguiente imagen:
![[Pasted image 20240825193648.png]]

Y si analizamos el código fuente vemos el siguiente mensaje:
![[Pasted image 20240825193727.png]]

Por lo que procedemos nuevamente a hacer un escaneo con `gobuster` en busca de más directorios con el diccionario "common.txt" desde la raíz:
![[Pasted image 20240825200244.png]]

Como vemos encontramos un directorio `/cgi-bin/` por lo que podemos hacer un escaneo con `gobuster` en busca de *scripts* o archivos para explotar un posible *shellshock*.
![[Pasted image 20240825200316.png]]

Como vemos encontramos este archivo `/cgi-bin/underworld`, su contenido es el siguiente:
![[Pasted image 20240825200429.png]]

## ShellShock
Así que podemos intentar generar un *shellshock* mediante el "User-Agent" con `burpsuite`. Por ejemplo podemos lanzar una traza ICMP a nuestra máquina y ponernos en escucha con `tcpdump` para ver si tenemos RCE:
![[Pasted image 20240825200624.png]]
![[Pasted image 20240825200650.png]]

Como podemos tenemos RCE por lo que podemos ejecutar el siguiente comando:
![[Pasted image 20240825200940.png]]

Y si nos ponemos en esucha con `nc` por el puerto 443 ganamos acceso a la máquina como el usuario "cerberus":
![[Pasted image 20240825201022.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240825201103.png]]
![[Pasted image 20240825201202.png]]

## Escalada de privilegios
Si listamos los usuarios del sistema vemos que solo hay 3:
![[Pasted image 20240825201538.png]]

Si enumeramos tareas cron utilizando `pspy`, encontramos la siguiente tarea:
![[Pasted image 20240825225514.png]]

Como no tenemos acceso al contenido de los archivos que se ejecutan, vamos a interceptar el tráfico de red con `tcpdump` para ver si podemos ver alguna cosa interesante:
```bash
tcpdump -i lo -v
```
![[Pasted image 20240825230952.png]]

Como podemos ver, vemos unas credenciales del usuario "hades" al conectarse por FTP. Por lo que podemos migrar a "hades" utilizando sus credenciales:
![[Pasted image 20240825231518.png]]

Si observamos el *script* de Python que ejecuta "root" ubicado en `/opt/fptclient/fptclient.py` vemos que utiliza la librería "ftplib":
![[Pasted image 20240825231713.png]]

Si mostramos la ubicación con Python de esta librería vemos que se encuentra en `/usr/lib/python2.7`:
![[Pasted image 20240825231756.png]]

Por lo que si listamos los permisos de este directorio vemos que tenemos capacidad de escritura en esta libreria ya que "hades" pertenece al grupo de "gods":
![[Pasted image 20240825232537.png]]

Por lo que podemos modificarlo y asignarle el permiso SUID a la "bash" añadiendo este código al archivo `ftplib.py`:
![[Pasted image 20240825233141.png]]

Si dejamos un tiempo a que se ejecute la tarea cron y listamos el permiso de la "bash" vemos que ahora es SUID:
![[Pasted image 20240825233416.png]]

Por lo que si ejecutamos el comando `/bin/bash -p` obtenemos una "bash" como el usuario "root":
![[Pasted image 20240825233343.png]]


___
#web-enumeration #shellshock-attack #abusing-internal-services #abusing-cron-tasks #abusing-special-user-groups  
___