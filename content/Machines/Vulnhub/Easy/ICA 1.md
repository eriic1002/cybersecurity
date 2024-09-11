#ctf-machine #vulnhub #easy-machine #linux [Vulnhub Link]()

## Enumeración inicial
Primeramente debemos de identificar la IPv4 de nuestra máquina víctima con un escaneo ARP utilizando `arp-scan`:
![[Pasted image 20240826002310.png]]

Como se trata de una máquina importada en VMWare sabemos que el OUI de la MAC es "00:0c" por lo que la máquina objetiva es la "192.168.159.144".

Si le lanzamos una traza ICMP a la máquina víctima vemos que su TTL=64 por lo que probablemente se trate de una máquina Linux:
![[Pasted image 20240826002449.png]]


### Nmap
Hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos en la máquina víctima:
![[Pasted image 20240826002644.png]]

Como podemos ver hay 4 puertos abiertos, el puerto 22, 80, 3306 y 33060. Por lo que hacemos un segundo escaneo para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240826003029.png]]

 En el puerto 22 corre el servicio "OpenSSH 8.4p1" de Debian por lo que podemos asegurar que se trata de un sistema Linux. Además corren los servicios de" Apache" y "MySQL".

Si hacemos un último escaneo con `nmap` utilizando el script "http-enum" para encontrar directorios bajo la web que corre por el puerto 80 vemos lo siguiente:
![[Pasted image 20240826003244.png]]


## Enumeración web
Si accedemos a la web vemos un panel de autentificación:
![[Pasted image 20240826004041.png]]

Pero no es vulnerable a SQLInjection ni tenemos credenciales. Si enumeramos los directorios que nos ha reportado `nmap` vemos que hay un archivo `database.yml` en `/core/config/`. Por lo que si mostramos su contenido vemos unas credenciales de acceso a la base de datos:
![[Pasted image 20240826004301.png]]

Podemos intentar conectarnos a través de MySQL con estas credenciales:
![[Pasted image 20240826004803.png]]

Y como podemos ver obtenemos acceso. Por lo que podemos mostrar las bases de datos:
![[Pasted image 20240826004855.png]]

Como vemos solo hay 2 relevantes.  Así que si mostramos las tablas de "qdpm" vemos que hay una tabla "users" y "configuration":
![[Pasted image 20240826005009.png]]
![[Pasted image 20240826010748.png]]

Por lo que podemos mostrar todo su contenido, pero vemos que no hay nada en "users":
![[Pasted image 20240826005128.png]]
En cambio, en la tabla "configuration" vemos unas credenciales:
![[Pasted image 20240826010839.png]]

Podemos seguir enumerando la otra base de datos llamada "staff":
![[Pasted image 20240826005319.png]]
![[Pasted image 20240826005335.png]]

Si mostramos el contenido de las tablas "login" y "user" vemos lo siguiente:
![[Pasted image 20240826005551.png]]

Como se puede ver, las contraseñas parecen estar en base 64 por lo que podemos decodificarlas:
![[Pasted image 20240826010342.png]]

Podemos probar de conectarnos con los diferentes nombres de usuarios y las diferentes contraseñas para ver si tenemos acceso por SSH. Por lo que si finalmente probamos con "dexter" y la contraseña "7ZwV4qtg42cmUXGX", obtenemos acceso:
![[Pasted image 20240826012012.png]]


## Escalada de privilegios
Una vez como "dexter" dentro de la máquina víctima podemos ver la siguiente nota:
![[Pasted image 20240826012050.png]]

Si listamos los usuarios de la máquina vemos que hay 3:
![[Pasted image 20240826012318.png]]

Y del usuario "travis" tenemos una contraseña por lo que podemos probarla:
![[Pasted image 20240826012409.png]]

Como podemos ver hemos obtenido acceso y si accedemos a `/home/travis` podemos ver la primera flag*:
![[Pasted image 20240826012702.png]]

Si mostramos los archivos con permisos SUID podemos ver el siguiente archivo fuera de lo normal:
![[Pasted image 20240826012649.png]]

Si mostramos las cadenas leíbles podemos ver que se utiliza el comando "cat" de forma relativa:
![[Pasted image 20240826014852.png]]

Por lo que si alteramos el PATH y creamos un archivo con el nombre "cat" podemos ejecutar el comando que queramos ya que el sistema buscara primero el binario de "cat" en nuestro directorio. 

Por lo que primeramente alteramos el PATH para añadir primeramente la ruta `/tmp`.
![[Pasted image 20240826015036.png]]

Una vez alterado creamos un archivo con nombre "cat" en `/tmp` con el siguiente contenido:
```bash
#!/bin/bash
chmod +u /bin/bash
```

Y le damos permisos de ejecución:
![[Pasted image 20240826015510.png]]

Por lo que al ejecutar el archivo SUID `/opt/get_access` el usuario "root" dará permiso SUID a la "bash":
![[Pasted image 20240826015439.png]]

Así que si ejecutamos `bash -p` obtenemos una bash como usuario "root":
![[Pasted image 20240826015548.png]]

Finalmente, si accedemos al directorio `/root` podemos visualizar la última *flag* (no sin antes eliminar nuestro "cat" personalizado):
![[Pasted image 20240826015824.png]]

___
#abusing-suid #path-hijacking #information-leakage 
___