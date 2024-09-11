#ctf-machine #vulnhub #medium-machine #linux [VulnHub Link](https://www.vulnhub.com/entry/symfonos-52,415/)

## Enumeración inicial
Como no conocemos la IPv4 de la máquina víctima, primeramente hacemos un escaneo ARP con `arp-scan`:
![[Pasted image 20240901123023.png]]

Como vemos, nuestra máquina es la "192.168.159.148", ya que su OUI es "00:0c" que corresponde a las máquinas que se importan en VMWare.

Si lanzamos una traza ICMP con `ping` podemos decir que probablemente se trate de una máquina Linux, ya que su valor de TTL=64 y las máquinas Linux suelen tener ese valor de TTL.
![[Pasted image 20240901123120.png]]

### Nmap
Hacemos un primer escaneo con `nmap` para identificar los puertos TCP abiertos en la máquina:
![[Pasted image 20240901123253.png]]

Como vemos hay 4 puertos abiertos, el puerto 22, 80, 389 y 636. 

Hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos puertos abiertos:
![[Pasted image 20240901123456.png]]

Como vemos está expuesto el puerto 22 con el servicio OpenSSH 7.9p1, en el puerto 80 corre el servicio Apache y finalmente en el puerto 389 el servicio OpenLDAP.

Hacemos un tercer escaneo con `nmap` para hacer *fuzzing* de algunos directorios web que corren por el puerto 80:
![[Pasted image 20240901124028.png]]

Como vemos hay un directorio `/admin.php`.


## Enumeración web
Si accedemos a la web vemos una imagen en la página principal:
![[Pasted image 20240901124720.png]]

Podemos acceder al panel de autentificación que hemos encontrado con `nmap` y vemos lo siguiente:
![[Pasted image 20240901124805.png]]

Si analizamos como se tramita la solicitud de login con `burpsuite`, vemos que se trata de una solicitud por GET:
![[Pasted image 20240901125103.png]]

Como sabemos que por detrás corre LDAP podemos intentar utilizar `*` para hacer *bypass* del login:
![[Pasted image 20240901125314.png]]

Como vemos obtenemos acceso.

Si accedemos a la sección de "Portraits" vemos lo siguiente:
![[Pasted image 20240901125403.png]]

Como vemos se está utilizando un parámetro llamado "url" para apuntar al recurso por lo que podemos modificarlo y utilizar un *wrapper* de tipo "file" para apuntar a un archivo de la máquina como el `/etc/passwd`:
![[Pasted image 20240901125529.png]]

Como vemos, tenemos un LFI. Por lo que podemos intentar apuntar a los *logs* de Apache o SSH para ver si podemos acontecer un *log poisoning*. Pero no logramos visualizar *logs*. Podemos intentar apuntar al recurso `/admin.php` con *wrappers* de PHP para verlo en base64:
![[Pasted image 20240901152459.png]]

Y como vemos, aparece una cadena en base 64. Por lo que si la decodificamos podemos ver las credenciales de LDAP:
![[Pasted image 20240901152608.png]]

Si intentamos conectarnos podemos ver 2 cadenas en base 64 de contraseñas:
![[Pasted image 20240901152718.png]]

Por lo que si decodificamos la contraseña de "zeus":
![[Pasted image 20240901152808.png]]

Podemos probar de conectarnos mediante SSH con el usuario "zeus" y la contraseña:
![[Pasted image 20240901153015.png]]

Y como vemos, obtenemos acceso.

## Escalada de privilegios
Una vez dentro de la máquina si listamos los permisos a nivel de *sudoers* del usuario "zeus" vemos el siguiente binario:
![[Pasted image 20240901153213.png]]

Por lo que si ejecutamos el binario con la opción "-l", aparecera un modo *paginate* en el que podremos ejecutar "!/bin/bash" y obtendremos una "bash" como *root*:
![[Pasted image 20240901153556.png]]

Por lo que si accedemos al directorio `/root` podemos visualizar la *flag*:
![[Pasted image 20240901153644.png]]

___
#ldap-injection #local-file-inclusion #abusing-sudoers 
___