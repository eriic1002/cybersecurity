#ctf-machine #other #easy-machine #windows #simulacion-eccptv2   [[Simulation eCPPTv2 Map.canvas|Simulation eCPPTv2 Map]]

## Pivoting
Esta máquina es la continuación de la máquina (Fawkes). Como vemos que en la máquina Fawkes no hay más interfaces de red, volvemos a la máquina Nagini para seguir con esta máquina:
![[Pasted image 20240830110835.png]]

Como habíamos visto, hay otro host (Dumbledore):
![[Pasted image 20240830111148.png]]

Por lo que no hay que configurar el *proxy* porque ya tenemos alcance a la máquina ya que lo configuramos anteriormente.
## Enumeracion inicial
Hacemos un primer escaneo con `nmap` junto a `xargs` y `proxychains` para detectar puertos TCP abiertos en la máquina víctima:
>[!NOTE] Utilizamos `xargs` para agilizar el escaneo, ya que es bastante lento.

![[Pasted image 20240830123838.png]]

Como vemos solo hay un puerto abierto, el puerto 445 y se trata de una máquina Windows. Hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corre para este puerto:
![[Pasted image 20240830124305.png]]

Lanzamos un tercer escaneo de scripts de `nmap` que sean de tipo "vuln" and "safe" por lo que encontramos que podemos obtener RCE:
![[Pasted image 20240830124805.png]]

Aparte de `nmap` lanzamos la herramienta `crackmapexec` para ver que nos reporta:
![[Pasted image 20240830124854.png]]


## RCE
Como es vulnerable a *Eternal Blue* (ms17-010), utilizamos la herramienta `auto-blue` para explotar la vulnerabilidad:
https://github.com/3ndG4me/AutoBlue-MS17-010

Primeramente, utilizamos el `eternal_checker` para ver los "named pipe" para abusar de la vulnerabilidad:
![[Pasted image 20240830125444.png]]

Como vemos hay uno por lo que podemos ejecutar el `zzz-exploit` que nos otorga automáticamente una "cmd":
![[Pasted image 20240830130527.png]]

Y podemos visualizar la *flag*:
![[Pasted image 20240830130844.png]]

Como la consola no es del todo interactiva, nos descargamos `netcat` para Windows de este recurso:
https://eternallybored.org/misc/netcat/

Y ahora tenemos que compartirlo con SMB, pero esta máquina no tiene conexión directa con nuestra máquina por lo que tenemos que hacer *port forwarding*. 

Primero en la máquina 192.168.100.128 (10.10.0.129) ejecutamos `socat` para que todo que le llegue al puerto 445 lo mande para la máquina "10.10.0.128" (192.168.159.147) por el puerto 445:
![[Pasted image 20240830142500.png]]

Y ahora en la máquina "10.10.0.128" (192.168.159.147) ejecutar `socat` para enviar todo lo que reciba por el puerto 445 a la mi máquina por el puerto 445:
![[Pasted image 20240830142641.png]]

Por lo que si ahora compartimos a nivel de red el recurso utilizando `smbserver`:
![[Pasted image 20240830142843.png]]

Y listamos su contenido desde la máquina Windows:
![[Pasted image 20240830143044.png]]

Vemos el archivo que queremos descargar. Por lo que utilizamos `copy` para obtenerlo.
![[Pasted image 20240830143425.png]]

Una vez copiado, aprovechamos el túnel del puerto 445 para ponernos en escucha desde nuestra máquina:
![[Pasted image 20240830143809.png]]

Y enviar la *reverse shell* con `netcat`:
![[Pasted image 20240830143706.png]]
![[Pasted image 20240830154041.png]]


___
#eternal-blue
___

