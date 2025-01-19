# Single Domain URLs Finding

### Waymore

```
waymore -i "testphp.vulnweb.com" -n -mode U -oU testphp.vulnweb.com.txt
```

### waybackurls

```
waybackurls -no-subs testphp.vulnweb.com
```

### Gau

```
gau testphp.vulnweb.com --providers wayback,commoncrawl,otx,urlscan --threads 70 | tee urls.txt
```

### Katana

```
katana -u testphp.vulnweb.com -fs fqdn -rl 170 -timeout 5 -retry 2 -aff -d 5 -ef ttf,woff,svg,png,css -ps -pss waybackarchive,commoncrawl,alienvault -silent -o urls.txt
```

# Multi Domain URLs find

### Waymore

```
waymore -i "vulnweb.com" -mode U | tee vulnweb.com.txt
```

### Waybackurls

```
waybackurls vulnweb.com | tee vulnweb.com.txt
````

### Gau

```
gau --subs vulnweb.com --providers wayback,commoncrawl,otx,urlscan --threads 70 | tee urls.txt
```

### Katana

```
katana -u vulnweb.com -rl 170 -timeout 5 -retry 2 -aff -d 5 -ef ttf,woff,svg,png,css -ps -pss waybackarchive,commoncrawl,alienvault -silent -o urls.txt
```

# Subdomain list URLs finding

```
cat $allurls | while read subdomains; do waybackurls -no-subs "$subdomains" | tee -a bug_bounty_report/$domain_Without_Protocol/recon/links/waybackurls-mass.txt; done

cat $allurls | while read subdomains; do waymore -i "$subdomains" -n -mode U | tee -a bug_bounty_report/$domain_Without_Protocol/recon/links/waymore-mass.txt; done

cat $allurls | while read subdomains; do katana -u "$subdomains" -fs fqdn -rl 170 -timeout 5 -retry 2 -aff -d 4 -ef ttf,woff,svg,png,css -ps -pss waybackarchive,commoncrawl,alienvault -silent -o bug_bounty_report/$domain_Without_Protocol/recon/links/katana-mass.txt; done
```


# Uncover Hidden Parameters in Seconds 🕵️‍♂️
Extract hidden parameters from URLs effortlessly.

```
cat alive.txt |rush curl -skl “{}” |grep “type\=\”hidden\”” |grep -Eo “name\=\”[^\”]+\”” |cut -d”\”” -f2 | sort -u’ | anew params.txt
```

# Uncover Hidden Parameters in Seconds 🕵️‍♂️
Extract hidden parameters from URLs effortlessly.

```
cat alive.txt |rush curl -skl “{}” |grep “type\=\”hidden\”” |grep -Eo “name\=\”[^\”]+\”” |cut -d”\”” -f2 | sort -u’ | anew params.txt
```

# Reveal Secrets in JavaScript Files 🕵️‍♂️
Identify sensitive data in JavaScript files like a pro.

```
cat alive.txt | rush 'hakrawler -plain -js -depth 2 -url {}' | rush 'python3 /root/Tools/SecretFinder/SecretFinder.py -i {} -o cli' | anew secretfinder
```

Crush Directories with Effortless Bruteforce 🔍
Discover hidden directories and files effortlessly.

```
cat alive.txt | xargs -I@ sh -c 'ffuf -c -w /path/to/wordlist -D -e php,aspx,html,do,ashx -u @/FUZZ -ac -t 200' | tee -a dir-ffuf.txt
```

Expose Log4J Vulnerabilities with Ease 🔍
Identify Log4J vulnerabilities on the fly.

```
cat alive.txt | xargs -I@ sh -c 'python3 /path/to/log4j-scan.py -u @"
```

Hunt Down Sneaky Open Redirects 🎯
Uncover open redirects like a seasoned hunter.
```
gau http://vuln.target.com | gf redirect | qsreplace “$LHOST” | xargs -I % -P 25 sh -c ‘curl -Is “%” 2>&1 | grep -q “Location: $LHOST” && echo “VULN! %”’
```

Capture Screenshots in a Snap 📷
Capture screenshots of live websites effortlessly.

```
assetfinder -subs-only http://target.com | httpx -silent -timeout 50 | xargs -I@ sh -c 'gowitness single @'
```

Know Your WordPress Version 📝
Discover the WordPress version of a target website instantly.

```
curl -s 'https://target.com/readme.html' | grep 'Version'
```

Unearth Subdomains Containing JavaScript 🌐
Find subdomains with JavaScript files in a snap.

```
echo "domain" | haktrails subdomains | httpx -silent | getJS --complete | anew JS
```

Bypass 403 Login Pages with Finesse 🚪
Bypass 403 login pages like a pro.

```
cat hosts.txt | httpx -path /login -p 80,443,8080,8443 -mc 401,403 -silent -t 300 | unfurl format %s://%d | httpx -path //login -mc 200 -t 300 -nc -silent
```
