import argparse
import sys
import requests
from bs4 import BeautifulSoup
import random
import time

HELP = """\
This script is designed for information collection via Google,
first it collects dorks from GHDB and update local files if you
specify -u,then it reads dorks from local file and use them on 
the site which you can set via -s.Of course you can only use few
dorks file not all of them via -r(-r 1-9),If you can't access 
google you can set a socks5 proxy(such as -p 127.0.0.1:1080).
index of dork file:
1    Footholds
2    Files Containing Usernames
3    Sensitive Directories
4    Web Server Detection
5    Vulnerable Files
6    Vulnerable Servers
7    Error Messages
8    Files Containing Juicy Info
9    Files Containing Passwords
10   Sensitive Online Shopping Info
11   Network or Vulnerability Data
12   Pages Containing Login Portals
13   Various Online Devices
14   Advisories and Vulnerabilities
"""
proxy = ''
update = ''
repo = ''
site = ''
page = ''

repo_list = ['Footholds','Files Containing Usernames','Sensitive Directories','Web Server Detection','Vulnerable Files','Vulnerable Servers',
        'Error Messages','Files Containing Juicy Info','Files Containing Passwords','Sensitive Online Shopping Info',
        'Network or Vulnerability Data','Pages Containing Login Portals','Various Online Devices','Advisories and Vulnerabilities']

user_agents = ['Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0', 
               'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
               'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.75 Safari/537.36',
               'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0']

def parse_options():
    parser = argparse.ArgumentParser(usage="usage:%(prog)s[-p 127.0.0.1:1080] [-r 1-9] -s example.com [-u]",description=HELP)
    parser.add_argument('-P','--proxy',action='store',type=str,dest='proxy',default='socks5://127.0.0.1:1080',
                        metavar='host:post',
                      help='specify socks5 proxy')
    parser.add_argument('-r','--repo',action='store',type=str,dest='repo',default='1-14',
                        metavar='1-14',
                      help='sepcify which repos to use')    
    parser.add_argument('-s','--site',action='store',type=str,dest='site',default=None,
                      help='specify which site you want to konw')
    parser.add_argument('-u','--update',action='store_true',dest='update',default=False,
                        help='update repo files')
    parser.add_argument('-p','--page',action='store',type=int,dest='page',
                        default=10,
                     help='how many page will crawl from google (default:10)')    
    options,args = parser.parse_known_args('-u -r 3-3 -s xidian.edu.cn'.split())
    global proxy 
    proxy = options.proxy
    global update
    update = options.update
    global repo
    repo =  options.repo
    global site
    site = options.site
    global page
    page = int(options.page)


def update_ghdb():
    baseURL = 'https://www.exploit-db.com/google-hacking-database/?action=search&ghdb_search_cat_id=%d&ghdb_search_text=&ghdb_search_page=%d'
    
    for i in range(14):
        print '[+] Updating %s'%repo_list[i]
        page = 1
        dorks_list = []
        while True:
            while True:
                try:
                    headers = {'User-Agent':user_agents[random.randint(0,len(user_agents)-1)]}
                    req = requests.get(baseURL%(i+1,page),headers = headers)
                    break
                except:
                    print '[-] Connection Error! Try again!'
                    
            content = req.text.encode(req.encoding)
            page += 1
            if 'No results' in content:
                break            
            soup = BeautifulSoup(content,'html.parser')
            tbody = soup.find('tbody')
            tr_list = tbody.find_all('tr')
            for tr in tr_list:
                try:
                    dorks_list.append(next(tr.find_all('td')[1].a.stripped_strings).encode('utf-8')+'\n')
                except StopIteration:
                    print '[-] Encounter None Type'
        with open('./repo/'+repo_list[i].replace(' ','_'),'wb') as f:
            f.writelines(dorks_list)
    print '[+] Done!'
    
def verify_google():
    
    google = []
    with open('google.txt','rb') as f:
        google_domain_list = f.readlines()
        
    headers = {'User-Agent':user_agents[random.randint(0,len(user_agents)-1)]}
    proxies = {'http':proxy,'https':proxy}
    print proxies
    print headers
    for google_domain in google_domain_list:
        url = 'https://%s/'%google_domain[:-2]
        try:
            print '[+]verifying %s'%url
            req = requests.get(url,headers=headers,proxies=proxies)
            if req.status_code == 200:
                google.append(url)
                print "[+]We CAN acceess it!"
            else:
                print "[-]Can't acceess it! Net code%d"%req.status_code
                
        except:
            print "[-]Can't acceess it!Please use a valid proxy"
    return google

def crawl_google():
    google_list = verify_google()
    if not google_list:
        print "[-]We can't access any Domain"
        return 
    proxies = {'http':proxy,'https':proxy}
    (start,end) = repo.split('-')
    start = int(start)-1
    end = int(end)
    if start > 13 or end > 14:
        print '[-]Repo index error!'
        return 
    for repo_index in range(start,end):
        with open('./repo/'+repo_list[repo_index].replace(' ','_'),'rb') as f:
            dork_list = f.readlines()
        for dork in dork_list:
            dork = dork.rstrip('\n')
            print '[+] using dork %s'%dork
            dork = 'search?hl=en&num=1000&q=%s'%dork + ' site:'+site
            page_num = 2
            while True:
                try:
                    baseurl = google_list[random.randint(0,len(google_list)-1)]
                except:
                    print '[-]All Domains are dead!'
                    return
                url = baseurl + dork                
                headers = {'User-Agent':user_agents[random.randint(0,len(user_agents)-1)]}
                time.sleep(random.randint(10,20))
                try:
                    req = requests.get(url,proxies=proxies,headers=headers)
                except:
                    print '[-]Exception'
                    continue
                if req.status_code == 200:
                    print "[+] Requested page %d"%(page_num-1)
                    soup = BeautifulSoup(req.text.encode(req.encoding),'html.parser')
                    h3_list = soup.findAll('h3',{'class':'r'})
                    if len(h3_list) == 0:
                        print "[-] Don't hava any data!"
                        break
                    for h3 in h3_list:
                        print "TITLE:%s\nURL:%s"%(h3.a.text,h3.a.get('href'))     
                        
                    a = soup.find('a',{'aria-label':'Page %d'%page_num})
                    if (not a) or page_num > page:
                        break
                    dork = a.get('href')
                    page_num += 1
                elif req.status_code == 503:
                    print req.request.headers
                    print "%s is blocked!"%baseurl
                    google_list.remove(baseurl)
                else:
                    break
                

if __name__ == '__main__':
    parse_options()
    #if update:
        #update_ghdb()
    if site:
        crawl_google()