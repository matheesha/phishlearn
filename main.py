import requests
import json
import urllib.parse
import re
import wordninja
import tldextract
from urllib.parse import urlparse
import enchant

def predict(url, results):
  encodedurl = urllib.parse.quote_plus(url)
  apivurl = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key=d9bc1934f0f6e78ba810027df7adbc53fe360d73&url=" + encodedurl
  payload={}
  headers = {}
  response = requests.request("GET", apivurl, headers=headers, data=payload)

  res = json.loads(response.text)
  detection_count = res['data']['report']['domain_blacklist']['detections']
  results['detection_count'] = detection_count
  risk_score = res['data']['report']['risk_score']['result']
  results['risk_score'] = risk_score
  results['is_shortner'] = res['data']['report']['site_category']['is_url_shortener']

  if(detection_count > 0 or risk_score > 30): 
    results['is_phishing'] = True
  else:
     results['is_phishing'] = False
  return results


ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

ipv6_pattern = r"^(?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):" \
               r"(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}" \
               r"(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})" \
               r"(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|" \
               r"(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})" \
               r"(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|" \
               r"(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::" \
               r"(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|" \
               r"(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}" \
               r"(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):" \
               r"(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):" \
               r"(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}" \
               r"(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|" \
               r"(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|" \
               r"(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}" \
               r"(?:(?:[0-9a-fA-F]{1,4})))?::))))$"

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# -1 if match found ??
# changed the result
def having_ip_address(urldomain):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    matchvalue = re.search(ip_address_pattern, urldomain)
    print(matchvalue)
    if matchvalue:
      return 1 
    else:
      return -1

# changed the result
def get_delimeters_nondot_count(hostname):
    delimeters = [';',':','_','?','=','&','[',']','/','\\', '@','$', '%', ',', '{', '}', '+', '-']
    count = 0
    for each_letter in hostname:
        if each_letter in delimeters:
            count = count + 1
    if count > 4: 
      return 1
    elif count > 2:
      return 0 
    else: return -1

def get_shortening_service(url):
    matchvalue = re.search(shortening_services, url)
    return 1 if matchvalue else -1

def get_special_char_count(hostname):
    count = 0
    special_characters = [';','+=','_','?','=','&','[',']']
    for each_letter in hostname:
        if each_letter in special_characters:
            count = count + 1
    # not sure whether 4 is right
    if count > 4:
      return 1
    else: return -1

def get_raw_word_list(url):
    splits = re.split('[/\.,;:_?=&/@$%+-/]', url)
    splits = list(filter(None, splits))
    return splits

def txt_to_list(txt_object):
        list = []
        for line in txt_object:
            list.append(line.strip())
        txt_object.close()
        return list
    
allbrand_txt = open("allbrands.txt", "r")
allbrandlist = txt_to_list(allbrand_txt)
keywords = txt_to_list(open("keywords.txt", "r"))


def get_scriptio_continua_calculations(hostname):
  #print(url)
  splits = get_raw_word_list(hostname)
  adjacentwords = list()
  seperatedwordcount = 0
  for word in splits:
    if word not in allbrandlist and word not in keywords and not en_dict.check(word) and word.isalpha():
      adjacentwords.append(word)
      wordlist = wordninja.split(word)
      wordlist = [x for x in wordlist if len(x)>2]
      if wordlist != None and len(wordlist) >0:
        if len(wordlist) >= 7 or len(max(wordlist, key=len)) <= 4:
          if get_is_random(word):
            seperatedwordcount = seperatedwordcount + 1
          else:
            seperatedwordcount = seperatedwordcount + len(wordlist)
        else:
            seperatedwordcount = seperatedwordcount + len(wordlist)
      else:
          seperatedwordcount = seperatedwordcount + 1
    else:
      eperatedwordcount = seperatedwordcount + 1
  average = 0
  if len(adjacentwords) > 0:
      average = sum( map(len, adjacentwords) ) / len(adjacentwords)

  if (seperatedwordcount > 6):
    return 1
  else: return -1

en_dict = enchant.Dict("en_US")

def get_raw_word_list(url):
    splits = re.split('[/\.,;:_?=&/@$%+-/]', url)
    splits = list(filter(None, splits))
    return splits

def get_is_random(word):
    if len(word) > 0:
        if not en_dict.check(word):
            sugestedList = en_dict.suggest(word)
            if len(sugestedList) == 0:
                return 1
            if word not in sugestedList:
                if len(word)>7:
                    for sug in sugestedList:
                        if word[:3] not in sug:
                            return 1
    return 0


def have_random_words(url):
  splits = get_raw_word_list(url)
  for word in splits:
    wordlist = wordninja.split(word)
    wordlist = [x for x in wordlist if len(x)>2]
    if wordlist != None and len(wordlist) >0:
        if len(wordlist) >= 7 or len(max(wordlist, key=len)) <= 4:
            if get_is_random(word):
              return 1
  return -1


def GetFeatures(url):
  extResult = tldextract.extract((url))
  splits = urlparse(url)
  domain = extResult.domain
  scheme=  splits.scheme
  hostname = splits.hostname
  registered_domain = extResult.registered_domain
  subdomain = extResult.subdomain
  path = splits.path
  port = splits.port
  query = splits.query

  features = dict()
  #features["IP Address in URL Domain"] = having_ip_address(hostname)
  features["Suspicious special characters in Domain"] = get_delimeters_nondot_count(hostname)
  # is it correct to use only the hostname
  features["Shortening service has been used"] = get_shortening_service(hostname)
  features["Heavy use of special characters"] = get_special_char_count(hostname)
  # features["(-) Prefix/Suffix in domain"] = get_prefix_suffix_in_domain(hostname)
  features["Suspicious continuous words in domain"] = get_scriptio_continua_calculations(hostname)
  features["Random words in domain"] = have_random_words(url)
  return features

from flask import Flask
from flask import request

app = Flask(__name__)

@app.route('/')
def index():
  return  {"name":"PhishLearn"}

@app.route("/predict")
def phishlex_api():
    url = request.args.get("url", "")
    results = dict()
    results = predict(url, results)
    results['features'] = GetFeatures(url)
    return results

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5500, debug=True)
    print("api")
