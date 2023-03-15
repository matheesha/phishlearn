import requests
import json
import urllib.parse
import requests
import requests_toolbelt.adapters.appengine
import wordninja
import enchant

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
      seperatedwordcount = seperatedwordcount + 1
  average = 0
  if len(adjacentwords) > 0:
      average = sum( map(len, adjacentwords) ) / len(adjacentwords)

  if (seperatedwordcount > 3):
    return 1
  else: return -1

def predict(url, results):
  encodedurl = urllib.parse.quote_plus(url)
  apivurl = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key=d9bc1934f0f6e78ba810027df7adbc53fe360d73&url=" + encodedurl
  payload={}
  headers = {}
  #response = requests.request("GET", apivurl, headers=headers, data=payload)
  api_response = requests.get(apivurl)
  res = json.loads(api_response.text)
  detection_count = res['data']['report']['domain_blacklist']['detections']
  results['detection_count'] = detection_count
  risk_score = res['data']['report']['risk_score']['result']
  results['risk_score'] = risk_score
  results['is_shortner'] = res['data']['report']['site_category']['is_url_shortener']
  results['is_free_hosting'] = res['data']['report']['site_category']['is_free_hosting']
  results['is_free_file_sharing'] = res['data']['report']['site_category']['is_free_file_sharing']
  domain = res['data']['report']['url_parts']['host'].split('.')[0]
  results['continuing_words'] = get_scriptio_continua_calculations(domain)

  if(detection_count > 0 or risk_score > 30): 
    results['is_phishing'] = True
  else:
     results['is_phishing'] = False
  return results


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
    return results

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5500, debug=True)
    print("api")
