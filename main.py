import requests
import json

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
  ##features["IP Address in URL Domain"] = having_ip_address(hostname)
  #features["Suspicious special characters in Domain"] = get_delimeters_nondot_count(hostname)
  ## is it correct to use only the hostname
  #features["Shortening service has been used"] = get_shortening_service(hostname)
  #features["Heavy use of special characters"] = get_special_char_count(hostname)
  ## features["(-) Prefix/Suffix in domain"] = get_prefix_suffix_in_domain(hostname)
  #features["Suspicious continuous words in domain"] = get_scriptio_continua_calculations(hostname)
  #features["Random words in domain"] = have_random_words(url)
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
    #results['features'] = dict() #GetFeatures(url)
    return results

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5500, debug=True)
    print("api")
