import requests
import json
import urllib.parse
import requests
import requests_toolbelt.adapters.appengine

def predict(url, results):
  encodedurl = urllib.parse.quote_plus(url)
  apivurl = "https://endpoint.apivoid.com/urlrep/v1/pay-as-you-go/?key=d9bc1934f0f6e78ba810027df7adbc53fe360d73&url=" + encodedurl
  payload={}
  headers = {}
  #response = requests.request("GET", apivurl, headers=headers, data=payload)
  api_response = requests.get(apivurl)
  #res = json.loads(api_response.text)
  return api_response


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
