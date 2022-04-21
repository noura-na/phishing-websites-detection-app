import streamlit as st
from urllib.parse import urlparse,urlencode
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib.request
import requests
import socket
import time
import pickle
import numpy as np
from googlesearch import search
from datetime import date, datetime
from dateutil.parser import parse as date_parse
import json
import base64
import csv
import urllib.request
import pandas as pd

import urllib.request

url = 'https://github.com/noura-na/phishing-websites-detection-app/releases/tag/model/download/model.sav'
# filename = url.split('/')[-1]

# myfile = urllib.request.urlretrieve(url, filename)

def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month

def ExtractFeatures(url):

    data_set = []

    if not re.match(r"^https?", url):
        url = "http://" + url

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999

    domain = re.findall(r"://([^/]+)/?", url)[0]
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    whois_response = whois.whois(domain)

    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": domain
    })

    try:
        global_rank = int(re.findall(
            r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        global_rank = -1

    # 1.having_IP_Address
    try:
        ipaddress.ip_address(url)
        data_set.append(-1)
    except:
        data_set.append(1)

    # 2.URL_Length
    if len(url) < 54:
        data_set.append(1)
    elif len(url) >= 54 and len(url) <= 75:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 3.Shortining_Service
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    if match:
        data_set.append(-1)
    else:
        data_set.append(1)

    # 4.having_At_Symbol
    if re.findall("@", url):
        data_set.append(-1)
    else:
        data_set.append(1)

    # 5.double_slash_redirecting
    list = [x.start(0) for x in re.finditer('//', url)]
    if list[len(list)-1] > 6:
        data_set.append(-1)
    else:
        data_set.append(1)

    # 6.Prefix_Suffix
    if re.findall(r"https?://[^\-]+-[^\-]+/", url):
        data_set.append(-1)
    else:
        data_set.append(1)

    # 7.having_Sub_Domain
    if len(re.findall("\.", url)) == 1:
        data_set.append(1)
    elif len(re.findall("\.", url)) == 2:
        data_set.append(0)
    else:
        data_set.append(-1)

    # 8.SSLfinal_State
    try:
        if response.text:
            data_set.append(1)
    except:
        data_set.append(-1)

    # 9.Domain_registeration_length
    expiration_date = whois_response.expiration_date
    registration_length = 0
    try:
        expiration_date = min(expiration_date)
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = abs((expiration_date - today).days)

        if registration_length / 365 <= 1:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(-1)

    # 10.Favicon
    if soup == -999:
        data_set.append(-1)
    else:
        try:
            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0)
                            for x in re.finditer('\.', head.link['href'])]
                    if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        data_set.append(1)
                        raise StopIteration
                    else:
                        data_set.append(-1)
                        raise StopIteration
        except StopIteration:
            pass

    # 11. port
    try:
        port = domain.split(":")[1]
        if port:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(1)

    # 12. HTTPS_token
    if re.findall(r"^https://", url):
        data_set.append(1)
    else:
        data_set.append(-1)

    # 13. Request_URL
    i = 0
    success = 0
    if soup == -999:
        data_set.append(-1)
    else:
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or domain in img['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or domain in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or domain in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or domain in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if percentage < 22.0:
                data_set.append(1)
            elif((percentage >= 22.0) and (percentage < 61.0)):
                data_set.append(0)
            else:
                data_set.append(-1)
        except:
            data_set.append(1)

    # 14. URL_of_Anchor
    percentage = 0
    i = 0
    unsafe = 0
    if soup == -999:
        data_set.append(-1)
    else:
        for a in soup.find_all('a', href=True):
            # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and :: might not be
                # there in the actual a['href']
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                unsafe = unsafe + 1
            i = i + 1

        try:
            percentage = unsafe / float(i) * 100
        except:
            data_set.append(1)

        if percentage < 31.0:
            data_set.append(1)
        elif ((percentage >= 31.0) and (percentage < 67.0)):
            data_set.append(0)
        else:
            data_set.append(-1)

    # 15. Links_in_tags
    i = 0
    success = 0
    if soup == -999:
        data_set.append(-1)
        data_set.append(0)
    else:
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or domain in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or domain in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1
        try:
            percentage = success / float(i) * 100
        except:
            data_set.append(1)

        if percentage < 17.0:
            data_set.append(1)
        elif((percentage >= 17.0) and (percentage < 81.0)):
            data_set.append(0)
        else:
            data_set.append(-1)

        # 16. SFH
        if len(soup.find_all('form', action=True))==0:
            data_set.append(1)
        else :
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    data_set.append(-1)
                    break
                elif url not in form['action'] and domain not in form['action']:
                    data_set.append(0)
                    break
                else:
                    data_set.append(1)
                    break

    # 17. Submitting_to_email
    if response == "":
        data_set.append(-1)
    else:
        if re.findall(r"[mail\(\)|mailto:?]", response.text):
            data_set.append(-1)
        else:
            data_set.append(1)

    # 18. Abnormal_URL
    if response == "":
        data_set.append(-1)
    else:
        if response.text == whois_response:
            data_set.append(1)
        else:
            data_set.append(-1)

    # 19. Redirect
    if response == "":
        data_set.append(-1)
    else:
        if len(response.history) <= 1:
            data_set.append(-1)
        elif len(response.history) <= 4:
            data_set.append(0)
        else:
            data_set.append(1)

    # 20. on_mouseover
    if response == "":
        data_set.append(-1)
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            data_set.append(1)
        else:
            data_set.append(-1)

    # 21. RightClick
    if response == "":
        data_set.append(-1)
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            data_set.append(1)
        else:
            data_set.append(-1)

    # 22. popUpWidnow
    if response == "":
        data_set.append(-1)
    else:
        if re.findall(r"alert\(", response.text):
            data_set.append(1)
        else:
            data_set.append(-1)

    # 23. Iframe
    if response == "":
        data_set.append(-1)
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            data_set.append(1)
        else:
            data_set.append(-1)

    # 24. age_of_domain
    if response == "":
        data_set.append(-1)
    else:
        try:
            registration_date = re.findall(
                    r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
            if diff_month(date.today(), date_parse(registration_date)) >= 6:
                data_set.append(-1)
            else:
                data_set.append(1)
        except:
            data_set.append(1)

    # 25. DNSRecord
    dns = 1
    try:
        d = whois.whois(domain)
    except:
        dns = -1
    if dns == -1:
        data_set.append(-1)
    else:
        if registration_length / 365 <= 1:
            data_set.append(-1)
        else:
            data_set.append(1)

    # 26. web_traffic
    try:
        rank = BeautifulSoup(urllib.request.urlopen(
            "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
        if (rank < 100000):
            data_set.append(1)
        else:
            data_set.append(0)
    except :
        data_set.append(-1)

    # 27. Page_Rank
    try:
        if global_rank > 0 and global_rank < 100000:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        data_set.append(1)

    # 28. Google_Index
    site = search(url, 5)
    if site:
        data_set.append(1)
    else:
        data_set.append(-1)

    # 29. Links_pointing_to_page
    if response == "":
        data_set.append(-1)
    else:
        number_of_links = len(re.findall(r"<a href=", response.text))
        if number_of_links == 0:
            data_set.append(1)
        elif number_of_links <= 2:
            data_set.append(0)
        else:
            data_set.append(-1)

    # 30. Statistical_report
    url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    try:
        ip_address = socket.gethostbyname(domain)
        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                             '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                             '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                             '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                             '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                             '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        if url_match:
            data_set.append(-1)
        elif ip_match:
            data_set.append(-1)
        else:
            data_set.append(1)
    except:
        print('Connection problem. Please check your internet connection')

    return data_set


st.title("Phishing Websites Detection")

# DB Management
import sqlite3 
conn = sqlite3.connect('data.db')
c = conn.cursor()
def create_usertable():
	c.execute('CREATE TABLE IF NOT EXISTS userstable(username TEXT,password TEXT)')


def add_userdata(username,password):
	c.execute('INSERT INTO userstable(username,password) VALUES (?,?)',(username,password))
	conn.commit()

def login_user(username,password):
	c.execute('SELECT * FROM userstable WHERE username =? AND password = ?',(username,password))
	data = c.fetchall()
	return data


# Security
#passlib,hashlib,bcrypt,scrypt
import hashlib 
def make_hashes(password):
	return hashlib.sha256(str.encode(password)).hexdigest()

def check_hashes(password,hashed_text):
	if make_hashes(password) == hashed_text:
		return hashed_text
	return False

def view_all_users():
	c.execute('SELECT * FROM userstable')
	data = c.fetchall()
	return data

def loginSys():
  menu = ["Home", "Login", "Signup"]
  choice = st.sidebar.selectbox("Menu", menu)

  if choice == "Home":
    st.subheader("Welcome")
    st.markdown("**Login or Signup to Access the System**")
  
  elif choice == "Login":
    st.subheader("Home Page")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type = 'password')
    
    if st.sidebar.checkbox("Login"):
      create_usertable()
      hashed_pass = make_hashes(password)
      result = login_user(username, check_hashes(password,hashed_pass))
      
      if result:  
        if username == "noura":
          st.success("Logged in as Adminstrator")
          menu_task = ["Analytics", "Add New Data", "Classify URL"]
          task = st.selectbox("Task", menu_task)
          
          if task == "Classify URL":
            st.subheader("**Enter URL To Classify:**")
            user_input = st.text_input("Input URL")
            features = ExtractFeatures(user_input)
            features = np.reshape(features, (-1,1)).T

            classify(user_input, features)
          
          elif task == "Analytics":
            st.markdown("** Verified Phishing Websites **")
            st.dataframe(df)
            st.markdown("**Current Users**")
            user_result = view_all_users()
            clean_db = pd.DataFrame(user_result, columns =['Username', 'Password'] )
            st.dataframe(clean_db)

          elif task == "Add New Data":
            data = st.file_uploader("Choose a CSV File")
            data = pd.DataFrame(data)
            data.to_csv("/home/n/Desktop/The Goal/SE-Project-mat/verified_phishing_sites.csv", mode = 'a', header = False)
        
        else:
          st.success("Logged in as {}".format(username))
          st.markdown("**URL Detection**")
          user_input = st.text_input("Input URL")
          features = ExtractFeatures(user_input)
          features = np.reshape(features, (-1,1))
          classify(user_input, features)
          st.button("Generate Report")
          # Create another option to generate report
      else:
        st.error("Password or username is wrong, please try again!")
    
  elif choice == "Signup":
    st.subheader("Create Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type = 'password')
      
    if st.button("Signup"):
      create_usertable()
      add_userdata(new_user, make_hashes(new_pass))
      st.success("You Have Successfully Created a Valid Account!")
      st.info("Go to Login Menu to Login")

df = pd.read_csv("verified_phishing_sites.csv")
df.drop(df.index[-1], inplace = True)
#df.drop('0', axis =1 , inplace = True)
@st.cache
def load_model():
	#object = pd.read_pickle(url2)
#  	with open("https://github.com/noura-na/phishing-websites-detection-app/releases/download/tag/model/model.sav", 'rb') as res:
# 	model = pickle.load(filename)

	from urllib.request import urlopen
	import cloudpickle as cp

	loaded_pickle_object = cp.load(urlopen("https://drive.google.com/file/d/1cKb_kPBnu8meKEmJy5ooux6sg5oQZwaH", 'rb')) 

	return loaded_pickle_object

model = load_model()

def makePrediction(features, url):
  probability = model.predict_proba(features)
  output = model.predict(features)
  if output[0] == 1:
    output = "Legitimate"
    st.success(output)
  else:
    df.loc[len(df.index)] = url
    df_new = df.copy()
    df_new.to_csv("verified_phishing_sites_updated.csv", index = False)
    output = "Phishing"
    st.warning(output)
  st.markdown('**Predicted Probability**')
  st.bar_chart(probability)

def checkinDB(user_input):
    if df[df['url'].str.contains(user_input)].count()[0]:
      st.warning("Phishing")
      return -1
    return 0

def classify(url, features):
  if checkinDB(url) != -1:
    makePrediction(features, url)


loginSys()
