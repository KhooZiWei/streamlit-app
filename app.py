import streamlit as st
from streamlit_option_menu import option_menu
import re
import tldextract
from urllib.parse import urlparse
import pandas as pd
import plotly.graph_objects as go
import matplotlib.pyplot as plt
import joblib


# Page 
st.set_page_config(
    page_title= "Malicious URL Detection", # Page title
    page_icon="./Icons/malicious.png", # Page Icon
)

# Sidebar
with st.sidebar:
    selected = option_menu(
        menu_title="Main Menu", # Menu Title
        options=["Home", "URL Classification Engine", "Feature Extraction Analysis", "About", "Documentation"], # Menu options
        icons=["house-fill", "link-45deg", "gear-fill", "info-circle-fill", "file-earmark-fill"],
        menu_icon="list-ul",
        default_index=0 # Default choose Home Page
    )

    # Display GIF in the sidebar
    st.sidebar.image("./Icons/hacker.png", use_column_width=True)

# Map Visualization
malicious_counts_by_region = pd.read_csv("malicious_counts_by_region.csv")

zmin = 0 
zmax = malicious_counts_by_region['count'].max() 

fig = go.Figure(data=go.Choropleth(
    locations=malicious_counts_by_region['url_region'],
    z=malicious_counts_by_region['count'],
    locationmode='country names',
    colorscale='rainbow',
    autocolorscale=False,
    colorbar_title='Count of Malicious URLs',
    zmin=zmin,
    zmax=zmax
))

fig.update_layout(title_text='Distribution of Malicious URLs by Country')


# Home Page
if selected == "Home":
    st.title("Malicious URL Detection")
    st.write("""
        Welcome to the realm of cybersecurity and malicious URL detection. 
        In this digital age, the internet is a vast landscape, and protecting our data against malicious URLs is more crucial than ever. 
        These URLs pose significant threats, often leading to harmful websites that spread viruses, malware, and other destructive programs. 
        The main goal of this detection is to empower users to distinguish between safe and malicious web addresses, enhancing their ability to make informed decisions. 
        With the rise of sophisticated phishing attacks, it's essential to stay vigilant. 
        This platform serves as a guardian, classifying URLs to safeguard your digital experience.
    """)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.plotly_chart(fig) # Display the choropleth map


# ML Model
# Load your pre-trained model
model = joblib.load('model_xgb.pkl')

def process_url(url):
    features = {}

    # Extract features from the URL and add them to the dictionary
    features['url_length'] = len(url)
    hostname = tldextract.extract(url).domain
    features['hostname_length'] = len(hostname)
    features['path_length'] = len(urlparse(url).path)

    # First Directory Length
    urlpath = urlparse(url).path
    try:
        features['fd_length'] = len(urlpath.split('/')[1])
    except:
        features['fd_length'] = 0

    # Length of Top Level Domain
    tld = tldextract.extract(url).suffix
    features['tld_length'] = len(tld) if tld else -1

    # Count special characters
    special_chars = ['-', '@', '?', '%', '.', '=']
    for char in special_chars:
        features[f'count{char}'] = url.count(char)

    # Count http
    features['count-http'] = url.count('http')

    # Count https
    features['count-https'] = url.count('https')

    # Count www
    features['count-www'] = url.count('www')

    # Count digits and letters
    features['count-digits'] = sum(c.isdigit() for c in url)
    features['count-letters'] = sum(c.isalpha() for c in url)

    # Count number of directories
    features['count_dir'] = url.count('/')

    # Use of IP or not in domain
    ip_pattern = re.compile(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}'  # IPv6
    )
    features['use_of_ip'] = -1 if ip_pattern.search(url) else 1

    # Check for shortening service
    shortening_services = ['bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 
                           't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 
                           'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 
                           'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 
                           'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 
                           'om.ly', 'to.ly', 'bit.do', 't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 
                           'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im', 'q.gs', 'is.gd', 
                           'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 
                           'yourls.org', 'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 
                           'qr.net', '1url.com', 'tweez.me', 'v.gd', 'tr.im', 'link.zip.net']
    features['short_url'] = -1 if any(service in url for service in shortening_services) else 1

    return pd.DataFrame([features])


# Function to classify URL
def classify_url(url):
    X_new = process_url(url)

    prediction = model.predict(X_new)[0]
    return prediction


# Malicious URL Detection Page
if selected == "URL Classification Engine":
    st.title("URL Classification Engine")
    st.write("""
        This tool uses an advanced XGBoost machine learning model to classify URLs into four 
        categories: Benign, Defacement, Phishing, and Malware. Simply enter a URL below, and the 
        engine will analyze and classify it based on its characteristics.
    """)
    st.write("")
    user_input_url = st.text_input("**Enter a URL to classify:**")
    if st.button("Detect"):
        result = classify_url(user_input_url)
        if result == 0:
            st.success("Secure: The URL is classified as Benign. It appears to be safe.")
        elif result == 1:
            st.error("Warning: The URL is classified as Defacement. It may contain harmful content.")
        elif result == 2:
            st.error("Warning: The URL is classified as Phishing. Be cautious of potential scams.")
        elif result == 3:
            st.error("Warning: The URL is classified as Malware. It could be dangerous to your device.")


# Load datasets
data1 = pd.read_csv('dataset1.csv')
data2 = pd.read_csv('dataset2.csv')

# List of features for the dropdown
features = ['url_length', 'hostname_length', 'path_length', 'fd_length', 'tld_length', 
            'count-', 'count@', 'count?', 'count%', 'count.', 'count=', 'count-http', 
            'count-https', 'count-www', 'count-digits', 'count-letters', 'count_dir']

# Create histograms
def create_histogram(feature):
    plt.figure(figsize=(12, 6))
    plt.hist(data1[feature], bins=20, color='#265073', edgecolor='black', alpha=0.5, label='Dataset 1')
    plt.hist(data2[feature], bins=20, color='#F3F3F3', edgecolor='black', alpha=0.5, label='Dataset 2')
    plt.title(f'Count of {feature}')
    plt.xlabel(feature)
    plt.ylabel('Count')
    plt.legend()
    st.pyplot(plt)


# Feature Extraction Analysis Page
if selected == "Feature Extraction Analysis":
    st.title("Feature Extraction Analysis")
    st.image(".\Icons\structure_url.png", caption="Structure of URL")
    st.write("""
        The image above illustrates the structure of a URL. 
        By entering a URL below, you will be presented with a table that displays the features extracted 
        from the URL. This will help you gain a clearer understanding of the URL's structure and its characteristics.
    """)
    st.write("")
    user_input_url = st.text_input("**Enter a URL to analyse its features:**")
    if st.button("Analyse"):
        features_df = process_url(user_input_url)
        st.write("")
        st.write("Features extracted from the URL:")
        st.dataframe(features_df)
        st.write("Note:")
        st.markdown("""
            - **use_of_ip**: Indicates if an IP address is used in the URL. "1" means not using, "-1' means it has an IP address.
            - **short_url**: Indicates if the URL is a shortened URL. "1" means it does not contain a shortening service, "-1" means it contains a shortening service.
        """)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("""
        <h4 style="color:#A0E9FF;">Histogram Visualization of URL Features</h4>
    """, unsafe_allow_html=True)
    # Sidebar for feature selection
    selected_feature = st.selectbox('**Select a feature for histogram:**', features)
    create_histogram(selected_feature) # Display the histogram for the selected feature


# About Page
if selected == "About":
    st.title("About")
    st.write("""
        Malicious URL Detection is a crucial aspect of cybersecurity, where machine learning models are employed 
        to identify and classify URLs as benign or malicious. This approach leverages advanced algorithms to analyze 
        URL patterns, going beyond the limitations of traditional blacklist methods. Blacklists often 
        fail to keep up with the rapidly evolving nature of cyber threats, as they can only block known malicious URLs. 
        Machine learning models, on the other hand, can learn and adapt to new patterns, offering a more dynamic and 
        proactive defense against emerging threats.
    """)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("""
        <h4 style="color:#A0E9FF;">Importance of Detecting Malicious URLs</h4>
    """, unsafe_allow_html=True)
    st.write("""  
        Detecting malicious URLs is vital for safeguarding personal and organizational data. Cyber attacks often 
        begin with a malicious link, leading to severe consequences like data breaches, financial loss, and compromised 
        privacy. Early detection of these URLs can prevent these attacks, protect sensitive information, and maintain 
        the integrity of digital systems. In an era where cyber threats are becoming more sophisticated, the ability to 
        accurately identify and block malicious URLs is more important than ever.
    """)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("""
        <h4 style="color:#A0E9FF;">Ways to Identify and Respond to Malicious Links</h4>
    """, unsafe_allow_html=True)
    st.video("https://youtu.be/LarpE5bfqoY?si=kiZJ-1SZna3zO37k")

# Documentation Page
if selected == "Documentation":
    st.title("Documentation")
    st.write("""
        This section serves as a comprehensive guide, detailing each page within the system. 
        It's designed to assist users in effectively navigating and utilizing the various features and functionalities 
        of the application.
    """)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.markdown("""
    <h4 style="color:#A0E9FF;">1. Home Page</h4>
    """, unsafe_allow_html=True)
    st.markdown("""
        - Introduces the concept of malicious URL detection and its significance in cybersecurity
        - Features a map visualization highlighting the prevalence of malicious URLs across different countries
    """)
    st.markdown("""
    <h4 style="color:#A0E9FF;">2. URL Classification Engine Page</h4>
    """, unsafe_allow_html=True)
    st.markdown("""
        - Utilizes an XGBoost machine learning model to categorize URLs into Benign, Phishing, Defacement, and Malware
        - Offers a user-friendly interface for URL input and real-time classification results
    """)
    st.markdown("""
    <h4 style="color:#A0E9FF;">3. Feature Extraction Analysis Page</h4>
    """, unsafe_allow_html=True)
    st.markdown("""
        - Demonstrates the process of extracting various features from a given URL
        - Provides histograms to visualize the distribution of different URL features across datasets
    """)
    st.markdown("""
    <h4 style="color:#A0E9FF;">4. About Page</h4>
    """, unsafe_allow_html=True)
    st.markdown("""
        - Explains the importance of detecting malicious URLs and the role of machine learning in this process
        - Includes a video guide on identifying and responding to malicious links
    """)
    st.markdown("<hr>", unsafe_allow_html=True)
    st.subheader("Dataset Used")
    st.write("")
    st.markdown("""
    <h5 style="color:#A0E9FF;">1. Malicious URLs dataset</h5>
    """, unsafe_allow_html=True)
    st.markdown("""
        - **Link:** https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
    """)
    st.markdown("""
    <h5 style="color:#A0E9FF;">2. Phishing Site URLs dataset</h5>
    """, unsafe_allow_html=True)
    st.markdown("""
        - **Link:** https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls?select=phishing_site_urls.csv
    """)
