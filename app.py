import streamlit as st
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from urllib.parse import urlparse
import re

# Load model & tokenizer
model = load_model("phishing_cnn_bigru_model.keras")
with open("tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 200

#Url feature analysis logic
# ----------------------------
# 1️⃣ DOMAIN & IDENTITY DECEPTION
def domain_identity_checks(url):
    reasons = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
        reasons.append("Uses IP address instead of domain name (common in phishing)")

    if any(char.isdigit() for char in domain):
        reasons.append("Domain contains numeric characters to mimic legitimate sites")

    if domain.count('.') > 3:
        reasons.append("Excessive subdomains used to hide real domain identity")

    return reasons

# ----------------------------
# 2️⃣ KEYWORD-BASED SOCIAL ENGINEERING
def keyword_checks(url):
    phishing_keywords = [
        "login", "verify", "secure", "update", "account",
        "bank", "signin", "confirm", "password", "paypal",
        "free", "reward", "urgent"
    ]

    reasons = []
    url_lower = url.lower()
    found = [k for k in phishing_keywords if k in url_lower]
    if found:
        reasons.append(f"Contains phishing-related keywords: {', '.join(found)}")
    return reasons

# ----------------------------
# 3️⃣ STRUCTURAL URL MANIPULATION
def structural_checks(url):
    reasons = []
    if '@' in url:
        reasons.append("Contains '@' symbol which can redirect to malicious domain")
    if url.count('-') > 3:
        reasons.append("Excessive hyphens used to imitate legitimate domains")
    if url.count('//') > 1:
        reasons.append("Multiple redirection symbols found")
    if len(url) > 80:
        reasons.append("Unusually long URL designed to obscure malicious intent")
    return reasons

# ----------------------------
# 4️⃣ SECURITY & PROTOCOL ISSUES
def security_checks(url):
    reasons = []
    if not url.startswith("https://"):
        reasons.append("Does not use HTTPS, indicating lack of encryption")
    if url.startswith("http://"):
        reasons.append("Uses insecure HTTP protocol")
    return reasons

# ----------------------------
# 5️⃣ TOP-LEVEL DOMAIN (TLD) RISK
def tld_checks(url):
    suspicious_tlds = [
        ".ru", ".tk", ".ml", ".ga", ".cf",
        ".xyz", ".top", ".info", ".biz"
    ]
    reasons = []
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            reasons.append(f"Uses suspicious top-level domain: {tld}")
    return reasons

# ----------------------------
# 6️⃣ BRAND IMPERSONATION DETECTION
def brand_impersonation_checks(url):
    brands = ["google", "paypal", "amazon", "facebook", "microsoft", "apple"]
    reasons = []
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    for brand in brands:
        if brand in url.lower() and brand not in domain:
            reasons.append(f"Possible brand impersonation attempt involving '{brand}'")
    return reasons

# ----------------------------
# MASTER FUNCTION
def analyze_url_features(url):
    reasons = []
    reasons += domain_identity_checks(url)
    reasons += keyword_checks(url)
    reasons += structural_checks(url)
    reasons += security_checks(url)
    reasons += tld_checks(url)
    reasons += brand_impersonation_checks(url)
    if not reasons:
        reasons.append("No significant phishing patterns detected in the URL")
    return reasons
#risk
def risk_contribution(url):
    scores = {
        "Domain": 0,
        "Keywords": 0,
        "Structure": 0,
        "Security": 0,
        "TLD": 0,
        "Brand": 0
    }

    # Domain
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if re.search(r'\d+\.\d+\.\d+\.\d+', domain) or any(char.isdigit() for char in domain):
        scores["Domain"] = 1

    if domain.count('.') > 3:
        scores["Domain"] += 1

    # Keywords
    keywords = ['login','verify','secure','update','account','bank','signin','confirm','password','paypal','free','reward','urgent']
    scores["Keywords"] = sum(word in url.lower() for word in keywords)

    # Structure
    scores["Structure"] = 0
    if '@' in url:
        scores["Structure"] += 1
    if url.count('-') > 3:
        scores["Structure"] += 1
    if url.count('//') > 1:
        scores["Structure"] += 1
    if len(url) > 80:
        scores["Structure"] += 1

    # Security
    scores["Security"] = 0 if url.startswith("https://") else 1

    # TLD
    suspicious_tlds = [".ru", ".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".info", ".biz"]
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            scores["TLD"] = 1

    # Brand
    brands = ["google","paypal","amazon","facebook","microsoft","apple"]
    for brand in brands:
        if brand in url.lower() and brand not in domain:
            scores["Brand"] = 1

    return scores


#highlight suspicious url
def highlight_url(url):
    suspicious_parts = []

    if '@' in url:
        suspicious_parts.append('@')
    suspicious_parts += [k for k in ['login','verify','secure','update','account','paypal'] if k in url.lower()]
    if url.startswith("http://"):
        suspicious_parts.append("http://")
    return suspicious_parts



# Prediction function
def predict_url(url):
    seq = tokenizer.texts_to_sequences([url])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding="post")
    prob = model.predict(padded)[0][0]
    label = "Phishing" if prob > 0.5 else "Benign"
    return label, prob

# UI
st.set_page_config(page_title="Phishing URL Detection", layout="centered")
st.title("🔐 Intelligent Phishing URL Detection")
st.write("Enter a URL to check whether it is **Phishing or Benign** using a Deep Learning model.")

url_input = st.text_input("🔗 Enter URL:")

if st.button("Check URL"):
    if url_input.strip() == "":
        st.warning("Please enter a URL")
    else:
        # 1️⃣ Model prediction
        label, prob = predict_url(url_input)

        # 2️⃣ Display result
        if label == "Phishing":
            st.error("🚨 Result: PHISHING URL")
        else:
            st.success("✅ Result: BENIGN URL")

        st.write(f"**Confidence Score:** {prob:.2f}")

        # 2️⃣.1 Risk Level (NEW)
        if prob > 0.85:
            risk = "🔴 High Risk"
        elif prob > 0.6:
            risk = "🟡 Medium Risk"
        else:
            risk = "🟢 Low Risk"

        st.subheader("⚠️ URL Risk Level")
        st.write(risk)


        # 3️⃣ Dynamic URL feature justification
        reasons = analyze_url_features(url_input)
        st.subheader("🔍 URL-specific Justification")
        for r in reasons:
            st.write("•", r)
        # 4️⃣ Dynamic risk contribution
        scores = risk_contribution(url_input)
        st.subheader("📊 URL Risk Contribution")
        plt.figure(figsize=(6,4))
        plt.bar(scores.keys(), scores.values(), color='orange')
        st.pyplot(plt)

        # 5️⃣ Highlight suspicious parts of URL
        parts = highlight_url(url_input)
        st.subheader("🔗 Highlighted Suspicious Parts")
        for p in parts:
            st.markdown(f"• **{p}**")
        # 6️⃣ confusion matrix
        y_true = [1]  # 1=phishing
        y_pred = [1] if label=="Phishing" else [0]

        cm = pd.DataFrame([[0,0],[0,0]], index=["Benign","Phishing"], columns=["Benign","Phishing"])
        cm.iloc[y_true[0], y_pred[0]] = 1

        st.subheader("📈 Confusion Matrix (Current Prediction)")
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
        st.pyplot(plt)
        

        st.subheader("📊 Prediction Confidence")
        st.progress(float(prob))
        st.write(f"Model confidence: **{prob*100:.2f}%**")

        scores = risk_contribution(url_input)

        st.subheader("📊 URL Risk Contribution")
        plt.figure(figsize=(6,4))
        plt.bar(scores.keys(), scores.values())
        plt.ylabel("Risk Level")
        plt.xlabel("Feature Category")
        st.pyplot(plt)

        



       
        