import re
import math
import joblib
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

model = joblib.load("models/text_threat_model.pkl")
vectorizer = joblib.load("models/text_vectorizer.pkl")

stemmer = PorterStemmer()
stop_words = set(stopwords.words('english'))

def preprocess_text(text):
    text = str(text)
    text = re.sub(r'http\\S+|www\\S+', ' ', text)
    text = re.sub(r'\\S+@\\S+', ' ', text)
    text = re.sub(r'escapenumber', ' ', text)
    text = re.sub(r'forwarded by|original message|subject|cc|sent|from|to', ' ', text)
    text = re.sub(r'[^a-zA-Z]', ' ', text)
    text = text.lower().split()
    text = [stemmer.stem(word) for word in text if word not in stop_words and len(word) > 2]
    return " ".join(text)

def scan_text_message(message):
    cleaned = preprocess_text(message)
    vec = vectorizer.transform([cleaned])

    decision = model.decision_function(vec)[0]
    pred = model.predict(vec)[0]

    confidence = round(100 / (1 + math.exp(-abs(decision))), 2)

    if pred == 1:
        status = "Dangerous Communication"
    else:
        status = "Legitimate Communication"

    return {
        "status": status,
        "confidence": confidence
    }