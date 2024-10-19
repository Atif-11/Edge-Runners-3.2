import streamlit as st
import os
import sqlite3
import bcrypt
import base64
import requests
from dotenv import load_dotenv

# Load the API key from the .env file
load_dotenv()
API_KEY = os.getenv("API_KEY")

# Initialize SQLite database connection
conn = sqlite3.connect('Users.db', check_same_thread=False)
c = conn.cursor()

# Create users table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT, password TEXT)''')
conn.commit()

# Hash the password before storing it
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Check the hashed password during login
def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

# Signup function
def signup(username, password):
    hashed_password = hash_password(password)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()

# Login function
def login(username, password):
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if user and check_password(password, user[0]):
        return True
    return False

# Function to encode the image to base64
def encode_image(image):
    return base64.b64encode(image.read()).decode('utf-8')

# Vision LLM call to process the image
def run_vision_llm(image, api_key):
    base64_image = encode_image(image)
    url = "https://api.aimlapi.com/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": "meta-llama/Llama-3.2-11B-Vision-Instruct-Turbo",
        "messages": [
            {
                "role": "assistant",
                "content": "You are a plant disease detector extracting important features for disease detection in plant images."
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "What features are in this plant image for a disease?"},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}}
                ]
            }
        ],
        "max_tokens": 100
    }

    response = requests.post(url, headers=headers, json=payload)
    response_data = response.json()

    if 'choices' in response_data:
        return response_data['choices'][0]['message']['content']
    else:
        return "No features found."

# Reasoning LLM call to provide disease prediction and recommendation
def run_reasoning_llm(plant_name, features, api_key):
    url = "https://api.aimlapi.com/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    payload = {
        "model": "meta-llama/Llama-3.2-3B-Instruct-Turbo",
        "messages": [
            {
                "role": "assistant",
                "content": 
                "You are a helpful disease detector. You reason for"
                "the potential plant disease based on provided features"
                "and then provide a single highly likely disease and specific recommendations"
            },
            {
                "role": "user",
                "content": (f"Based on these features: {features}, "
                            f"what is the most likely disease affecting the plant '{plant_name}'? "
                            "If plant looks healthy, say no disease detected.")
            }
        ],
        "max_tokens": 300
    }

    response = requests.post(url, headers=headers, json=payload)
    response_data = response.json()

    if 'choices' in response_data:
        response_content = response_data['choices'][0]['message']['content']
        
        if "Recommendation:" in response_content:
            disease, recommendation = response_content.split("Recommendation:")
            return disease.strip(), recommendation.strip()
        else:
            return response_content.strip(), "No recommendation provided."
    else:
        return "Unknown", "No recommendation."

# Streamlit frontend
def main():
    st.title("PlantGuard: AI-powered Plant Disease Detection")

    # Check if the user is logged in
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if st.session_state.logged_in:
        run_app(st.session_state.username)  # Run the main app if logged in
    else:
        # Sidebar for login/signup
        menu = ["Login", "Signup"]
        choice = st.sidebar.selectbox("Menu", menu)

        if choice == "Signup":
            st.subheader("Create a New Account")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Signup"):
                signup(username, password)
                st.success("Account created successfully! Please log in.")

        elif choice == "Login":
            st.subheader("Login to Your Account")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.button("Login"):
                if login(username, password):
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.success(f"Welcome, {username}!")
                    st.rerun()  # Rerun the app to go to the logged-in page
                else:
                    st.warning("Incorrect username or password.")

# Main application after login
def run_app(username):
    st.subheader("Plant Disease Detection System")
    
    # Logout button
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    # New page interface for plant name and image upload after login
    st.write(f"Logged in as: {username}")

    # Input for plant name and image upload
    plant_name = st.text_input("Plant Name", key="plant_name")
    uploaded_image = st.file_uploader("Upload an Image of the Plant", type=["jpg", "png", "jpeg"], key="image_uploader")

    if plant_name and uploaded_image and st.button("Diagnose"):
        # Step 1: Extract features using Vision LLM
        image_features = run_vision_llm(uploaded_image, API_KEY)
        
        # Step 2: Run reasoning LLM for disease prediction
        disease, recommendation = run_reasoning_llm(plant_name, image_features, API_KEY)
        
        # Display results on the app
        st.write(f"**Detected Disease**: {disease}")

if __name__ == '__main__':
    main()
