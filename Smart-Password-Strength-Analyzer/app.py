import streamlit as st
import plotly.graph_objects as go
from password_checker import *
from password_checker import generate_pdf_report

# ---------------- PAGE SETTINGS ----------------

st.set_page_config(
    page_title="Cyber Security Operations Center",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ---------------- HACKER THEME ----------------

st.markdown("""
<style>

/* Main Background */
.stApp {
    background-color: #0d1117;
    color: #00ff41;
}

/* Headers */
h1, h2, h3 {
    color: #00ff41 !important;
    text-align: center;
}

/* Paragraphs */
p {
    color: #c9d1d9;
}

/* Metrics */
div[data-testid="stMetric"] {
    background-color: #161b22;
    padding: 15px;
    border-radius: 15px;
    border: 1px solid #00ff41;
    text-align: center;
}

/* Input Box */
.stTextInput input {
    background-color: #161b22 !important;
    color: #00ff41 !important;
    border: 1px solid #00ff41 !important;
    border-radius: 10px;
}

/* Buttons */
.stButton > button {
    background-color: #00f;
    color: #000000 !important;
    font-weight: bold;
    font-size: 16px;
    border-radius: 10px;
    font-weight: bold;
}

.stButton > button:hover {
    background-color: wite;
}

/* Progress Bar */
.stProgress > div > div > div > div {
    background-color: #00ff41;
}

/* Success Box */
div[data-testid="stAlert"] {
    border-radius: 10px;
}

/* Hide Streamlit Footer */
footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# ---------------- CYBER BANNER ----------------

st.markdown("""
<h1>🛡 CYBER SECURITY OPERATIONS CENTER</h1>
<h3>Real-Time Password Threat Analysis Engine</h3>
<hr>
""", unsafe_allow_html=True)



# ---------------- PASSWORD GENERATOR ----------------

st.subheader(" Password Generator")

if st.button("Generate Secure Password"):
    st.success(generate_password())

# ---------------- PASSWORD INPUT ----------------

password = st.text_input(
    "Enter Password",
    type="password"
)

# ---------------- ANALYSIS ----------------

if password:

    score, strength = password_strength(password)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    st.subheader(" Cryptographic Hashes")

    hashes = generate_hashes(password)

    tab1, tab2, tab3, tab4 = st.tabs(
        ["MD5", "SHA1", "SHA256", "SHA512"]
    )

    with tab1:
        st.code(hashes["MD5"])

    with tab2:
        st.code(hashes["SHA1"])

    with tab3:
        st.code(hashes["SHA256"])

    with tab4:
        st.code(hashes["SHA512"])

    st.info("""
MD5 and SHA1 are considered insecure for password storage.
SHA256 and SHA512 are stronger cryptographic hash algorithms.
""")

    pdf_file = generate_pdf_report(
        score,
        strength,
        entropy,
        crack_time
    )

    with open(pdf_file, "rb") as file:

        st.download_button(
            label=" Download Security Report",
            data=file,
            file_name="Password_Security_Report.pdf",
            mime="application/pdf"
        )

   
    # ---------------- GAUGE CHART ----------------

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': "PASSWORD SECURITY METER"},
        gauge={
            'shape': "angular",
            'axis': {'range': [0, 100]},
            'bar': {'color': "#00ff41"},
            'steps': [
                {'range': [0, 30], 'color': "#ff0000"},
                {'range': [30, 60], 'color': "#ff9900"},
                {'range': [60, 80], 'color': "#ffff00"},
                {'range': [80, 100], 'color': "#00ff41"}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 8},
                'thickness': 1,
                'value': score
            }
        }
    ))

    fig.update_layout(
        paper_bgcolor="#0d1117",
        plot_bgcolor="#0d1117",
        font={'color': "#00ff41"},
        height=500
    )

    st.plotly_chart(fig, use_container_width=True)
    if score < 30:
     st.error(" CRITICAL SECURITY RISK")

    elif score < 60:
     st.warning(" MODERATE SECURITY")

    elif score < 80:
     st.info(" GOOD SECURITY")

    else:
     st.success(" MAXIMUM SECURITY")

    # ---------------- CHECKLIST ----------------

    st.subheader(" Security Checklist")

    checks = {
        "Length ≥ 12": len(password) >= 12,
        "Uppercase Letter": any(c.isupper() for c in password),
        "Lowercase Letter": any(c.islower() for c in password),
        "Number": any(c.isdigit() for c in password),
        "Special Character": any(not c.isalnum() for c in password),
    }

    for item, passed in checks.items():
        st.write(f"{'' if passed else ''} {item}")

    # ---------------- SUGGESTIONS ----------------

    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters")

    if not any(c.isupper() for c in password):
        suggestions.append("Add uppercase letters")

    if not any(c.islower() for c in password):
        suggestions.append("Add lowercase letters")

    if not any(c.isdigit() for c in password):
        suggestions.append("Add numbers")

    if not any(not c.isalnum() for c in password):
        suggestions.append("Add special characters")

    if suggestions:
        st.subheader(" Suggestions")

        for s in suggestions:
            st.warning(s)

    # ---------------- SECURITY REPORT ----------------

    st.subheader(" Security Report")

    st.progress(score)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Strength Score",
            f"{score}/100"
        )

    with col2:
        st.metric(
            "Entropy",
            f"{entropy} bits"
        )

    with col3:
        st.metric(
            "Estimated Crack Time",
            crack_time
        )

    # ---------------- SECURITY WARNINGS ----------------

    if is_common_password(password):
        st.error(
            "⚠ Common Password Detected!"
        )

    if has_repeated_characters(password):
        st.warning(
            "⚠ Repeated Characters Detected"
        )

    if has_sequential_pattern(password):
        st.warning(
            "⚠ Sequential Pattern Detected"
        )

    # ---------------- FINAL RESULT ----------------

    if strength == "Strong":
        st.success(" Strong Password")

    elif strength == "Medium":
        st.warning(" Medium Password")

    else:
        st.error(" Weak Password")

# ---------------- ABOUT ----------------

st.markdown("---")

st.subheader("About This Project")

st.write("""
Smart Password Strength Analyzer

Features:
✔ Password Strength Detection  
✔ Entropy Calculation  
✔ Crack Time Estimation  
✔ Common Password Detection  
✔ Repeated Character Detection  
✔ Sequential Pattern Detection  
✔ Secure Password Generator  

Built using Python and Streamlit.
""")
