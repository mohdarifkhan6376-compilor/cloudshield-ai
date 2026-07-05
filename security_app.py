import streamlit as st
import os
import json
from google import genai
from google.genai import types

# Streamlit Page Configuration
st.set_page_config(
    page_title="CloudShield AI | Enterprise Security",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for Premium Look
st.markdown("""
<style>
    .main { background-color: #f8f9fa; }
    .stButton>button { width: 100%; background-color: #0066cc; color: white; border-radius: 8px; }
    .stButton>button:hover { background-color: #0052a3; color: white; }
    .report-box { background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
</style>
""", unsafe_allow_html=True)

# 1. Shuruat wala direct validation code
if "GEMINI_API_KEY" in st.secrets:
    api_key = st.secrets["GEMINI_API_KEY"]
else:
    api_key = os.environ.get("GEMINI_API_KEY")

client = genai.Client(api_key=api_key)

# Layout Columns
col1, col2 = st.columns([1, 2])

with col1:
    st.markdown("## ⚙️ Scan Configuration")
    cloud_provider = st.selectbox("Select Cloud Provider", ["AWS", "GCP", "Azure"])
    
    st.markdown("### 📄 Raw Cloud Metadata (Input)")
    # Is variable ka naam humne raw_cloud_logs rakha hai jo niche use hoga
    raw_cloud_logs = st.text_area("JSON Metadata", height=300, placeholder="Paste your cloud asset JSON logs here...")

def analyze_vulnerabilities_with_gemini(cloud_provider, logs_data):
    system_instruction = (
        f"You are an expert Cloud Security DevSecOps Engineer. Your job is to analyze the provided "
        f"'{cloud_provider}' asset metadata for security vulnerabilities based on CIS Benchmarks and standard security frameworks. "
        "For EACH vulnerability found, you must provide EXACTLY this clean structure without mixing text:\n"
        "### 🔍 Issue: [Resource ID] - [Short Vulnerability Name]\n"
        "**💥 Risk Explanation:** [Provide a high-impact business and technical explanation of the risk]\n"
        "**💻 AWS CLI Command to Fix:**\n"
        "```bash\n"
        "[Insert clean, direct, copy-pasteable CLI command here]\n"
        "```\n"
        "**🛠️ Terraform Snippet to Remediate:**\n"
        "```hcl\n"
        "[Insert direct, copy-pasteable Terraform resource block here]\n"
        "```\n"
        "---"
    )
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"Analyze these logs and give remediations:\n{logs_data}",
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2
            )
        )
        return response.text
    except Exception as e:
        return f"Error during scan: {str(e)}"

with col2:
    st.markdown("## 📊 Audit Results & Dashboard")
    
    if st.button("🚀 Run AI Security Audit"):
        if not raw_cloud_logs.strip():
            st.warning("⚠️ Please provide raw cloud metadata input to run the audit.")
        else:
            with st.spinner("🕵️‍♂️ CloudShield AI is auditing your infrastructure logs..."):
                audit_result = analyze_vulnerabilities_with_gemini(cloud_provider, raw_cloud_logs)
                
                st.success("✅ Audit Completed Successfully!")
                st.markdown("### 📊 Detailed Remediation Report")
                st.markdown(audit_result)
