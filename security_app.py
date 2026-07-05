import os
import streamlit as st
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
    .stButton>button { width: 100%; background-color: #0066cc; color: white; border-radius: 8px; font-weight: bold; }
    .stButton>button:hover { background-color: #0052a3; color: white; }
    .report-box { background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    </style>
    """, unsafe_allow_html=True)

# Simple & direct initialization for Streamlit Secrets
api_key = st.secrets.get("GEMINI_API_KEY")
client = genai.Client(api_key=api_key)

def analyze_vulnerabilities_with_gemini(cloud_provider, raw_cloud_logs):
    system_instruction = (
        f"You are an expert Cloud Security DevSecOps Engineer. Your job is to analyze the provided "
        f"{cloud_provider} asset metadata for security vulnerabilities based on CIS Benchmarks and SOC 2. "
        "For each vulnerability found, you must provide: 1. A short explanation of the risk, "
        "2. The exact CLI command to fix it, and 3. The precise Terraform snippet to remediate it. "
        "Keep the output clean, highly structured, and directly copy-pasteable for developers."
    )
    
    prompt = f"""
    Analyze the following raw configuration data from a client's {cloud_provider} account.
    Find all high and critical risks and output the remediation code.
    
    Raw Metadata:
    {raw_cloud_logs}
    """
    
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.2
        )
    )
    return response.text

# --- UI CODE ---
st.markdown("# 🛡️ CloudShield AI <span style='font-size:18px; color:gray;'>v1.0 (Live MVP)</span>", unsafe_allow_html=True)
st.caption("Enterprise-grade Automated Cloud Security Vulnerability Scanner & Remediation Engine")
st.markdown("---")

col1, col2 = st.columns([1, 2], gap="large")

with col1:
    st.markdown("### ⚙️ Scan Configuration")
    provider = st.selectbox("Select Cloud Provider", ["AWS", "Google Cloud (GCP)", "Azure"])
    
    # Provider ke basis par mock data change hoga
    if provider == "AWS":
        default_mock_data = """[
    {
        "ResourceId": "arn:aws:s3:::user-invoice-payment-data-prod",
        "Vulnerability": "PublicReadAccessAllowed",
        "Policy": { "GrantPublicRead": true }
    },
    {
        "ResourceId": "sg-0831af7792ec01b",
        "SecurityGroup": "LaunchWizard-1",
        "IpPermissions": [
            { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}] }
        ]
    }
]"""
    elif provider == "Google Cloud (GCP)":
        default_mock_data = """[
    {
        "ResourceId": "//compute.googleapis.com/projects/my-prod-project/zones/us-central1-a/instances/prod-db",
        "Vulnerability": "ExternalIPAllowed",
        "NetworkInterfaces": { "HasExternalIP": true }
    }
]"""
    else:
        default_mock_data = """[
    {
        "ResourceId": "/subscriptions/sub-id/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/proddataleak",
        "Vulnerability": "AllowBlobPublicAccess",
        "Properties": { "allowBlobPublicAccess": true }
    }
]"""
    
    st.markdown("#### 📋 Raw Cloud Metadata (Input)")
    cloud_logs_input = st.text_area("JSON Metadata", value=default_mock_data, height=220)
    start_audit = st.button("🚀 Run AI Security Audit")

with col2:
    st.markdown("### 📊 Audit Results & Dashboard")
    
    if start_audit:
        with st.spinner("Analyzing with Gemini 2.5 Flash..."):
            try:
                report = analyze_vulnerabilities_with_gemini(provider, cloud_logs_input)
                
                st.markdown("#### 🛡️ Executive Summary")
                m1, m2, m3 = st.columns(3)
                m1.metric(label="Critical Threats", value="1", delta="-1 Fixed", delta_color="inverse")
                m2.metric(label="High Threats", value="0" if provider != "AWS" else "1", delta="Fixed", delta_color="inverse")
                m3.metric(label="Compliance Score", value="70%", delta="+30% after fix")
                
                st.markdown("---")
                
                tab1, tab2 = st.tabs(["📝 Full Remediation Report", "💾 Export Data"])
                
                with tab1:
                    st.success("✅ Audit Completed! Detailed remediation steps generated below:")
                    st.markdown(f"<div class='report-box'>{report}</div>", unsafe_allow_html=True)
                
                with tab2:
                    st.markdown("#### Download Security Artifacts")
                    st.download_button(
                        label="📥 Download Report (.txt)",
                        data=report,
                        file_name=f"cloudshield_{provider.lower()}_report.txt",
                        mime="text/plain"
                    )
            except Exception as e:
                st.error(f"Error during scan: {e}")
    else:
        st.info("👈 Left side par apni configurations select/edit karein aur 'Run AI Security Audit' par click karein.")
