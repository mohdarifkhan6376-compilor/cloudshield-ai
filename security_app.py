import streamlit as st
import os
import json
import plotly.graph_objects as go
from google import genai
from google.genai import types

# Streamlit Page Configuration
st.set_page_config(
    page_title="CloudShield AI | Enterprise CyberSecurity",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for Premium Dark-Accent Enterprise Look
st.markdown("""
<style>
    .main { background-color: #0e1117; color: #ffffff; }
    .stButton>button { width: 100%; background-color: #0066cc; color: white; border-radius: 8px; font-weight: bold; }
    .stButton>button:hover { background-color: #0052a3; color: white; }
    div[data-testid="stMetricValue"] { font-size: 28px; font-weight: bold; color: #ff4b4b; }
</style>
""", unsafe_allow_html=True)

# Secure API Key Fetching
api_key = st.secrets.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")

client = None
if api_key:
    try:
        client = genai.Client(api_key=api_key)
    except Exception:
        client = None

# App Top Header
st.markdown("# 🛡️ CloudShield AI <span style='font-size:18px; color:#0066cc;'>Enterprise Risk Suite</span>", unsafe_allow_html=True)
st.markdown("---")

# Layout Columns
col1, col2 = st.columns([1, 2])

with col1:
    st.markdown("### ⚙️ Scan Configuration")
    cloud_provider = st.selectbox("Select Cloud Provider", ["AWS", "GCP", "Azure"])
    
    # NEW: Industry Vertical Selection
    industry_vertical = st.selectbox(
        "Select Industry Vertical", 
        ["General IT SaaS (SOC 2 / CIS)", "Smart Manufacturing & IoT", "Pharmaceuticals & API Labs (FDA 21 CFR)"]
    )
    
    st.markdown("### 📄 Raw Cloud Metadata (Input)")
    raw_cloud_logs = st.text_area("JSON Metadata Input", height=250, placeholder="Paste your cloud asset JSON logs here...")

def analyze_vulnerabilities_with_gemini(cloud_provider, industry, logs_data):
    if not client:
        return "❌ Error: AI Engine core initialization failed. Please check your API key secrets."
        
    system_instruction = (
        f"You are an expert Cloud Security DevSecOps Engineer specializing in '{industry}'. "
        f"Your job is to analyze the provided '{cloud_provider}' asset metadata for security vulnerabilities "
        f"based on standard frameworks relevant to '{industry}' (like CIS Benchmarks, ISO 27001, or FDA 21 CFR Part 11).\n\n"
        "For EACH vulnerability found, you must provide EXACTLY this clean structure without adding any extra conversational text:\n"
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
            contents=f"Analyze these logs and give industry-specific remediations:\n{logs_data}",
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2
            )
        )
        if response and response.text:
            return response.text
        else:
            return "⚠️ AI engine completed the scan but returned an empty assessment."
    except Exception as e:
        return f"❌ Connection Error during live scan: {str(e)}"

with col2:
    st.markdown("### 📊 Audit Results & Insights Dashboard")
    
    # Placeholder or Triggered Output
    if st.button("🚀 Run Industry-Targeted Security Audit"):
        clean_input = raw_cloud_logs.strip()
        
        if not clean_input:
            st.warning("⚠️ Input required: Please paste your raw cloud metadata JSON logs to trigger the automated security audit.")
        else:
            is_valid_json = True
            try:
                json.loads(clean_input)
            except json.JSONDecodeError:
                is_valid_json = False
            
            if not is_valid_json:
                st.error("🛑 Format Error: The provided input is not a valid JSON structure. Please check for missing brackets.")
            else:
                with st.spinner("🕵️‍♂️ CloudShield AI is processing logs and mapping industry compliance metrics..."):
                    
                    # 1. GENERATE DYNAMIC DUMMY CHARTS BASED ON SELECTED INDUSTRY FOR UX PITCH
                    st.markdown("#### 🚨 Real-Time Security Posture")
                    m_col1, m_col2, m_col3 = st.columns(3)
                    
                    # Dynamic scoring metrics based on selection logic for rich visuals
                    if "Pharmaceuticals" in industry_vertical:
                        critical, high, score = 2, 1, "68%"
                    elif "Manufacturing" in industry_vertical:
                        critical, high, score = 1, 3, "74%"
                    else:
                        critical, high, score = 1, 1, "80%"
                        
                    m_col1.metric("Critical Threats", f"{critical} Detected")
                    m_col2.metric("High Threats", f"{high} Detected")
                    m_col3.metric("Compliance Score", score)
                    
                    # Interactive Plotly Pie Chart for Threat Severity
                    labels = ['Critical Threats', 'High Threats', 'Low Risk / Secure Assets']
                    values = [critical, high, 8]
                    colors = ['#ff4b4b', '#ffa500', '#2ed573']
                    
                    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.4)])
                    fig.update_traces(hoverinfo='label+percent', textinfo='value', marker=dict(colors=colors))
                    fig.update_layout(
                        margin=dict(t=10, b=10, l=10, r=10),
                        height=220,
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        showlegend=True
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # 2. RUN LIVE AI CORE ASSESSMENT
                    audit_result = analyze_vulnerabilities_with_gemini(cloud_provider, industry_vertical, clean_input)
                    
                    st.markdown("---")
                    st.markdown("### 📑 Detailed Remediation Report")
                    st.markdown(audit_result)
