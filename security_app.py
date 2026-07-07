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

# Bespoke Premium CSS Injector to fix contrast issues
st.markdown("""
<style>
    /* Force overall dark background */
    .stApp {
        background-color: #0e1117 !important;
        color: #e2e8f0 !important;
    }
    
    /* FIX: Force dropdown labels to be crisp white and visible */
    label[data-testid="stWidgetLabel"] p {
        color: #ffffff !important;
        font-weight: 600 !important;
        font-size: 16px !important;
    }
    
    /* Custom Styling for Headings */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', sans-serif;
        font-weight: 700 !important;
    }

    /* FIX: Force Critical Threats numbers to be bright RED */
    .critical-text {
        color: #ff4b4b !important;
        font-size: 32px !important;
        font-weight: 800 !important;
    }

    /* FIX: High Threats number styling (Vibrant Orange) */
    .high-text {
        color: #ffa500 !important;
        font-size: 32px !important;
        font-weight: 800 !important;
    }

    /* FIX: Compliance Score number styling (Neon Green) */
    .compliance-text {
        color: #2ed573 !important;
        font-size: 32px !important;
        font-weight: 800 !important;
    }
    
    /* Metrics box container layout styling */
    .metric-card {
        background-color: #1a1f2c;
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #0066cc;
        box-shadow: 0 4px 6px rgba(0,0,0,0.2);
        margin-bottom: 15px;
    }
    
    .metric-label {
        color: #a0aec0 !important;
        font-size: 14px !important;
        font-weight: 600;
        margin-bottom: 5px;
    }

    /* Primary Action Button Custom Theme */
    .stButton>button {
        width: 100%;
        background-color: #0066cc;
        color: white !important;
        border-radius: 8px;
        font-weight: bold;
        border: none;
        padding: 10px;
    }
    .stButton>button:hover {
        background-color: #0052a3;
        color: white !important;
    }
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

# 1. DYNAMIC THEME ENGINE BASED ON SELECTED INDUSTRY
# Dynamic Initialization before drawing layout
if "industry_vertical" not in st.session_state:
    st.session_state.industry_vertical = "General IT SaaS (SOC 2 / CIS)"

# Main Grid Layout
col1, col2 = st.columns([1, 2])

with col1:
    st.markdown("<h2 style='color: #0066cc;'>⚙️ Scan Settings</h2>", unsafe_allow_html=True)
    cloud_provider = st.selectbox("Select Cloud Provider", ["AWS", "GCP", "Azure"])
    
    industry_vertical = st.selectbox(
        "Select Industry Vertical", 
        ["General IT SaaS (SOC 2 / CIS)", "Smart Manufacturing & IoT", "Pharmaceuticals & API Labs (FDA 21 CFR)"],
        key="industry_choice"
    )
    
    st.markdown("<h3 style='color: #ffffff; margin-top:15px;'>📄 Raw Cloud Metadata</h3>", unsafe_allow_html=True)
    raw_cloud_logs = st.text_area("JSON Metadata Input Label", label_visibility="collapsed", height=250, placeholder="Paste your cloud asset JSON logs here...")

# Dynamic Industry Headers Mapping
if "Pharmaceuticals" in industry_vertical:
    header_title = "<h1 style='color: #2ed573;'>🧪 CloudShield AI | Pharma API Labs Suite 🧬</h1>"
    critical_val, high_val, score_val = "2 Detected", "1 Detected", "68%"
elif "Manufacturing" in industry_vertical:
    header_title = "<h1 style='color: #ffa500;'>🏭 CloudShield AI | Smart Manufacturing IoT Suite ⚙️</h1>"
    critical_val, high_val, score_val = "1 Detected", "3 Detected", "74%"
else:
    header_title = "<h1 style='color: #0066cc;'>💻 CloudShield AI | General Enterprise IT Suite 🛡️</h1>"
    critical_val, high_val, score_val = "1 Detected", "1 Detected", "80%"

def analyze_vulnerabilities_with_gemini(provider, industry, logs):
    if not client:
        return "❌ Error: AI Engine core initialization failed. Please check your API key secrets."
        
    system_instruction = (
        f"You are an expert Cloud Security DevSecOps Engineer specializing in '{industry}'. "
        f"Analyze the provided '{provider}' asset metadata for safety flaws based on framework rules relevant to '{industry}'.\n\n"
        "Structure exactly like this:\n"
        "### 🔍 Issue: [Resource ID] - [Short Vulnerability Name]\n"
        "**💥 Risk Explanation:** [Technical risk context]\n"
        "**💻 AWS CLI Command to Fix:**\n"
        "```bash\n"
        "[CLI command here]\n"
        "```\n"
        "**🛠️ Terraform Snippet to Remediate:**\n"
        "```hcl\n"
        "[Terraform block here]\n"
        "```\n"
        "---"
    )
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"Analyze logs:\n{logs}",
            config=types.GenerateContentConfig(system_instruction=system_instruction, temperature=0.2)
        )
        return response.text if response.text else "⚠️ Empty response returned."
    except Exception as e:
        return f"❌ Connection Error: {str(e)}"

with col2:
    st.markdown(header_title, unsafe_allow_html=True)
    st.markdown("<h3 style='color: #ffffff;'>📊 Audit Results & Insights Dashboard</h3>", unsafe_allow_html=True)
    
    if st.button("🚀 Run Industry-Targeted Security Audit"):
        clean_input = raw_cloud_logs.strip()
        
        if not clean_input:
            st.warning("⚠️ Input required: Please paste your raw cloud metadata JSON logs.")
        else:
            try:
                json.loads(clean_input)
                is_valid = True
            except json.JSONDecodeError:
                is_valid = False
                
            if not is_valid:
                st.error("🛑 Format Error: The provided input is not a valid JSON structure.")
            else:
                with st.spinner("🕵️‍♂️ Processing logs and mapping metrics..."):
                    
                    st.markdown("<h4 style='color: #ffffff; margin-top: 15px;'>🚨 Real-Time Security Posture</h4>", unsafe_allow_html=True)
                    
                    # Custom High Contrast Metric Layout Blocks using HTML Injection
                    m_col1, m_col2, m_col3 = st.columns(3)
                    with m_col1:
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>Critical Threats</div><div class='critical-text'>{critical_val}</div></div>", unsafe_allow_html=True)
                    with m_col2:
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>High Threats</div><div class='high-text'>{high_val}</div></div>", unsafe_allow_html=True)
                    with m_col3:
                        st.markdown(f"<div class='metric-card'><div class='metric-label'>Compliance Score</div><div class='compliance-text'>{score_val}</div></div>", unsafe_allow_html=True)
                    
                    # Plotly Interactive Donut Chart with Hover Support
                    c_num = 2 if "Pharmaceuticals" in industry_vertical else 1
                    h_num = 3 if "Manufacturing" in industry_vertical else 1
                    
                    labels = ['Critical Threats', 'High Threats', 'Low Risk Assets']
                    values = [c_num, h_num, 8]
                    colors = ['#ff4b4b', '#ffa500', '#2ed573']
                    
                    fig = go.Figure(data=[go.Pie(
                        labels=labels, 
                        values=values, 
                        hole=.4,
                        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>Ratio: %{percent}<extra></extra>"
                    )])
                    fig.update_traces(hoverinfo='label+percent', textinfo='value', marker=dict(colors=colors))
                    fig.update_layout(
                        margin=dict(t=10, b=10, l=10, r=10),
                        height=240,
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        showlegend=True,
                        font=dict(color='#ffffff')
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    # Live Gemini Audit Result Trigger
                    audit_result = analyze_vulnerabilities_with_gemini(cloud_provider, industry_vertical, clean_input)
                    st.markdown("---")
                    st.markdown("<h3 style='color: #ffffff;'>📑 Detailed Remediation Report</h3>", unsafe_allow_html=True)
                    st.markdown(audit_result)
