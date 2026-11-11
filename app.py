import streamlit as st
import pandas as pd
import zipfile
import io
import Levenshtein as Lev

# --- CONFIGURATION ---
SANCTIONS_LIST = ["Acme Trading LLC", "Global Corp", "Iran", "North Korea", "Syria"]
HIGH_RISK_COUNTRIES = ["Iran", "North Korea", "Syria"]

st.set_page_config(page_title="Summit Risk Agent", layout="wide")
st.title("🛡️ Summit Risk Vendor Risk Agent")
st.markdown("**Demo: Upload a ZIP with a vendor CSV and PDFs.**")

# --- SIDEBAR (The Safety Rules) ---
st.sidebar.header("Agent Rules")
st.sidebar.info("1. Quarantine runs before LLM reads.\n2. No auto-blocking. Human approval required.\n3. Levenshtein matching for fuzzy names.")

# --- MAIN APP ---
uploaded_file = st.file_uploader("Upload Vendor ZIP", type=["zip"])

if uploaded_file is not None:
    with zipfile.ZipFile(uploaded_file) as z:
        csv_files = [f for f in z.namelist() if f.endswith('.csv')]
        
        if not csv_files:
            st.error("No CSV found in the ZIP.")
        else:
            df = pd.read_csv(io.BytesIO(z.read(csv_files[0])))
            df.columns = df.columns.str.strip().str.lower()
            
            st.write("### 1. Pre-Flight Check")
            st.success(f"Found {len(df)} vendors in CSV.")
            
            results = []
            quarantined_files = []
            
            with st.spinner("Screening vendors..."):
                for index, row in df.iterrows():
                    name = str(row['name'])
                    country = str(row['country'])
                    reg_num = str(row['registration_number'])
                    
                    score = 0
                    reason = "Clean"
                    status = "Low Risk: Clean"
                    
                                        # 1. Quarantine Scan (Mock)
                    for file_in_zip in z.namelist():
                        if reg_num in file_in_zip:
                            file_content = z.read(file_in_zip).decode('utf-8', errors='ignore')
                            if "ignore previous instructions" in file_content.lower() or "note to ai" in file_content.lower():
                                score = 100
                                reason = "Quarantined: Malicious file found"
                                status = "Quarantined: File Malicious"
                                quarantined_files.append(file_in_zip)
                                break # Stop checking once we find the file
                            score = 100
                            reason = "Quarantined: Malicious file found"
                            status = "Quarantined: File Malicious"
                            quarantined_files.append(reg_num)
                    
                    # 2. Sanctions Check (Only if not quarantined)
                    if status != "Quarantined: File Malicious":
                        if name in SANCTIONS_LIST:
                            score = 100
                            reason = "Exact sanctions match"
                            status = "High Risk"
                        elif any(Lev.ratio(name.lower(), s.lower()) > 0.85 for s in SANCTIONS_LIST):
                            score = 75
                            reason = "Fuzzy sanctions match"
                            status = "High Risk"
                        elif country in HIGH_RISK_COUNTRIES:
                            score = 25
                            reason = "High-risk country"
                            status = "Needs Review"
                            
                    results.append({
                        "Vendor Name": name,
                        "Country": country,
                        "Score": score,
                        "Reason": reason,
                        "Status": status
                    })

            st.write("### 2. Screening Results")
            res_df = pd.DataFrame(results)
            st.dataframe(res_df, use_container_width=True)
            
            if quarantined_files:
                st.error(f"🚨 **Quarantine Alert:** Malicious files detected: {', '.join(quarantined_files)}")
            else:
                st.success("✅ No malicious files detected.")

            st.write("### 3. Human Approval Queue")
            st.info("The agent prepares. The human sends. No vendor is cleared until you click Approve.")
            
            for index, row in res_df.iterrows():
                with st.expander(f"Review: {row['Vendor Name']} (Status: {row['Status']})"):
                    st.write(f"**Score:** {row['Score']} | **Reason:** {row['Reason']}")
                    col1, col2, col3 = st.columns(3)
                    if col1.button(f"✅ Approve {row['Vendor Name']}", key=f"approve_{index}"):
                        st.success(f"Vendor {row['Vendor Name']} Approved & Logged.")
                    if col2.button(f"❌ Dismiss {row['Vendor Name']}", key=f"dismiss_{index}"):
                        st.warning(f"Vendor {row['Vendor Name']} Dismissed (Reason required).")
                    if col3.button(f"⚠️ Escalate {row['Vendor Name']}", key=f"escalate_{index}"):
                        st.info(f"Vendor {row['Vendor Name']} Escalated to Management.")