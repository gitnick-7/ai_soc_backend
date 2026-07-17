import sqlite3
import os
import base64
from email.message import EmailMessage
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import json
import smtplib
from typing import TypedDict
from email.mime.text import MIMEText
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, END

# Load environment variables
load_dotenv()

# 1. Define the State
class ThreatState(TypedDict):
    sender: str
    subject: str
    body: str
    threat_category: str
    reasoning: str
    assigned_team: str
    assigned_email: str
    victim_email: str      
    victim_password: str

# Initialize the LLM
llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    api_key=os.getenv("GROQ_API_KEY")
)

# 2. The AI Analyzer Node with Multi-Tier Checklists
def analyze_threat(state: ThreatState):
    subject = state.get("subject", "")
    body = state.get("body", "")
    sender = state.get("sender", "")

    print(f"[SYSTEM LOG] Running forensics graph node against vector payload from: {sender}")

    system_prompt = """You are an elite Security Operations Center (SOC) AI Analyst. 
    Your objective is to perform a forensic inspection on corporate emails. You must apply the following evaluation mode checklists for every single inbound transmission:

    EVALUATION CHECKLISTS:
    - Credential Theft Checklist: 
        1. Does the URL/domain mismatch the sender's apparent organization?
        2. Is there artificial urgency, an MFA reset request, or an account suspension trigger?
        3. Are there generic "Sign In", "Verify Account", or forced password reset links?
        4. Rule: If any credential update/verification element exists, classify strictly as Credential Theft.
    - Financial Fraud Checklist:
        1. Does the request mimic executive management impersonation (CEO/CFO external address spoofing)?
        2. Are processing instructions (routing details, corporate invoice adjustments) highly irregular?
        3. Is there high psychological pressure to bypass traditional procurement validation routines?
    - Malware Payload Checklist:
        1. Are there dangerous local file extension signatures (.exe, .zip, .html, .iso, .scr)?
        2. Does the text direct the user to trigger macros or execute "enable content" adjustments?
        3. Is there a misleading link pattern attempting to drop or execute background payloads?
    - Safe/Spam Checklist (Analyze Carefully):
        1. Is this unsolicited marketing, a promotional offer, or a generic newsletter? (If yes, specify 'Benign Spam / Marketing' in your reasoning).
        2. Is this standard B2B operational exchange, calendar invites, or internal team coordination? (If yes, specify 'Safe Internal Communication' in your reasoning).
        3. Does the text completely lack actionable social engineering techniques or malicious links? 
        4. Rule: Do not classify as Safe/Spam if ANY login verification is requested.

    OUTPUT FORMAT:
    You must output ONLY valid JSON. Do not include markdown design blocks, introductory headers, or trailing comments.
    Use exactly these structural parameters:
    {
        "threat_category": "<Choose ONE: Credential Theft, Financial Fraud, Malware Payload, Safe/Spam>",
        "reasoning": "<Provide 1 concise sentence detailing the precise forensic check. If Safe/Spam, explicitly specify whether it is 'Benign Marketing/Spam' or 'Safe Internal Communication'>"
    }"""

    response = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"Sender: {sender}\nSubject: {subject}\nBody: {body}")
    ])

    raw_content = response.content.replace("```json", "").replace("```", "").strip()
    
    try:
        parsed_data = json.loads(raw_content)
    except json.JSONDecodeError:
        print("❌ [SYSTEM ERROR] AI classification schema failed structural parse. Triaging to fallback state.")
        parsed_data = {
            "threat_category": "Safe/Spam", 
            "reasoning": "Forensic telemetry dropped due to raw text parser collision."
        }

    return {
        "threat_category": parsed_data.get("threat_category", "Safe/Spam"), 
        "reasoning": parsed_data.get("reasoning", "Classified successfully by Groq AI-SOC Core Engine")
    }

# 3. Dynamic Database Routing Node with Multi-Tier Safety Fallback
def assign_specialist(state: ThreatState):
    category = state.get("threat_category", "")

    # Skip routing entirely for safe metrics
    if category == "Safe/Spam":
        print("🟢 [SYSTEM LOG] Payload declared clean. Skipping database assignment.")
        return {"assigned_team": "None", "assigned_email": "None"}

    # Define verified production queues
    valid_threats = ["Malware Payload", "Financial Fraud", "Credential Theft"]
    
    # SAFETY NET OVERRIDE: Prevent logic drift by forcing deviations into the Malware cluster
    if category not in valid_threats:
        print(f"⚠️ [SYSTEM OVERRIDE] AI signature drift found: '{category}'. Overwriting destination parameters to Malware Payload.")
        category = "Malware Payload"
        
    conn = sqlite3.connect('soc_system.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, email FROM specialists WHERE specialization = ?", (category,))
    result = cursor.fetchone()
    conn.close()

    if result:
        print(f"📡 [SYSTEM LOG] Node mapping succeeded. Routing target packet to team: {result[0]} ({result[1]})")
        return {
            "threat_category": category,
            "assigned_team": result[0], 
            "assigned_email": result[1]
        }
    else:
        print(f"⚠️ [SYSTEM ALERT] Operational queue missing for '{category}' in specialists cluster. Activating failsafe routing.")
        return {
            "threat_category": category,
            "assigned_team": "Emergency Malware Queue", 
            "assigned_email": "barniks45@gmail.com"
        }

# 4. Outbound Automated Alert Relay Node (HTTPS API VERSION)
def forward_alert_email(state: ThreatState):
    specialist_email = state.get("assigned_email")
    category = state.get("threat_category")
    
    if category == "Safe/Spam" or not specialist_email or specialist_email == "None":
        return state
        
    email_body = f"""
    ⚠️ AI-SOC AUTOMATED INCIDENT RESPONSE ALERT ⚠️
    --------------------------------------------------
    Threat Signature: {category}
    Forensic Reasoning: {state.get("reasoning")}
    
    VECTOR ORIGIN POOL:
    Sender: {state.get("sender")}
    Subject: {state.get("subject")}
    
    RAW TELEMETRY SIG DUMP:
    {state.get("body")}
    
    [ALERT] Immediate system isolation and forensic review required by dedicated team node.
    - AI-SOC Automated Triage Engine v3.0
    """
    
    # Build the email
    message = EmailMessage()
    message.set_content(email_body)
    message['To'] = specialist_email
    message['From'] = 'me' # Gmail API automatically uses the authenticated account
    message['Subject'] = f"CRITICAL SOC ALERT: {category} Mitigation Required"

    # Encode for the API
    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    create_message = {'raw': encoded_message}

    try:
        # Load credentials from Render Environment Variable
        token_content = os.getenv("TOKEN_JSON_CONTENT")
        token_dict = json.loads(token_content)
        creds = Credentials.from_authorized_user_info(token_dict)
        
        # Connect to Gmail API (Operates on Port 443 - Bypasses Firewall!)
        service = build('gmail', 'v1', credentials=creds)
        send_message = service.users().messages().send(userId="me", body=create_message).execute()
        
        print(f"✅ [SUCCESS LOG] Outbound report securely pushed via HTTPS API to: {specialist_email}")
    except Exception as e:
        print(f"⚠️ [API FAIL] Could not reach Gmail HTTPS endpoint. Error trace: {e}")
        
    return state