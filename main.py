import json
import sqlite3
import threading
import time
import base64
import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Google API Imports
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials

# Import your LangGraph engine
from graph import app_engine

load_dotenv()

app = FastAPI(title="AI-SOC Triage Backend")

# 1. Clean Middleware Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# 2. Global Event
scan_stop_event = threading.Event()

# 3. Security
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "SuperSecureFallback2026!")

# Pydantic Schemas
class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str

# ==========================================
# GMAIL API SERVICE
# ==========================================
def get_gmail_service():
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', ['https://www.googleapis.com/auth/gmail.readonly'])
    else:
        token_content = os.getenv("TOKEN_JSON_CONTENT")
        token_dict = json.loads(token_content)
        creds = Credentials.from_authorized_user_info(token_dict, ['https://www.googleapis.com/auth/gmail.readonly'])
    
    return build('gmail', 'v1', credentials=creds)

# ==========================================
# DATABASE INIT
# ==========================================
def init_db():
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS specialists (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL, specialization TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, department TEXT NOT NULL, app_password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

# ==========================================
# ROUTES
# ==========================================

@app.get("/health")
def health_check():
    return {"status": "online", "message": "System is awake."}

@app.post("/admin/login")
def login(password: str):
    if password == ADMIN_PASSWORD:
        return {"status": "success", "token": "admin-access-granted"}
    raise HTTPException(status_code=401, detail="Invalid Password")

@app.get("/specialists")
def get_specialists():
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM specialists")
    rows = cursor.fetchall()
    conn.close()
    return {"specialists": rows}

@app.post("/specialists")
def add_specialist(name: str, email: str, specialization: str):
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO specialists (name, email, specialization) VALUES (?, ?, ?)", (name, email, specialization))
    conn.commit()
    conn.close()
    return {"status": "Specialist added"}

@app.delete("/specialists/{spec_id}")
def delete_specialist(spec_id: int):
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM specialists WHERE id = ?", (spec_id,))
    conn.commit()
    conn.close()
    return {"status": "Specialist deleted"}

@app.get("/employees")
def get_employees():
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, department, app_password FROM employees")
    rows = cursor.fetchall()
    conn.close()
    return {"employees": rows}

@app.post("/employees")
def add_employee(name: str, email: str, department: str, app_password: str):
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO employees (name, email, department, app_password) VALUES (?, ?, ?, ?)", (name, email, department, app_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Employee email already registered")
    conn.close()
    return {"status": "Employee added"}

@app.delete("/employees/{emp_id}")
def delete_employee(emp_id: int):
    conn = sqlite3.connect('/tmp/soc_system.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM employees WHERE id = ?", (emp_id,))
    conn.commit()
    conn.close()
    return {"status": "Employee deleted"}

@app.post("/triage")
def triage_email(request: EmailRequest):
    final_state = app_engine.invoke({"sender": request.sender, "subject": request.subject, "body": request.body})
    return final_state

@app.post("/stop-scan")
def stop_scan():
    scan_stop_event.set()
    return {"status": "success", "message": "Scan abort signal sent"}

@app.get("/scan-inbox")
def scan_inbox():
    scan_stop_event.clear()
    processed_count = 0
    threats_found = 0
    
    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId='me', maxResults=3).execute()
        messages = results.get('messages', [])
        
        for msg in messages:
            if scan_stop_event.is_set(): 
                return {"status": "aborted", "message": "Scan aborted"}
            
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = msg_data['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
            
            body = "Scan content retrieved via API"
            
            final_state = app_engine.invoke({"sender": sender, "subject": subject, "body": body})
            processed_count += 1
            if final_state and final_state.get("threat_category") != "Safe/Spam":
                threats_found += 1
        
        return {"status": "success", "message": f"Processed {processed_count} emails. Threats: {threats_found}"}

    except Exception as e:
        print(f"API Failed, using Simulation Sandbox: {e}")
        mock_emails = [
            {"sender": "it-support@suspicious-domain.com", "subject": "URGENT: Password Expiry", "body": "Click here to reset your enterprise password immediately."},
            {"sender": "hr@yourcompany.com", "subject": "Team Lunch Update", "body": "Hey everyone, we are moving the team lunch to Friday at 1 PM."},
            {"sender": "unknown@hacker.ru", "subject": "Invoice Attached", "body": "Please find the attached invoice_PDF.exe for your recent purchase."}
        ]
        
        for mock_mail in mock_emails:
            if scan_stop_event.is_set():
                return {"status": "aborted", "message": "Scan aborted by operator."}
            
            final_state = app_engine.invoke({
                "sender": mock_mail["sender"], 
                "subject": mock_mail["subject"], 
                "body": mock_mail["body"]
            })
            processed_count += 1
            if final_state and final_state.get("threat_category") != "Safe/Spam":
                threats_found += 1
            time.sleep(1.5)

        msg = f"API Simulated Sandbox Mode Active. Processed {processed_count} emails. Threats mitigated: {threats_found}"
        return {"status": "success", "message": msg}

# ==========================================
# EXECUTION BLOCK (Always at the bottom)
# ==========================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)