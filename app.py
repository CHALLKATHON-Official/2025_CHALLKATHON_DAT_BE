# Flask 웹 서버 구성
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
# Google OAuth2 인증
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
# Gmail API 사용
from googleapiclient.discovery import build
# 환경변수 설정
from dotenv import load_dotenv
# OpenAI API 사용
import openai
# SQLite 데이터베이스
import sqlite3
# 이메일 처리, OS, JSON 등 유틸
from email.mime.text import MIMEText
import os
import json
import base64
import re

# 환경변수 로드
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# OpenAI API 키 설정
openai.api_key = os.getenv('OPENAI_API_KEY')

# Google OAuth2 설정
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'  # Google Cloud Console에서 다운로드

class MailSummaryService:
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """데이터베이스 초기화"""
        conn = sqlite3.connect('mail_summary.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                sender TEXT,
                subject TEXT,
                content TEXT,
                summary TEXT,
                received_date TEXT,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_gmail_service(self, credentials):
        """Gmail API 서비스 객체 생성"""
        return build('gmail', 'v1', credentials=credentials)
    
    def get_unread_emails(self, service, max_results=50):
        """읽지 않은 메일 수집"""
        try:
            # 읽지 않은 메일 검색
            results = service.users().messages().list(
                userId='me',
                q='is:unread',
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for message in messages:
                msg = service.users().messages().get(
                    userId='me',
                    id=message['id']
                ).execute()
                
                email_data = self.parse_email(msg)
                if email_data:
                    emails.append(email_data)
            
            return emails
        
        except Exception as e:
            print(f"메일 수집 오류: {e}")
            return []
    
    def parse_email(self, message):
        """메일 메시지 파싱"""
        try:
            headers = message['payload'].get('headers', [])
            
            # 헤더에서 정보 추출
            sender = ""
            subject = ""
            date = ""
            
            for header in headers:
                if header['name'] == 'From':
                    sender = header['value']
                elif header['name'] == 'Subject':
                    subject = header['value']
                elif header['name'] == 'Date':
                    date = header['value']
            
            # 메일 본문 추출
            content = self.extract_email_content(message['payload'])
            
            return {
                'message_id': message['id'],
                'sender': sender,
                'subject': subject,
                'content': content,
                'date': date
            }
        
        except Exception as e:
            print(f"메일 파싱 오류: {e}")
            return None
    
    def extract_email_content(self, payload):
        """메일 본문 추출"""
        content = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    content = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
        else:
            if payload['mimeType'] == 'text/plain':
                data = payload['body']['data']
                content = base64.urlsafe_b64decode(data).decode('utf-8')
        
        # HTML 태그 제거
        content = re.sub(r'<[^>]+>', '', content)
        return content.strip()
    
    def summarize_email(self, content, subject):
        """OpenAI를 사용하여 메일 요약"""
        try:
            prompt = f"""
            다음 이메일을 한국어로 간단하고 명확하게 요약해주세요.
            중요한 정보와 액션 아이템이 있다면 포함해주세요.
            
            제목: {subject}
            내용: {content[:1000]}  # 내용이 너무 길면 자르기
            
            요약 (100자 이내):
            """
            
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "당신은 이메일 요약 전문가입니다."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            print(f"요약 생성 오류: {e}")
            return "요약을 생성할 수 없습니다."
    
    def save_email(self, email_data, summary):
        """데이터베이스에 메일 저장"""
        conn = sqlite3.connect('mail_summary.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO emails 
                (message_id, sender, subject, content, summary, received_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                email_data['message_id'],
                email_data['sender'],
                email_data['subject'],
                email_data['content'],
                summary,
                email_data['date']
            ))
            
            conn.commit()
        except Exception as e:
            print(f"데이터베이스 저장 오류: {e}")
        finally:
            conn.close()

# Flask 라우트들
service = MailSummaryService()

@app.route('/')
def index():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/auth')
def auth():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    
    flow.fetch_token(authorization_response=request.url)
    
    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    return redirect(url_for('index'))

@app.route('/api/fetch-emails', methods=['POST'])
def fetch_emails():
    if 'credentials' not in session:
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        # 저장된 인증정보로 서비스 생성
        creds = Credentials(**session['credentials'])
        gmail_service = service.get_gmail_service(creds)
        
        # 읽지 않은 메일 수집
        emails = service.get_unread_emails(gmail_service)
        
        # 각 메일 요약 및 저장
        processed_emails = []
        for email_data in emails:
            summary = service.summarize_email(email_data['content'], email_data['subject'])
            service.save_email(email_data, summary)
            
            processed_emails.append({
                'sender': email_data['sender'],
                'subject': email_data['subject'],
                'summary': summary,
                'date': email_data['date'],
                'message_id': email_data['message_id']
            })
        
        return jsonify({
            'success': True,
            'emails': processed_emails,
            'count': len(processed_emails)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/emails')
def get_emails():
    """저장된 메일 목록 조회"""
    conn = sqlite3.connect('mail_summary.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT sender, subject, summary, received_date, message_id
        FROM emails
        ORDER BY received_date DESC
        LIMIT 50
    ''')
    
    emails = []
    for row in cursor.fetchall():
        emails.append({
            'sender': row[0],
            'subject': row[1],
            'summary': row[2],
            'date': row[3],
            'message_id': row[4]
        })
    
    conn.close()
    return jsonify(emails)

if __name__ == '__main__':
    app.run(host='localhost', debug=True, port=5000)