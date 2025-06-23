from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from openai import OpenAI
import sqlite3
import os
from dotenv import load_dotenv
import json
import base64
from email.mime.text import MIMEText
import re
from datetime import datetime, timedelta
import dateutil.parser

# 환경변수 로드
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# OpenAI 클라이언트 설정 (신버전 방식)
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Google OAuth2 설정
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'

class MailSummaryService:
    def __init__(self):
        self.init_db()

    def init_db(self):
        """데이터베이스 초기화"""
        conn = sqlite3.connect('mail_summary.db')
        cursor = conn.cursor()
        
        # 사용자 설정 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT UNIQUE,
                work_start_time TEXT,
                work_end_time TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 기존 emails 테이블 삭제 후 재생성 (컬럼 구조 수정)
        cursor.execute('DROP TABLE IF EXISTS emails')
        cursor.execute('''
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                sender TEXT,
                subject TEXT,
                content TEXT,
                summary TEXT,
                received_date TEXT,
                received_timestamp INTEGER,
                is_read BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def save_user_settings(self, user_email, work_start_time, work_end_time):
        """사용자 출퇴근 시간 설정 저장"""
        conn = sqlite3.connect('mail_summary.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO user_settings 
                (user_email, work_start_time, work_end_time, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_email, work_start_time, work_end_time))
            conn.commit()
            return True
        except Exception as e:
            print(f"사용자 설정 저장 오류: {e}")
            return False
        finally:
            conn.close()

    def get_user_settings(self, user_email):
        """사용자 출퇴근 시간 설정 조회"""
        conn = sqlite3.connect('mail_summary.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT work_start_time, work_end_time 
                FROM user_settings 
                WHERE user_email = ?
            ''', (user_email,))
            result = cursor.fetchone()
            if result:
                return {
                    'work_start_time': result[0],
                    'work_end_time': result[1]
                }
            return None
        except Exception as e:
            print(f"사용자 설정 조회 오류: {e}")
            return None
        finally:
            conn.close()

    def get_credentials_from_session(self):
        """세션에서 인증 정보를 가져와 Credentials 객체 생성"""
        if 'credentials' not in session:
            return None
        
        creds_data = session['credentials']
        
        # 필요한 필드들이 모두 있는지 확인
        required_fields = ['token', 'refresh_token', 'token_uri', 'client_id', 'client_secret']
        for field in required_fields:
            if field not in creds_data or not creds_data[field]:
                print(f"필수 필드 누락: {field}")
                return None
        
        credentials = Credentials(
            token=creds_data['token'],
            refresh_token=creds_data['refresh_token'],
            token_uri=creds_data['token_uri'],
            client_id=creds_data['client_id'],
            client_secret=creds_data['client_secret'],
            scopes=creds_data.get('scopes', SCOPES)
        )
        
        # 토큰이 만료되었다면 갱신
        if credentials.expired:
            try:
                credentials.refresh(Request())
                # 갱신된 토큰을 세션에 저장
                session['credentials'].update({
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token
                })
                print("토큰이 성공적으로 갱신되었습니다.")
            except Exception as e:
                print(f"토큰 갱신 실패: {e}")
                return None
        
        return credentials

    def get_gmail_service(self, credentials=None):
        """Gmail API 서비스 객체 생성"""
        if credentials is None:
            credentials = self.get_credentials_from_session()
        
        if credentials is None:
            raise Exception("유효한 인증 정보가 없습니다.")
        
        return build('gmail', 'v1', credentials=credentials)

    def get_unread_emails_by_datetime(self, service, start_datetime, end_datetime, max_results=100):
        """지정된 날짜/시간 범위의 읽지 않은 메일 수집"""
        try:
            # 날짜/시간 형식을 Gmail API 쿼리 형식으로 변환
            start_timestamp = int(start_datetime.timestamp())
            end_timestamp = int(end_datetime.timestamp())
            
            # Gmail 검색 쿼리 생성 (타임스탬프 기반)
            query = f'is:unread after:{start_timestamp} before:{end_timestamp}'
            print(f"Gmail 검색 쿼리: {query}")
            
            # 읽지 않은 메일 검색
            results = service.users().messages().list(
                userId='me',
                q=query,
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
                    # 날짜/시간 범위 내에 있는지 추가 확인
                    email_datetime = datetime.fromtimestamp(email_data['timestamp'])
                    if start_datetime <= email_datetime <= end_datetime:
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
            
            # 날짜를 타임스탬프로 변환
            timestamp = int(dateutil.parser.parse(date).timestamp()) if date else 0
            
            return {
                'message_id': message['id'],
                'sender': sender,
                'subject': subject,
                'content': content,
                'date': date,
                'timestamp': timestamp
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
                    if 'data' in part['body']:
                        data = part['body']['data']
                        content = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        break
        else:
            if payload['mimeType'] == 'text/plain':
                if 'data' in payload['body']:
                    data = payload['body']['data']
                    content = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        
        # HTML 태그 제거
        content = re.sub(r'<[^>]+>', '', content)
        return content.strip()

    def summarize_email(self, content, subject):
        """OpenAI를 사용하여 메일 요약 (신버전 API)"""
        try:
            prompt = f"""
다음 이메일을 한국어로 간단하고 명확하게 요약해주세요.
중요한 정보와 액션 아이템이 있다면 포함해주세요.

제목: {subject}
내용: {content[:1500]}

요약 (150자 이내):
"""
            response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "당신은 이메일 요약 전문가입니다. 간결하고 핵심적인 요약을 제공해주세요."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=200,
                temperature=0.3
            )
            
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(f"요약 생성 오류: {e}")
            return f"요약을 생성할 수 없습니다. 오류: {str(e)}"

    def save_email(self, email_data, summary):
        """데이터베이스에 메일 저장"""
        conn = sqlite3.connect('mail_summary.db')
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO emails 
                (message_id, sender, subject, content, summary, received_date, received_timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_data['message_id'],
                email_data['sender'],
                email_data['subject'],
                email_data['content'],
                summary,
                email_data['date'],
                email_data['timestamp']
            ))
            conn.commit()
        except Exception as e:
            print(f"데이터베이스 저장 오류: {e}")
        finally:
            conn.close()

# Flask 라우트들
service = MailSummaryService()

def require_auth():
    """인증 확인 데코레이터"""
    if 'credentials' not in session:
        return False
    
    # 인증 정보 유효성 확인
    credentials = service.get_credentials_from_session()
    return credentials is not None

@app.route('/')
def index():
    if not require_auth():
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
        include_granted_scopes='true',
        prompt='consent'  # 항상 consent 화면을 표시하여 refresh_token 확보
    )
    
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session.get('state')
    if not state:
        return redirect(url_for('login'))
    
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # credentials.json에서 client_id와 client_secret 읽기
        with open(CLIENT_SECRETS_FILE, 'r') as f:
            client_config = json.load(f)
            client_id = client_config['web']['client_id']
            client_secret = client_config['web']['client_secret']
        
        # 세션에 완전한 인증 정보 저장
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': client_id,
            'client_secret': client_secret,
            'scopes': credentials.scopes
        }
        
        print("인증 정보 저장 완료:")
        print(f"- Token: {'있음' if credentials.token else '없음'}")
        print(f"- Refresh Token: {'있음' if credentials.refresh_token else '없음'}")
        print(f"- Client ID: {'있음' if client_id else '없음'}")
        print(f"- Client Secret: {'있음' if client_secret else '없음'}")
        
        # 사용자 이메일 정보 가져오기
        gmail_service = service.get_gmail_service(credentials)
        profile = gmail_service.users().getProfile(userId='me').execute()
        session['user_email'] = profile['emailAddress']
        
        # 기존 사용자 설정 확인
        user_settings = service.get_user_settings(profile['emailAddress'])
        if not user_settings:
            return redirect(url_for('work_time_setup'))
        
        return redirect(url_for('index'))
        
    except Exception as e:
        print(f"OAuth 콜백 처리 중 오류: {e}")
        return redirect(url_for('login'))

@app.route('/work-time-setup')
def work_time_setup():
    if not require_auth():
        return redirect(url_for('login'))
    return render_template('work_time_setup.html')

@app.route('/api/save-work-time', methods=['POST'])
def save_work_time():
    if not require_auth() or 'user_email' not in session:
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        data = request.get_json()
        work_start_time = data.get('work_start_time')
        work_end_time = data.get('work_end_time')
        
        if not work_start_time or not work_end_time:
            return jsonify({'error': '출근 시간과 퇴근 시간을 모두 입력해주세요.'}), 400
        
        success = service.save_user_settings(
            session['user_email'],
            work_start_time,
            work_end_time
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': '설정 저장에 실패했습니다.'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/fetch-emails', methods=['POST'])
def fetch_emails_proxy():
    return fetch_emails()

@app.route('/api/fetch-emails', methods=['POST'])
def fetch_emails():
    if not require_auth():
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        # 요청에서 날짜/시간 범위 가져오기
        data = request.get_json()
        start_datetime_str = data.get('start_datetime')
        end_datetime_str = data.get('end_datetime')
        
        if not start_datetime_str or not end_datetime_str:
            return jsonify({'error': '시작 날짜/시간과 종료 날짜/시간을 입력해주세요.'}), 400
        
        # 문자열을 datetime 객체로 변환
        start_datetime = datetime.fromisoformat(start_datetime_str)
        end_datetime = datetime.fromisoformat(end_datetime_str)
        
        # Gmail 서비스 생성
        gmail_service = service.get_gmail_service()
        
        # 지정된 날짜/시간 범위의 읽지 않은 메일 수집
        emails = service.get_unread_emails_by_datetime(gmail_service, start_datetime, end_datetime)
        
        if not emails:
            return jsonify({
                'success': True,
                'summaries': [],
                'count': 0,
                'message': '지정된 기간에 읽지 않은 메일이 없습니다.'
            })
        
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
            'summaries': processed_emails,
            'count': len(processed_emails)
        })
        
    except Exception as e:
        print(f"메일 처리 오류: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user-settings', methods=['GET', 'POST'])
def user_settings():
    if not require_auth() or 'user_email' not in session:
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    if request.method == 'GET':
        settings = service.get_user_settings(session['user_email'])
        if settings:
            return jsonify({
                'working_hours_set': True,
                'work_start_time': settings['work_start_time'],
                'work_end_time': settings['work_end_time']
            })
        else:
            return jsonify({'working_hours_set': False})
    
    elif request.method == 'POST':
        data = request.get_json()
        work_start_time = data.get('work_start_time')
        work_end_time = data.get('work_end_time')
        
        if not work_start_time or not work_end_time:
            return jsonify({'error': '출근 시간과 퇴근 시간을 모두 입력해주세요.'}), 400
        
        success = service.save_user_settings(
            session['user_email'],
            work_start_time,
            work_end_time
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': '설정 저장에 실패했습니다.'}), 500

@app.route('/api/emails')
def get_emails():
    """저장된 메일 목록 조회"""
    if not require_auth():
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    conn = sqlite3.connect('mail_summary.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT sender, subject, summary, received_date, message_id
        FROM emails 
        ORDER BY received_timestamp DESC 
        LIMIT 100
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

@app.route('/logout')
def logout():
    """로그아웃"""
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='localhost', debug=True, port=5000)