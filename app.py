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
from typing import Dict, List, Optional
import schedule
import threading
import time
import tempfile
import pytz
import requests
from bs4 import BeautifulSoup
import feedparser

# 환경변수 로드
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# OpenAI 클라이언트 설정
openai_client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

# Google OAuth2 설정
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def create_client_secrets_file():
    """환경변수에서 Google OAuth 설정을 가져와서 임시 파일 생성"""
    client_config = {
        "web": {
            "client_id": os.getenv('GOOGLE_CLIENT_ID'),
            "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "redirect_uris": []  # 동적으로 설정됨
        }
    }
    
    # 환경변수가 없으면 에러 발생
    if not client_config["web"]["client_id"] or not client_config["web"]["client_secret"]:
        raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables must be set")
    
    # 임시 파일에 저장
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
    json.dump(client_config, temp_file)
    temp_file.close()
    return temp_file.name

# 전역 변수 설정
try:
    CLIENT_SECRETS_FILE = create_client_secrets_file()
except ValueError as e:
    print(f"OAuth 설정 오류: {e}")
    CLIENT_SECRETS_FILE = None

class EnhancedMailSummaryService:
    def __init__(self):
        self.init_db()
        # 개발 환경에서만 스케줄러 시작 (CloudType에서는 임시로 비활성화)
        if os.getenv('FLASK_ENV') != 'production':
            self.start_weekly_recap_scheduler()
            self.start_news_update_scheduler()
    
    def init_db(self):
        """데이터베이스 초기화 - 향상된 스키마"""
        # CloudType 환경에서는 /tmp 디렉토리 사용
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # 사용자 설정 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT UNIQUE,
                work_start_time TEXT,
                work_end_time TEXT,
                news_topic TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # emails 테이블
        cursor.execute('DROP TABLE IF EXISTS emails')
        cursor.execute('''
            CREATE TABLE emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                sender TEXT,
                subject TEXT,
                content TEXT,
                summary TEXT,
                category TEXT,
                priority_score INTEGER DEFAULT 0,
                gmail_link TEXT,
                received_date TEXT,
                received_timestamp INTEGER,
                is_read BOOLEAN DEFAULT FALSE,
                is_pinned BOOLEAN DEFAULT FALSE,
                is_completed BOOLEAN DEFAULT FALSE,
                original_order INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 뉴스 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS news_articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                author TEXT,
                source TEXT,
                published_date TEXT,
                summary TEXT,
                original_url TEXT,
                topic TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # 주간 회고 테이블
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS weekly_recaps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT,
                week_start_date TEXT,
                total_emails INTEGER,
                most_contacted_person TEXT,
                longest_email_sender TEXT,
                fastest_reply_time TEXT,
                avg_emails_per_day REAL,
                recap_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_credentials_from_session(self):
        """세션에서 인증 정보를 가져와 Credentials 객체 생성"""
        if 'credentials' not in session:
            return None
        
        creds_data = session['credentials']
        
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
        
        if credentials.expired:
            try:
                credentials.refresh(Request())
                session['credentials'].update({
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token
                })
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
    
    def get_unread_emails_by_datetime_optimized(self, service, start_datetime, end_datetime, max_results=100):
        """날짜 범위 최적화된 메일 수집 - 시간 단위 필터링 개선"""
        try:
            # timezone 정보 제거
            if start_datetime.tzinfo is not None:
                start_datetime = start_datetime.replace(tzinfo=None)
            if end_datetime.tzinfo is not None:
                end_datetime = end_datetime.replace(tzinfo=None)
            
            # Gmail 검색을 위해 날짜 범위를 하루씩 확장
            # (Gmail의 날짜 검색은 정확하지 않을 수 있으므로)
            search_start = start_datetime - timedelta(days=1)
            search_end = end_datetime + timedelta(days=1)
            
            # Gmail 검색 쿼리에 날짜 범위 추가
            start_date_str = search_start.strftime('%Y/%m/%d')
            end_date_str = search_end.strftime('%Y/%m/%d')
            
            # after와 before를 사용하여 날짜 범위 지정
            query = f'is:unread after:{start_date_str} before:{end_date_str}'
            print(f"Gmail 검색 쿼리: {query}")
            print(f"실제 필터링 범위: {start_datetime} ~ {end_datetime}")
            
            results = service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results * 2  # 더 많은 메일을 가져와서 필터링
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            print(f"Gmail에서 가져온 메시지 수: {len(messages)}")
            
            for idx, message in enumerate(messages):
                try:
                    msg = service.users().messages().get(
                        userId='me',
                        id=message['id'],
                        format='full'
                    ).execute()
                    
                    email_data = self.parse_email(msg)
                    if email_data:
                        # 메일의 실제 수신 시간을 파싱
                        email_datetime = self.parse_email_datetime(email_data['date'])
                        
                        if email_datetime:
                            # 정확한 시간 비교
                            print(f"메일 시간: {email_datetime}, 발신자: {email_data['sender'][:30]}")
                            
                            if start_datetime <= email_datetime <= end_datetime:
                                email_data['original_order'] = idx
                                email_data['timestamp'] = int(email_datetime.timestamp())
                                emails.append(email_data)
                                print(f"✅ 범위 내 메일 추가: {email_data['sender']} - {email_datetime}")
                            else:
                                print(f"❌ 범위 외 메일 제외: {email_data['sender']} - {email_datetime}")
                    
                except Exception as e:
                    print(f"개별 메일 처리 오류: {e}")
                    continue
            
            print(f"최종 필터링된 메일 수: {len(emails)}")
            
            # 시간순으로 정렬
            emails.sort(key=lambda x: x['timestamp'])
            
            return emails
        
        except Exception as e:
            print(f"메일 수집 오류: {e}")
            return []
    
    def parse_email_datetime(self, date_string):
        """이메일 날짜 문자열을 datetime 객체로 변환"""
        try:
            # dateutil.parser를 사용하여 다양한 형식의 날짜 파싱
            parsed_date = dateutil.parser.parse(date_string)
            
            # 시간대 정보가 있으면 UTC로 변환 후 naive datetime으로 변경
            if parsed_date.tzinfo is not None:
                # UTC로 변환
                parsed_date = parsed_date.astimezone(pytz.UTC)
                # naive datetime으로 변경
                parsed_date = parsed_date.replace(tzinfo=None)
            
            return parsed_date
        except Exception as e:
            print(f"날짜 파싱 오류: {e}, 날짜 문자열: {date_string}")
            return None
    
    def parse_email(self, message):
        """메일 메시지 파싱"""
        try:
            headers = message['payload'].get('headers', [])
            
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
            
            content = self.extract_email_content(message['payload'])
            
            email_data = {
                'message_id': message['id'],
                'sender': sender,
                'subject': subject,
                'content': content,
                'date': date,
                'timestamp': 0  # 나중에 업데이트됨
            }
            
            return email_data
        
        except Exception as e:
            print(f"메일 파싱 오류: {e}")
            return None
    
    def extract_email_content(self, payload):
        """메일 본문 추출"""
        content = ""
        
        def extract_text_from_part(part):
            if part.get('mimeType') == 'text/plain':
                if 'data' in part.get('body', {}):
                    data = part['body']['data']
                    return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            elif part.get('mimeType') == 'text/html':
                if 'data' in part.get('body', {}):
                    data = part['body']['data']
                    html_content = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    return re.sub(r'<[^>]+>', '', html_content)
            return ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                text = extract_text_from_part(part)
                if text:
                    content = text
                    break
                if 'parts' in part:
                    for subpart in part['parts']:
                        text = extract_text_from_part(subpart)
                        if text:
                            content = text
                            break
                if content:
                    break
        else:
            content = extract_text_from_part(payload)
        
        content = re.sub(r'<[^>]+>', '', content)
        return content.strip()
    
    def get_enhanced_email_summary_and_category(self, content: str, subject: str, sender: str) -> Dict:
        """향상된 메일 요약 및 카테고리 분류"""
        try:
            prompt = f"""
다음 이메일을 분석해서 JSON 형태로 응답해주세요:

발신자: {sender}
제목: {subject}
내용: {content[:3000]}

다음 형태로 응답해주세요:
{{
    "summary": "메일의 핵심 내용을 구체적으로 요약 (4-6문장)",
    "category": "회신필요|참고용|중요하지않음|스팸",
    "intent": "요청|정보전달|회의일정|광고|기타",
    "action_needed": "구체적으로 해야할 액션이나 'None'",
    "deadline": "마감일이 있다면 추출, 없으면 'None'"
}}

요약 작성 지침:
- 단순히 메일의 종류를 설명하지 말고, 실제 내용을 구체적으로 요약하세요
- 중요한 날짜, 시간, 장소, 인물, 금액 등의 구체적인 정보를 포함하세요
- 업데이트 내용이라면 어떤 기능이 추가/변경되었는지 구체적으로 설명하세요
- 요청사항이 있다면 무엇을 요청하는지 명확히 표현하세요
- 회의나 일정이 있다면 언제, 어디서, 무엇을 논의하는지 포함하세요
- 사용자가 메일을 열지 않고도 핵심 내용을 완전히 파악할 수 있도록 작성하세요

분류 기준:
- 회신필요: 답변, 확인, 승인, 의사결정이 필요한 메일
- 참고용: 정보 전달, 공지, 업데이트, 보고서 등
- 중요하지않음: 뉴스레터, 자동 알림, 프로모션 등
- 스팸: 광고, 피싱, 의심스러운 발신자의 메일

카테고리별 우선순위는 자동으로 설정됩니다:
- 회신필요: 1순위
- 참고용: 2순위
- 중요하지않음: 3순위
- 스팸: 4순위
"""
            
            response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "당신은 이메일 분석 전문가입니다. 정확한 JSON 형태로만 응답하세요."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.3
            )
            
            result_text = response.choices[0].message.content.strip()
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1]
            
            result = json.loads(result_text)
            
            # 카테고리별 우선순위 점수 설정
            priority_scores = {
                '회신필요': 1,
                '참고용': 2,
                '중요하지않음': 3,
                '스팸': 4
            }
            
            category = result.get('category', '참고용')
            priority_score = priority_scores.get(category, 3)
            
            return {
                'summary': result.get('summary', '요약을 생성할 수 없습니다.'),
                'category': category,
                'priority_score': priority_score,
                'intent': result.get('intent', '기타'),
                'action_needed': result.get('action_needed', 'None'),
                'deadline': result.get('deadline', 'None')
            }
        
        except Exception as e:
            print(f"요약 및 분석 생성 오류: {e}")
            return {
                'summary': f"요약을 생성할 수 없습니다. 오류: {str(e)}",
                'category': '참고용',
                'priority_score': 2,
                'intent': '기타',
                'action_needed': 'None',
                'deadline': 'None'
            }
    
    def generate_gmail_link(self, message_id: str) -> str:
        """Gmail 웹 링크 생성"""
        return f"https://mail.google.com/mail/u/0/#inbox/{message_id}"
    
    def save_enhanced_email(self, email_data: Dict, analysis_result: Dict, original_order: int):
        """향상된 이메일 저장 - 원래 순서 포함"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            gmail_link = self.generate_gmail_link(email_data['message_id'])
            
            cursor.execute('''
                INSERT OR REPLACE INTO emails 
                (message_id, sender, subject, content, summary, category, priority_score, 
                 gmail_link, received_date, received_timestamp, original_order)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                email_data['message_id'],
                email_data['sender'],
                email_data['subject'],
                email_data['content'],
                analysis_result['summary'],
                analysis_result['category'],
                analysis_result['priority_score'],
                gmail_link,
                email_data['date'],
                email_data['timestamp'],
                original_order
            ))
            conn.commit()
        except Exception as e:
            print(f"데이터베이스 저장 오류: {e}")
        finally:
            conn.close()
    
    def get_today_summary_stats(self, user_email: str) -> Dict:
        """오늘의 메일 요약 통계"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN category = '회신필요' THEN 1 ELSE 0 END) as reply_needed,
                SUM(CASE WHEN category = '참고용' THEN 1 ELSE 0 END) as reference,
                SUM(CASE WHEN category = '중요하지않음' THEN 1 ELSE 0 END) as not_important,
                SUM(CASE WHEN category = '스팸' THEN 1 ELSE 0 END) as spam
            FROM emails 
            WHERE DATE(received_date) = ?
        ''', (today,))
        
        result = cursor.fetchone()
        conn.close()
        
        return {
            'total': result[0] or 0,
            'reply_needed': result[1] or 0,
            'reference': result[2] or 0,
            'not_important': result[3] or 0,
            'spam': result[4] or 0
        }
    
    def save_user_settings(self, user_email, work_start_time, work_end_time, news_topic=None):
        """사용자 출퇴근 시간 및 뉴스 주제 설정 저장"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO user_settings 
                (user_email, work_start_time, work_end_time, news_topic, updated_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_email, work_start_time, work_end_time, news_topic))
            conn.commit()
            return True
        except Exception as e:
            print(f"사용자 설정 저장 오류: {e}")
            return False
        finally:
            conn.close()
    
    def get_user_settings(self, user_email):
        """사용자 출퇴근 시간 및 뉴스 주제 설정 조회"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT work_start_time, work_end_time, news_topic 
                FROM user_settings 
                WHERE user_email = ?
            ''', (user_email,))
            result = cursor.fetchone()
            if result:
                return {
                    'work_start_time': result[0],
                    'work_end_time': result[1],
                    'news_topic': result[2]
                }
            return None
        except Exception as e:
            print(f"사용자 설정 조회 오류: {e}")
            return None
        finally:
            conn.close()
    
    def toggle_email_status(self, message_id: str, status_type: str, value: bool) -> bool:
        """메일 상태 토글 (핀/완료)"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        try:
            if status_type == 'pinned':
                cursor.execute('UPDATE emails SET is_pinned = ? WHERE message_id = ?', (value, message_id))
            elif status_type == 'completed':
                cursor.execute('UPDATE emails SET is_completed = ? WHERE message_id = ?', (value, message_id))
            conn.commit()
            return True
        except Exception as e:
            print(f"상태 업데이트 오류: {e}")
            return False
        finally:
            conn.close()
    
    def generate_weekly_recap(self, user_email: str) -> Dict:
        """주간 회고 데이터 생성"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
        today = datetime.now().strftime('%Y-%m-%d')
        
        cursor.execute('SELECT COUNT(*) FROM emails WHERE DATE(received_date) BETWEEN ? AND ?', (week_ago, today))
        total_emails = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT sender, COUNT(*) as count 
            FROM emails 
            WHERE DATE(received_date) BETWEEN ? AND ?
            GROUP BY sender 
            ORDER BY count DESC 
            LIMIT 1
        ''', (week_ago, today))
        most_contacted = cursor.fetchone()
        
        cursor.execute('''
            SELECT sender, LENGTH(content) as len
            FROM emails 
            WHERE DATE(received_date) BETWEEN ? AND ?
            ORDER BY len DESC 
            LIMIT 1
        ''', (week_ago, today))
        longest_email = cursor.fetchone()
        
        conn.close()
        
        recap_data = {
            'total_emails': total_emails,
            'most_contacted_person': most_contacted[0] if most_contacted else 'N/A',
            'longest_email_sender': longest_email[0] if longest_email else 'N/A',
            'week_period': f'{week_ago} ~ {today}',
            'avg_emails_per_day': round(total_emails / 7, 1)
        }
        
        return recap_data
    
    def start_weekly_recap_scheduler(self):
        """주간 회고 스케줄러 시작"""
        def run_scheduler():
            schedule.every().sunday.at("22:00").do(self.create_weekly_recap_for_all_users)
            while True:
                schedule.run_pending()
                time.sleep(3600)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
    
    def create_weekly_recap_for_all_users(self):
        """모든 사용자의 주간 회고 생성"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT DISTINCT user_email FROM user_settings')
        users = cursor.fetchall()
        
        for (user_email,) in users:
            recap_data = self.generate_weekly_recap(user_email)
            
            cursor.execute('''
                INSERT INTO weekly_recaps 
                (user_email, week_start_date, total_emails, most_contacted_person, 
                 longest_email_sender, avg_emails_per_day, recap_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_email,
                (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d'),
                recap_data['total_emails'],
                recap_data['most_contacted_person'],
                recap_data['longest_email_sender'],
                recap_data['avg_emails_per_day'],
                json.dumps(recap_data)
            ))
        
        conn.commit()
        conn.close()
    
    def fetch_news_articles(self, topic):
        """뉴스 기사 크롤링"""
        try:
            # Google News RSS 피드 사용
            search_query = topic.replace(' ', '+')
            url = f"https://news.google.com/rss/search?q={search_query}&hl=ko&gl=KR&ceid=KR:ko"
            
            feed = feedparser.parse(url)
            articles = []
            
            for entry in feed.entries[:5]:  # 상위 5개만 가져오기
                # 제목에서 언론사 추출
                title_parts = entry.title.rsplit(' - ', 1)
                if len(title_parts) == 2:
                    clean_title = title_parts[0]
                    source = title_parts[1]
                else:
                    clean_title = entry.title
                    source = '알 수 없음'

                # author 필드 없는 경우 source 사용
                author = entry.get('author', source)
                if not author or author == '':
                    author = source

                # description에서 추가 정보 추출 시도
                description = entry.get('description', '')
                if description and not author:
                    # 일부 RSS 피드는 description에 언론사 정보를 포함함
                    desc_parts = description.split(' - ')
                    if len(desc_parts) > 1:
                        author = desc_parts[-1].strip()

                article = {
                    'title': clean_title,
                    'author': author if author else source, # author가 없으면 source 사용
                    'source': source, # 언론사
                    'published_date': entry.get('published', datetime.now().strftime('%Y-%m-%d')),
                    'original_url': entry.link,
                    'topic': topic,
                    'summary': ''  # 일단 빈 문자열로 저장
                }
                articles.append(article)
            
            return articles[:3]  # 3개만 반환
        
        except Exception as e:
            print(f"뉴스 크롤링 오류: {e}")
            return []
    
    def summarize_news_article(self, article_url, article_title=""):
        """뉴스 기사 URL로부터 요약 - 개선된 버전"""
        try:
            # 기사 내용 크롤링
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'ko-KR,ko;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Google News 리다이렉트 URL 처리
            if 'news.google.com' in article_url:
                response = requests.get(article_url, headers=headers, allow_redirects=True, timeout=10)
                article_url = response.url  # 실제 기사 URL로 변경
            
            response = requests.get(article_url, headers=headers, timeout=10)
            response.encoding = response.apparent_encoding
            
            soup = BeautifulSoup(response.content, 'html.parser')

            # 언론사 정보 추출
            source_info = None

            # 1. meta 태그에서 언론사 정보 찾기
            meta_tags = [
                {'property': 'og:site_name'},
                {'name': 'twitter:site'},
                {'name': 'publisher'},
                {'property': 'article:publisher'},
                {'name': 'author'},
                {'property': 'article:author'}
            ]

            for meta_tag in meta_tags:
                tag = soup.find('meta', meta_tag)
                if tag and tag.get('content'):
                    source_info = tag.get('content')
                    break

            # 2. URL에서 도메인 추출하여 언론사 추정
            if not source_info:
                from urllib.parse import urlparse
                domain = urlparse(article_url).netloc
                domain_parts = domain.split('.')
                if len(domain_parts) >= 2:
                    source_info = domain_parts[-2].upper() # naver.com -> NAVER
            
            # 스크립트와 스타일 태그 제거
            for script in soup(["script", "style"]):
                script.decompose()
            
            content = ""
            
            # 다양한 뉴스 사이트의 본문 선택자들
            selectors = [
                'article',
                '[class*="article-body"]',
                '[class*="article-content"]',
                '[class*="article_body"]',
                '[class*="news-content"]',
                '[class*="content-text"]',
                '[class*="story-body"]',
                '[id*="article-body"]',
                '[id*="articleBody"]',
                '[itemprop="articleBody"]',
                'div.article',
                'div.content',
                'div.text',
                'main'
            ]
            
            for selector in selectors:
                elements = soup.select(selector)
                if elements:
                    for elem in elements:
                        text = elem.get_text(separator=' ', strip=True)
                        if len(text) > len(content):
                            content = text
            
            # 본문을 찾지 못한 경우, p 태그들을 수집
            if len(content) < 200:
                paragraphs = soup.find_all('p')
                p_texts = []
                for p in paragraphs:
                    text = p.get_text(strip=True)
                    if len(text) > 50:  # 충분한 길이의 문단만
                        p_texts.append(text)
                if p_texts:
                    content = ' '.join(p_texts[:10])  # 최대 10개 문단

            # 내용 정리
            content = ' '.join(content.split())
            if len(content) > 1500:
                content = content[:1500] + "..."
            
            # 여전히 내용이 부족한 경우 제목 기반 요약
            if len(content) < 100 and article_title:
                prompt = f"""
다음은 뉴스 기사의 제목입니다: "{article_title}"

이 제목을 바탕으로 기사가 다룰 것으로 예상되는 내용을 1-2문장으로 설명해주세요.
추측이 아닌 일반적인 설명으로 작성해주세요.
"""
                
                response = openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "당신은 뉴스 전문가입니다."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=150,
                    temperature=0.5
                )
                
                return response.choices[0].message.content.strip()
            
            # 내용 정리
            content = ' '.join(content.split())
            
            # 너무 길면 자르기
            if len(content) > 3000:
                content = content[:3000] + "..."
            
            # OpenAI API로 요약
            prompt = f"""
당신은 뉴스 요약 전문가입니다. 다음 뉴스 내용을 바탕으로, 바쁜 일반 독자가 한눈에 이해할 수 있도록 핵심 내용을 한국어로 2~3문장으로 친절하고 자연스럽게 요약해주세요:

제목: {article_title}

내용:
{content[:1000]}

요약:
"""
            
            response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "당신은 뉴스 기사를 정확하고 간결하게 요약하는 전문가입니다. 핵심 정보를 빠뜨리지 않고 전달합니다."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=300,
                temperature=0.5
            )
            
            return response.choices[0].message.content.strip()

            if source_info:
                return f"{summary}\n\n(출처: {source_info})"
            else:
                return summary
            
        except requests.exceptions.Timeout:
            return "기사를 불러오는데 시간이 초과되었습니다."
        except Exception as e:
            print(f"기사 요약 오류: {e} - URL: {article_url}")
            # 제목만이라도 있으면 제목 기반 설명 제공
            if article_title:
                return f"'{article_title}'에 대한 기사입니다. 원문을 확인하시려면 링크를 클릭하세요."
            return "기사 요약을 생성할 수 없습니다."
    
    def save_news_articles(self, articles):
        """뉴스 기사 저장"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        try:
            # 기존 기사 삭제
            if articles:
                cursor.execute('DELETE FROM news_articles WHERE topic = ?', (articles[0]['topic'],))
            
            # 새 기사 저장
            for article in articles:
                author = article.get('author', article.get('source', '알 수 없음'))
                if author == '알 수 없음' and 'source' in article:
                    author = article['source']

                cursor.execute('''
                    INSERT INTO news_articles 
                    (title, author, published_date, summary, original_url, topic)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    article['title'],
                    author,
                    article['published_date'],
                    article.get('summary', ''),
                    article['original_url'],
                    article['topic'],
                    article.get('source', author)
                ))
            
            conn.commit()
        except Exception as e:
            print(f"뉴스 저장 오류: {e}")
        finally:
            conn.close()
    
    def get_latest_news(self, topic):
        """최신 뉴스 가져오기"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT title, author, published_date, summary, original_url
            FROM news_articles
            WHERE topic = ?
            ORDER BY created_at DESC
            LIMIT 3
        ''', (topic,))
        
        results = cursor.fetchall()
        conn.close()
        
        articles = []
        for row in results:
            articles.append({
                'title': row[0],
                'author': row[1],
                'published_date': row[2],
                'summary': row[3],
                'original_url': row[4]
            })
        
        return articles
    
    def update_news_for_all_users(self):
        """모든 사용자의 뉴스 업데이트"""
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT DISTINCT news_topic FROM user_settings WHERE news_topic IS NOT NULL')
        topics = cursor.fetchall()
        conn.close()
        
        for (topic,) in topics:
            articles = self.fetch_news_articles(topic)
            if articles:
                # 각 기사에 대해 요약 생성
                for article in articles:
                    summary = self.summarize_news_article(article['original_url'], article['title'])
                    article['summary'] = summary
                
                self.save_news_articles(articles)
    
    def start_news_update_scheduler(self):
        """뉴스 업데이트 스케줄러 시작"""
        def run_scheduler():
            schedule.every(6).hours.do(self.update_news_for_all_users)
            while True:
                schedule.run_pending()
                time.sleep(3600)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()

# 서비스 인스턴스 생성
service = EnhancedMailSummaryService()

# 인증 확인 함수
def require_auth():
    """인증 확인 데코레이터"""
    if 'credentials' not in session:
        return False
    
    credentials = service.get_credentials_from_session()
    return credentials is not None

# routes
@app.route('/')
def index():
    if not require_auth():
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/test')
def test():
    """환경변수 설정 확인용 테스트 라우트"""
    google_client_id = os.getenv('GOOGLE_CLIENT_ID')
    openai_key = os.getenv('OPENAI_API_KEY')
    flask_secret = os.getenv('FLASK_SECRET_KEY')
    
    return f"""
    <h1>환경변수 테스트</h1>
    <p>Google Client ID: {'설정됨' if google_client_id else '설정되지 않음'}</p>
    <p>OpenAI API Key: {'설정됨' if openai_key else '설정되지 않음'}</p>
    <p>Flask Secret Key: {'설정됨' if flask_secret else '설정되지 않음'}</p>
    <p>CLIENT_SECRETS_FILE: {'생성됨' if CLIENT_SECRETS_FILE else '생성되지 않음'}</p>
    <p><a href="/login">로그인 페이지로 이동</a></p>
    """

@app.route('/auth')
def auth():
    if not CLIENT_SECRETS_FILE:
        return "OAuth 설정이 올바르지 않습니다. 환경변수를 확인하세요.", 500
    
    try:
        # 환경변수에서 redirect URI 가져오기 (없으면 기본값 사용)
        redirect_uri = os.getenv('OAUTH_REDIRECT_URI')
        if not redirect_uri:
            # 기본값 설정
            redirect_uri = "https://port-0-mailsummaryservice-mcab1he3ab59c5d8.sel5.cloudtype.app/oauth2callback"
        
        print(f"사용할 Redirect URI: {redirect_uri}")  # 디버깅용
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        session['state'] = state
        session['redirect_uri'] = redirect_uri
        return redirect(authorization_url)
    except Exception as e:
        print(f"OAuth 인증 시작 오류: {e}")
        return f"인증 설정 오류: {str(e)}", 500

@app.route('/oauth2callback')
def oauth2callback():
    if not CLIENT_SECRETS_FILE:
        return redirect(url_for('login'))
    
    state = session.get('state')
    redirect_uri = session.get('redirect_uri')
    
    if not state or not redirect_uri:
        print("세션에 state 또는 redirect_uri가 없습니다.")
        return redirect(url_for('login'))
    
    print(f"콜백에서 사용할 Redirect URI: {redirect_uri}")  # 디버깅용
    print(f"실제 요청 URL: {request.url}")  # 디버깅용
    
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=redirect_uri
        )
        
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # 환경변수에서 client 정보 가져오기
        client_id = os.getenv('GOOGLE_CLIENT_ID')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
        
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': client_id,
            'client_secret': client_secret,
            'scopes': credentials.scopes
        }
        
        gmail_service = service.get_gmail_service(credentials)
        profile = gmail_service.users().getProfile(userId='me').execute()
        session['user_email'] = profile['emailAddress']
        
        user_settings = service.get_user_settings(profile['emailAddress'])
        if not user_settings:
            return redirect(url_for('work_time_setup'))
        
        return redirect(url_for('index'))
    
    except Exception as e:
        print(f"OAuth 콜백 처리 중 오류: {e}")
        return f"인증 처리 오류: {str(e)}", 500

@app.route('/work-time-setup')
def work_time_setup():
    if not require_auth():
        return redirect(url_for('login'))
    return render_template('work_time_setup.html')

@app.route('/news-topic-setup')
def news_topic_setup():
    if not require_auth():
        return redirect(url_for('login'))
    return render_template('news_topic_setup.html')

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
        
        # 기존 설정 가져오기
        user_settings = service.get_user_settings(session['user_email'])
        news_topic = user_settings['news_topic'] if user_settings else None
        
        success = service.save_user_settings(
            session['user_email'],
            work_start_time,
            work_end_time,
            news_topic
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': '설정 저장에 실패했습니다.'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/save-news-topic', methods=['POST'])
def save_news_topic():
    if not require_auth() or 'user_email' not in session:
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        data = request.get_json()
        news_topic = data.get('news_topic')
        
        if not news_topic:
            return jsonify({'error': '관심 주제를 입력해주세요.'}), 400
        
        # 기존 설정 가져오기
        user_settings = service.get_user_settings(session['user_email'])
        if not user_settings:
            return jsonify({'error': '출퇴근 시간을 먼저 설정해주세요.'}), 400
        
        success = service.save_user_settings(
            session['user_email'],
            user_settings['work_start_time'],
            user_settings['work_end_time'],
            news_topic
        )
        
        if success:
            # 뉴스 즉시 업데이트
            articles = service.fetch_news_articles(news_topic)
            if articles:
                # 각 기사에 대해 요약 생성
                for article in articles:
                    summary = service.summarize_news_article(article['original_url'], article['title'])
                    article['summary'] = summary
                
                service.save_news_articles(articles)
            return jsonify({'success': True})
        else:
            return jsonify({'error': '설정 저장에 실패했습니다.'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fetch-emails', methods=['POST'])
def fetch_emails():
    """향상된 메일 수집 및 분석"""
    if not require_auth():
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        data = request.get_json()
        start_datetime_str = data.get('start_datetime')
        end_datetime_str = data.get('end_datetime')
        
        if not start_datetime_str or not end_datetime_str:
            return jsonify({'error': '시작 날짜/시간과 종료 날짜/시간을 입력해주세요.'}), 400
        
        start_datetime = datetime.fromisoformat(start_datetime_str.replace('Z', '+00:00')).replace(tzinfo=None)
        end_datetime = datetime.fromisoformat(end_datetime_str.replace('Z', '+00:00')).replace(tzinfo=None)
        
        print(f"검색 범위: {start_datetime} ~ {end_datetime}")
        
        gmail_service = service.get_gmail_service()
        
        # 메일 수집
        emails = service.get_unread_emails_by_datetime_optimized(gmail_service, start_datetime, end_datetime)
        
        print(f"수집된 메일 수: {len(emails)}")
        
        if not emails:
            # 기간 내 전체 통계는 0으로 설정
            return jsonify({
                'success': True,
                'summaries': [],
                'count': 0,
                'stats': {
                    'total': 0,
                    'reply_needed': 0,
                    'reference': 0,
                    'not_important': 0,
                    'spam': 0
                },
                'message': '지정된 기간에 읽지 않은 메일이 없습니다.'
            })
        
        # 각 메일 분석 및 저장
        processed_emails = []
        stats = {
            'total': 0,
            'reply_needed': 0,
            'reference': 0,
            'not_important': 0,
            'spam': 0
        }
        
        for idx, email_data in enumerate(emails):
            try:
                analysis_result = service.get_enhanced_email_summary_and_category(
                    email_data['content'], 
                    email_data['subject'], 
                    email_data['sender']
                )
                
                # 원래 순서 포함하여 저장
                service.save_enhanced_email(email_data, analysis_result, email_data.get('original_order', idx))
                
                # 카테고리별 통계 업데이트
                stats['total'] += 1
                category = analysis_result['category']
                if category == '회신필요':
                    stats['reply_needed'] += 1
                elif category == '참고용':
                    stats['reference'] += 1
                elif category == '중요하지않음':
                    stats['not_important'] += 1
                elif category == '스팸':
                    stats['spam'] += 1
                
                processed_emails.append({
                    'message_id': email_data['message_id'],
                    'sender': email_data['sender'],
                    'subject': email_data['subject'],
                    'summary': analysis_result['summary'],
                    'category': analysis_result['category'],
                    'priority_score': analysis_result['priority_score'],
                    'gmail_link': service.generate_gmail_link(email_data['message_id']),
                    'date': email_data['date'],
                    'action_needed': analysis_result['action_needed'],
                    'deadline': analysis_result['deadline'],
                    'is_pinned': False,
                    'is_completed': False,
                    'original_order': email_data.get('original_order', idx)
                })
                
                print(f"메일 처리 완료: {email_data['sender']} - {analysis_result['summary'][:50]}...")
            
            except Exception as e:
                print(f"메일 분석 오류: {e}")
                continue
        
        return jsonify({
            'success': True,
            'summaries': processed_emails,
            'count': len(processed_emails),
            'stats': stats
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
                'work_end_time': settings['work_end_time'],
                'news_topic': settings.get('news_topic', '')
            })
        else:
            return jsonify({'working_hours_set': False})
    
    elif request.method == 'POST':
        data = request.get_json()
        work_start_time = data.get('work_start_time')
        work_end_time = data.get('work_end_time')
        news_topic = data.get('news_topic')
        
        if not work_start_time or not work_end_time:
            return jsonify({'error': '출근 시간과 퇴근 시간을 모두 입력해주세요.'}), 400
        
        success = service.save_user_settings(
            session['user_email'],
            work_start_time,
            work_end_time,
            news_topic
        )
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'error': '설정 저장에 실패했습니다.'}), 500

@app.route('/api/toggle-email-status', methods=['POST'])
def toggle_email_status():
    """메일 상태 토글 (핀/완료)"""
    data = request.get_json()
    message_id = data.get('message_id')
    status_type = data.get('status_type')
    value = data.get('value')
    
    success = service.toggle_email_status(message_id, status_type, value)
    return jsonify({'success': success})

@app.route('/api/get-news', methods=['GET'])
def get_news():
    """최신 뉴스 가져오기"""
    if not require_auth() or 'user_email' not in session:
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        user_settings = service.get_user_settings(session['user_email'])
        if not user_settings or not user_settings.get('news_topic'):
            return jsonify({'success': True, 'articles': [], 'topic': None})
        
        topic = user_settings['news_topic']
        articles = service.get_latest_news(topic)
        
        # 만약 저장된 기사가 없다면 새로 크롤링
        if not articles:
            new_articles = service.fetch_news_articles(topic)
            if new_articles:
                # 각 기사에 대해 요약 생성
                for article in new_articles:
                    summary = service.summarize_news_article(article['original_url'], article['title'])
                    article['summary'] = summary
                
                service.save_news_articles(new_articles)
                articles = service.get_latest_news(topic)
        
        # 요약이 비어있는 기사들에 대해 요약 생성
        for article in articles:
            if not article.get('summary') or article['summary'] == '':
                summary = service.summarize_news_article(article['original_url'], article['title'])
                article['summary'] = summary
                
                # DB 업데이트
                db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
                if db_path.startswith('sqlite:///'):
                    db_path = db_path.replace('sqlite:///', '')
                
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE news_articles 
                    SET summary = ? 
                    WHERE original_url = ?
                ''', (summary, article['original_url']))
                conn.commit()
                conn.close()
        
        return jsonify({
            'success': True,
            'articles': articles,
            'topic': topic
        })
    
    except Exception as e:
        print(f"뉴스 가져오기 오류: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/summarize-article', methods=['POST'])
def summarize_article():
    """뉴스 기사 요약"""
    if not require_auth():
        return jsonify({'error': '인증이 필요합니다.'}), 401
    
    try:
        data = request.get_json()
        article_url = data.get('url')
        article_title = data.get('title', '')
        
        if not article_url:
            return jsonify({'error': 'URL이 필요합니다.'}), 400
        
        # URL로 요약 시도
        summary = service.summarize_news_article(article_url, article_title)
        
        # DB에 요약 업데이트
        db_path = os.getenv('DATABASE_URL', '/tmp/mail_summary.db')
        if db_path.startswith('sqlite:///'):
            db_path = db_path.replace('sqlite:///', '')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE news_articles 
            SET summary = ? 
            WHERE original_url = ?
        ''', (summary, article_url))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'summary': summary
        })
    
    except Exception as e:
        print(f"기사 요약 오류: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/logout')
def logout():
    """로그아웃"""
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)