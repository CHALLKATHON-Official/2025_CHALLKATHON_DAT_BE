# 📩 매일메일: AI 메일 분류 및 자동 요약 서비스
> 하루에도 수십 통씩 쌓이는 메일, 일일이 확인하느라 시간 낭비하고 계신가요? **매일 메일**은 출퇴근 시간 동안에 쌓인 메일을 AI가 자동으로 요약하고 정리해주는 웹 서비스입니다!


## 🧑‍💻 개발자 소개  

  
| 이름 | 전공 | 역할 | 
| ------ | ------ | ------ |
| 김동영 | 영어통번역학과 | 서비스 기획 |
| 고홍규 | 수학과 | 프론트엔드 및 백엔드 개발 |
| 이서희 |컴퓨터공학과 | 백엔드 및 프론트엔드 개발 |

## ⚙️ 기술 스택
  
**Back-End**
- Python / Flask
- Google Gmail API, Google OAuth2
- OpenAI GPT-3.5 Turbo (메일/뉴스 요약)
- SQLite (로컬 DB)
- schedule (자동 뉴스 요약)

**Front-End**
- React (Vite 기반)
- Tailwind CSS, Framer Motion, React Spring
- Chart.js (메일 통계 시각화)

**Infra**
- 배포 플랫폼: Cloudtype
- 자동 배포 브랜치: main
- 실행 명령어: python app.py
- 서비스 포트: 8080
- 환경변수 관리: python-dotenv


## 📁 파일 구조 (요약)


```sh
📦 프로젝트 루트/
├── app.py                  # Flask 백엔드 진입점
├── templates/
│   └── index.html          # 메인 페이지
│   └── login.html          # 로그인 페이지
│   └── work_time_setup.html           # 출퇴근 시간 설정 페이지
│   └── news_topic_setup.html          # 관심 주제 설정 페이지
├── static/
│   └── assets/             # JS/CSS 파일
├── credentials.json        # Google OAuth2 인증파일 (로컬에서만 사용)
├── .env                    # 환경변수 파일 (GOOGLE, DB, OPENAI 등)
└── database/
    └── mail_summary.db     # SQLite 데이터베이스
```


## 🌟 주요 기능 소개


| 기능 | 설명 | 
| ------ | ------ |
| Google 계정 연동 | OAuth2를 통한 안전한 로그인 및 Gmail 접근 권한 획득 |
| 메일 수집 및 요약 | 지정 시간 사이의 미확인 메일 수집 및 AI 요약 수행 |
| 우선순위 분류 | 회신 필요, 참고용, 중요하지 않음, 스팸으로 자동 분류 |
| 메일 상태 관리 | 메일 고정 및 완료 처리 기능 제공 |
| 출퇴근 시간 설정 | 유저 설정 기반 메일 조회 시간 자동 조절 |
| 관심 주제 뉴스 요약 | 사용자 키워드 기반 뉴스 크롤링 및 AI 요약 |
| 메일 통계 시각화 | 시간대별 메일 수신량을 차트로 시각화 |


## 🔄 FE & BE 연동 방식


- React 앱은 vite build로 빌드하여 index.html, JS/CSS를 Flask에 통합
- /api/fetch-emails 등의 엔드포인트를 통해 React에서 백엔드로 비동기 요청 처리
- JSON 형태로 요약된 메일 데이터와 통계 응답
  

## 🚀 배포

- 플랫폼: Cloudtype
- 배포 레포지토리: CHALLKATHON-Official/2025_CHALLKATHON_DAT_BE
- 브랜치: main 기준 자동 배포
- 환경변수:
```sh
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
FLASK_SECRET_KEY
DATABASE_URL
OPENAI_API_KEY
```
- 포트: 8080
- start command: **python app.py**
