
<h1 align="center">📩 매일메일</h1>
<p align="center"><strong>AI 메일 분류 및 자동 요약 서비스</strong></p>

<p align="center">
  하루에도 수십 통씩 쌓이는 메일, 일일이 확인하느라 시간 낭비하고 계신가요?<br />
  <strong>매일메일</strong>은 출퇴근 시간 동안에 쌓인 메일을<br />
  AI가 자동으로 요약하고 정리해주는 웹 서비스입니다!
</p>
<br><br><br>

## 🧑‍💻 개발자 소개  

  
| 이름 | 전공 | 역할 | 
| ------ | ------ | ------ |
| 김동영 | 영어통번역학과 | 서비스 기획 |
| 고홍규 | 수학과 | 프론트엔드 및 백엔드 개발 |
| 이서희 |컴퓨터공학과 | 백엔드 및 프론트엔드 개발 |
<br><br><br>
## 🛠️ Tech Stack

### 🔧 Back-End  
- ![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)  
- ![Flask](https://img.shields.io/badge/Flask-000000?style=flat&logo=flask&logoColor=white)  
- ![Gmail API](https://img.shields.io/badge/Gmail_API-EA4335?style=flat&logo=gmail&logoColor=white)  
- ![OAuth2](https://img.shields.io/badge/OAuth2-4285F4?style=flat&logo=google&logoColor=white)  
- ![OpenAI](https://img.shields.io/badge/OpenAI-412991?style=flat&logo=openai&logoColor=white) — GPT-3.5 Turbo (메일/뉴스 요약)  
- ![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat&logo=sqlite&logoColor=white) — 로컬 DB  
- ![Schedule](https://img.shields.io/badge/Schedule-FFD43B?style=flat&logo=python&logoColor=black) — 자동 뉴스 요약  

### 🎨 Front-End  
- ![React](https://img.shields.io/badge/React-61DAFB?style=flat&logo=react&logoColor=black)  
- ![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat&logo=vite&logoColor=white)  
- ![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-06B6D4?style=flat&logo=tailwindcss&logoColor=white)  
- ![Framer Motion](https://img.shields.io/badge/Framer_Motion-EF476F?style=flat&logo=framer&logoColor=white)  
- ![React Spring](https://img.shields.io/badge/React_Spring-88CCCA?style=flat&logo=react&logoColor=black)  
- ![Chart.js](https://img.shields.io/badge/Chart.js-FF6384?style=flat&logo=chartdotjs&logoColor=white)  

### ☁️ Infra & DevOps  
- 배포 플랫폼: ![Cloudtype](https://img.shields.io/badge/Cloudtype-0090F9?style=flat&logo=vercel&logoColor=white)  
- 자동 배포 브랜치: `main`  
- 실행 명령어: `python app.py`  
- 서비스 포트: `8080`  
- 환경변수 관리: `python-dotenv`  
<br><br><br>
---



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

<br><br><br>
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

<br><br><br>
## 🔄 FE & BE 연동 방식


- React 앱은 vite build로 빌드
- 이후 index.html, JS/CSS를 Flask에 통합


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
