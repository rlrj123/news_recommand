from flask import Flask, request, render_template_string, redirect, url_for, session
#이게 애플리케이션 구현
from flask_sqlalchemy import SQLAlchemy
#이게 데이터베이스 관리하는 라이브러리
from flask_migrate import Migrate
#이게 db 마이스레이션 도와줌 db쉽게 바꿈
from flask_wtf import CSRFProtect
#CSRF 보호기능
from flask_session import Session
#이건 세션을 움직이는것
from flask_wtf.csrf import generate_csrf
#Flask-WTF 라이브러리에서 제공하는 CSRF 토큰 생성 함수
#이걸로 html이나 AJAX 요청에 포함시키기 위해 사용
import requests
#HTTP 요청을 쉽게 보내주는 라이브러리가 서버와 상호작용을 위해
from bs4 import BeautifulSoup
#html을 사용가능하게 함
import os
#os 모듈은 운영체제와 상호작용할 수 있는 기능
from datetime import datetime
#날짜와 시간을 다루고 특정 날짜 생성과 시간 비교에 사용
import logging
#너는 대충 로그인이고
from werkzeug.security import generate_password_hash, check_password_hash
#패스워드 해싱 및 보안 관련 비밀번호를 지켜주는 
import random
import re
import difflib

app = Flask(__name__)
#이걸로 이름을 app로 만들고
# 로깅 설정
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
#이걸로 디버깅 정보 저장으로 상황을 알려줌
# 환경 변수 로드 (보안 강화)
from dotenv import load_dotenv
load_dotenv()
#이걸로 사용하는 환경 변수 및 보안 설정
# 비밀 키 설정 (CSRF 보호를 위해 필수)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')
#비밀키 설정하는 것  세션과 CSRF를 보호
# CSRF 보호 설정
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY', 'your_csrf_secret_key')
#이건 CSRF 보호가 필요한 비밀키 설정 암호화 위해
app.config['WTF_CSRF_TIME_LIMIT'] = None
#CSRF 토큰의 유효기간 설정 만료시간을 설정한다 거기에 None를 써서 만료되지 않도록 한다
csrf = CSRFProtect(app)
#이건 보호 활성화 Protect를 보호합니다

# 서버 측 세션 관리를 위한 설정
app.config['SESSION_TYPE'] = 'filesystem'
#이건 세션 저장 방식 설정 나는 이걸 filesystem으로 넣는다
app.config['SESSION_FILE_DIR'] = './flask_session/'
#세션 파일 저장 경로 설정
app.config['SESSION_PERMANENT'] = False
#세션이 영구적인지 여부 False로 해서 영구적이지 않다
Session(app)
#대충 관리용 파일 db 관리
# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#이건 이 db를 연결한다 그리고 아래 Flase을 줘서 필요한 경우 아무거나 가져올수있다
# SQLAlchemy 초기화
db = SQLAlchemy(app)

# Flask-Migrate 설정 추가
migrate = Migrate(app, db)

# 사용자 테이블 모델 정의
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password = db.Column(db.String(128), nullable=False)
    searches = db.relationship('SearchHistory', order_by='SearchHistory.timestamp', back_populates='user')
    clicks = db.relationship('ClickHistory', order_by='ClickHistory.timestamp', back_populates='user')
#이건 db에 들어가는 테이블 만드는 것
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

# 검색 기록 모델 정의
class SearchHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False, index=True)
    query = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    #이게 검색한게 db에 저장할수있도록 테이블 만드는것
    user = db.relationship('User', back_populates='searches')

# 클릭 기록 모델 정의
class ClickHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), db.ForeignKey('user.username'), nullable=False, index=True)
    news_title = db.Column(db.String(200), nullable=False, index=True)
    news_link = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    #이게 클릭
    user = db.relationship('User', back_populates='clicks')

# 사전에 정의된 넓은 카테고리와 관련 키워드
CATEGORIES = {
    '스포츠': ['축구', '야구', '농구', '배구'],
    '연예': ['연예인', '드라마', '영화', '아이돌', '가수', '배우'],
    '정치': ['정부', '대통령', '국회', '정당'],
    '경제': ['증시', '환율', '부동산', '금융', '스타트업'],
    '세계': ['해외', '국제', '유엔', 'NATO'],
    '테크': ['기술', 'IT', 'AI', '인공지능', '스타트업'],
    '문화': ['예술', '전시', '문학', '음악', '공연'],
    '일반': []
}
#이게 일반 화면 카테고리
# 특정 키워드 기반 카테고리 매핑
SPECIFIC_KEYWORDS = {
    '손흥민': '스포츠',
    '김정은': '정치',
}#이건 지워야하는것

# 연관 카테고리 매핑 추가
RELATED_CATEGORIES = {
    '스포츠': ['축구', '야구', '농구', '배구'],
    '연예': ['연예인', '드라마', '영화', '아이돌', '가수', '배우'],
    '정치': ['정부', '대통령', '국회', '정당'],
    '경제': ['증시', '환율', '부동산', '금융', '스타트업'],
    '세계': ['해외', '국제', '유엔', 'NATO'],
    '테크': ['기술', 'IT', 'AI', '인공지능', '스타트업'],
    '문화': ['예술', '전시', '문학', '음악', '공연'],
    '일반': []
}
#이게 알고리즘과 연관되어있는 카테고리
# 제목 정규화 함수
def normalize_title(title):#이게 정류화하는거
    title = title.lower().strip()#이건 변환과 공백 제거
    title = re.sub(r'[^\w\s]', '', title)#이게 특수문자
    title = re.sub(r'\s+', ' ', title)#여러 공백 하나로 만들기
    return title#그리고 완성된 정규화 문자

# 카테고리 추출 함수
def extract_category_from_title(title):
    title = normalize_title(title)
    stopwords = ['기사', '보도', '뉴스', '단독', '속보']#이게 불용어 제거
    words = title.split()#제목 단어 단위로 구분
    filtered_words = [word for word in words if word not in stopwords]#이게 필요없는거 제거하고 필요있는 의미만 나오게 함
    
    for category, keywords in CATEGORIES.items():#키워드 순회
        for keyword in keywords:#같은게 있으면 찾는다
            if keyword in filtered_words:
                #필터링된 단어에 키워드가 포함되어있는지 확인
                return category#늇제목에서 특정 카테고리와 매칭되면 카테고리 변환
    return '일반'#아니면 일반

# 검색어에서 카테고리 추출 함수
def extract_category_from_query(query):
    #검색어를 입력 받아 카테고리를 찾아 반환하는 역활
    query = normalize_title(query)
    #이게 검색어 정규화
    for keyword, category in SPECIFIC_KEYWORDS.items():
        #특정 키워드 매핑 검사 특정 키워드와 카테고리를 미리 정의한 역활
        if keyword in query:#해당 카테고리로 변환
            return category
    
    for category, keywords in CATEGORIES.items():
        for keyword in keywords:
            if keyword in query:#이게 찾았을때 키워드로 카테고리 변환
                return category
    return '일반'#없으면 일반

# 뉴스 크롤링 함수
def crawl_news(query, max_pages=5):
    news_items = []
    page = 1
    while page <= max_pages:
        url = f"https://search.naver.com/search.naver?where=news&sm=tab_jum&query={query}&start={(page-1)*10+1}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            html = response.text
            soup = BeautifulSoup(html, 'html.parser')
            links = soup.select(".news_tit")
            
            if not links:
                logging.info(f"No news found on page {page} for query '{query}'.")
                break
            
            for link in links:
                title = link.text.strip()
                href = link.get('href')
                category = extract_category_from_title(title)
                logging.debug(f"Crawled news - Title: {title}, Link: {href}, Category: {category}")
                
                if title and href:
                    news_items.append({'title': title, 'link': href, 'category': category})
                else:
                    logging.warning(f"Invalid news item - Title: {title}, Link: {href}")
        
        except requests.RequestException as e:
            logging.error(f"Failed to crawl news on page {page} for query '{query}': {e}")
            break
        
        page += 1
    
    return news_items

# 중복 제거 함수
def deduplicate_news(news_list, similarity_threshold=0.8):
    unique_news = []
    seen_titles = []

    for item in news_list:
        normalized_title = normalize_title(item['title'])

        if normalized_title in seen_titles:
            logging.debug(f"Exact duplicate removed: {item['title']}")
            continue

        is_duplicate = False
        for seen_title in seen_titles:
            similarity = difflib.SequenceMatcher(None, normalized_title, seen_title).ratio()
            if similarity >= similarity_threshold:
                logging.debug(f"Similar duplicate removed: {item['title']} (Similarity: {similarity:.2f})")
                is_duplicate = True
                break

        if not is_duplicate:
            unique_news.append(item)
            seen_titles.append(normalized_title)

    logging.info(f"Deduplicated {len(news_list) - len(unique_news)} out of {len(news_list)} news items.")
    return unique_news

# 클릭 기록 저장 함수
def save_click_history(username, title, link):
    #클릭한 뉴스 테이블에 사용자 이름 제목 링크를 붙여논다
    category = extract_category_from_title(title)
    #그리고 제목을 카테고리로
    logging.debug(f"Extracted category '{category}' from title '{title}'.")
    #로그인 상세 정보를 카테고리를 제목에 맞게 설정
    
    normalized_title = normalize_title(title)#정규화된 제목으로
    existing_click = ClickHistory.query.filter_by(username=username, news_title=title).first()
    #기본 클릭을 테이블에 카테고리를 사용자이름과 뉴스 제목으로 한다
    if existing_click:
        logging.info(f"Duplicate news not saved: {title} | Link: {link}")
        return
    
    new_click = ClickHistory(username=username, news_title=title, news_link=link, category=category)
    try:#새로운 클릭이면 다 나오게 하고
        db.session.add(new_click)
        db.session.commit()
        logging.info(f"Saved news: {title} | Link: {link} | Category: {category}")
    except Exception as e:#월래 있던거면 저장
        db.session.rollback()
        logging.error(f"Failed to save news: {title} | Link: {link} | Error: {e}")

# 검색 기록 저장 함수
def save_search_history(username, query):
    new_search = SearchHistory(username=username, query=query)#이름을 확인하고 제목을 확인
    try:
        db.session.add(new_search)
        db.session.commit()
        logging.info(f"Saved search query: {query}")#그리고 저장
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to save search query: {query} | Error: {e}")#이름이 없으면 오류 나옴

# 클릭 기반 카테고리 뉴스 추천 함수
def get_recommendations(username, query=None):
    #최근 클릭과 검색어로 바탕화면 최우기
    recent_clicks = ClickHistory.query.filter_by(username=username).order_by(ClickHistory.timestamp.desc()).limit(10).all()
    clicked_titles = {normalize_title(click.news_title) for click in ClickHistory.query.filter_by(username=username).all()}
    
    category_counts = {}
    
    if recent_clicks:
        for click in recent_clicks:
            category = click.category
            category_counts[category] = category_counts.get(category, 0) + 2
            #이게 클릭할때 마다 1시 늘어서 새로운 내용은 가중치 1이 늘고
            related_categories = RELATED_CATEGORIES.get(category, [])
            for related in related_categories:
                category_counts[related] = category_counts.get(related, 0) + 0.5
                #비슷한걸 클릭하면 0.5가 늘어난다

    if query:
        category_from_query = extract_category_from_query(query)
        if category_from_query != '일반':
            category_counts[category_from_query] = category_counts.get(category_from_query, 0) + 1
#이게 검색을 카테고리 로 가중치화한거
    total_clicks = sum(category_counts.values())
    if total_clicks == 0:#클릿한 수의 가중치를 더해서 추천뉴스가 나오게
        logging.info(f"No click history and no relevant query for user '{username}'.")
        return []

    category_weights = {category: count / total_clicks for category, count in category_counts.items()}
    
    recommendations = []#이게 카테고리 크롤링 약간 검색이나 사용중 카테고리에서
    for category, weight in category_weights.items():
        num_news = max(1, int(weight * 5))
        for _ in range(num_news):
            news_items = crawl_news(category, max_pages=1)
            filtered_news = [item for item in news_items if normalize_title(item['title']) not in clicked_titles]
            recommendations.extend(filtered_news)
    
    recommendations = deduplicate_news(recommendations, similarity_threshold=0.8)
    random.shuffle(recommendations)
    
    logging.debug(f"Unique recommendations count: {len(recommendations)}")
    
    return recommendations

# HTML 템플릿 (뉴스 검색 결과 페이지)
html_template = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>네이버 뉴스 검색 결과</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 0; }
        .container { width: 80%; margin: 0 auto; padding: 20px; background-color: white; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        .news-item { margin-bottom: 20px; padding-bottom: 10px; border-bottom: 1px solid #ddd; }
        .news-item h2 { font-size: 18px; margin: 0 0 10px 0; }
        .news-item a { color: #1e90ff; text-decoration: none; }
        .search-form { margin-bottom: 20px; }
        .login { text-align: right; margin-bottom: 20px; }
        .login a { margin-left: 20px; }
        .categories { margin-top: 20px; }
        .categories button { margin-right: 15px; font-size: 18px; padding: 10px 15px; cursor: pointer; }
        .dropdown { position: relative; display: inline-block; }
        .dropdown-content {
            display: none;
            position: absolute;
            background-color: #f9f9f9;
            min-width: 160px;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
            z-index: 1;
        }
        .dropdown:hover .dropdown-content {
            display: block;
        }
        .dropdown-content a {
            color: black;
            padding: 12px 16px;
            text-decoration: none;
            display: block;
        }
        .dropdown-content a:hover {background-color: #f1f1f1}
    </style>
</head>
<body>
    <div class="container">
        <h1>네이버 뉴스 검색 결과</h1>
        <div class="login">
            {% if 'username' in session %}
                <p>{{ session['username'] }}님 환영합니다! <a href="{{ url_for('logout') }}">로그아웃</a></p>
            {% else %}
                <a href="{{ url_for('login') }}">로그인</a>
                <a href="{{ url_for('signup') }}">회원가입</a>
            {% endif %}
        </div>
        
        <form class="search-form" method="get" action="{{ url_for('index') }}">
            <input type="text" name="query" placeholder="검색어를 입력하세요" value="{{ query }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <button type="submit">검색</button>
        </form>
        
        <div class="categories">
            {% for category, subcategories in CATEGORIES_WITH_SUBCATEGORIES.items() %}
                {% if subcategories %}
                    <div class="dropdown">
                        <button>{{ category }}</button>
                        <div class="dropdown-content">
                            {% for sub in subcategories %}
                                <a href="{{ url_for('index', query=sub) }}">{{ sub }}</a>
                            {% endfor %}
                        </div>
                    </div>
                {% else %}
                    <button onclick="location.href='{{ url_for('index', query=category) }}'">{{ category }}</button>
                {% endif %}
            {% endfor %}
        </div>
        
        {% if query and news_items %}
            <h2>검색 결과</h2>
            {% for item in news_items %}
            <div class="news-item">
                <h2><a href="{{ item['link'] | escape }}" target="_blank" onclick="trackClick('{{ item['title'] | escape }}', '{{ item['link'] | escape }}')">{{ item['title'] }}</a></h2>
                <p>카테고리: {{ item['category'] }}</p>
            </div>
            {% endfor %}
        {% endif %}
        
        {% if recommendations %}
            <h2>추천 뉴스</h2>
            {% for item in recommendations %}
            <div class="news-item">
                <h2><a href="{{ item['link'] | escape }}" target="_blank" onclick="trackClick('{{ item['title'] | escape }}', '{{ item['link'] | escape }}')">{{ item['title'] }}</a></h2>
                <p>카테고리: {{ item['category'] }}</p>
            </div>
            {% endfor %}
        {% endif %}
        
        {% if not query and not news_items and not recommendations %}
            <p>검색 결과가 없습니다.</p>
        {% endif %}
        
    </div>
    <script>
        function trackClick(title, link) {
            console.log(`Tracking click: Title="${title}", Link="${link}"`);
            fetch('/track_click', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': '{{ csrf_token }}'
                },
                body: JSON.stringify({ title: title, link: link })
            }).then(response => {
                if (response.ok) {
                    console.log("Click tracked successfully");
                } else {
                    console.error("Error tracking click: Server responded with status", response.status);
                }
            }).catch(error => console.error("Error tracking click:", error));
        }
    </script>
</body>
</html>
"""

# 로그인 HTML 템플릿
login_template = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 페이지</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }
        .container { width: 300px; margin: 100px auto; padding: 20px; background-color: white; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; }
        .form-group input { width: 100%; padding: 8px; }
        .btn { width: 100%; padding: 10px; background-color: #1e90ff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>로그인</h1>
        <form method="post" action="{{ url_for('login') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div class="form-group">
                <label for="username">아이디</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">비밀번호</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">로그인</button>
        </form>
    </div>
</body>
</html>
"""

# 회원가입 HTML 템플릿
signup_template = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>회원가입 페이지</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }
        .container { width: 300px; margin: 100px auto; padding: 20px; background-color: white; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; }
        .form-group input { width: 100%; padding: 8px; }
        .btn { width: 100%; padding: 10px; background-color: #1e90ff; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>회원가입</h1>
        <form method="post" action="{{ url_for('signup') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            <div class="form-group">
                <label for="username">아이디</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">비밀번호</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">회원가입</button>
        </form>
    </div>
</body>
</html>
"""

# 403 에러 핸들러 추가 (선택 사항)
@app.errorhandler(403)
def forbidden_error(error):
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <title>접근 금지</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding-top: 50px; }
            .container { display: inline-block; text-align: left; }
            a { color: #1e90ff; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>403 - 접근 금지</h1>
            <p>이 페이지에 접근할 권한이 없습니다.</p>
            <a href="{{ url_for('index') }}">홈으로 돌아가기</a>
        </div>
    </body>
    </html>
    """), 403

# 로그인 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            logging.warning("Login attempt with missing username or password.")
            return "아이디와 비밀번호를 입력하세요.", 400

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            logging.info(f"User '{username}' logged in successfully.")
            return redirect(url_for('index'))
        else:
            logging.warning(f"Failed login attempt for username '{username}'.")
            return "로그인 실패! 아이디와 비밀번호를 확인하세요.", 401

    return render_template_string(login_template, csrf_token=generate_csrf())

# 로그아웃 라우트
@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        logging.info(f"User '{username}' logged out.")
    return redirect(url_for('index'))

# 회원가입 라우트
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if not username or not password:
            logging.warning("Signup attempt with missing username or password.")
            return "아이디와 비밀번호를 입력하세요.", 400

        if User.query.filter_by(username=username).first():
            logging.warning(f"Signup attempt with existing username '{username}'.")
            return "이미 존재하는 사용자입니다.", 400

        new_user = User(username=username)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            logging.info(f"New user '{username}' signed up successfully.")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Failed to sign up user '{username}': {e}")
            return f"회원가입 실패: {e}", 500

    return render_template_string(signup_template, csrf_token=generate_csrf())

# 클릭 기록 저장 라우트
@app.route('/track_click', methods=['POST'])
def track_click():
    if 'username' not in session:
        logging.warning("Unauthorized access attempt to /track_click.")
        return '', 403

    data = request.get_json()
    title = data.get('title')
    link = data.get('link')

    if not title or not link:
        logging.error("Invalid data received in /track_click. Title or Link missing.")
        return 'Invalid data', 400

    # 클릭 기록 저장 함수 호출
    save_click_history(session['username'], title, link)

    return '', 200

# 메인 페이지 (뉴스 검색)
@app.route('/', methods=['GET'])
def index():
    query = request.args.get('query', '').strip()
    news_items = []

    # 검색어가 있을 경우 뉴스 검색 수행
    if query:
        encoded_query = requests.utils.quote(query)
        news_items = crawl_news(encoded_query, max_pages=5)
        news_items = deduplicate_news(news_items, similarity_threshold=0.8)

        if 'username' in session:
            save_search_history(session['username'], query)
    else:
        if 'username' not in session:
            # 로그인하지 않은 사용자: 기본 검색어로 "최신 뉴스" 사용
            query = '최신 뉴스'
            encoded_query = requests.utils.quote(query)
            news_items = crawl_news(encoded_query, max_pages=5)
            news_items = deduplicate_news(news_items, similarity_threshold=0.8)

    # 로그인한 사용자일 때 추천 뉴스 가져오기
    recommendations = []
    if 'username' in session:
        recommendations = get_recommendations(session['username'], query=query)

    return render_template_string(
        html_template,
        query=query,
        news_items=news_items,
        recommendations=recommendations,
        csrf_token=generate_csrf(),
        CATEGORIES_WITH_SUBCATEGORIES=CATEGORIES
    )

if __name__ == "__main__":
    if not os.path.exists('./flask_session/'):#이게 세션 설정
        os.makedirs('./flask_session/')
    app.run(debug=True)
