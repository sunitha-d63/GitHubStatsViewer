import os, time, re
from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
import requests
from flask_caching import Cache
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev_secret")
cache = Cache(app, config={"CACHE_TYPE": "SimpleCache", "CACHE_DEFAULT_TIMEOUT": 600})

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
    raise RuntimeError("Missing GitHub OAuth environment variables")

oauth = OAuth(app)
oauth.register(
    name='github',
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'repo'},
)

API_BASE = 'https://api.github.com'

@app.route("/")
def index():
    if 'github_token' in session:
        return redirect(url_for('dashboard'))
    return '<a href="/login">Login with GitHub</a>'

@app.route("/login")
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)

@app.route("/authorize")
def authorize():
    token = oauth.github.authorize_access_token()
    session['github_token'] = token
    return redirect(url_for('dashboard'))

def github_fetch(url):
    token = session['github_token']['access_token']
    resp = requests.get(url, headers={
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github+json'
    })
    if resp.status_code == 202:
        time.sleep(2)
        return github_fetch(url)
    if resp.status_code == 403 and resp.headers.get('X-RateLimit-Remaining') == '0':
        reset = int(resp.headers.get('X-RateLimit-Reset')) * 1000
        raise Exception(f"Rate limit exceeded. Try after {time.ctime(reset/1000)}")
    resp.raise_for_status()
    return resp.json(), resp.headers

def get_repos():
    key = 'user_repos'
    if cache.get(key):
        return cache.get(key)
    all_repos = []
    page = 1
    while True:
        data, _ = github_fetch(f"{API_BASE}/user/repos?per_page=100&page={page}")
        if not data:
            break
        all_repos += data
        page += 1
    cache.set(key, all_repos)
    return all_repos

def count_commits(owner, repo_name):
    resp = requests.get(f"{API_BASE}/repos/{owner}/{repo_name}/commits?per_page=1",
                        headers={'Authorization': f"token {session['github_token']['access_token']}"})
    resp.raise_for_status()
    link = resp.headers.get('link', '')
    if 'rel="last"' in link:
        m = re.search(r'&page=(\d+)>; rel="last"', link)
        return int(m.group(1)) if m else 0
    return len(resp.json())

@app.route("/dashboard")
def dashboard():
    if 'github_token' not in session:
        return redirect(url_for('index'))
    try:
        repos = get_repos()
        stats = []
        for r in repos:
            langs, _ = github_fetch(r['languages_url'])
            commits = count_commits(r['owner']['login'], r['name'])
            stats.append({
                'name': r['name'],
                'stars': r.get('stargazers_count', 0),
                'languages': langs,
                'commits': commits,
            })
        return jsonify({'user': oauth.github.get('user').json().get('login'), 'data': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
