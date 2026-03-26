import threading
import subprocess
from flask import render_template, request, make_response
from flask.cli import AppGroup
from flask import Flask, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
import os
import dotenv
from flask_caching import Cache
import redis


from __init__ import app, cors


dotenv.load_dotenv()

# Environment-based API domain selection
LOCAL_API_URL = os.environ.get("LOCAL_API_URL", "http://127.0.0.1:5000")
PROD_API_URL = os.environ.get("PROD_API_URL", "https://your-secret-domain.com")
FLASK_ENV = os.environ.get("FLASK_ENV", "production")

if FLASK_ENV == "development":
    API_URL = LOCAL_API_URL
else:
    API_URL = PROD_API_URL


# Global context processor to inject API_URL into all templates
@app.context_processor
def inject_api_url():
    return dict(API_URL=API_URL)

# Enable gzip compression - reduces bandwidth by 70-80%
Compress(app)

pwss = os.getenv('redisp')

# Use Redis connection pool for better performance
redis_pool = redis.ConnectionPool(
    host='172.17.0.1',
    port=6379,
    password=pwss,
    max_connections=100,
    decode_responses=True,
    socket_keepalive=True,
    socket_connect_timeout=5,
    socket_timeout=5,
    retry_on_timeout=True,
    health_check_interval=30
)

def test_redis_connection():
    """Test if Redis is accessible"""
    try:
        r = redis.Redis(connection_pool=redis_pool)
        r.ping()
        return True
    except Exception as e:
        print(f"Redis connection test failed: {e}")
        return False

# Configure cache with fallback to simple cache
redis_available = test_redis_connection()

if redis_available:
    cache = Cache(app, config={
        'CACHE_TYPE': 'redis',
        'CACHE_REDIS_HOST': '172.17.0.1',
        'CACHE_REDIS_PORT': 6379,
        'CACHE_REDIS_PASSWORD': pwss,
        'CACHE_DEFAULT_TIMEOUT': 3600,
        'CACHE_KEY_PREFIX': 'flask_',
        'CACHE_OPTIONS': {
            'connection_pool': redis_pool
        }
    })
    print("✅ Redis cache initialized successfully")
else:
    cache = Cache(app, config={
        'CACHE_TYPE': 'simple',
        'CACHE_DEFAULT_TIMEOUT': 3600
    })
    print("⚠️ Redis not available, using simple cache")

def get_key_for_limiter():
    """Custom key function that allows dev bypass"""
    dev_token = request.headers.get('X-Dev-Token')
    if dev_token and dev_token == os.getenv('DEV_TOKEN'):
        return None
    return get_remote_address()

# Increase rate limits for burst traffic
if redis_available:
    try:
        limiter = Limiter(
            key_func=get_key_for_limiter,
            default_limits=["2000 per day", "200 per hour", "70 per minute"],
            storage_uri=f"redis://:{pwss}@172.17.0.1:6379",
            storage_options={
                'socket_keepalive': True, 
                'socket_timeout': 5,
                'connection_pool': redis_pool
            }
        )
        limiter.init_app(app)
        print("✅ Redis limiter initialized successfully")
    except Exception as e:
        print(f"❌ Redis limiter failed: {e}")
        limiter = Limiter(
            key_func=get_key_for_limiter,
            default_limits=["2000 per day", "200 per hour"],
            storage_uri="memory://"
        )
        limiter.init_app(app)
        print("⚠️ Using memory storage as fallback")
else:
    limiter = Limiter(
        key_func=get_key_for_limiter,
        default_limits=["2000 per day", "200 per hour"],
        storage_uri="memory://"
    )
    limiter.init_app(app)
    print("⚠️ Redis not available, using memory storage")

# Add aggressive caching headers for static content
@app.after_request
def add_cache_and_security_headers(response):
    if request.path in ['/', '/about', '/projects', '/blender', '/table', '/resume', '/blogs', '/tutorials']:
        response.cache_control.max_age = 3600
        response.cache_control.public = True
        response.headers['Vary'] = 'Accept-Encoding'
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    return response

@app.route('/robots.txt')
@cache.cached(timeout=86400)
def serve_robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    """Lightweight health check for load balancer"""
    return jsonify({"status": "healthy"}), 200

@app.route('/status', methods=['POST'])
@limiter.exempt
def status():
    """Detailed status check with authentication"""
    header = request.headers.get('X-Status-Key')
    expected_key = os.getenv('STATUS_KEY')
    
    if header != expected_key:
        return jsonify({"error": "Unauthorized"}), 401
    
    redis_status = test_redis_connection()
    cache_stats = None
    if redis_status:
        try:
            cache_stats = cache.cache._read_client.info('stats')
        except:
            cache_stats = "Unable to fetch stats"
    
    return jsonify({
        "status": "healthy",
        "redis_connected": redis_status,
        "cache_stats": cache_stats
    }), 200

@app.errorhandler(404)
@cache.cached(timeout=3600)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom rate limit error handler"""
    return jsonify({
        "error": "Too many requests",
        "message": "Please slow down and try again in a few minutes"
    }), 429

@app.before_request
def log_suspicious_requests():
    """Lightweight security logging"""
    if request.path in ['/health', '/status']:
        return
    
    user_agent = request.headers.get('User-Agent', '')
    
    if any(bot in user_agent.lower() for bot in ['sqlmap', 'nikto', 'nmap', 'masscan']):
        app.logger.warning(f"Suspicious user agent: {user_agent} from {request.remote_addr}")
        return jsonify({"error": "Forbidden"}), 403
    
    if '../' in request.path or '..' in request.path:
        app.logger.warning(f"Path traversal attempt: {request.path} from {request.remote_addr}")
        return jsonify({"error": "Forbidden"}), 403

# Cache all static pages aggressively
@app.route('/')
@cache.cached(timeout=3600)
def index():
    return render_template("index.html")

@app.route('/login')
def login():
    return render_template("login.html", API_URL=API_URL)

@app.route('/about')
@cache.cached(timeout=3600)
def about():
    return render_template("about.html")

@app.route('/bday')
@cache.cached(timeout=3600)
def card():
    return render_template("card.html")

@app.route('/projects')
@cache.cached(timeout=3600)
def projects():
    return render_template("projects.html")

@app.route('/animation')
@cache.cached(timeout=3600)
def animation():
    return render_template("animation.html")

@app.route('/emuseum')
@cache.cached(timeout=3600)
def emuseum():
    return render_template("emuseum.html")

@app.route('/moreaboutme')
@cache.cached(timeout=3600)
def moreaboutme():
    return render_template("moreaboutme.html")


@app.route('/profile')
def profile():
    return render_template("profile.html")

@app.route('/resume')
@cache.cached(timeout=3600)
def officialresume():
    return render_template("officialresume.html")

@app.route('/blender')
@cache.cached(timeout=3600)
def blender():
    return render_template("blender.html")

@app.route('/blogs')
@cache.cached(timeout=3600)
def blogs():
    return render_template("blogs.html")

@app.route('/tutorials')
@cache.cached(timeout=3600)
def tutorials():
    return render_template("tutorials.html")

@app.route('/table/')
@cache.cached(timeout=3600)
def table():
    return render_template("table.html")

@app.before_request
def before_request():
    """CORS handling"""
    allowed_origin = request.headers.get('Origin')
    if allowed_origin in ['http://localhost:8086', 'http://127.0.0.1:8086', 'https://nighthawkcoders.github.io']:
        cors._origins = allowed_origin

custom_cli = AppGroup('custom', help='Custom commands')
app.cli.add_command(custom_cli)

if __name__ == "__main__":
    is_production = os.getenv('FLASK_ENV') == 'production'
    app.run(
        debug=not is_production,
        host="0.0.0.0",
        port="8086",
        threaded=True
    )