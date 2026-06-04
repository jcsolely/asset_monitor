# -*- coding: utf-8 -*-
# ==========================================
# 环境配置
# ==========================================
import os
import re
import time

from flask import Flask, jsonify, request, make_response, redirect, url_for, send_from_directory
from functools import wraps
from sm4_crypto import set_salt
from database import (
    init_db, validate_csrf_token, refresh_csrf_token,
    create_session, validate_session, delete_session, delete_user,
    save_user_with_login_info, sanitize_input,
    get_cache, set_cache, delete_cache, update_user_cookies,
    set_monitor_last
)
from unicom_service import UserService
from sms_login import (
    send_code as sms_send_code,
    validate_tencent_captcha,
    sms_login as sms_do_login,
    generate_device_id,
    generate_appid
)


# ==========================================
# 全局配置
# ==========================================
# 初始化加密密钥（必须设置环境变量 APP_SALT）
APP_SALT = os.environ.get('APP_SALT', '')
if not APP_SALT: raise RuntimeError('请设置环境变量 APP_SALT（应用加密密钥），否则无法启动')
set_salt(APP_SALT)

app = Flask(__name__)

# 登录过期时间（天）
LOGIN_EXPIRE_DAYS = 30

# 缓存有效期（秒）
CACHE_DURATION = 30

# 请求去重（防止重复点击）
request_locks = {}
# 请求去重锁有效期（秒）
REQUEST_LOCK_DURATION = 1

# API 代理前缀（直连时为空，nginx 代理时由 nginx 处理前缀）
API_PROXY_PREFIX = ''

# Cookie 公共配置
COOKIE_HTTPONLY = True
COOKIE_SECURE = False
COOKIE_SAMESITE = 'Lax'

# 初始化数据库
init_db()

# 模板目录
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')

# 公开路由（不需要登录）
PUBLIC_ROUTES = [
    '/login',
    '/sms-login',
    '/favicon.ico',
    '/api/login',
    '/api/sms/send-code',
    '/api/sms/validate-captcha',
    '/api/sms/login',
]

# 受保护的页面路由
PROTECTED_PAGES = ['/']


# ==========================================
# 中间件 & 装饰器
# ==========================================
@app.after_request
def set_security_headers(response):
    """安全响应头"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://turing.captcha.qcloud.com https://turing.captcha.gtimg.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://turing.captcha.qcloud.com https://turing.captcha.gtimg.com; style-src 'self' 'unsafe-inline' https://turing.captcha.qcloud.com https://turing.captcha.gtimg.com; font-src 'self' data:; frame-src https://turing.captcha.qcloud.com https://turing.captcha.gtimg.com https://img.client.10010.com; connect-src 'self' https://turing.captcha.qcloud.com https://turing.captcha.gtimg.com https://loginxhm.10010.com; img-src 'self' data: https://turing.captcha.qcloud.com https://turing.captcha.gtimg.com;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response

@app.before_request
def check_login():
    """全局登录检查"""
    # 静态资源和公开路由直接放行
    if request.path.startswith('/static/') or request.path in PUBLIC_ROUTES:
        return None

    if request.path.startswith('/api/'):
        session_token = request.cookies.get('session_token')
        user = validate_session(session_token)
        if not user:
            return jsonify({"status": "error", "msg": "未登录或登录已过期"}), 401
        request.current_user = user
        return None

    for page in PROTECTED_PAGES:
        if request.path == page or request.path.startswith(page):
            session_token = request.cookies.get('session_token')
            user = validate_session(session_token)
            if not user:
                return redirect(url_for('login_page'))
            request.current_user = user
            break

    return None

def csrf_protect(f):
    """CSRF保护装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')
        # 优先从请求头获取，其次从请求体获取
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token:
            data = request.get_json(silent=True) or {}
            csrf_token = data.get('csrf_token') or request.form.get('csrf_token')
        if not validate_csrf_token(session_token, csrf_token):
            return jsonify({"status": "error", "msg": "CSRF验证失败，请刷新页面重试"}), 403
        return f(*args, **kwargs)
    return decorated_function

def prevent_duplicate_request(f):
    """防止重复请求装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_data = getattr(request, 'current_user', None)
        if not user_data:
            return f(*args, **kwargs)
        user_id = user_data.get('id', '')
        lock_key = f"{user_id}:{request.path}"
        now = time.time()
        if lock_key in request_locks:
            if now - request_locks[lock_key] < REQUEST_LOCK_DURATION:
                return jsonify({"status": "error", "msg": "请求过于频繁，请稍后再试"}), 429
        request_locks[lock_key] = now
        expired_keys = [k for k, v in request_locks.items() if now - v > REQUEST_LOCK_DURATION]
        for k in expired_keys:
            del request_locks[k]
        return f(*args, **kwargs)
    return decorated_function

def route(path, **kwargs):
    """带代理前缀的路由装饰器"""
    return app.route(f"{API_PROXY_PREFIX}{path}", **kwargs)

def mask_mobile(mobile):
    """手机号脱敏：138****1234"""
    if not mobile or len(mobile) < 7:
        return mobile or ''
    return mobile[:3] + '****' + mobile[7:]

def is_valid_phone(phone):
    """验证手机号格式：11位数字，1开头"""
    return bool(re.match(r'^1[3-9]\d{9}$', phone))


# ==========================================
# 页面渲染
# ==========================================
@route('/')
def index():
    """主页"""
    with open(os.path.join(TEMPLATES_DIR, 'index.html'), 'r', encoding='utf-8') as f:
        return f.read()

@route('/login')
def login_page():
    """登录页面"""
    session_token = request.cookies.get('session_token')
    user = validate_session(session_token)
    if user:
        return redirect(url_for('index'))
    with open(os.path.join(TEMPLATES_DIR, 'login.html'), 'r', encoding='utf-8') as f:
        return f.read()

@route('/static/<path:filename>')
def serve_static(filename):
    """静态文件"""
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    return send_from_directory(static_dir, filename)

@route('/favicon.ico')
def favicon():
    """网站图标"""
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), 'favicon.ico', mimetype='image/x-icon')

@route('/sms-login')
def sms_login_page():
    """短信登录页面"""
    session_token = request.cookies.get('session_token')
    user = validate_session(session_token)
    if user:
        return redirect(url_for('index'))
    with open(os.path.join(TEMPLATES_DIR, 'sms-login.html'), 'r', encoding='utf-8') as f:
        return f.read()


# ==========================================
# 短信登录接口
# ==========================================
@route('/api/sms/send-code', methods=['POST'])
def api_sms_send_code():
    """发送短信验证码"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "msg": "请求数据格式错误"}), 400

    phone = sanitize_input(data.get('phone', '').strip())
    appid = sanitize_input(data.get('appid', '').strip())
    result_token = sanitize_input(data.get('resultToken', '').strip())

    if not phone:
        return jsonify({"status": "error", "msg": "请输入手机号"}), 400
    if not is_valid_phone(phone):
        return jsonify({"status": "error", "msg": "手机号格式不正确"}), 400

    # 获取或生成 device_id
    device_id = request.cookies.get('sms_device_id', '')
    if not device_id:
        device_id = generate_device_id()

    result = sms_send_code(phone, appid, device_id, result_token)

    resp = make_response(jsonify(result))
    # 设置 device_id cookie（7天有效）
    resp.set_cookie('sms_device_id', device_id, max_age=7*24*60*60, httponly=COOKIE_HTTPONLY, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
    return resp

@route('/api/sms/validate-captcha', methods=['POST'])
def api_sms_validate_captcha():
    """校验腾讯验证码"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "msg": "请求数据格式错误"}), 400

    ticket = sanitize_input(data.get('ticket', '').strip())
    rand_str = sanitize_input(data.get('randstr', '').strip())
    mobile_hex = sanitize_input(data.get('mobile', '').strip())
    phone = sanitize_input(data.get('phone', '').strip())
    appid = sanitize_input(data.get('appid', '').strip())

    if not ticket or not rand_str:
        return jsonify({"status": "error", "msg": "ticket/randstr 不能为空"}), 400

    device_id = request.cookies.get('sms_device_id', '')
    if not device_id:
        device_id = generate_device_id()

    result = validate_tencent_captcha(mobile_hex, ticket, rand_str, phone, appid, device_id)
    return jsonify(result)

@route('/api/sms/login', methods=['POST'])
def api_sms_login():
    """短信验证码登录 → 获取 token_online → 走原有登录流程"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "msg": "请求数据格式错误"}), 400

    phone = sanitize_input(data.get('phone', '').strip())
    code = sanitize_input(data.get('code', '').strip())
    appid = sanitize_input(data.get('appid', '').strip())

    if not phone or not code:
        return jsonify({"status": "error", "msg": "请输入手机号和验证码"}), 400
    if not is_valid_phone(phone):
        return jsonify({"status": "error", "msg": "手机号格式不正确"}), 400

    device_id = request.cookies.get('sms_device_id', '')
    if not device_id:
        device_id = generate_device_id()

    # 第一步：短信验证码登录，获取 token_online
    sms_result = sms_do_login(phone, code, appid, device_id)
    if sms_result.get('status') != 'success':
        return jsonify({"status": "fail", "msg": sms_result.get('msg', '登录失败')})

    token_online = sms_result.get('token_online', '')
    if not token_online:
        return jsonify({"status": "fail", "msg": "登录成功但未获取到 token_online"})

    # 第二步：用 token_online 走原有登录流程
    try:
        user = UserService(token_online)
        login_info = user.ensure_login()
        if not login_info or not login_info.get('ecs_token'):
            return jsonify({"status": "fail", "msg": "Token 在线验证失败，请重试"}), 400

        sms_ecs_token = sms_result.get('ecs_token', '')
        sms_appid = sms_result.get('appid', '')
        user_id = save_user_with_login_info(login_info, token_online, app_id=sms_appid, ecs_token=sms_ecs_token)
        session_token, csrf_token = create_session(user_id)

        response = make_response(jsonify({
            "status": "success",
            "msg": "登录成功",
            "csrf_token": csrf_token
        }))
        response.set_cookie('session_token', session_token, max_age=LOGIN_EXPIRE_DAYS*24*60*60, httponly=COOKIE_HTTPONLY, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
        return response
    except Exception as e:
        return jsonify({"status": "fail", "msg": "登录失败：" + str(e)}), 500


# ==========================================
# 认证接口
# ==========================================
@route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """获取CSRF令牌（需要已登录）"""
    session_token = request.cookies.get('session_token')
    if not session_token:
        return jsonify({"status": "error", "msg": "未登录"}), 401
    
    csrf_token = refresh_csrf_token(session_token)
    if not csrf_token:
        return jsonify({"status": "error", "msg": "会话无效或已过期"}), 401
    
    return jsonify({"status": "success", "token": csrf_token})

@route('/api/check-login', methods=['POST'])
def check_login_api():
    """检查登录状态（无需CSRF保护，此接口用于验证登录状态）"""
    user_data = request.current_user
    return jsonify({
        "status": "success",
        "data": {"mobile": mask_mobile(user_data.get('mobile', ''))}
    })

@route('/api/token-info', methods=['GET'])
@csrf_protect
def get_token_info():
    """获取当前用户的 Token 信息"""
    user_data = request.current_user
    return jsonify({
        "status": "success",
        "data": {
            "token_online": user_data.get('token', ''),
            "ecs_token": user_data.get('ecs_token', ''),
            "app_id": user_data.get('app_id', '')
        }
    })

@route('/api/login', methods=['POST'])
def login():
    """用户登录（无需CSRF验证，因为登录本身是建立安全连接）"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "msg": "请求数据格式错误"}), 400

    token = sanitize_input(data.get('token', '').strip())
    if not token:
        return jsonify({"status": "error", "msg": "请输入Token"}), 400

    try:
        user = UserService(token)

        login_info = user.ensure_login()
        if not login_info or not login_info.get('ecs_token'):
            return jsonify({"status": "error", "msg": "登录验证失败，请检查Token是否有效"}), 400

        user_id = save_user_with_login_info(login_info, token)
        session_token, csrf_token = create_session(user_id)

        response = make_response(jsonify({"status": "success", "msg": "登录成功", "csrf_token": csrf_token}))
        response.set_cookie('session_token', session_token, max_age=LOGIN_EXPIRE_DAYS*24*60*60, httponly=COOKIE_HTTPONLY, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)
        return response
    except Exception as e:
        return jsonify({"status": "error", "msg": "登录失败：" + str(e)}), 500

@route('/api/logout', methods=['POST'])
@csrf_protect
def logout():
    """退出登录"""
    session_token = request.cookies.get('session_token')
    if session_token:
        user = validate_session(session_token)
        if user:
            delete_user(user['id'])
    delete_session(session_token)

    response = make_response(jsonify({"status": "success", "msg": "已退出登录"}))
    response.delete_cookie('session_token')
    return response


# ==========================================
# 数据接口
# ==========================================
@route('/api/account')
@csrf_protect
@prevent_duplicate_request
def api_account():
    """获取账户信息"""
    user_data = request.current_user
    user_id = user_data['id']

    cached = get_cache(user_id, 'account', CACHE_DURATION)
    if cached and cached.get('success'):
        return jsonify({"status": "success", "data": cached})

    cached_cookies = user_data.get('cookies', {})
    user = UserService(user_data['token'], cached_cookies)
    data = user.get_remain_data()

    if not data.get('success'):
        login_info = user.refresh_session()
        if login_info and login_info.get('cookies'):
            update_user_cookies(user_id, login_info['cookies'])
            data = user.get_remain_data()

    if data and data.get('success'):
        set_cache(user_id, 'account', data)

    return jsonify({"status": "success", "data": data})

@route('/api/assets')
@csrf_protect
@prevent_duplicate_request
def api_assets():
    """获取资产信息"""
    user_data = request.current_user
    user_id = user_data['id']

    cached = get_cache(user_id, 'assets', CACHE_DURATION)
    if cached and cached.get('success'):
        return jsonify({"status": "success", "data": cached})

    cached_cookies = user_data.get('cookies', {})
    user = UserService(user_data['token'], cached_cookies, user_id=user_id)
    data = user.get_flow_data()

    if not data.get('success'):
        login_info = user.refresh_session()
        if login_info and login_info.get('cookies'):
            update_user_cookies(user_id, login_info['cookies'])
            data = user.get_flow_data()

    if data and data.get('success'):
        set_cache(user_id, 'assets', data)

    return jsonify({"status": "success", "data": data})

@route('/api/reset-monitor', methods=['POST'])
@csrf_protect
def api_reset_monitor():
    """重置监控数据"""
    user_data = request.current_user
    user_id = user_data['id']
    data = request.get_json(silent=True) or {}
    current = data.get('current', {})

    try:
        set_monitor_last(user_id, {
            "direct_flow": current.get('direct_flow', 0),
            "general_flow": current.get('general_flow', 0),
            "free_flow": current.get('free_flow', 0),
            "time": current.get('time', '')
        })
        delete_cache(user_id, 'assets')
        return jsonify({"status": "success", "msg": "已重置"})
    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)})

@route('/api/speed')
@csrf_protect
@prevent_duplicate_request
def api_speed():
    """获取5G速率信息"""
    user_data = request.current_user
    user_id = user_data['id']

    cached = get_cache(user_id, 'speed', CACHE_DURATION)
    if cached and cached.get('success'):
        return jsonify({"status": "success", "data": cached})

    cached_cookies = user_data.get('cookies', {})
    user = UserService(user_data['token'], cached_cookies)
    data = user.get_speed_data()

    if not data.get('success'):
        login_info = user.refresh_session()
        if login_info and login_info.get('cookies'):
            update_user_cookies(user_id, login_info['cookies'])
            data = user.get_speed_data()

    if data and data.get('success'):
        set_cache(user_id, 'speed', data)

    return jsonify({"status": "success", "data": data})

@route('/api/orders')
@csrf_protect
@prevent_duplicate_request
def api_orders():
    """获取已订业务信息"""
    user_data = request.current_user
    user_id = user_data['id']

    cached = get_cache(user_id, 'orders', CACHE_DURATION)
    if cached and cached.get('success'):
        return jsonify({"status": "success", "data": cached})

    cached_cookies = user_data.get('cookies', {})
    user = UserService(user_data['token'], cached_cookies)
    data = user.get_orders_data()

    if not data.get('success'):
        login_info = user.refresh_session()
        if login_info and login_info.get('cookies'):
            update_user_cookies(user_id, login_info['cookies'])
            data = user.get_orders_data()

    if data and data.get('success'):
        set_cache(user_id, 'orders', data)

    return jsonify({"status": "success", "data": data})

@route('/api/prizes')
@csrf_protect
@prevent_duplicate_request
def api_prizes():
    """获取兑换记录"""
    user_data = request.current_user
    user_id = user_data['id']

    cached = get_cache(user_id, 'prizes', CACHE_DURATION)
    if cached is not None:
        return jsonify({"status": "success", "data": cached})

    cached_cookies = user_data.get('cookies', {})
    user = UserService(user_data['token'], cached_cookies)
    data = user.get_prize_data()

    if not data.get('success'):
        login_info = user.refresh_session()
        if login_info and login_info.get('cookies'):
            update_user_cookies(user_id, login_info['cookies'])
            data = user.get_prize_data()

    if data and data.get('success'):
        set_cache(user_id, 'prizes', data)

    return jsonify({"status": "success", "data": data})


# ==========================================
# 启动入口
# ==========================================
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
