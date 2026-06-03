# -*- coding: utf-8 -*-
import sqlite3
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timedelta
from contextlib import contextmanager
from sm4_crypto import sm4_encrypt, sm4_decrypt

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # 创建用户表（如果不存在）
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            mobile TEXT NOT NULL,
            token TEXT NOT NULL,
            app_id TEXT DEFAULT '',
            cookies TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # 创建登录会话表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            csrf_token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # 创建数据缓存表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS data_cache (
            user_id TEXT NOT NULL,
            cache_key TEXT NOT NULL,
            cache_data TEXT NOT NULL,
            expires_at REAL NOT NULL,
            PRIMARY KEY (user_id, cache_key)
        )
    ''')
    
    conn.commit()
    conn.close()
    
    # 初始化监控数据表
    init_monitor_table()

@contextmanager
def get_db():
    """获取数据库连接上下文管理器"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def hash_token(token):
    """对令牌进行哈希"""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def create_session(user_id):
    """创建用户会话（删除该用户旧会话）"""
    session_token = secrets.token_urlsafe(48)
    csrf_token = secrets.token_urlsafe(32)
    now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    expires_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + 30*24*60*60))
    
    with get_db() as conn:
        cursor = conn.cursor()
        # 删除该用户的旧会话
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        # 创建新会话
        cursor.execute(
            'INSERT INTO sessions (user_id, session_token, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
            (user_id, hash_token(session_token), hash_token(csrf_token), expires_str, now_str)
        )
        conn.commit()
    
    return session_token, csrf_token

def validate_session(session_token):
    """验证用户会话"""
    if not session_token:
        return None
    
    hashed = hash_token(session_token)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.mobile, u.token, u.app_id, u.cookies, s.csrf_token
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.expires_at > ?
        ''', (hashed, datetime.now().isoformat()))
        
        row = cursor.fetchone()
        if row:
            result = dict(row)
            # 解密敏感字段
            try:
                result['mobile'] = sm4_decrypt(result['mobile'])
            except Exception:
                pass
            try:
                result['token'] = sm4_decrypt(result['token'])
            except Exception:
                pass
            try:
                result['cookies'] = json.loads(sm4_decrypt(result['cookies']))
            except Exception:
                result['cookies'] = json.loads(result.get('cookies', '{}'))
            return result
    
    return None

def validate_csrf_token(session_token, csrf_token):
    """验证CSRF令牌（与session绑定）"""
    if not session_token or not csrf_token:
        return False
    
    hashed_session = hash_token(session_token)
    hashed_csrf = hash_token(csrf_token)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 1 FROM sessions 
            WHERE session_token = ? AND csrf_token = ? AND expires_at > ?
        ''', (hashed_session, hashed_csrf, datetime.now().isoformat()))
        
        return cursor.fetchone() is not None

def refresh_csrf_token(session_token):
    """刷新CSRF令牌"""
    if not session_token:
        return None
    
    new_csrf = secrets.token_urlsafe(32)
    hashed_session = hash_token(session_token)
    hashed_csrf = hash_token(new_csrf)
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE sessions SET csrf_token = ? WHERE session_token = ? AND expires_at > ?
        ''', (hashed_csrf, hashed_session, datetime.now().isoformat()))
        conn.commit()
    
    return new_csrf

def delete_session(session_token):
    """删除用户会话（退出登录）"""
    if not session_token:
        return
    
    hashed = hash_token(session_token)
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE session_token = ?', (hashed,))
        conn.commit()

def delete_user(user_id):
    """删除用户及其所有相关数据"""
    if not user_id:
        return
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM data_cache WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM monitor_data WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()

def get_cache(user_id, cache_key, max_age=30):
    """获取缓存数据"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT cache_data, expires_at FROM data_cache 
            WHERE user_id = ? AND cache_key = ?
        ''', (user_id, cache_key))
        row = cursor.fetchone()
        if row:
            expires_at = row['expires_at']
            if time.time() < expires_at:
                try:
                    return json.loads(sm4_decrypt(row['cache_data']))
                except Exception:
                    return json.loads(row['cache_data'])
            # 过期删除
            cursor.execute('DELETE FROM data_cache WHERE user_id = ? AND cache_key = ?', (user_id, cache_key))
            conn.commit()
    return None

def set_cache(user_id, cache_key, data, max_age=30):
    """设置缓存数据"""
    expires_at = time.time() + max_age
    with get_db() as conn:
        cursor = conn.cursor()
        enc_data = sm4_encrypt(json.dumps(data, ensure_ascii=False))
        cursor.execute('''
            INSERT INTO data_cache (user_id, cache_key, cache_data, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, cache_key) DO UPDATE SET
                cache_data = excluded.cache_data,
                expires_at = excluded.expires_at
        ''', (user_id, cache_key, enc_data, expires_at))
        conn.commit()

def delete_cache(user_id, cache_key):
    """删除指定缓存"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM data_cache WHERE user_id = ? AND cache_key = ?', (user_id, cache_key))
        conn.commit()

def save_user_with_login_info(login_info, token, app_id=''):
    """保存或更新用户信息（根据手机号识别用户）"""
    mobile = login_info.get('mobile', '')
    cookies = login_info.get('cookies', {})
    user_id = hash_token(mobile) if mobile else hash_token(token)
    
    # 加密敏感字段
    enc_mobile = sm4_encrypt(mobile)
    enc_token = sm4_encrypt(token)
    enc_cookies = sm4_encrypt(json.dumps(cookies, ensure_ascii=False))
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE id = ?', (user_id,))
        existing = cursor.fetchone()
        
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if existing:
            cursor.execute('''
                UPDATE users SET mobile = ?, token = ?, app_id = ?, cookies = ?, last_login = ?
                WHERE id = ?
            ''', (enc_mobile, enc_token, app_id, enc_cookies, now_str, user_id))
        else:
            cursor.execute('''
                INSERT INTO users (id, mobile, token, app_id, cookies, last_login)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, enc_mobile, enc_token, app_id, enc_cookies, now_str))
        conn.commit()
    
    return user_id

def update_user_cookies(user_id, cookies):
    """更新用户的会话Cookie（SM4加密存储）"""
    enc_cookies = sm4_encrypt(json.dumps(cookies, ensure_ascii=False))
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users SET cookies = ?, updated_at = ? WHERE id = ?
        ''', (enc_cookies, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
        conn.commit()

def sanitize_input(value, max_length=2000):
    """清理输入数据，防止XSS"""
    if not isinstance(value, str):
        return value
    
    # 移除HTML标签字符
    value = value.replace('<', '&lt;').replace('>', '&gt;')
    value = value.replace('"', '&quot;').replace("'", '&#x27;')
    
    # 限制长度
    return value[:max_length]

def init_monitor_table():
    """初始化监控数据表"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitor_data (
                user_id TEXT NOT NULL,
                month TEXT NOT NULL,
                direct_flow REAL DEFAULT 0,
                general_flow REAL DEFAULT 0,
                free_flow REAL DEFAULT 0,
                time TEXT DEFAULT '',
                PRIMARY KEY (user_id, month)
            )
        ''')
        conn.commit()

def get_monitor_last(user_id):
    """获取用户当月的监控 last 数据"""
    now = datetime.now()
    month_key = f"{now.year}-{now.month:02d}"
    default_data = {"direct_flow": 0, "general_flow": 0, "free_flow": 0, "time": f"{now.year}-{now.month:02d}-01 00:00:00"}
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT direct_flow, general_flow, free_flow, time FROM monitor_data
            WHERE user_id = ? AND month = ?
        ''', (user_id, month_key))
        row = cursor.fetchone()
        if row:
            return {
                "direct_flow": row['direct_flow'],
                "general_flow": row['general_flow'],
                "free_flow": row['free_flow'],
                "time": row['time']
            }
    return default_data

def set_monitor_last(user_id, data):
    """保存用户当月的监控 last 数据"""
    now = datetime.now()
    month_key = f"{now.year}-{now.month:02d}"
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO monitor_data (user_id, month, direct_flow, general_flow, free_flow, time)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, month) DO UPDATE SET
                direct_flow = excluded.direct_flow,
                general_flow = excluded.general_flow,
                free_flow = excluded.free_flow,
                time = excluded.time
        ''', (user_id, month_key, data.get('direct_flow', 0), data.get('general_flow', 0), data.get('free_flow', 0), data.get('time', '')))
        conn.commit()

def reset_monitor_last(user_id):
    """重置用户当月的监控 last 数据"""
    now = datetime.now()
    default_time = f"{now.year}-{now.month:02d}-01 00:00:00"
    set_monitor_last(user_id, {
        "direct_flow": 0,
        "general_flow": 0,
        "free_flow": 0,
        "time": default_time
    })
