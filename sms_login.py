# -*- coding: utf-8 -*-
"""
联通短信验证码登录模块
"""
import os
import time
import base64
import binascii
import requests
import urllib3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

urllib3.disable_warnings()

# ==========================================
# 常量
# ==========================================
DEFAULT_APPID = "8f0af12ad9912d306b5053abf90c7ebbb695887bc870ae0706d573c348539c26c5c0a878641fcc0d3e90acb9be1e6ef858a59af546f3c826988332376b7d18c8ea2398ee3a9c3db947e2471d32a49612"

RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc+CZK9bBA9IU+gZUOc6FUGu7y
O9WpTNB0PzmgFBh96Mg1WrovD1oqZ+eIF4LjvxKXGOdI79JRdve9NPhQo07+uqGQ
gE4imwNnRx7PFtCRryiIEcUoavuNtuRVoBAm6qdB0SrctgaqGfLgKvZHOnwTjyNq
jBUxzMeQlEC2czEMSwIDAQAB
-----END PUBLIC KEY-----"""

UA_TEMPLATE = (
    "Mozilla/5.0 (Linux; Android 13; M2007J3SC Build/TKQ1.220829.002; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/107.0.5304.141 Mobile Safari/537.36; "
    "unicom{{version:android@11.0800,desmobile:{phone}}};"
    "deviceltype{{deviceBrand:Xiaomi,deviceModel:M2007J3SC}};{{yw_code:}}"
)


# ==========================================
# RSA 加密
# ==========================================
def rsa_encrypt(data):
    """RSA 加密"""
    if not data:
        return ""
    try:
        public_key = serialization.load_pem_public_key(RSA_PUBLIC_KEY.encode())
        chunk_size = 117  # 1024位公钥 PKCS1 最大块
        data_bytes = data.encode('utf-8')
        output = b""
        for i in range(0, len(data_bytes), chunk_size):
            chunk = data_bytes[i:i + chunk_size]
            encrypted = public_key.encrypt(chunk, asym_padding.PKCS1v15())
            output += encrypted
        return base64.b64encode(output).decode('utf-8')
    except Exception:
        return ""


# ==========================================
# 生成随机 deviceId
# ==========================================
def generate_device_id():
    return binascii.hexlify(os.urandom(16)).decode('utf-8')


# ==========================================
# 生成随机 appid
# ==========================================
def generate_appid():
    def rnd():
        return str(int.from_bytes(os.urandom(1), 'big') % 10)
    return (
        rnd() + "f" + rnd() + "af" +
        rnd() + rnd() + "ad" +
        rnd() + "912d306b5053abf90c7ebbb695887bc" +
        "870ae0706d573c348539c26c5c0a878641fcc0d3e90acb9be1e6ef858a" +
        "59af546f3c826988332376b7d18c8ea2398ee3a9c3db947e2471d32a49612"
    )


# ==========================================
# HTTP 请求
# ==========================================
def _post_form(url, data, ua):
    """发送 form-urlencoded POST 请求"""
    headers = {
        "Host": "m.client.10010.com",
        "User-Agent": ua,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Requested-With": "com.sinovatech.unicom.ui"
    }
    try:
        res = requests.post(url, data=data, headers=headers, timeout=15, verify=False)
        return res.json()
    except requests.exceptions.JSONDecodeError:
        return {"code": "Err", "msg": "HTML 响应(IP 可能被风控)"}
    except Exception as e:
        return {"code": "Err", "msg": f"请求异常: {e}"}


def _post_json(url, data, extra_headers=None):
    """发送 JSON POST 请求"""
    headers = {
        "Content-Type": "application/json",
        "X-Requested-With": "com.sinovatech.unicom.ui"
    }
    if extra_headers:
        headers.update(extra_headers)
    try:
        res = requests.post(url, json=data, headers=headers, timeout=15, verify=False)
        return res.json()
    except requests.exceptions.JSONDecodeError:
        return {"code": "Err", "msg": "HTML 响应(IP 可能被风控)"}
    except Exception as e:
        return {"code": "Err", "msg": f"请求异常: {e}"}


# ==========================================
# 发送验证码
# ==========================================
def send_code(phone, appid, device_id, result_token=""):
    """
    发送短信验证码
    返回: {"status": "success"|"fail"|"need_captcha", ...}
    """
    if not appid or len(appid) < 20:
        appid = DEFAULT_APPID

    ua = UA_TEMPLATE.format(phone=phone)
    timestamp = time.strftime("%Y%m%d%H%M%S")

    mobile_encrypted = rsa_encrypt(phone)
    rt = result_token if result_token else ""

    post_data = (
        f"isFirstInstall=1&simCount=1&yw_code=&deviceOS=android13"
        f"&mobile={requests.utils.quote(mobile_encrypted)}"
        f"&netWay=Wifi&loginCodeLen=6"
        f"&deviceId={device_id}&deviceCode={device_id}"
        f"&version=android@11.0800&send_flag="
        f"&resultToken={requests.utils.quote(rt)}"
        f"&keyVersion=&provinceChanel=general"
        f"&appId={appid}&deviceModel=M2007J3SC"
        f"&androidId={device_id[:16]}&deviceBrand=Xiaomi"
        f"&timestamp={timestamp}"
    )

    url = "https://m.client.10010.com/mobileService/sendRadomNum.htm"
    res = _post_form(url, post_data, ua)

    # 判断是否成功
    ok = False
    code = str(res.get("code", ""))
    rsp_code = str(res.get("rsp_code", ""))
    status = str(res.get("status", ""))

    if code in ("0", "0000"):
        ok = True
    if rsp_code == "0000":
        ok = True
    if status == "success":
        ok = True

    if ok:
        return {"status": "success", "msg": res.get("msg", "验证码已发送")}

    # 判断是否需要验证码
    dsc = res.get("dsc", "") or res.get("rsp_desc", "") or res.get("desc", "")
    need_captcha = False
    if code in ("ECS99998", "ECS99999"):
        need_captcha = True
    if "ECS1164" in dsc:
        need_captcha = True

    if need_captcha:
        return {
            "status": "need_captcha",
            "msg": dsc or "需要安全验证",
            "mobile": res.get("mobile", "")
        }

    msg = res.get("msg", "") or res.get("desc", "") or res.get("rsp_desc", "") or "发送失败"
    return {"status": "fail", "msg": f"发送失败: {msg}"}


# ==========================================
# 腾讯验证码校验
# ==========================================
def validate_tencent_captcha(mobile_hex, ticket, rand_str, phone, appid, device_id):
    """
    校验腾讯验证码
    返回: {"status": "success"|"fail", "resultToken": "...", ...}
    """
    if not appid or len(appid) < 20:
        appid = DEFAULT_APPID

    ua = UA_TEMPLATE.format(phone=phone)

    url = "https://loginxhm.10010.com/login-web/v1/chartCaptcha/validateTencentCaptcha"
    payload = {
        "seq": binascii.hexlify(os.urandom(16)).decode(),
        "captchaType": "10",
        "mobile": mobile_hex,
        "ticket": ticket,
        "randStr": rand_str,
        "imei": device_id
    }
    extra_headers = {
        "Origin": "https://img.client.10010.com",
        "Referer": "https://img.client.10010.com/loginRisk/index.html"
    }

    res = _post_json(url, payload, extra_headers)

    if str(res.get("code", "")) == "0000":
        token = ""
        data = res.get("data", {})
        if isinstance(data, dict):
            token = data.get("resultToken", "")
        return {"status": "success", "resultToken": token}

    msg = res.get("msg", "") or res.get("dsc", "") or res.get("desc", "") or "校验失败"
    return {"status": "fail", "msg": msg}


# ==========================================
# 短信验证码登录
# ==========================================
def sms_login(phone, code, appid, device_id):
    """
    使用短信验证码登录
    返回: {"status": "success"|"fail", "token_online": "...", "ecs_token": "...", ...}
    """
    if not appid or len(appid) < 20:
        appid = DEFAULT_APPID

    ua = UA_TEMPLATE.format(phone=phone)
    timestamp = time.strftime("%Y%m%d%H%M%S")

    mobile_encrypted = rsa_encrypt(phone)
    code_encrypted = rsa_encrypt(code)

    post_data = (
        f"isFirstInstall=1&simCount=1&yw_code=&loginStyle=0&isRemberPwd=true"
        f"&deviceOS=android13"
        f"&mobile={requests.utils.quote(mobile_encrypted)}"
        f"&netWay=Wifi&version=android@11.0800"
        f"&deviceId={device_id}"
        f"&password={requests.utils.quote(code_encrypted)}"
        f"&keyVersion=&provinceChanel=general"
        f"&appId={appid}&deviceModel=M2007J3SC"
        f"&androidId={device_id[:16]}&deviceBrand=Xiaomi"
        f"&timestamp={timestamp}"
    )

    url = "https://m.client.10010.com/mobileService/radomLogin.htm"
    res = _post_form(url, post_data, ua)

    code_val = str(res.get("code", ""))
    if code_val in ("0", "0000"):
        token_online = res.get("token_online", "")
        ecs_token = res.get("ecs_token", "")
        return {
            "status": "success",
            "token_online": token_online,
            "ecs_token": ecs_token,
            "appid": appid,
            "msg": "登录成功"
        }

    desc = res.get("desc", "") or "未知错误"
    return {
        "status": "fail",
        "msg": f"登录失败: {desc} [Code:{code_val}]"
    }
