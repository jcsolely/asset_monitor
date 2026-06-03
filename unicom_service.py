# -*- coding: utf-8 -*-
import time
import requests
import urllib3
urllib3.disable_warnings()


# ==========================================
# 后端核心业务逻辑
# ==========================================
class UserService:
    def __init__(self, token, cached_cookies=None, user_id=None):
        self.session = requests.Session()
        self.session.verify = False
        self.token = token
        self.user_id = user_id
        self._session_ready = False
        self._login_info = None
        self.session.headers.update({
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; Mi 10 Pro MIUI/21.11.3);unicom{version:android@11.0802}",
            "Referer": "https://m.client.10010.com/",
            "Connection": "keep-alive"
        })
        if cached_cookies and isinstance(cached_cookies, dict):
            for name, value in cached_cookies.items():
                self.session.cookies.set(name, value, domain='.10010.com')
            self._session_ready = True

    # ========== 通用工具 ==========

    @staticmethod
    def _safe_float(v):
        return float(v) if v else 0.0

    def _raw_request(self, method, url, **kwargs):
        try:
            return self.session.request(method, url, timeout=10, **kwargs)
        except Exception:
            return None

    def _parse_vice_cards(self, detail):
        """解析主副卡使用情况"""
        cards = []
        for vc in detail.get('viceCardlist', []):
            if isinstance(vc, dict):
                cards.append({
                    "usernumber": vc.get('usernumber', ''),
                    "use": self._safe_float(vc.get('use', 0)),
                    "isMainCard": vc.get('viceCardflag') == '1',
                    "isCurrentLogin": vc.get('currentLoginFlag') == '1'
                })
        cards.sort(key=lambda x: not x['isMainCard'])
        return cards

    def _parse_details(self, details, default_name, with_vice=True, with_total=True):
        """解析详情列表，统一输出字段"""
        result = []
        for d in details:
            obj = {
                "code": str(d.get('feePolicyId', d.get('code', ''))),
                "name": str(d.get('feePolicyName', d.get('name', default_name))),
                "use": self._safe_float(d.get('use', 0)),
                "remain": self._safe_float(d.get('remain', 0)),
            }
            if with_total:
                obj["total"] = self._safe_float(d.get('total', 0))
            if with_vice:
                obj["viceCardlist"] = self._parse_vice_cards(d)
            result.append(obj)
        return result

    # ========== 会话管理 ==========

    def _establish_session(self):
        if self._session_ready:
            return self._login_info or True
        if not self.token:
            return False
        url = "https://m.client.10010.com/mobileService/onLine.htm"
        data = {
            'isFirstInstall': '1',
            'netWay': 'Wifi',
            'version': 'android@11.0000',
            'token_online': self.token,
            'provinceChanel': 'general',
            'deviceModel': 'ALN-AL10',
            'step': 'dingshi',
            'androidId': '291a7deb1d716b5a',
            'reqtime': int(time.time() * 1000)
        }
        res = self._raw_request('post', url, data=data)
        if not res:
            return False
        result = res.json()
        code = result.get('code')
        if code == '0' or code == 0:
            self._session_ready = True
            self._cookies = self.session.cookies.get_dict()
            self._login_info = {
                "mobile": result.get('desmobile', ''),
                "ecs_token": result.get('ecs_token', ''),
                "t3_token": result.get('t3_token', ''),
                "private_token": result.get('private_token', ''),
                "token_online": result.get('token_online', ''),
                "cookies": self._cookies
            }
            return self._login_info
        else:
            print(f"登录失败[{code}]: {result.get('dsc', '未知错误')}")
            return False

    def refresh_session(self):
        """强制刷新会话（Cookie失效时调用）"""
        self._session_ready = False
        self._login_info = None
        self.session.cookies.clear()
        return self._establish_session()

    def request(self, method, url, **kwargs):
        if not self._session_ready:
            self._establish_session()
        return self._raw_request(method, url, **kwargs)

    def ensure_login(self):
        return self._establish_session()

    # ========== 数据获取 ==========

    def get_remain_data(self):
        """获取话费余额及套餐详情"""
        url = "https://m.client.10010.com/servicequerybusiness/balancenew/accountBalancenew.htm"
        res = self.request("get", url)
        data = {
            "success": False, "query_time": '',
            "balance": "0.00", "fee": "0.00", "packages": []
        }
        if not (res and res.status_code == 200):
            return data
        try:
            result = res.json()
            if result.get('code') != '0000':
                return data
            data["success"] = True
            data['query_time'] = result.get('queryTime', time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            data['balance'] = result.get('curntbalancecust', '0.00')
            data['fee'] = result.get('realfeecust', '0.00')
            for item in result.get('realTimeFeeSpecialFlagThree', []):
                for sub in item.get('subItems', []):
                    bill = sub.get('bill', {})
                    if bill:
                        data['packages'].append({
                            "name": bill.get('integrateitem', '未知项'),
                            "price": float(bill.get('price', 0)),
                            "adiscnt": float(bill.get('adiscnt', 0)),
                            "realfee": float(bill.get('realfee', 0))
                        })
        except Exception as e:
            print(f"解析话费数据异常: {e}")
        return data

    def get_orders_data(self):
        """获取已订业务信息"""
        url = "https://m.client.10010.com/servicebusiness/newOrdered/queryOrderRelationship"
        res = self.request("post", url, data={"reqtime": int(time.time() * 1000)})
        data = {
            "success": False, "query_time": '',
            "main_product": {}, "value_added": [],
            "flow_products": [], "services": []
        }
        if not (res and res.status_code == 200):
            return data
        try:
            result = res.json()
            if result.get('code') != '0000':
                return data
            data["success"] = True
            rd = result.get('data', {})
            data["query_time"] = rd.get('queryTime', '').replace('/', '-')

            main_list = rd.get('mainProductInfo', [])
            if main_list:
                main = main_list[0]
                data["main_product"] = {
                    "name": main.get('productName', ''),
                    "start_date": main.get('startDate', ''),
                    "end_date": main.get('endDate', '')
                }

            for item in rd.get('valueAdded', []):
                data["value_added"].append({
                    "name": item.get('productName', ''),
                    "fee": item.get('productFee', ''),
                    "start_date": item.get('startDate', ''),
                    "end_date": item.get('endDate', '')
                })

            for item in rd.get('liuLiangProductInfo', []):
                discnt_list = item.get('discntInfo', [])
                discnt_name = discnt_list[0].get('discntName', '') if discnt_list else ''
                data["flow_products"].append({
                    "name": discnt_name or item.get('packageName', ''),
                    "package": item.get('packageName', ''),
                    "product": item.get('productName', ''),
                    "start_date": item.get('startDate', ''),
                    "end_date": item.get('endDate', '')
                })

            for item in rd.get('serviceinfo', []):
                data["services"].append({
                    "name": item.get('servicename', ''),
                    "package": item.get('packagename', ''),
                    "product": item.get('productname', ''),
                    "time": item.get('completedateFmt', '')
                })
        except Exception as e:
            print(f"解析已订业务数据异常: {e}")
        return data

    def get_flow_data(self):
        """获取流量、语音、短信资产数据"""
        url = "https://m.client.10010.com/servicequerybusiness/operationservice/queryOcsPackageFlowLeftContentRevisedInJune"
        res = self.request("post", url, data={"reqtime": int(time.time() * 1000)})
        data = {
            "success": False, "query_time": '',
            "flow": {"shared": {"used": 0.0, "total": 0.0, "details": []}, "unshared": {"used": 0.0, "total": 0.0, "details": []}, "free": {"used": 0.0, "details": []}},
            "voice": {"shared": {"used": 0.0, "total": 0.0, "details": []}, "unshared": {"used": 0.0, "total": 0.0, "details": []}},
            "sms": {"shared": {"used": 0.0, "total": 0.0, "details": []}, "unshared": {"used": 0.0, "total": 0.0, "details": []}}
        }
        if not (res and res.status_code == 200):
            return data
        try:
            result = res.json()
        except:
            return data
        if result == 999999 or result.get('code') != '0000':
            return data

        data["success"] = True
        data["query_time"] = result.get('time', time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

        # ===== 共享流量 =====
        share = result.get('shareData', {}).get('details', [])
        shared_details = self._parse_details(share, '流量包')
        data["flow"]["shared"]["details"] = shared_details
        data["flow"]["shared"]["used"] = sum(d['use'] for d in shared_details)
        data["flow"]["shared"]["total"] = sum(d['total'] for d in shared_details)

        # ===== 公免流量 =====
        ml_res = result.get('MlResources', [])
        if isinstance(ml_res, list) and ml_res:
            free_details = self._parse_details(ml_res[0].get('details', []), '公免流量', with_vice=False, with_total=False)
            data["flow"]["free"]["details"] = free_details
            data["flow"]["free"]["used"] = sum(d['use'] for d in free_details)

        # ===== 语音/短信共享 =====
        RESOURCE_MAP = {
            'Voice': ('voice', '语音包'),
            'smsList': ('sms', '短信包'),
        }
        for res_item in result.get('resources', []):
            if not isinstance(res_item, dict):
                continue
            mapping = RESOURCE_MAP.get(res_item.get('type'))
            if not mapping:
                continue
            cat, default_name = mapping
            u = self._safe_float(res_item.get('userResource'))
            r = self._safe_float(res_item.get('remainResource'))
            data[cat]["shared"]["used"] = u
            data[cat]["shared"]["total"] = u + r
            data[cat]["shared"]["details"] = self._parse_details(res_item.get('details', []), default_name)

        # ===== 不共享资源 =====
        UNSHARED_MAP = {
            'unsharedFlowList': ('flow', '流量包'),
            'unsharedVoiceList': ('voice', '语音包'),
            'unsharedSmsList': ('sms', '短信包'),
        }
        for item in result.get('unshared', []):
            mapping = UNSHARED_MAP.get(item.get('type'))
            if not mapping:
                continue
            cat, default_name = mapping
            for detail in item.get('details', []):
                u = self._safe_float(detail.get('use', 0))
                r = self._safe_float(detail.get('remain', 0))
                t = self._safe_float(detail.get('total', 0))
                if u > 0 or r > 0 or t > 0:
                    data[cat]["unshared"]["details"].append({
                        "code": str(detail.get('feePolicyId', detail.get('code', ''))),
                        "name": str(detail.get('feePolicyName', detail.get('name', default_name))),
                        "use": u, "remain": r, "total": t
                    })
                    data[cat]["unshared"]["used"] += u
                    data[cat]["unshared"]["total"] += t

        # ===== 用量监控数据 =====
        direct_flow = general_flow = free_flow = 0.0
        for item in result.get('flowSumList', []):
            xv = self._safe_float(item.get('xusedvalue', 0))
            if str(item.get('flowtype', '')) == '2':
                direct_flow += xv
            else:
                general_flow += xv
        for ml in result.get('MlResources', []):
            for d in ml.get('details', []):
                free_flow += self._safe_float(d.get('use', 0))

        last_data = {"direct_flow": 0, "general_flow": 0, "free_flow": 0, "time": ""}
        if self.user_id:
            try:
                from database import get_monitor_last
                last_data = get_monitor_last(self.user_id)
            except Exception:
                pass

        data["monitor"] = {
            "current": {
                "direct_flow": round(direct_flow, 2),
                "general_flow": round(general_flow, 2),
                "free_flow": round(free_flow, 2),
                "time": data["query_time"]
            },
            "last": last_data
        }
        return data

    def get_speed_data(self):
        """获取5G速率信息"""
        url = "https://m.client.10010.com/servicebusiness/query/fiveg/getbasicdata"
        res = self.request("post", url, data={"reqtime": int(time.time() * 1000)})
        data = {
            "success": False, "query_time": '',
            "speed": {"rate": "", "package_name": "", "corner": "", "network_state": ""}
        }
        if not (res and res.status_code == 200):
            return data
        try:
            result = res.json()
            if result.get('code') != '0000':
                return data
            data["success"] = True
            data["query_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            rate_info = result.get('rateResource', {})
            data["speed"]["rate"] = rate_info.get('rate', '')
            data["speed"]["package_name"] = rate_info.get('packageName', '')
            data["speed"]["corner"] = rate_info.get('corner', '')
            data["speed"]["network_state"] = result.get('networkSwitchResource', {}).get('state', '')
        except Exception as e:
            print(f"解析速率数据异常: {e}")
        return data

    def get_prize_data(self):
        """获取兑换记录"""
        url = "https://act.10010.com/SigninApp/convert/phoneDetails"
        res = self.request("post", url, data={"log_type": "1", "number": "1", "list_num": ""},
                          headers={"Origin": "https://img.client.10010.com"})
        data = {"success": False, "query_time": '', "data": []}
        if not (res and res.status_code == 200):
            return data
        try:
            result = res.json()
            if result.get('status') != '0000':
                return data
            data["success"] = True
            data["query_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            count = 0
            for item in result.get('data', {}).get('detailedBO', []):
                if count >= 5:
                    break
                remark = item.get('remark', '')
                buss_name = item.get('from_bussname', '')
                if "兑换" in remark or "兑换" in buss_name:
                    data["data"].append({
                        "time": item.get('order_time', ''),
                        "remark": remark,
                        "amount": item.get('booksNumber') or item.get('books_number') or "0"
                    })
                    count += 1
        except:
            pass
        return data
