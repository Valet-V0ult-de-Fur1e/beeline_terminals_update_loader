import json
import os
import requests 
from datetime import datetime

class TerminalInterface:
    def __init__(self, local_url, api_url, device_id, terminal_login, password, log_dir="./logs"):
        self.url = local_url
        self.device_id = device_id
        self.terminal_login = terminal_login
        self.password = password
        self.api_url = api_url
        self.access_token = None
        self.refresh_token = None
        self.log_dir = log_dir
        self.session = requests.Session() 
        os.makedirs(self.log_dir, exist_ok=True)
        
    def _log_request(self, method, url, headers=None, json_data=None, files=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] {method} {url}\n"
        if headers:
            log_entry += f"Headers: {headers}\n"
        if json_data:
            log_entry += f"JSON Data: {json_data}\n"
        if files:
            log_entry += f"Files: {[f for f in files.keys()]}\n"
        log_entry += "-" * 50 + "\n"
        return log_entry
    
    def _log_response(self, response):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] Response Status: {response.status_code}\n"
        log_entry += f"Response Headers: {dict(response.headers)}\n"
        try:
            response_json = response.json()
            log_entry += f"Response JSON: {json.dumps(response_json, ensure_ascii=False, indent=2)}\n"
        except json.JSONDecodeError:
            log_entry += f"Response Text: {response.text}\n"
            log_entry += f"Response Content Length: {len(response.content)} bytes\n"
        log_entry += "=" * 70 + "\n"
        return log_entry
    
    def _make_request(self, method, endpoint, headers=None, json_data=None, files=None, params=None):
        url = f"{self.url}{endpoint}" if not endpoint.startswith(('http://', 'https://')) else endpoint
        request_log = self._log_request(method, url, headers, json_data, files)
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                files=files,
                params=params,
                timeout=30
            )
            response_log = self._log_response(response)
            log_filename = os.path.join(self.log_dir, f"terminal_{self.device_id}_log.txt")
            with open(log_filename, 'a', encoding='utf-8') as log_file:
                log_file.write(request_log)
                log_file.write(response_log)
            return response
        except requests.exceptions.RequestException as e:
            error_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            error_log = f"[{error_timestamp}] Request failed: {str(e)}\n"
            error_log += "=" * 70 + "\n"
            log_filename = os.path.join(self.log_dir, f"terminal_{self.device_id}_log.txt")
            with open(log_filename, 'a', encoding='utf-8') as log_file:
                log_file.write(error_log)
            raise e
        
    def check_health(self):
        try:
            response = self._make_request("GET", f"{self.api_url}/health_check")
            if 200 <= response.status_code < 300:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    if response.status_code == 200:
                        return {}
                    else:
                        return None
            else:
                return None
        except Exception as e:
            print(f"Health check failed: {e}")
            return None
        
    def login(self):
        try:
            response = self._make_request("POST", "/auth/login", 
                                        json_data={"username": self.terminal_login, "password": self.password})
            data = response.json()
            if 'access_token' in data.keys():
                self.access_token = data['access_token']
            if 'refresh_token' in data.keys():
                self.refresh_token = data['refresh_token']
            print(f"Login response: {data}")
            return data
        except Exception as e:
            print(f"Login failed: {e}")
            return None
        
    def refresh_token(self):
        try:
            headers = {"Authorization": self.refresh_token} if self.refresh_token else {}
            response = self._make_request("POST", "/auth/refresh", 
                                        headers=headers, 
                                        json_data={"device_id": self.device_id})
            data = response.json()
            if 'access_token' in data.keys():
                self.access_token = data['access_token']
            print(f"Refresh token response: {data}")
            return data
        except Exception as e:
            print(f"Token refresh failed: {e}")
            return None
        
    def _get_auth_headers(self):
        if self.access_token:
            return {"Authorization": self.access_token}
        return {}
    
    def _safe_json_response(self, response, operation_name):
        try:
            result = response.json()
            print(f"{operation_name} response: {result}")
            return result
        except json.JSONDecodeError:
            print(f"{operation_name} raw response: {response.text}")
            print(f"Status code: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            return {"raw_response": response.text, "status_code": response.status_code, "headers": dict(response.headers)}
        
    def set_pipeline_out_control_settings(self, logo_stand_by_file_path, logo_file_path):
        headers = self._get_auth_headers()
        try:
            print("Starting pipeline settings configuration...")
            response1 = self._make_request(
                "POST",
                "/pipelineomini/remote_transaction", 
                headers=headers, 
                json_data={"enabled": True, "deviceName": self.device_id, "deviceNameIsHostName": True, "pingUrl": "", "timePing": 5}
            )
            self._safe_json_response(response1, "Remote transaction")
            with open(logo_file_path, 'rb') as f:
                response2 = self._make_request(
                    "POST",
                    "/pipelineomini/installassets/waiting", 
                    headers=headers, 
                    files={'file': f}
                )
                self._safe_json_response(response2, "Waiting logo upload")
            with open(logo_stand_by_file_path, 'rb') as f:
                response3 = self._make_request(
                    "POST",
                    "/pipelineomini/installassets/standby", 
                    headers=headers, 
                    files={'file': f}
                )
                self._safe_json_response(response3, "Standby logo upload")
            print("Pipeline settings configuration completed.")
            return True
        except Exception as e:
            print(f"Pipeline settings failed: {e}")
            return False
        
    def set_terminal_files(self, file_path):
        headers = self._get_auth_headers()
        try:
            print(f"Installing package from {file_path}...")
            with open(file_path, 'rb') as f:
                response1 = self._make_request(
                    "POST",
                    "/system/packages/manual_install", 
                    headers=headers, 
                    files={'file': f}
                )
                self._safe_json_response(response1, "Package install")
            print("Getting installed packages list...")
            response2 = self._make_request(
                "GET",
                "/system/packages/installed", 
                headers=headers
            )
            self._safe_json_response(response2, "Installed packages")
            return True
        except Exception as e:
            print(f"Terminal files failed: {e}")
            return False
        
    def configure_crypto_tunnel(self, stage="prod", tls_mode="one-way"):
        headers = self._get_auth_headers()
        config_data = {"stage": stage, "tls_mode": tls_mode}
        print(f"Configuring crypto tunnel with: {config_data}")
        try:
            response = self._make_request(
                "POST",
                "/security/cryptotunnel_conf",
                headers=headers,
                json_data=config_data
            )
            self._safe_json_response(response, "Crypto tunnel configuration")
            return response.json()
        except Exception as e:
            print(f"Crypto tunnel configuration failed: {e}")
            return None
        
    def upload_crypto_tunnel_cert(self, cert_file_path, cert_type="ca", stage="test"):
        headers = self._get_auth_headers()
        print(f"Uploading crypto tunnel certificate from {cert_file_path} (type: {cert_type}, stage: {stage})")
        try:
            with open(cert_file_path, 'rb') as f:
                response = self._make_request(
                    "POST",
                    "/security/cryptotunnel_cert",
                    headers=headers,
                    files={'file': f},
                    params={'cert_type': cert_type, 'stage': stage}
                )
                self._safe_json_response(response, "Crypto tunnel certificate upload")
                return response.json()
        except Exception as e:
            print(f"Crypto tunnel certificate upload failed: {e}")
            return None
        
    def generate_openvpn_cert_request(self, common_name, city, org_name):
        headers = self._get_auth_headers()
        params = {
            'common_name': common_name,
            'city': city,
            'org_name': org_name
        }
        print(f"Generating OpenVPN certificate request with params: {params}")
        try:
            response = self._make_request(
                "GET",
                "/security/openvpn_cert_req",
                headers=headers,
                params=params
            )
            print(f"OpenVPN cert request status code: {response.status_code}")
            print(f"Content-Type: {response.headers.get('content-type')}")
            print(f"Content-Disposition: {response.headers.get('content-disposition')}")
            if response.status_code == 200 and response.headers.get('content-type', '').startswith('application/'):
                filename = f"{common_name}.csr"
                with open(filename, 'wb') as f:
                    f.write(response.content)
                print(f"Certificate request saved as {filename}")
                print(f"Downloaded {len(response.content)} bytes")
                return {"status": "success", "filename": filename, "content_type": response.headers.get('content-type')}
            else:
                print(f"OpenVPN certificate request response: {response.text}")
                print(f"Status code: {response.status_code}")
                return {"status": "error", "status_code": response.status_code, "response": response.text}
        except Exception as e:
            print(f"OpenVPN certificate request failed: {e}")
            return None
        
    def upload_openvpn_cert(self, cert_file_path, is_ca=True):
        headers = self._get_auth_headers()
        print(f"Uploading OpenVPN certificate from {cert_file_path} (is_ca: {is_ca})")
        try:
            with open(cert_file_path, 'rb') as f:
                response = self._make_request(
                    "POST",
                    "/security/openvpn_cert",
                    headers=headers,
                    files={'file': f},
                    params={'is_ca': str(is_ca).lower()}
                )
                self._safe_json_response(response, "OpenVPN certificate upload")
                return response.json()
        except Exception as e:
            print(f"OpenVPN certificate upload failed: {e}")
            return None
        
    def configure_openvpn(self, addresses, tun_mtu=1500, protocol="tcp", crl_verify=False):
        headers = self._get_auth_headers()
        config = {
            "addresses": addresses,
            "tun_mtu": tun_mtu,
            "protocol": protocol,
            "crl_verify": crl_verify
        }
        print(f"Configuring OpenVPN with: {config}")
        try:
            response = self._make_request(
                "POST",
                "/security/openvpn_conf",
                headers=headers,
                json_data=config
            )
            self._safe_json_response(response, "OpenVPN configuration")
            return response.json()
        except Exception as e:
            print(f"OpenVPN configuration failed: {e}")
            return None
        
    def upload_openvpn_crl(self, crl_file_path):
        headers = self._get_auth_headers()
        print(f"Uploading OpenVPN CRL from {crl_file_path}")
        try:
            with open(crl_file_path, 'rb') as f:
                response = self._make_request(
                    "POST",
                    "/security/openvpn_crl",
                    headers=headers,
                    files={'file': f}
                )
                if response.status_code == 200 and len(response.content) == 0:
                    print("OpenVPN CRL upload response: Success (empty response)")
                    return {"status": "success", "message": "CRL uploaded successfully"}
                else:
                    self._safe_json_response(response, "OpenVPN CRL upload")
                    return response.json()
        except Exception as e:
            print(f"OpenVPN CRL upload failed: {e}")
            return None
        
    def start_openvpn(self):
        headers = self._get_auth_headers()
        print("Starting OpenVPN service...")
        try:
            response = self._make_request("GET", "/security/openvpn_start", headers=headers)
            self._safe_json_response(response, "OpenVPN start")
            return response.json()
        except Exception as e:
            print(f"OpenVPN start failed: {e}")
            return None
        