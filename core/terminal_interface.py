# core/terminal_interface.py
import json
import os
import requests 
from datetime import datetime

class TerminalInterface:
    def __init__(self, device_id, password, terminal_login="cryptouser",
                 host_name="", common_name="", city="", org_name="",
                 primary_ip="", secondary_ip="", local_ip="",
                 pin_code="", timezone="", # Добавляем новые параметры
                 port=4011, health_port=7777, log_dir="./logs"):        # Основной порт для всех запросов
        self.port = port
        # Порт для health check
        self.health_port = health_port
        self.device_id = device_id
        self.terminal_login = terminal_login
        self.access_token = None
        self.refresh_token = None
        self.log_dir = log_dir
        self.session = requests.Session() 
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Поля из таблицы
        self.host_name = host_name
        self.common_name = common_name
        self.city = city
        self.org_name = org_name
        self.primary_ip = primary_ip      # IP №1 (основной)
        self.secondary_ip = secondary_ip  # IP №2 (резервный)
        self.local_ip = local_ip          # IP локальный (по умолчанию используется)
        self.password = password          # Пароль
        self.pin_code = pin_code          # Пин-код (новое поле)
        self.timezone = timezone          # Временная зона (новое поле)
        # Активный IP для запросов (по умолчанию — локальный)
        self.active_ip = local_ip

    def _get_base_url(self, use_health_port=False):
        """Возвращает текущий активный URL."""
        port = self.health_port if use_health_port else self.port
        return f"http://{self.active_ip}:{port}"

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

    def _make_request(self, method, endpoint, headers=None, json_data=None, files=None, params=None, use_health_port=False):
        # Используем активный IP и соответствующий порт для формирования URL
        url = f"{self._get_base_url(use_health_port=use_health_port)}{endpoint}" if not endpoint.startswith(('http://', 'https://')) else endpoint

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
            # health_check использует health_port (7777)
            response = self._make_request("GET", "/health_check", use_health_port=True)
            print(response.json())
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
            # print(f"Login response: {data}")
            return data
        except Exception as e:
            # print(f"Login failed: {e}")
            return None
    
    def set_password(self):
        try:
            response = self._make_request("POST", "/security/password",
                                        json_data={"password": self.password})
            data = response.json()
            if 'access_token' in data.keys():
                self.access_token = data['access_token']
            if 'refresh_token' in data.keys():
                self.refresh_token = data['refresh_token']
            print(f"Set password response: {data}")
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
            # print(f"Refresh token response: {data}")
            return data
        except Exception as e:
            # print(f"Token refresh failed: {e}")
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

    def set_pipeline_out_control_settings(self, logo_stand_by_file_path, logo_file_path, pingUrl="", timePing=5):
        headers = self._get_auth_headers()
        try:
            print("Starting pipeline settings configuration...")
            response1 = self._make_request(
                "POST",
                "/pipelineomini/remote_transaction",
                headers=headers,
                json_data={"enabled": True, "deviceName": self.device_id, "deviceNameIsHostName": True, "pingUrl": pingUrl, "timePing": timePing}
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
                files = {
                    'details': (None, '{"self_install":true}', 'application/json'),
                    'files[0]': (os.path.basename(file_path), f, 'application/x-gzip')
                }
                response1 = self._make_request(
                    "POST",
                    "/system/packages/manual_install",
                    headers=headers,
                    files=files
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

    def generate_openvpn_cert_request(self, common_name=None, city=None, org_name=None, output_folder="./cert_requests"):
        if common_name is None:
            common_name = self.common_name
        if city is None:
            city = self.city
        if org_name is None:
            org_name = self.org_name

        # Создаем папку если она не существует
        os.makedirs(output_folder, exist_ok=True)
        
        # Формируем имя файла
        filename = f"{common_name}.csr"
        filepath = os.path.join(output_folder, filename)
        
        # Проверяем, существует ли уже файл
        if os.path.exists(filepath):
            print(f"Certificate request already exists: {filepath}")
            return {"status": "exists", "filename": filepath, "message": "Certificate request already exists"}
        
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
                with open(filepath, 'wb') as f:
                    f.write(response.content)
                print(f"Certificate request saved as {filepath}")
                print(f"Downloaded {len(response.content)} bytes")
                return {"status": "success", "filename": filepath, "content_type": response.headers.get('content-type')}
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

    def configure_openvpn(self, addresses=None, tun_mtu=1500, protocol="tcp", crl_verify=False):
        if addresses is None:
            addresses = [self.primary_ip, self.secondary_ip]
            addresses = [ip for ip in addresses if ip]

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
                    # Try to parse as JSON first
                    try:
                        response_json = response.json()
                        # Check if it contains an error status
                        if 'status' in response_json and isinstance(response_json['status'], dict) and response_json['status'].get('code', 0) != 0:
                            print(f"OpenVPN CRL upload error: {response_json}")
                            return response_json  # Return the error response
                        else:
                            self._safe_json_response(response, "OpenVPN CRL upload")
                            return response_json
                    except json.JSONDecodeError:
                        # If it's not JSON, return the raw response
                        print(f"OpenVPN CRL upload response: {response.text}")
                        return {"status": "error", "message": response.text, "status_code": response.status_code}
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
    
    def reset_password_via_pin(self, pin):
        """Сброс пароля с использованием PIN-кода."""
        try:
            response = self._make_request("POST", "/security/reset_password",
                                        json_data={"pin": pin})
            # Проверяем статус код
            if response.status_code == 200:
                print(f"Password reset successfully for terminal {self.device_id}")
                return True
            else:
                print(f"Password reset failed for terminal {self.device_id} with status {response.status_code}")
                print(f"Response: {response.text}")
                return False
        except Exception as e:
            print(f"Error during password reset for terminal {self.device_id}: {e}")
            return False

    def set_datetime(self, datetime_str):
        headers = self._get_auth_headers()
        print(f"Setting datetime to: {datetime_str}")
        try:
            response = self._make_request(
                "POST",
                "/datetime",
                headers=headers,
                json_data={"dateTime": datetime_str}
            )
            # Handle empty response (204 No Content or 200 with empty body)
            if response.status_code in [200, 204] and len(response.content) == 0:
                print("Set datetime response: Success (empty response)")
                return {"status": "success", "message": "Datetime set successfully"}
            else:
                try:
                    response_json = response.json()
                    self._safe_json_response(response, "Set datetime")
                    return response_json
                except json.JSONDecodeError:
                    print(f"Set datetime raw response: {response.text}")
                    print(f"Status code: {response.status_code}")
                    return {"status": "error", "message": response.text, "status_code": response.status_code}
        except Exception as e:
            print(f"Set datetime failed: {e}")
            return None

    def set_datetime_settings(self, timezone="Europe/Moscow", primary_ntp_server="", secondary_ntp_server=""):
        headers = self._get_auth_headers()
        settings_data = {
            "timeZone": timezone,
            "primaryNTPServer": primary_ntp_server,
            "secondaryNTPServer": secondary_ntp_server
        }
        print(f"Setting datetime settings: {settings_data}")
        try:
            response = self._make_request(
                "POST",
                "/datetime/settings",
                headers=headers,
                json_data=settings_data
            )
            # Handle empty response (204 No Content or 200 with empty body)
            if response.status_code in [200, 204] and len(response.content) == 0:
                print("Set datetime settings response: Success (empty response)")
                return {"status": "success", "message": "Datetime settings set successfully"}
            else:
                try:
                    response_json = response.json()
                    self._safe_json_response(response, "Set datetime settings")
                    return response_json
                except json.JSONDecodeError:
                    print(f"Set datetime settings raw response: {response.text}")
                    print(f"Status code: {response.status_code}")
                    return {"status": "error", "message": response.text, "status_code": response.status_code}
        except Exception as e:
            print(f"Set datetime settings failed: {e}")
            return None

    # ========== МЕТОДЫ ПЕРЕКЛЮЧЕНИЯ IP ==========

    def set_active_ip(self, ip_type="local"):
        """
        Устанавливает активный IP-адрес для выполнения запросов.
        Args:
            ip_type (str): "local", "primary", "secondary" или конкретный IP-адрес
        Returns:
            bool: Успешно ли установлен IP
        """
        print(f"IP type set to: {ip_type}")
        if ip_type == "local":
            self.active_ip = self.local_ip
        elif ip_type == "primary":
            self.active_ip = self.primary_ip
        elif ip_type == "secondary":
            self.active_ip = self.secondary_ip
        elif isinstance(ip_type, str) and ip_type.count('.') == 3:
            self.active_ip = ip_type
        else:
            print(f"Unknown IP type: {ip_type}. Use 'local', 'primary', 'secondary' or valid IP address.")
            return False

        print(f"Active IP set to: {self.active_ip}")
        return True

    def use_local_ip(self):
        """Переключается на локальный IP."""
        return self.set_active_ip("local")

    def use_primary_ip(self):
        """Переключается на основной IP."""
        return self.set_active_ip("primary")

    def use_secondary_ip(self):
        """Переключается на резервный IP."""
        return self.set_active_ip("secondary")

    def get_current_config(self):
        """Возвращает текущую конфигурацию терминала."""
        return {
            "host_name": self.host_name,
            "common_name": self.common_name,
            "city": self.city,
            "org_name": self.org_name,
            "primary_ip": self.primary_ip,
            "secondary_ip": self.secondary_ip,
            "local_ip": self.local_ip,
            "active_ip": self.active_ip,
            "port": self.port,
            "health_port": self.health_port,
            "device_id": self.device_id,
            "terminal_login": self.terminal_login,
            "password": self.password,
            "pin_code": self.pin_code, # Добавляем в конфиг
            "timezone": self.timezone  # Добавляем в конфиг
        }

    def update_from_table_row(self, row_dict):
        """
        Обновляет конфигурацию терминала из словаря, соответствующего строке таблицы.
        Args:
            row_dict (dict): Словарь с ключами: Host name, Common name, Город, Наименование организации,
                            IP № 1 (основной), IP № 2 (резервный), IP локальный, Пароль, Пин-код, Временная зона
        """
        mapping = {
            "Host name": "host_name",
            "Common name": "common_name",
            "Город": "city",
            "Наименование организации": "org_name",
            "IP № 1 (основной)": "primary_ip",
            "IP № 2 (резервный)": "secondary_ip",
            "IP локальный": "local_ip",
            "Пароль": "password",
            "Пин-код": "pin_code", # Добавляем маппинг для пин-кода
            "Временная зона": "timezone" # Добавляем маппинг для временной зоны
        }
        for table_key, attr_name in mapping.items():
            if table_key in row_dict:
                setattr(self, attr_name, row_dict[table_key])
        if "Host name" in row_dict:
            self.device_id = row_dict["Host name"]
            self.terminal_login = row_dict["Host name"]
        self.active_ip = self.local_ip
        print(f"Terminal {self.device_id} configuration updated from table row.")