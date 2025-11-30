# core/terminal_manager.py
import pandas as pd
from .terminal_interface import TerminalInterface
import threading
import time
import os
from datetime import datetime
from PySide6.QtCore import Signal, QObject

class TerminalManager(QObject):
    progress_updated = Signal(int, int)  # current, total
    
    def __init__(self, config_manager):
        super().__init__()
        self.terminals = []
        self.config_manager = config_manager
        self.terminal_table_widget = None  # Will be set from UI
        self.terminal_cert_mapping = {} # Словарь для хранения соответствия terminal_id -> cert_path

    def set_terminal_table_widget(self, terminal_table_widget):
        self.terminal_table_widget = terminal_table_widget
        
    def get_terminal_cert_path(self, terminal_id):
        """Возвращает путь к пользовательскому сертификату для терминала."""
        return self.terminal_cert_mapping.get(terminal_id)
    
    def match_certificates_from_folder(self, folder_path):
        if not os.path.isdir(folder_path):
            print(f"Invalid folder path: {folder_path}")
            return

        # Собираем все .crt и .pem файлы из папки
        cert_files = []
        for filename in os.listdir(folder_path):
            if filename.lower().endswith(('.crt', '.pem')):
                cert_files.append(filename)

        # Сопоставляем файлы с терминалами по common_name
        matched_count = 0
        for terminal in self.terminals:
            # Ищем файл, содержащий common_name (или host_name, если common_name пуст)
            target_name = terminal.common_name or terminal.host_name
            matched_file = None
            for cert_filename in cert_files:
                if target_name.lower() in cert_filename.lower():
                    matched_file = cert_filename
                    break

            if matched_file:
                full_cert_path = os.path.join(folder_path, matched_file)
                self.terminal_cert_mapping[terminal.device_id] = full_cert_path
                matched_count += 1
                print(f"Matched certificate {matched_file} for terminal {terminal.device_id} (common_name: {target_name})")
                # Обновляем таблицу, если виджет доступен
                if self.terminal_table_widget:
                    self.terminal_table_widget.update_user_cert_in_table(terminal, full_cert_path)
            else:
                print(f"No matching certificate found for terminal {terminal.device_id} (common_name: {target_name})")
                # Убираем старое сопоставление, если есть
                if terminal.device_id in self.terminal_cert_mapping:
                    del self.terminal_cert_mapping[terminal.device_id]

        print(f"Successfully matched {matched_count} certificates out of {len(self.terminals)} terminals.")
    
    
    def load_terminals_from_excel(self, file_path):
        df = pd.read_excel(file_path)
        self.terminals = []
        for _, row in df.iterrows():
            terminal = TerminalInterface(
                device_id=row['Host name'],
                password=row['Пароль'],
                host_name=row['Host name'],
                common_name=row['Common name'],
                city=row['Город'],
                org_name=row['Наименование организации'],
                primary_ip=row['IP № 1 (основной)'],
                secondary_ip=row['IP № 2 (резервный)'],
                local_ip=row['IP локальный'],
                pin_code=row.get('Пин-код', ''), # Используем .get() для безопасного получения значения
                timezone=row.get('Временная зона', '') # Используем .get() для безопасного получения значения
            )
            print(terminal)
            self.terminals.append(terminal)
    
    def apply_settings_to_terminals(self, terminals_with_rows, settings, tab_name):
        total_terminals = len(terminals_with_rows)
        completed_count = 0

        # Start all terminals in parallel
        threads = []
        for i, (terminal, row_index) in enumerate(terminals_with_rows):
            thread = threading.Thread(
                target=self.apply_settings_to_terminal,
                args=(terminal, settings, row_index, tab_name, total_terminals)
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            # Update progress after each thread completes
            completed_count += 1
            self.progress_updated.emit(completed_count, total_terminals)
    
    def apply_settings_to_terminal(self, terminal, settings, row_index, tab_name, total_terminals):
        try:
            # Update status based on tab name
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(row_index, f"Applying {tab_name} settings...")

            # Apply settings based on active tab
            success = False
            if tab_name.lower() == "registration_reset_password":
                success = self.apply_reset_password_settings(terminal, settings, row_index)
            elif tab_name.lower() == "registration_set_password":
                success = self.apply_set_password_settings(terminal, settings, row_index)
            elif tab_name.lower() == "pipeline":
                success = self.apply_pipeline_settings(terminal, settings, row_index)
            elif tab_name.lower() == "tls":
                success = self.apply_tls_settings(terminal, settings, row_index)
            elif tab_name.lower() == "firmware":
                success = self.apply_firmware_settings(terminal, settings, row_index)
            elif tab_name.lower() == "openvpn":
                success = self.apply_openvpn_settings(terminal, settings, row_index)
            elif tab_name.lower() == "crl":
                success = self.apply_crl_settings(terminal, settings, row_index)
            elif tab_name.lower() == "cert request":
                success = self.apply_cert_request_settings(terminal, settings, row_index)
            elif tab_name.lower() == "server cert":
                success = self.apply_server_cert_settings(terminal, settings, row_index)
            elif tab_name.lower() == "client cert":
                success = self.apply_client_cert_settings(terminal, settings, row_index)
            elif tab_name.lower() == "datetime":
                success = self.apply_datetime_settings(terminal, settings, row_index)
            elif tab_name.lower() == "openvpn_start":
                success = self.open_vpn_start(terminal, settings, row_index)

            # Update status to completed or error based on success
            if success:
                if self.terminal_table_widget:
                    self.terminal_table_widget.update_terminal_status(row_index, f"{tab_name} completed")
            else:
                if self.terminal_table_widget:
                    self.terminal_table_widget.update_terminal_status(row_index, f"{tab_name} failed")
        except Exception as e:
            print(f"Error applying {tab_name} settings to terminal {terminal.device_id}: {e}")
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(row_index, f"Error: {str(e)}")

    def apply_reset_password_settings(self, terminal, settings, row_index):
        """Применяет настройки сброса пароля через PIN."""
        try:
            # Вызываем метод интерфейса
            success = terminal.reset_password_via_pin(terminal.pin_code)
            return success
        except Exception as e:
            print(f"Error resetting password for terminal {terminal.device_id}: {e}")
            return False
    
    def open_vpn_start(self, terminal, settings, row_index):
        try:
            # Вызываем метод интерфейса
            success = terminal.start_openvpn()
            return success
        except Exception as e:
            print(f"Error start open vpn for terminal {terminal.device_id}: {e}")
            return False

    def apply_set_password_settings(self, terminal, settings, row_index):
        """Применяет настройки установки пароля."""
        # Логика установки пароля аналогична apply_pipeline_settings
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            # Login
            login_result = terminal.login()
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            # Успешно установлен пароль
            return True
        except Exception as e:
            print(f"Set password failed for terminal {terminal.device_id}: {e}")
            return False

    def apply_pipeline_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Apply pipeline settings
            if settings.get('standby_logo_path') and settings.get('work_logo_path'):
                success = terminal.set_pipeline_out_control_settings(
                    settings['standby_logo_path'],
                    settings['work_logo_path']
                )
                return success
            else:
                return True  # No pipeline settings to apply, but operation was successful
        except Exception as e:
            print(f"Pipeline settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_tls_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Apply TLS settings
            success = True
            if settings.get('ebs_test_cert_path'):
                result = terminal.upload_crypto_tunnel_cert(
                    settings['ebs_test_cert_path'],
                    cert_type="ca",
                    stage="test"
                )
                if result is None:
                    success = False
            
            if settings.get('ebs_prod_cert_path'):
                result = terminal.upload_crypto_tunnel_cert(
                    settings['ebs_prod_cert_path'],
                    cert_type="ca",
                    stage="prod"
                )
                if result is None:
                    success = False
            
            if success:
                result = terminal.configure_crypto_tunnel(
                    stage=settings.get('tls_stage', 'prod'),
                    tls_mode=settings.get('tls_mode', 'one-way')
                )
                if result is None:
                    success = False
            
            return success
        except Exception as e:
            print(f"TLS settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_firmware_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Apply firmware update
            if settings.get('firmware_path'):
                success = terminal.set_terminal_files(settings['firmware_path'])
                return success
            else:
                return True  # No firmware to update, but operation was successful
        except Exception as e:
            print(f"Firmware settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_openvpn_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Apply OpenVPN settings
            if settings.get('ip_addresses'):
                addresses = [
                    {"ip": addr['ip'], "port": addr['port']}
                    for addr in settings['ip_addresses']
                ]
                result = terminal.configure_openvpn(addresses)
                return result is not None
            else:
                return True  # No OpenVPN settings to apply, but operation was successful
        except Exception as e:
            print(f"OpenVPN settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_crl_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Upload CRL
            if settings.get('crl_path'):
                result = terminal.upload_openvpn_crl(settings['crl_path'])
                
                # Check if result indicates success
                if result is None:
                    return False
                elif isinstance(result, dict):
                    # Check for error status in the response
                    if 'status' in result:
                        if isinstance(result['status'], dict) and result['status'].get('code', 0) != 0:
                            print(f"CRL upload failed for terminal {terminal.device_id}: {result['status'].get('message', 'Unknown error')}")
                            return False
                        elif result.get('status') == 'success':
                            return True
                        else:
                            # If status is a dict but no error code, consider it successful
                            return True
                    else:
                        # If no 'status' key, consider it successful
                        return True
                elif isinstance(result, str):
                    # If it's a string response (like success message), consider it successful
                    return True
                else:
                    # If result is not a dict or string, just check if it's truthy
                    return bool(result)
            else:
                return True  # No CRL to upload, but operation was successful
        except Exception as e:
            print(f"CRL settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_cert_request_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Generate certificate request with automatic folder creation
            if settings.get('output_folder'):
                result = terminal.generate_openvpn_cert_request(
                    output_folder=settings['output_folder']
                )
                
                # Check if result indicates success
                if result is None:
                    print(f"Certificate request failed for terminal {terminal.device_id}: No response")
                    return False
                elif isinstance(result, dict):
                    # Check for error status in the response
                    if result.get('status') == 'error':
                        print(f"Certificate request error for terminal {terminal.device_id}: {result.get('response', 'Unknown error')}")
                        return False
                    elif result.get('status') == 'exists':
                        # Certificate request already exists, which is not an error
                        print(f"Certificate request already exists for {terminal.common_name}")
                        return True
                    elif result.get('status') == 'success':
                        # Success case - CSR was downloaded
                        return True
                    else:
                        # Check if it's a 500 error or other error response
                        # If the terminal method returns an error response, it should be handled properly
                        if 'status_code' in result and result['status_code'] >= 400:
                            print(f"Certificate request failed for terminal {terminal.device_id}: HTTP {result['status_code']}")
                            return False
                        else:
                            # If no explicit status, assume success if filename exists
                            return 'filename' in result
                else:
                    # If result is not a dict, it's probably an error
                    print(f"Certificate request failed for terminal {terminal.device_id}: Unexpected response format")
                    return False
            else:
                return True  # No cert request to generate, but operation was successful
        except Exception as e:
            print(f"Certificate request settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_server_cert_settings(self, terminal, settings, row_index):
        try:
            # Set password first
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Login
            login_result = terminal.login()
            
            # Check if login was successful
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            
            # Upload server certificate
            if settings.get('server_cert_path'):
                result = terminal.upload_openvpn_cert(settings['server_cert_path'], is_ca=True)
                
                # Check if result indicates success
                if result is None:
                    print(f"Server certificate upload failed for terminal {terminal.device_id}: No response")
                    return False
                elif isinstance(result, dict):
                    # Check for error status in the response
                    if 'status' in result:
                        if isinstance(result['status'], dict):
                            status_code = result['status'].get('code', 0)
                            if status_code != 0:
                                message = result['status'].get('message', 'Unknown error')
                                print(f"Server certificate upload failed for terminal {terminal.device_id}: {message}")
                                return False
                            else:
                                # Status code 0 means success
                                return True
                        else:
                            # If status is not a dict, check if it contains success indicators
                            return True
                    else:
                        # If no 'status' key, consider it successful
                        return True
                else:
                    # If result is not a dict, just check if it's truthy
                    return bool(result)
            else:
                return True  # No server cert to upload, but operation was successful
        except Exception as e:
            print(f"Server cert settings failed for terminal {terminal.device_id}: {e}")
            return False
        
    def apply_client_cert_settings(self, terminal, settings, row_index):
        try:
            password_result = terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            login_result = terminal.login()
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False

            # Upload client certificate (is_ca=False)
            # Используем путь из сопоставления TerminalManager или атрибута терминала
            cert_path = self.get_terminal_cert_path(terminal.device_id)
            cert_path = os.path.normpath(cert_path)
            cert_path = cert_path.replace(os.path.sep, '/')
            if not cert_path and hasattr(terminal, 'user_cert_path') and terminal.user_cert_path:
                cert_path = terminal.user_cert_path

            if cert_path:
                print(f"Uploading client certificate {cert_path} for terminal {terminal.device_id}")
                result = terminal.upload_openvpn_cert(cert_path, is_ca=False) # is_ca=False для клиентского сертификата
                return result is not None
            else:
                print(f"No client certificate found for terminal {terminal.device_id}")
                return True
        except Exception as e:
            print(f"Client cert settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def apply_datetime_settings(self, terminal, settings, row_index):
        try:
            # 1. Установка пароля и логин (как и раньше)
            password_result = terminal.set_password()
            time.sleep(1)
            login_result = terminal.login()
            if login_result is None or 'access_token' not in login_result:
                print(f"Login failed for terminal {terminal.device_id}")
                return False
            from datetime import datetime
            utc_now = datetime.utcnow()
            formatted_datetime = utc_now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            result1 = terminal.set_datetime(formatted_datetime)
            if result1 is None or ('status_code' in result1 and result1['status_code'] >= 400):
                 print(f"Failed to set datetime for terminal {terminal.device_id}")
                 return False
            result2 = terminal.set_datetime_settings(
                timezone="Europe/Moscow", # Установка московской зоны
                primary_ntp_server="",
                secondary_ntp_server=""
            )
            if result2 is None or ('status_code' in result2 and result2['status_code'] >= 400):
                 print(f"Failed to set Moscow timezone for terminal {terminal.device_id}")
                 return False
            timezone_to_set = terminal.timezone
            result3 = terminal.set_datetime_settings(
                timezone=timezone_to_set,
                primary_ntp_server=settings.get('primary_ntp', ''),
                secondary_ntp_server=settings.get('secondary_ntp', '')
            )
            if result3 is None or ('status_code' in result3 and result3['status_code'] >= 400):
                 print(f"Failed to set table timezone for terminal {terminal.device_id}")
                 return False
            return True # Все шаги выполнены успешно
        except Exception as e:
            print(f"DateTime settings failed for terminal {terminal.device_id}: {e}")
            return False
    
    def refresh_all_tokens(self):
        for terminal in self.terminals:
            try:
                terminal.refresh_token()
            except Exception as e:
                # print(f"Error refreshing token for terminal {terminal.device_id}: {e}")
                pass