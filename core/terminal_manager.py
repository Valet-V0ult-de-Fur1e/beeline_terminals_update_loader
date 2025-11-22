import pandas as pd
from .terminal_interface import TerminalInterface
import threading
import time
import os
from datetime import datetime

class TerminalManager:
    def __init__(self, config_manager):
        self.terminals = []
        self.config_manager = config_manager
        self.terminal_table_widget = None  # Will be set from UI
    
    def set_terminal_table_widget(self, terminal_table_widget):
        self.terminal_table_widget = terminal_table_widget
    
    def load_terminals_from_excel(self, file_path):
        df = pd.read_excel(file_path)
        
        self.terminals = []
        for _, row in df.iterrows():
            terminal = TerminalInterface(
                device_id=row['Host name'],
                password=row['Пароль'],
                terminal_login=row['Host name'],
                host_name=row['Host name'],
                common_name=row['Common name'],
                city=row['Город'],
                org_name=row['Наименование организации'],
                primary_ip=row['IP № 1 (основной)'],
                secondary_ip=row['IP № 2 (резервный)'],
                local_ip=row['IP локальный']
            )
            self.terminals.append(terminal)
    
    def apply_settings_to_terminals(self, terminals, settings):
        # Start all terminals in parallel
        threads = []
        for i, terminal in enumerate(terminals):
            thread = threading.Thread(
                target=self.apply_settings_to_terminal,
                args=(terminal, settings, i)
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
    
    def apply_settings_to_terminal(self, terminal, settings, terminal_index):
        try:
            # Update status to "In Progress"
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Setting password...")
            
            # Set password first
            terminal.set_password()
            time.sleep(1)  # Wait for password to be set
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Logging in...")
            
            # Login
            terminal.login()
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Applying pipeline settings...")
            
            # Apply pipeline settings
            if settings['pipeline']['standby_logo_path'] and settings['pipeline']['work_logo_path']:
                terminal.set_pipeline_out_control_settings(
                    settings['pipeline']['standby_logo_path'],
                    settings['pipeline']['work_logo_path']
                )
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Applying TLS settings...")
            
            # Apply TLS settings
            if settings['tls']['ebs_test_cert_path']:
                terminal.upload_crypto_tunnel_cert(
                    settings['tls']['ebs_test_cert_path'],
                    cert_type="ca",
                    stage="test"
                )
            if settings['tls']['ebs_prod_cert_path']:
                terminal.upload_crypto_tunnel_cert(
                    settings['tls']['ebs_prod_cert_path'],
                    cert_type="ca",
                    stage="prod"
                )
            terminal.configure_crypto_tunnel(
                stage=settings['tls']['tls_stage'],
                tls_mode=settings['tls']['tls_mode']
            )
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Updating firmware...")
            
            # Apply firmware update
            if settings['firmware']['firmware_path']:
                terminal.set_terminal_files(settings['firmware']['firmware_path'])
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Configuring OpenVPN...")
            
            # Apply OpenVPN settings
            if settings['openvpn']['ip_addresses']:
                addresses = [
                    {"ip": addr['ip'], "port": addr['port']}
                    for addr in settings['openvpn']['ip_addresses']
                ]
                terminal.configure_openvpn(addresses)
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Uploading CRL...")
            
            # Upload CRL
            if settings['crl']['crl_path']:
                terminal.upload_openvpn_crl(settings['crl']['crl_path'])
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Generating certificate request...")
            
            # Generate certificate request with automatic folder creation
            if settings['cert_request']['output_folder']:
                cert_request_result = terminal.generate_openvpn_cert_request(
                    output_folder=settings['cert_request']['output_folder']
                )
                if cert_request_result and cert_request_result.get('status') == 'exists':
                    print(f"Certificate request already exists for {terminal.common_name}")
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Uploading server certificate...")
            
            # Upload server certificate
            if settings['server_cert']['server_cert_path']:
                terminal.upload_openvpn_cert(settings['server_cert']['server_cert_path'], is_ca=True)
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Uploading client certificate...")
            
            # Upload client certificate
            if settings['client_cert']['client_cert_path']:
                terminal.upload_openvpn_cert(settings['client_cert']['client_cert_path'], is_ca=False)
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Setting date time...")
            
            # Set date time with proper ISO 8601 format (like "2025-11-19T18:23:13.641Z")
            # Use UTC time to ensure Z suffix
            utc_now = datetime.utcnow()
            formatted_datetime = utc_now.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            terminal.set_datetime(formatted_datetime)
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Setting date time settings...")
            
            # Set date time settings
            terminal.set_datetime_settings(
                timezone=settings['datetime']['timezone'],
                primary_ntp_server=settings['datetime']['primary_ntp'],
                secondary_ntp_server=settings['datetime']['secondary_ntp']
            )
            
            # Update status
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Starting OpenVPN...")
            
            # Start OpenVPN
            terminal.start_openvpn()
            
            # Update status to completed
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, "Completed")
            
        except Exception as e:
            print(f"Error applying settings to terminal {terminal.device_id}: {e}")
            if self.terminal_table_widget:
                self.terminal_table_widget.update_terminal_status(terminal_index, f"Error: {str(e)}")
    
    def refresh_all_tokens(self):
        for terminal in self.terminals:
            try:
                terminal.refresh_token()
            except Exception as e:
                print(f"Error refreshing token for terminal {terminal.device_id}: {e}")