import sys
import os
import json
import pandas as pd
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QPushButton, QGroupBox, QFormLayout, QLineEdit,
    QCheckBox, QLabel, QMessageBox, QTextEdit, QSpinBox, QHBoxLayout,
    QComboBox, QProgressBar, QHeaderView, QScrollArea, QFrame, QToolButton
)
from PySide6.QtCore import Qt, QThread, Signal
from model import *

CONFIG_FILE = "config.json"
HISTORY_FILE = "terminal_history.json"

def ping_ip(ip, port=7777, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False
    

class MainConfigWorker:
    def __init__(self, terminal_data, config):
        self.terminal_data = terminal_data
        self.config = config
        
    def run(self):
        host_name = self.terminal_data.get('Host name', 'Unknown')
        ip_main = self.terminal_data.get('IP № 1 (основной)', '')
        ip_local = self.terminal_data.get('IP локальный', '')
        terminal_login = self.terminal_data.get('Логин', '')
        password = self.terminal_data.get('Пароль', '')
        use_local_ip = self.terminal_data.get('use_local_ip', False)
        target_ip = ip_local if use_local_ip else ip_main
        base_config = self.config.get('base_config', {})
        logo_stand_by_path = base_config.get('logo_stand_by_file_path', '')
        logo_waiting_path = base_config.get('logo_file_path', '')
        system_package_path = base_config.get('system_package_file_path', '')
        openvpn_addresses = self.config.get('openvpn_addresses', [])
        openvpn_protocol = self.config.get('openvpn_protocol', 'tcp')
        term_interface = TerminalInterface(
            local_url=f"http://{target_ip}",
            api_url="/api",
            device_id=host_name,
            terminal_login=terminal_login,
            password=password,
            log_dir=self.config.get('log_dir', './logs')
        )
        success = True
        messages = []
        try:
            health_result = term_interface.check_health()
            if health_result is None or (isinstance(health_result, dict) and 'error' in health_result):
                 success = False
                 messages.append(f"Health check failed: {health_result.get('error', 'Received error structure from health check')}")
        except Exception as e:
            success = False
            messages.append(f"Health check error: {str(e)}")
        if success:
            try:
                term_interface.set_password(password)
            except Exception as e:
                success = False
                messages.append(f"Set password error: {str(e)}")
            try:
                login_result = term_interface.login()
                if not login_result or not isinstance(login_result, dict) or 'access_token' not in login_result:
                    success = False
                    messages.append("Login failed or did not return access token")
            except Exception as e:
                success = False
                messages.append(f"Login error: {str(e)}")
            if success:
                if logo_stand_by_path and logo_waiting_path:
                    try:
                        pipeline_success = term_interface.set_pipeline_out_control_settings(logo_stand_by_path, logo_waiting_path)
                        if not pipeline_success:
                            success = False
                            messages.append("Pipeline settings failed")
                    except Exception as e:
                        success = False
                        messages.append(f"Pipeline settings error: {str(e)}")
                if system_package_path:
                    try:
                        install_success = term_interface.set_terminal_files(system_package_path)
                        if not install_success:
                            success = False
                            messages.append("Package install failed")
                    except Exception as e:
                        success = False
                        messages.append(f"Package install error: {str(e)}")
        if len(openvpn_addresses):
            open_vpn_cofiguration = term_interface.configure_openvpn(openvpn_addresses, protocol=openvpn_protocol)
            if open_vpn_cofiguration is None:
                success = False
                messages.append("OpenVPN configuration failed")
        # Upload OpenVPN client certificate (is_ca=False)
        openvpn_client_cert_path = self.config.get('openvpn_client_cert_file', '')
        if openvpn_client_cert_path and os.path.isfile(openvpn_client_cert_path):
            try:
                upload_cert_result = term_interface.upload_openvpn_cert(openvpn_client_cert_path, is_ca=True)
                if not (isinstance(upload_cert_result, dict) and upload_cert_result.get('status') == 'success'):
                    success = False
                    messages.append("Upload OpenVPN client cert failed")
            except Exception as e:
                success = False
                messages.append(f"OpenVPN client cert upload error: {str(e)}")

        # Upload OpenVPN CRL
        openvpn_crl_path = self.config.get('openvpn_crl_file', '')
        if openvpn_crl_path and os.path.isfile(openvpn_crl_path):
            try:
                upload_crl_result = term_interface.upload_openvpn_crl(openvpn_crl_path)
                if not (isinstance(upload_crl_result, dict) and upload_crl_result.get('status') == 'success'):
                    success = False
                    messages.append("Upload OpenVPN CRL failed")
            except Exception as e:
                success = False
                messages.append(f"OpenVPN CRL upload error: {str(e)}")
        if success:
            final_status = "OK"
        else:
            final_status = f"Error: {'; '.join(messages)}"
        if 'host_name' not in locals():
             host_name = self.terminal_data.get('Host name', 'Unknown_Device')
        return (host_name, final_status)
    
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Terminal Configurator")
        self.resize(1400, 850)
        self.terminals_df = None
        self.executor = None
        self.futures = []
        self.term_status = {}
        self.total_tasks = 0
        self.completed_tasks = 0
        self.history = self.load_history()
        self.current_stage = "health_check"
        self.load_config()
        self.setup_directories()
        self.setup_ui()
        self.load_config_into_ui()
        
    def load_history(self):
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading history: {e}")
        return {}
    
    def save_history(self):
        try:
            with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Error saving history: {e}")
            
    def load_config(self):
        defaults = {
            'use_local_ip': False,
            'system_package': '',
            'crypto_ca_prod': '',
            'crypto_ca_test': '',
            'openvpn_cert': '',
            'openvpn_crl_file': '',
            'openvpn_client_cert_file': '',
            'openvpn_cert_is_ca': True,
            'crl_file': '',
            'logo_standby': '',
            'logo_waiting': '',
            'csr_output_dir': './csr_output',
            'log_dir': './logs',
            'openvpn_protocol': 'tcp',
            'openvpn_addresses': [
                {'ip': '', 'port': 1194},
                {'ip': '', 'port': 1194},
                {'ip': '', 'port': 1194},
                {'ip': '', 'port': 1194},
            ],
            'base_config': {
                'logo_stand_by_file_path': '',
                'logo_file_path': '',
                'system_package_file_path': ''
            },
            'upload_cert_config': {
                'certificates_dir': './certs'
            }
        }
        if os.path.isfile(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    self.global_config = json.load(f)
                for k, v in defaults.items():
                    if k not in self.global_config:
                        self.global_config[k] = v
            except Exception as e:
                QMessageBox.warning(self, "Внимание", f"Не удалось загрузить config.json: {e}")
                self.global_config = defaults
        else:
            self.global_config = defaults
            
    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.global_config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось сохранить config.json: {e}")
            
    def setup_directories(self):
        os.makedirs(self.global_config['csr_output_dir'], exist_ok=True)
        os.makedirs(self.global_config['log_dir'], exist_ok=True)
        os.makedirs(self.global_config['upload_cert_config']['certificates_dir'], exist_ok=True)
        
    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        h_stage = QHBoxLayout()
        h_stage.addWidget(QLabel("Этап:"))
        self.stage_combo = QComboBox()
        self.stage_combo.addItems([
            "health_check", "base_config", "request_cert", 
            "upload_cert", "start_openvpn"
        ])
        self.stage_combo.currentTextChanged.connect(self.on_stage_changed)
        h_stage.addWidget(self.stage_combo)
        self.settings_btn = QPushButton("⚙️ Настройки")
        self.settings_btn.clicked.connect(self.open_stage_settings)
        h_stage.addWidget(self.settings_btn)
        self.action_btn = QPushButton("Запустить")
        self.action_btn.clicked.connect(self.execute_current_stage)
        h_stage.addWidget(self.action_btn)
        layout.addLayout(h_stage)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        h_filters = QHBoxLayout()
        self.filter_name = QLineEdit()
        self.filter_name.setPlaceholderText("Фильтр по имени...")
        self.filter_ip = QLineEdit()
        self.filter_ip.setPlaceholderText("Фильтр по IP...")
        self.filter_status = QComboBox()
        self.filter_status.addItems(["Все", "Ожидание", "Выполнено", "Ошибка"])
        h_filters.addWidget(QLabel("Имя:"))
        h_filters.addWidget(self.filter_name)
        h_filters.addWidget(QLabel("IP:"))
        h_filters.addWidget(self.filter_ip)
        h_filters.addWidget(QLabel("Статус:"))
        h_filters.addWidget(self.filter_status)
        layout.addLayout(h_filters)
        h_btns = QHBoxLayout()
        btn_load = QPushButton("📁 Загрузить Excel")
        btn_load.clicked.connect(self.load_excel)
        btn_save_excel = QPushButton("💾 Сохранить Excel")
        btn_save_excel.clicked.connect(self.save_excel)
        btn_save_config = QPushButton("⚙️ Сохранить настройки")
        btn_save_config.clicked.connect(self.save_config)
        h_btns.addWidget(btn_load)
        h_btns.addWidget(btn_save_excel)
        h_btns.addWidget(btn_save_config)
        layout.addLayout(h_btns)
        self.table = QTableWidget()
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        layout.addWidget(self.table)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(QLabel("Логи:"))
        layout.addWidget(self.log_text)
        self.on_stage_changed()
        
    def on_stage_changed(self):
        stage = self.stage_combo.currentText()
        stage_names = {
            "health_check": "Проверить связь",
            "base_config": "Указать настройки",
            "request_cert": "Запросить сертификат",
            "upload_cert": "Загрузить сертификат",
            "start_openvpn": "Запустить OpenVPN"
        }
        self.action_btn.setText(stage_names.get(stage, "Запустить"))
        self.settings_btn.setVisible(stage == "base_config" or stage == "upload_cert")
        if self.terminals_df is not None:
            self.display_table()
            
    def open_stage_settings(self):
        if self.stage_combo.currentText() == "base_config":
            self.open_base_config_settings()
        elif self.stage_combo.currentText() == "upload_cert":
            self.open_upload_cert_settings()
            
    def open_base_config_settings(self):
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройки базовой конфигурации")
        dialog.resize(600, 450)
        layout = QVBoxLayout(dialog)
        logo_group = QGroupBox("Настройки логотипов")
        logo_form = QFormLayout()
        self.logo_standby_le = QLineEdit()
        btn_logo_standby = QPushButton("Обзор...")
        btn_logo_standby.clicked.connect(lambda: self.select_file("logo_standby", self.logo_standby_le))
        h_logo_standby = QHBoxLayout()
        h_logo_standby.addWidget(self.logo_standby_le)
        h_logo_standby.addWidget(btn_logo_standby)
        logo_form.addRow("Логотип standby:", h_logo_standby)
        self.logo_waiting_le = QLineEdit()
        btn_logo_waiting = QPushButton("Обзор...")
        btn_logo_waiting.clicked.connect(lambda: self.select_file("logo_waiting", self.logo_waiting_le))
        h_logo_waiting = QHBoxLayout()
        h_logo_waiting.addWidget(self.logo_waiting_le)
        h_logo_waiting.addWidget(btn_logo_waiting)
        logo_form.addRow("Логотип ожидания:", h_logo_waiting)
        logo_group.setLayout(logo_form)
        layout.addWidget(logo_group)
        firmware_group = QGroupBox("Настройки прошивки")
        firmware_form = QFormLayout()
        self.system_package_le = QLineEdit()
        btn_system_package = QPushButton("Обзор...")
        btn_system_package.clicked.connect(lambda: self.select_file("system_package", self.system_package_le))
        h_system_package = QHBoxLayout()
        h_system_package.addWidget(self.system_package_le)
        h_system_package.addWidget(btn_system_package)
        firmware_form.addRow("Файл прошивки:", h_system_package)
        firmware_group.setLayout(firmware_form)
        layout.addWidget(firmware_group)
        cert_group = QGroupBox("OpenVPN сертификаты и CRL")
        cert_form = QFormLayout()

        self.openvpn_client_cert_le = QLineEdit()
        btn_client_cert = QPushButton("Обзор...")
        btn_client_cert.clicked.connect(lambda: self.select_file("openvpn_client_cert_file", self.openvpn_client_cert_le))
        h_client_cert = QHBoxLayout()
        h_client_cert.addWidget(self.openvpn_client_cert_le)
        h_client_cert.addWidget(btn_client_cert)
        cert_form.addRow("Сертификат Beeline (.crt):", h_client_cert)

        # CRL файл
        self.openvpn_crl_le = QLineEdit()
        btn_crl = QPushButton("Обзор...")
        btn_crl.clicked.connect(lambda: self.select_file("openvpn_crl_file", self.openvpn_crl_le))
        h_crl = QHBoxLayout()
        h_crl.addWidget(self.openvpn_crl_le)
        h_crl.addWidget(btn_crl)
        cert_form.addRow("Файл CRL (.pem):", h_crl)

        cert_group.setLayout(cert_form)
        layout.addWidget(cert_group)
        server_group = QGroupBox("Настройки серверов")
        server_layout = QVBoxLayout()
        self.server_scroll = QScrollArea()
        self.server_container = QWidget()
        self.server_layout = QVBoxLayout(self.server_container)
        self.server_scroll.setWidget(self.server_container)
        self.server_scroll.setWidgetResizable(True)
        add_server_btn = QPushButton("Добавить сервер")
        add_server_btn.clicked.connect(self.add_server_row)
        server_layout.addWidget(add_server_btn)
        server_layout.addWidget(self.server_scroll)
        server_group.setLayout(server_layout)
        layout.addWidget(server_group)
        h_proto = QHBoxLayout()
        h_proto.addWidget(QLabel("Протокол OpenVPN:"))
        self.proto_combo_settings = QComboBox()
        self.proto_combo_settings.addItems(["tcp", "udp"])
        h_proto.addWidget(self.proto_combo_settings)
        layout.addLayout(h_proto)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        self.logo_standby_le.setText(self.global_config.get('base_config', {}).get('logo_stand_by_file_path', ''))
        self.logo_waiting_le.setText(self.global_config.get('base_config', {}).get('logo_file_path', ''))
        self.system_package_le.setText(self.global_config.get('base_config', {}).get('system_package_file_path', ''))
        self.proto_combo_settings.setCurrentText(self.global_config.get('openvpn_protocol', 'tcp'))
        for addr in self.global_config.get('openvpn_addresses', []):
            self.add_server_row(addr['ip'], addr['port'])
        if dialog.exec() == QDialog.Accepted:
            self.global_config['base_config'] = {
                'logo_stand_by_file_path': self.logo_standby_le.text(),
                'logo_file_path': self.logo_waiting_le.text(),
                'system_package_file_path': self.system_package_le.text()
            }
            self.global_config['openvpn_protocol'] = self.proto_combo_settings.currentText()
            servers = []
            for i in range(self.server_layout.count()):
                widget = self.server_layout.itemAt(i).widget()
                if hasattr(widget, 'ip_le') and hasattr(widget, 'port_sb'):
                    servers.append({
                        'ip': widget.ip_le.text(),
                        'port': widget.port_sb.value()
                    })
            self.global_config['openvpn_addresses'] = servers
            self.openvpn_client_cert_le.setText(self.global_config.get('openvpn_client_cert_file', ''))
            self.openvpn_crl_le.setText(self.global_config.get('openvpn_crl_file', ''))
            self.save_config()
            
    def open_upload_cert_settings(self):
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройки загрузки сертификатов")
        dialog.resize(500, 150)
        layout = QVBoxLayout(dialog)
        cert_dir_layout = QHBoxLayout()
        self.cert_dir_le = QLineEdit()
        btn_cert_dir = QPushButton("Обзор...")
        btn_cert_dir.clicked.connect(lambda: self.select_directory("upload_cert_config_certificates_dir", self.cert_dir_le))
        cert_dir_layout.addWidget(QLabel("Папка с сертификатами:"))
        cert_dir_layout.addWidget(self.cert_dir_le)
        cert_dir_layout.addWidget(btn_cert_dir)
        layout.addLayout(cert_dir_layout)
        auto_fill_btn = QPushButton("Автозаполнение сертификатов по имени")
        auto_fill_btn.clicked.connect(self.auto_fill_certificates)
        layout.addWidget(auto_fill_btn)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        self.cert_dir_le.setText(self.global_config.get('upload_cert_config', {}).get('certificates_dir', './certs'))
        if dialog.exec() == QDialog.Accepted:
            self.global_config['upload_cert_config'] = {
                'certificates_dir': self.cert_dir_le.text()
            }
            self.save_config()
            os.makedirs(self.global_config['upload_cert_config']['certificates_dir'], exist_ok=True)
            
    def auto_fill_certificates(self):
        if self.terminals_df is None:
            return
        cert_dir = self.global_config.get('upload_cert_config', {}).get('certificates_dir', './certs')
        if not os.path.exists(cert_dir):
            QMessageBox.warning(self, "Ошибка", f"Папка сертификатов не найдена: {cert_dir}")
            return
        crt_files = [f for f in os.listdir(cert_dir) if f.lower().endswith('.crt')]
        for i in range(len(self.terminals_df)):
            common_name = str(self.terminals_df.iloc[i]['Common name'])
            matched_file = None
            for crt_file in crt_files:
                if common_name.lower() in crt_file.lower() or crt_file.lower().replace('.crt', '') == common_name.lower():
                    matched_file = os.path.join(cert_dir, crt_file)
                    break
            if matched_file:
                self.terminals_df.at[i, 'Клиентский сертификат (.crt)'] = matched_file
        self.display_table()
        
    def add_server_row(self, ip='', port=1194):
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel)
        layout = QHBoxLayout(frame)
        ip_le = QLineEdit(ip)
        port_sb = QSpinBox()
        port_sb.setRange(1, 65535)
        port_sb.setValue(port)
        remove_btn = QToolButton()
        remove_btn.setText("❌")
        remove_btn.clicked.connect(lambda: self.remove_server_row(frame))
        layout.addWidget(QLabel("IP:"))
        layout.addWidget(ip_le)
        layout.addWidget(QLabel("Порт:"))
        layout.addWidget(port_sb)
        layout.addWidget(remove_btn)
        frame.ip_le = ip_le
        frame.port_sb = port_sb
        self.server_layout.insertWidget(self.server_layout.count()-2, frame)
        
    def remove_server_row(self, frame):
        self.server_layout.removeWidget(frame)
        frame.deleteLater()
        
    def execute_current_stage(self):
        stage = self.stage_combo.currentText()
        if stage == "health_check":
            self.start_health_check()
        elif stage == "base_config":
            self.start_base_configuration()
        elif stage == "request_cert":
            self.start_certificate_request()
        elif stage == "upload_cert":
            self.start_certificate_upload()
        elif stage == "start_openvpn":
            self.start_openvpn()
            
    def start_base_configuration(self):
        selected = self.get_selected_terminals()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного терминала")
            return
        self.log_text.append(f"\n--- Указание настроек ---")
        self.term_status = {}
        self.total_tasks = len(selected)
        self.completed_tasks = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {self.total_tasks}")
        widgets_to_disable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_disable:
            if widget != self.progress_bar:
                widget.setEnabled(False)
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.futures = []
        for term_data in selected:
            worker = MainConfigWorker(term_data, self.global_config)
            future = self.executor.submit(worker.run)
            self.futures.append(future)
        self.monitor_thread = QThread()
        self.monitor_thread.run = self.wait_for_completion
        self.monitor_thread.finished.connect(self.on_all_finished)
        self.monitor_thread.start()
        
    def _start_generic_task(self, terminals_list, worker_class, task_name):
        if not terminals_list:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного терминала")
            return
        self.log_text.append(f"\n--- {task_name} ---")
        self.term_status = {}
        self.total_tasks = len(terminals_list)
        self.completed_tasks = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {self.total_tasks}")
        widgets_to_disable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_disable:
            if widget != self.progress_bar:
                widget.setEnabled(False)
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.futures = []
        for term_data in terminals_list:
            worker = worker_class(term_data, self.global_config)
            future = self.executor.submit(worker.run)
            self.futures.append(future)
        self.monitor_thread = QThread()
        self.monitor_thread.run = self.wait_for_completion
        self.monitor_thread.finished.connect(self.on_all_finished)
        self.monitor_thread.start()
        
    def on_terminal_finished(self, device_id, status):
        self.completed_tasks += 1
        self.term_status[device_id] = status
        progress_percent = int((self.completed_tasks / self.total_tasks) * 100)
        self.progress_bar.setValue(progress_percent)
        self.progress_bar.setFormat(f"{self.completed_tasks} / {self.total_tasks}")
        for i in range(self.table.rowCount()):
            item = self.table.item(i, 1)
            if item and item.text() == device_id:
                self.table.item(i, self.table.columnCount() - 1).setText(status)
                break
            
    def start_health_check(self):
        selected = self.get_selected_terminals()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного терминала")
            return
        self.log_text.append(f"\n--- Проверка связи ---")
        self.term_status = {}
        self.total_tasks = len(selected)
        self.completed_tasks = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {self.total_tasks}")
        widgets_to_disable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_disable:
            if widget != self.progress_bar:
                widget.setEnabled(False)
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.futures = []
        for term_data in selected:
            future = self.executor.submit(self.check_terminal_health, term_data)
            self.futures.append(future)
        self.monitor_thread = QThread()
        self.monitor_thread.run = self.wait_for_completion
        self.monitor_thread.finished.connect(self.on_all_finished)
        self.monitor_thread.start()
        
    def check_terminal_health(self, term_data):
        host_name = term_data.get('Host name', 'Unknown')
        use_local = term_data.get('IP Selection', 'main') == 'local'
        ip = term_data.get('IP локальный') if use_local else term_data.get('IP № 1 (основной)', '')
        try:
            term_interface = TerminalInterface(
                local_url=f"http://{ip}",
                api_url="/api",
                device_id=host_name,
                terminal_login=term_data.get('Логин', ''),
                password=term_data.get('Пароль', ''),
                log_dir=self.global_config.get('log_dir', './logs')
            )
            result = term_interface.check_health()
            if result is None or (isinstance(result, dict) and 'error' in result):
                 status = f"Ошибка: {result.get('error', 'Health check returned error structure')}"
            else:
                 status = "ОК"
        except Exception as e:
            status = f"Ошибка: {str(e)}"
        if host_name not in self.history:
            self.history[host_name] = {}
        self.history[host_name]['health_check'] = {
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        self.save_history()
        self.term_status[host_name] = status
        self.completed_tasks += 1
        progress_percent = int((self.completed_tasks / self.total_tasks) * 100)
        self.progress_bar.setValue(progress_percent)
        self.progress_bar.setFormat(f"{self.completed_tasks} / {self.total_tasks}")
        for i in range(self.table.rowCount()):
            item = self.table.item(i, 1)
            if item and item.text() == host_name:
                status_col_index = -1
                for j in range(self.table.columnCount()):
                     header_item = self.table.horizontalHeaderItem(j)
                     if header_item and header_item.text() == 'Статус':
                         status_col_index = j
                         break
                if status_col_index != -1:
                    self.table.item(i, status_col_index).setText(status)
                break
        return (host_name, status)
    
    def start_certificate_request(self):
        selected = self.get_selected_terminals()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного терминала")
            return
        self.log_text.append(f"\n--- Запрос сертификатов ---")
        self.term_status = {}
        self.total_tasks = len(selected)
        self.completed_tasks = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {self.total_tasks}")
        widgets_to_disable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_disable:
            if widget != self.progress_bar:
                widget.setEnabled(False)
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.futures = []
        for term_data in selected:
            future = self.executor.submit(self.request_terminal_certificate, term_data)
            self.futures.append(future)
        self.monitor_thread = QThread()
        self.monitor_thread.run = self.wait_for_completion
        self.monitor_thread.finished.connect(self.on_all_finished)
        self.monitor_thread.start()
        
    def request_terminal_certificate(self, term_data):
        host_name = term_data.get('Host name', 'Unknown')
        common_name = term_data.get('Common name', host_name)
        city = term_data.get('Город', 'Unknown')
        org_name = term_data.get('Наименование организации', 'Unknown')
        use_local = term_data.get('IP Selection', 'main') == 'local'
        ip = term_data.get('IP локальный') if use_local else term_data.get('IP № 1 (основной)', '')
        try:
            term_interface = TerminalInterface(
                local_url=f"http://{ip}",
                api_url="/api",
                device_id=host_name,
                terminal_login=term_data.get('Логин', ''),
                password=term_data.get('Пароль', ''),
                log_dir=self.global_config.get('log_dir', './logs')
            )
            csr_result = term_interface.generate_openvpn_cert_request(common_name, city, org_name)
            status = "Запрос создан" if csr_result and csr_result.get('status') == 'success' else "Ошибка запроса"
        except Exception as e:
            status = f"Ошибка: {str(e)}"
        if host_name not in self.history:
            self.history[host_name] = {}
        self.history[host_name]['certificate_request'] = {
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        self.save_history()
        self.term_status[host_name] = status
        self.completed_tasks += 1
        progress_percent = int((self.completed_tasks / self.total_tasks) * 100)
        self.progress_bar.setValue(progress_percent)
        self.progress_bar.setFormat(f"{self.completed_tasks} / {self.total_tasks}")
        for i in range(self.table.rowCount()):
            item = self.table.item(i, 1)
            if item and item.text() == host_name:
                self.table.item(i, self.table.columnCount() - 1).setText(status)
                break
        return (host_name, status)
    
    def start_certificate_upload(self):
        selected = self.get_selected_terminals()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного терминала")
            return
        self.log_text.append(f"\n--- Загрузка сертификатов ---")
        self.term_status = {}
        self.total_tasks = len(selected)
        self.completed_tasks = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {self.total_tasks}")
        widgets_to_disable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_disable:
            if widget != self.progress_bar:
                widget.setEnabled(False)
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.futures = []
        for term_data in selected:
            future = self.executor.submit(self.upload_terminal_certificate, term_data)
            self.futures.append(future)
        self.monitor_thread = QThread()
        self.monitor_thread.run = self.wait_for_completion
        self.monitor_thread.finished.connect(self.on_all_finished)
        self.monitor_thread.start()
        
    def upload_terminal_certificate(self, term_data):
        host_name = term_data.get('Host name', 'Unknown')
        cert_path = term_data.get('Клиентский сертификат (.crt)', '')
        if not cert_path or not os.path.exists(cert_path):
            status = "Файл сертификата не найден"
        else:
            try:
                use_local = term_data.get('IP Selection', 'main') == 'local'
                ip = term_data.get('IP локальный') if use_local else term_data.get('IP № 1 (основной)', '')
                term_interface = TerminalInterface(
                    local_url=f"http://{ip}",
                    api_url="/api",
                    device_id=host_name,
                    terminal_login=term_data.get('Логин', ''),
                    password=term_data.get('Пароль', ''),
                    log_dir=self.global_config.get('log_dir', './logs')
                )
                upload_result = term_interface.upload_openvpn_cert(cert_path, is_ca=False)
                status = "Сертификат загружен" if upload_result else "Ошибка загрузки"
            except Exception as e:
                status = f"Ошибка: {str(e)}"
        if host_name not in self.history:
            self.history[host_name] = {}
        self.history[host_name]['certificate_upload'] = {
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        self.save_history()
        self.term_status[host_name] = status
        self.completed_tasks += 1
        progress_percent = int((self.completed_tasks / self.total_tasks) * 100)
        self.progress_bar.setValue(progress_percent)
        self.progress_bar.setFormat(f"{self.completed_tasks} / {self.total_tasks}")
        for i in range(self.table.rowCount()):
            item = self.table.item(i, 1)
            if item and item.text() == host_name:
                self.table.item(i, self.table.columnCount() - 1).setText(status)
                break
        return (host_name, status)
    
    def start_openvpn(self):
        selected = self.get_selected_terminals()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Не выбрано ни одного терминала")
            return
        self.log_text.append(f"\n--- Запуск OpenVPN ---")
        self.term_status = {}
        self.total_tasks = len(selected)
        self.completed_tasks = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {self.total_tasks}")
        widgets_to_disable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_disable:
            if widget != self.progress_bar:
                widget.setEnabled(False)
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.futures = []
        for term_data in selected:
            future = self.executor.submit(self.start_terminal_openvpn, term_data)
            self.futures.append(future)
        self.monitor_thread = QThread()
        self.monitor_thread.run = self.wait_for_completion
        self.monitor_thread.finished.connect(self.on_all_finished)
        self.monitor_thread.start()
        
    def start_terminal_openvpn(self, term_data):
        host_name = term_data.get('Host name', 'Unknown')
        try:
            use_local = term_data.get('IP Selection', 'main') == 'local'
            ip = term_data.get('IP локальный') if use_local else term_data.get('IP № 1 (основной)', '')
            term_interface = TerminalInterface(
                local_url=f"http://{ip}",
                api_url="/api",
                device_id=host_name,
                terminal_login=term_data.get('Логин', ''),
                password=term_data.get('Пароль', ''),
                log_dir=self.global_config.get('log_dir', './logs')
            )
            start_result = term_interface.start_openvpn()
            status = "OpenVPN запущен" if start_result else "Ошибка запуска"
        except Exception as e:
            status = f"Ошибка: {str(e)}"
        if host_name not in self.history:
            self.history[host_name] = {}
        self.history[host_name]['openvpn_start'] = {
            'status': status,
            'timestamp': datetime.now().isoformat()
        }
        self.save_history()
        self.term_status[host_name] = status
        self.completed_tasks += 1
        progress_percent = int((self.completed_tasks / self.total_tasks) * 100)
        self.progress_bar.setValue(progress_percent)
        self.progress_bar.setFormat(f"{self.completed_tasks} / {self.total_tasks}")
        for i in range(self.table.rowCount()):
            item = self.table.item(i, 1)
            if item and item.text() == host_name:
                self.table.item(i, self.table.columnCount() - 1).setText(status)
                break
        return (host_name, status)
    
    def select_file(self, key, line_edit):
        path, _ = QFileDialog.getOpenFileName(self, f"Выберите файл для {key}")
        if path:
            line_edit.setText(path)
            self.global_config[key] = path
            
    def select_directory(self, key, line_edit):
        path = QFileDialog.getExistingDirectory(self, f"Выберите папку для {key}")
        if path:
            line_edit.setText(path)
            self.global_config[key] = path
            os.makedirs(path, exist_ok=True)
            
    def load_config_into_ui(self):
        cfg = self.global_config
        
    def load_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "Выберите Excel файл", "", "Excel Files (*.xlsx *.xls)")
        if not path:
            return
        try:
            df = pd.read_excel(path, dtype=str)
            required_cols = [
                'Host name', 'Common name', 'Город', 'Наименование организации',
                'IP № 1 (основной)', 'IP № 2 (резервный)', 'IP локальный', 'Пароль'
            ]
            optional_cols = ['Клиентский сертификат (.crt)']
            for col in optional_cols:
                if col not in df.columns:
                    df[col] = ''
            if not all(col in df.columns for col in required_cols):
                raise ValueError("Неверная структура файла")
            if 'Статус' not in df.columns:
                df['Статус'] = ''
            self.terminals_df = df
            self.display_table()
            self.log_text.append(f"Загружено {len(df)} терминалов")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить Excel:\n{e}")
            
    def _select_cert_file(self, row, col):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите клиентский сертификат (.crt)",
            "",
            "Certificate Files (*.crt *.pem);;All Files (*)"
        )
        if path:
            item = QTableWidgetItem(path)
            self.table.setItem(row, col, item)
            
    def display_table(self):
        if self.terminals_df is None:
            return
        df = self.terminals_df.copy()
        columns_to_hide = ['Загрузить клиентский сертификат']
        df = df.drop(columns=[col for col in columns_to_hide if col in df.columns])
        self.table.setRowCount(len(df))
        self.table.setColumnCount(len(df.columns) + 1)
        headers = ['✅'] + df.columns.tolist()
        self.table.setHorizontalHeaderLabels(headers)
        cert_path_col_idx = df.columns.get_loc('Клиентский сертификат (.crt)') + 1 if 'Клиентский сертификат (.crt)' in df.columns else -1
        status_col_idx = df.columns.get_loc('Статус') + 1 if 'Статус' in df.columns else -1
        for i, row in df.iterrows():
            main_cb = QCheckBox()
            main_cb.setChecked(True)
            self.table.setCellWidget(i, 0, main_cb)
            for j, col in enumerate(df.columns):
                table_col = j + 1
                val = row[col] if pd.notna(row[col]) else ""
                if col == 'Клиентский сертификат (.crt)':
                    btn = QPushButton("Обзор...")
                    btn.clicked.connect(lambda _, row=i, col_idx=table_col: self._select_cert_file(row, col_idx))
                    self.table.setCellWidget(i, table_col, btn)
                    item = QTableWidgetItem(str(val))
                    self.table.setItem(i, table_col, item)
                else:
                    item = QTableWidgetItem(str(val))
                    if col == 'Статус':
                        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    self.table.setItem(i, table_col, item)
                    
    def save_excel(self):
        if self.terminals_df is None:
            QMessageBox.warning(self, "Предупреждение", "Нет данных")
            return
        for i in range(self.table.rowCount()):
            for j, col in enumerate(self.terminals_df.columns):
                table_col = j + 1
                if col == 'Клиентский сертификат (.crt)':
                    item = self.table.item(i, table_col)
                    self.terminals_df.at[i, col] = item.text() if item else ""
                else:
                    item = self.table.item(i, table_col)
                    self.terminals_df.at[i, col] = item.text() if item else ""
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить Excel", "", "Excel Files (*.xlsx)")
        if path:
            self.terminals_df.to_excel(path, index=False)
            self.log_text.append(f"Результаты сохранены в {path}")
            
    def get_selected_terminals(self):
        selected = []
        for i in range(self.table.rowCount()):
            cb_widget = self.table.cellWidget(i, 0)
            if cb_widget and cb_widget.isChecked():
                row_dict = {}
                for j, col in enumerate(self.terminals_df.columns):
                    item = self.table.item(i, j + 1)
                    row_dict[col] = item.text() if item else ""
                selected.append(row_dict)
        return selected
    
    def wait_for_completion(self):
        for future in as_completed(self.futures):
            device_id, status = future.result()
            self.on_terminal_finished(device_id, status)
            
    def on_all_finished(self):
        self.monitor_thread.quit()
        widgets_to_enable = (
            self.findChildren(QPushButton) +
            self.findChildren(QLineEdit) +
            self.findChildren(QCheckBox) +
            self.findChildren(QComboBox) +
            self.findChildren(QSpinBox)
        )
        for widget in widgets_to_enable:
            if widget != self.progress_bar:
                widget.setEnabled(True)
        self.log_text.append("✅ Задача завершена.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())