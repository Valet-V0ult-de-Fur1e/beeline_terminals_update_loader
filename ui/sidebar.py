from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QGroupBox, QPushButton, QComboBox,
    QLineEdit, QCheckBox, QSpinBox, QDoubleSpinBox, QLabel,
    QFileDialog, QTabWidget, QScrollArea, QFrame, QTabBar, QHBoxLayout
)
from PySide6.QtCore import Signal, QSize
import os

class SidebarWidget(QWidget):
    apply_settings_signal = Signal()
    
    def __init__(self, terminal_manager):
        super().__init__()
        self.terminal_manager = terminal_manager
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create tab widget for different settings sections
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.West)  # Place tabs on the left side
        
        # Pipeline Settings
        self.pipeline_tab = self.create_pipeline_tab()
        self.tab_widget.addTab(self.pipeline_tab, "Pipeline")
        
        # TLS Settings
        self.tls_tab = self.create_tls_tab()
        self.tab_widget.addTab(self.tls_tab, "TLS")
        
        # Firmware Settings
        self.firmware_tab = self.create_firmware_tab()
        self.tab_widget.addTab(self.firmware_tab, "Firmware")
        
        # OpenVPN Settings
        self.openvpn_tab = self.create_openvpn_tab()
        self.tab_widget.addTab(self.openvpn_tab, "OpenVPN")
        
        # CRL Settings
        self.crl_tab = self.create_crl_tab()
        self.tab_widget.addTab(self.crl_tab, "CRL")
        
        # Certificate Request Settings
        self.cert_req_tab = self.create_cert_request_tab()
        self.tab_widget.addTab(self.cert_req_tab, "Cert Request")
        
        # Server Cert Settings
        self.server_cert_tab = self.create_server_cert_tab()
        self.tab_widget.addTab(self.server_cert_tab, "Server Cert")
        
        # Client Cert Settings
        self.client_cert_tab = self.create_client_cert_tab()
        self.tab_widget.addTab(self.client_cert_tab, "Client Cert")
        
        # DateTime Settings
        self.datetime_tab = self.create_datetime_tab()
        self.tab_widget.addTab(self.datetime_tab, "DateTime")
        
        layout.addWidget(self.tab_widget)
        
        # Apply Settings button
        self.apply_btn = QPushButton("Apply Settings to Selected")
        self.apply_btn.clicked.connect(self.on_apply_settings)
        layout.addWidget(self.apply_btn)
        
        # Add stretch to push buttons to bottom
        layout.addStretch()
        
    def create_pipeline_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Hostname
        self.hostname_edit = QLineEdit()
        layout.addWidget(QLabel("Hostname:"))
        layout.addWidget(self.hostname_edit)
        
        # External control settings
        self.ext_control_enabled = QCheckBox("Enable external control")
        layout.addWidget(self.ext_control_enabled)
        
        self.use_hostname = QCheckBox("Use device name as hostname")
        self.use_hostname.setChecked(True)
        layout.addWidget(self.use_hostname)
        
        # Logo paths
        self.standby_logo_btn = QPushButton("Select Standby Logo")
        self.standby_logo_btn.clicked.connect(self.select_standby_logo)
        self.standby_logo_path = QLineEdit()
        layout.addWidget(QLabel("Standby Logo:"))
        layout.addWidget(self.standby_logo_btn)
        layout.addWidget(self.standby_logo_path)
        
        self.work_logo_btn = QPushButton("Select Work Logo")
        self.work_logo_btn.clicked.connect(self.select_work_logo)
        self.work_logo_path = QLineEdit()
        layout.addWidget(QLabel("Work Logo:"))
        layout.addWidget(self.work_logo_btn)
        layout.addWidget(self.work_logo_path)
        
        layout.addStretch()
        return tab
    
    def create_tls_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Certificate paths
        self.ebs_test_cert_btn = QPushButton("Select EBS Test Certificate")
        self.ebs_test_cert_btn.clicked.connect(self.select_ebs_test_cert)
        self.ebs_test_cert_path = QLineEdit()
        layout.addWidget(QLabel("EBS Test Certificate:"))
        layout.addWidget(self.ebs_test_cert_btn)
        layout.addWidget(self.ebs_test_cert_path)
        
        self.ebs_prod_cert_btn = QPushButton("Select EBS Prod Certificate")
        self.ebs_prod_cert_btn.clicked.connect(self.select_ebs_prod_cert)
        self.ebs_prod_cert_path = QLineEdit()
        layout.addWidget(QLabel("EBS Prod Certificate:"))
        layout.addWidget(self.ebs_prod_cert_btn)
        layout.addWidget(self.ebs_prod_cert_path)
        
        # TLS Mode
        self.tls_mode_combo = QComboBox()
        self.tls_mode_combo.addItems(["one-way", "two-way"])
        layout.addWidget(QLabel("TLS Mode:"))
        layout.addWidget(self.tls_mode_combo)
        
        # Stage
        self.tls_stage_combo = QComboBox()
        self.tls_stage_combo.addItems(["test", "prod"])
        layout.addWidget(QLabel("Stage:"))
        layout.addWidget(self.tls_stage_combo)
        
        # Start TLS
        self.start_tls_btn = QPushButton("Start TLS")
        layout.addWidget(self.start_tls_btn)
        
        layout.addStretch()
        return tab
    
    def create_firmware_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.firmware_btn = QPushButton("Select Firmware Archive")
        self.firmware_btn.clicked.connect(self.select_firmware)
        self.firmware_path = QLineEdit()
        layout.addWidget(QLabel("Firmware Archive:"))
        layout.addWidget(self.firmware_btn)
        layout.addWidget(self.firmware_path)
        
        layout.addStretch()
        return tab
    
    def create_openvpn_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # IP addresses list
        self.ip_list_group = QGroupBox("IP Addresses")
        ip_layout = QVBoxLayout(self.ip_list_group)
        
        self.ip_list = QVBoxLayout()
        ip_layout.addLayout(self.ip_list)
        
        # Add IP button
        self.add_ip_btn = QPushButton("Add IP Address")
        self.add_ip_btn.clicked.connect(self.add_ip_address)
        ip_layout.addWidget(self.add_ip_btn)
        
        layout.addWidget(self.ip_list_group)
        
        layout.addStretch()
        
        # Initialize with one IP field
        self.add_ip_address()
        return tab
    
    def create_crl_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.crl_btn = QPushButton("Select CRL File")
        self.crl_btn.clicked.connect(self.select_crl)
        self.crl_path = QLineEdit()
        layout.addWidget(QLabel("CRL File:"))
        layout.addWidget(self.crl_btn)
        layout.addWidget(self.crl_path)
        
        layout.addStretch()
        return tab
    
    def create_cert_request_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.cert_request_folder_btn = QPushButton("Select CSR Output Folder")
        self.cert_request_folder_btn.clicked.connect(self.select_cert_request_folder)
        self.cert_request_folder_path = QLineEdit()
        layout.addWidget(QLabel("CSR Output Folder:"))
        layout.addWidget(self.cert_request_folder_btn)
        layout.addWidget(self.cert_request_folder_path)
        
        layout.addStretch()
        return tab
    
    def create_server_cert_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.server_cert_btn = QPushButton("Select Server Certificate")
        self.server_cert_btn.clicked.connect(self.select_server_cert)
        self.server_cert_path = QLineEdit()
        layout.addWidget(QLabel("Server Certificate:"))
        layout.addWidget(self.server_cert_btn)
        layout.addWidget(self.server_cert_path)
        
        layout.addStretch()
        return tab
    
    def create_client_cert_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.client_cert_btn = QPushButton("Select Client Certificate")
        self.client_cert_btn.clicked.connect(self.select_client_cert)
        self.client_cert_path = QLineEdit()
        layout.addWidget(QLabel("Client Certificate:"))
        layout.addWidget(self.client_cert_btn)
        layout.addWidget(self.client_cert_path)
        
        layout.addStretch()
        return tab
    
    def create_datetime_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Time zone
        self.timezone_combo = QComboBox()
        self.timezone_combo.addItems(["Europe/Moscow", "UTC", "Europe/London", "America/New_York"])
        layout.addWidget(QLabel("Time Zone:"))
        layout.addWidget(self.timezone_combo)
        
        # NTP servers
        self.primary_ntp = QLineEdit()
        layout.addWidget(QLabel("Primary NTP Server:"))
        layout.addWidget(self.primary_ntp)
        
        self.secondary_ntp = QLineEdit()
        layout.addWidget(QLabel("Secondary NTP Server:"))
        layout.addWidget(self.secondary_ntp)
        
        layout.addStretch()
        return tab
    
    def add_ip_address(self):
        ip_frame = QFrame()
        ip_frame.setFrameStyle(QFrame.StyledPanel)
        ip_layout = QHBoxLayout(ip_frame)
        
        ip_edit = QLineEdit()
        ip_edit.setPlaceholderText("IP Address")
        ip_layout.addWidget(ip_edit)
        
        port_spin = QSpinBox()
        port_spin.setRange(1, 65535)
        port_spin.setValue(1194)
        ip_layout.addWidget(port_spin)
        
        remove_btn = QPushButton("Remove")
        remove_btn.clicked.connect(lambda: self.remove_ip_address(ip_frame))
        ip_layout.addWidget(remove_btn)
        
        self.ip_list.addWidget(ip_frame)
    
    def remove_ip_address(self, frame):
        self.ip_list.removeWidget(frame)
        frame.deleteLater()
    
    def select_standby_logo(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Standby Logo", "", "Image Files (*.png *.jpg *.jpeg *.gif *.bmp)")
        if file_path:
            self.standby_logo_path.setText(file_path)
    
    def select_work_logo(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Work Logo", "", "Image Files (*.png *.jpg *.jpeg *.gif *.bmp)")
        if file_path:
            self.work_logo_path.setText(file_path)
    
    def select_ebs_test_cert(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select EBS Test Certificate", "", "Certificate Files (*.crt *.pem)")
        if file_path:
            self.ebs_test_cert_path.setText(file_path)
    
    def select_ebs_prod_cert(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select EBS Prod Certificate", "", "Certificate Files (*.crt *.pem)")
        if file_path:
            self.ebs_prod_cert_path.setText(file_path)
    
    def select_firmware(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Firmware Archive", "", "Archive Files (*.tar.gz *.zip)")
        if file_path:
            self.firmware_path.setText(file_path)
    
    def select_crl(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CRL File", "", "CRL Files (*.pem *.crl)")
        if file_path:
            self.crl_path.setText(file_path)
    
    def select_cert_request_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select CSR Output Folder")
        if folder_path:
            self.cert_request_folder_path.setText(folder_path)
    
    def select_server_cert(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Server Certificate", "", "Certificate Files (*.crt *.pem)")
        if file_path:
            self.server_cert_path.setText(file_path)
    
    def select_client_cert(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Client Certificate", "", "Certificate Files (*.crt *.pem)")
        if file_path:
            self.client_cert_path.setText(file_path)
    
    def on_apply_settings(self):
        self.apply_settings_signal.emit()
    
    def get_settings(self):
        settings = {
            'pipeline': {
                'hostname': self.hostname_edit.text(),
                'ext_control_enabled': self.ext_control_enabled.isChecked(),
                'use_hostname': self.use_hostname.isChecked(),
                'standby_logo_path': self.standby_logo_path.text(),
                'work_logo_path': self.work_logo_path.text()
            },
            'tls': {
                'ebs_test_cert_path': self.ebs_test_cert_path.text(),
                'ebs_prod_cert_path': self.ebs_prod_cert_path.text(),
                'tls_mode': self.tls_mode_combo.currentText(),
                'tls_stage': self.tls_stage_combo.currentText()
            },
            'firmware': {
                'firmware_path': self.firmware_path.text()
            },
            'openvpn': {
                'ip_addresses': self.get_ip_addresses()
            },
            'crl': {
                'crl_path': self.crl_path.text()
            },
            'cert_request': {
                'output_folder': self.cert_request_folder_path.text()
            },
            'server_cert': {
                'server_cert_path': self.server_cert_path.text()
            },
            'client_cert': {
                'client_cert_path': self.client_cert_path.text()
            },
            'datetime': {
                'timezone': self.timezone_combo.currentText(),
                'primary_ntp': self.primary_ntp.text(),
                'secondary_ntp': self.secondary_ntp.text()
            }
        }
        return settings
    
    def get_ip_addresses(self):
        ip_addresses = []
        for i in range(self.ip_list.count()):
            widget = self.ip_list.itemAt(i).widget()
            if widget and widget.layout():
                ip_edit = widget.layout().itemAt(0).widget()
                port_spin = widget.layout().itemAt(1).widget()
                if ip_edit and port_spin:
                    ip_addresses.append({
                        'ip': ip_edit.text(),
                        'port': port_spin.value()
                    })
        return ip_addresses
    
    def load_from_config(self, config):
        # Load pipeline settings
        if 'pipeline' in config:
            pipeline = config['pipeline']
            self.hostname_edit.setText(pipeline.get('hostname', ''))
            self.ext_control_enabled.setChecked(pipeline.get('ext_control_enabled', False))
            self.use_hostname.setChecked(pipeline.get('use_hostname', True))
            self.standby_logo_path.setText(pipeline.get('standby_logo_path', ''))
            self.work_logo_path.setText(pipeline.get('work_logo_path', ''))
        
        # Load TLS settings
        if 'tls' in config:
            tls = config['tls']
            self.ebs_test_cert_path.setText(tls.get('ebs_test_cert_path', ''))
            self.ebs_prod_cert_path.setText(tls.get('ebs_prod_cert_path', ''))
            self.tls_mode_combo.setCurrentText(tls.get('tls_mode', 'one-way'))
            self.tls_stage_combo.setCurrentText(tls.get('tls_stage', 'prod'))
        
        # Load firmware settings
        if 'firmware' in config:
            firmware = config['firmware']
            self.firmware_path.setText(firmware.get('firmware_path', ''))
        
        # Load OpenVPN settings
        if 'openvpn' in config:
            openvpn = config['openvpn']
            # Clear existing IP addresses
            for i in reversed(range(self.ip_list.count())):
                widget = self.ip_list.itemAt(i).widget()
                self.ip_list.removeWidget(widget)
                widget.deleteLater()
            # Add IP addresses from config
            for addr in openvpn.get('ip_addresses', []):
                self.add_ip_address()
                # Set the values (implementation depends on how you handle this)
        
        # Load CRL settings
        if 'crl' in config:
            crl = config['crl']
            self.crl_path.setText(crl.get('crl_path', ''))
        
        # Load certificate request settings
        if 'cert_request' in config:
            cert_req = config['cert_request']
            self.cert_request_folder_path.setText(cert_req.get('output_folder', ''))
        
        # Load server certificate settings
        if 'server_cert' in config:
            server_cert = config['server_cert']
            self.server_cert_path.setText(server_cert.get('server_cert_path', ''))
        
        # Load client certificate settings
        if 'client_cert' in config:
            client_cert = config['client_cert']
            self.client_cert_path.setText(client_cert.get('client_cert_path', ''))
        
        # Load datetime settings
        if 'datetime' in config:
            datetime_settings = config['datetime']
            self.timezone_combo.setCurrentText(datetime_settings.get('timezone', 'Europe/Moscow'))
            self.primary_ntp.setText(datetime_settings.get('primary_ntp', ''))
            self.secondary_ntp.setText(datetime_settings.get('secondary_ntp', ''))
    
    def get_config_for_save(self):
        return {
            'pipeline': {
                'hostname': self.hostname_edit.text(),
                'ext_control_enabled': self.ext_control_enabled.isChecked(),
                'use_hostname': self.use_hostname.isChecked(),
                'standby_logo_path': self.standby_logo_path.text(),
                'work_logo_path': self.work_logo_path.text()
            },
            'tls': {
                'ebs_test_cert_path': self.ebs_test_cert_path.text(),
                'ebs_prod_cert_path': self.ebs_prod_cert_path.text(),
                'tls_mode': self.tls_mode_combo.currentText(),
                'tls_stage': self.tls_stage_combo.currentText()
            },
            'firmware': {
                'firmware_path': self.firmware_path.text()
            },
            'openvpn': {
                'ip_addresses': self.get_ip_addresses()
            },
            'crl': {
                'crl_path': self.crl_path.text()
            },
            'cert_request': {
                'output_folder': self.cert_request_folder_path.text()
            },
            'server_cert': {
                'server_cert_path': self.server_cert_path.text()
            },
            'client_cert': {
                'client_cert_path': self.client_cert_path.text()
            },
            'datetime': {
                'timezone': self.timezone_combo.currentText(),
                'primary_ntp': self.primary_ntp.text(),
                'secondary_ntp': self.secondary_ntp.text()
            }
        }