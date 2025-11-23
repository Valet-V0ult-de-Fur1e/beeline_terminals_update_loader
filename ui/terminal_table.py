from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QFileDialog, QComboBox
)
from PySide6.QtCore import Signal, Qt, QThread, QMutex, QMutexLocker
import threading

class TerminalTableWidget(QWidget):
    terminal_status_changed = Signal(int, int)  # current, total
    
    def __init__(self, terminal_manager, sidebar):
        super().__init__()
        self.terminal_manager = terminal_manager
        self.sidebar = sidebar
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Create table
        self.table = QTableWidget()
        self.table.setColumnCount(13)  # Updated column count
        self.table.setHorizontalHeaderLabels([
            "Use", "Host name", "Common name", "City", "Organization", 
            "Primary IP", "Secondary IP", "Local IP", "Password", 
            "IP Type", "Certificate", "Status", "Health Check"
        ])
        
        # Configure table
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        layout.addWidget(self.table)
        
        # Initially show load button
        self.load_button = QPushButton("Load Excel File")
        self.load_button.clicked.connect(self.on_load_excel)
        layout.addWidget(self.load_button)
        
    def on_load_excel(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Excel File", "", "Excel Files (*.xlsx *.xls)")
        if file_path:
            try:
                self.terminal_manager.load_terminals_from_excel(file_path)
                self.refresh_table()
                self.load_button.setVisible(False)
            except Exception as e:
                print(f"Error loading Excel: {e}")
    
    def refresh_table(self):
        self.table.setRowCount(len(self.terminal_manager.terminals))
        
        for row, terminal in enumerate(self.terminal_manager.terminals):
            # Use checkbox
            use_checkbox = QTableWidgetItem()
            use_checkbox.setCheckState(Qt.Checked)
            self.table.setItem(row, 0, use_checkbox)
            
            # Original data
            self.table.setItem(row, 1, QTableWidgetItem(terminal.host_name))
            self.table.setItem(row, 2, QTableWidgetItem(terminal.common_name))
            self.table.setItem(row, 3, QTableWidgetItem(terminal.city))
            self.table.setItem(row, 4, QTableWidgetItem(terminal.org_name))
            self.table.setItem(row, 5, QTableWidgetItem(terminal.primary_ip))
            self.table.setItem(row, 6, QTableWidgetItem(terminal.secondary_ip))
            self.table.setItem(row, 7, QTableWidgetItem(terminal.local_ip))
            self.table.setItem(row, 8, QTableWidgetItem(terminal.password))
            
            # IP Type selection
            ip_combo = QComboBox()
            ip_combo.addItems(["local", "primary", "secondary"])
            # Set current selection based on terminal's active IP
            if terminal.active_ip == terminal.local_ip:
                ip_combo.setCurrentText("local")
            elif terminal.active_ip == terminal.primary_ip:
                ip_combo.setCurrentText("primary")
            elif terminal.active_ip == terminal.secondary_ip:
                ip_combo.setCurrentText("secondary")
            self.table.setCellWidget(row, 9, ip_combo)
            
            # Certificate file selection
            cert_btn = QPushButton("Select")
            cert_btn.clicked.connect(lambda _, r=row: self.select_certificate(r))
            self.table.setCellWidget(row, 10, cert_btn)
            
            # Status
            self.table.setItem(row, 11, QTableWidgetItem("Ready"))
            
            # Health check button
            health_btn = QPushButton("Check Health")
            health_btn.clicked.connect(lambda _, r=row: self.check_health(r))
            self.table.setCellWidget(row, 12, health_btn)
    
    def select_certificate(self, row):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Certificate", "", "Certificate Files (*.crt *.pem)")
        if file_path:
            # Update terminal with certificate path
            if row < len(self.terminal_manager.terminals):
                terminal = self.terminal_manager.terminals[row]
                # You might want to store this in the terminal object
                terminal.client_cert_path = file_path
    
    def check_health(self, row):
        if row < len(self.terminal_manager.terminals):
            terminal = self.terminal_manager.terminals[row]
            
            # Get IP type from combo box and set active IP
            ip_combo = self.table.cellWidget(row, 9)
            if ip_combo:
                ip_type = ip_combo.currentText()
                terminal.set_active_ip(ip_type)
            
            # Update status
            self.table.setItem(row, 11, QTableWidgetItem("Checking..."))
            
            # Perform health check in a separate thread
            def health_check_thread():
                health_result = terminal.check_health()
                if health_result is not None:
                    # Update status in main thread
                    self.table.setItem(row, 11, QTableWidgetItem("Healthy"))
                else:
                    self.table.setItem(row, 11, QTableWidgetItem("Unhealthy"))
            
            thread = threading.Thread(target=health_check_thread)
            thread.daemon = True
            thread.start()
    
    def get_selected_terminals(self):
        selected = []
        for row in range(self.table.rowCount()):
            use_item = self.table.item(row, 0)
            if use_item and use_item.checkState() == Qt.Checked:
                if row < len(self.terminal_manager.terminals):
                    terminal = self.terminal_manager.terminals[row]
                    
                    # Get IP type from combo box and set active IP
                    ip_combo = self.table.cellWidget(row, 9)
                    if ip_combo:
                        ip_type = ip_combo.currentText()
                        terminal.set_active_ip(ip_type)
                    
                    # Add both terminal and row index
                    selected.append((terminal, row))
        return selected
    
    def update_terminal_status(self, row, status):
        """Update status for specific terminal row"""
        if row < self.table.rowCount():
            self.table.setItem(row, 11, QTableWidgetItem(status))