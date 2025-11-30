# ui/main_window.py
import os
import json
from PySide6.QtWidgets import (
    QMainWindow, QHBoxLayout, QWidget, QSplitter, QStatusBar,
    QFileDialog, QMessageBox, QProgressBar, QTabWidget
)
from PySide6.QtCore import Qt, QTimer, Signal
from ui.sidebar import SidebarWidget
from ui.terminal_table import TerminalTableWidget
from core.terminal_manager import TerminalManager
from core.config_manager import ConfigManager

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ATM Terminal Configuration Manager")
        self.setGeometry(100, 100, 1400, 800)
        
        self.config_manager = ConfigManager()
        self.terminal_manager = TerminalManager(self.config_manager)
        
        self.init_ui()
        self.load_config()
        
        # Timer for token refresh
        self.token_refresh_timer = QTimer()
        self.token_refresh_timer.timeout.connect(self.terminal_manager.refresh_all_tokens)
        self.token_refresh_timer.start(50000)  # Refresh every 50 seconds (before 60-second expiry)
        
    def init_ui(self):
        # Create central widget and splitter
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QHBoxLayout(central_widget)
        
        # Create splitter for sidebar and main content
        self.splitter = QSplitter(Qt.Horizontal)
        
        # Create sidebar
        self.sidebar = SidebarWidget(self.terminal_manager)
        self.splitter.addWidget(self.sidebar)
        
        # Create tab widget for main content
        self.tab_widget = QTabWidget()
        
        # Create terminal table
        self.terminal_table = TerminalTableWidget(self.terminal_manager, self.sidebar)
        self.terminal_manager.set_terminal_table_widget(self.terminal_table)  # Connect for status updates
        self.tab_widget.addTab(self.terminal_table, "Terminals")
        
        self.splitter.addWidget(self.tab_widget)
        self.splitter.setSizes([300, 1100])  # Set initial sizes
        
        layout.addWidget(self.splitter)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Create progress bar in status bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Connect signals
        self.sidebar.apply_settings_signal.connect(self.on_apply_active_tab_settings)
        
    def on_load_excel(self, file_path):
        try:
            self.terminal_manager.load_terminals_from_excel(file_path)
            self.terminal_table.refresh_table()
            self.status_bar.showMessage(f"Loaded {len(self.terminal_manager.terminals)} terminals from {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load Excel file: {str(e)}")
    
    def on_apply_active_tab_settings(self, tab_name):
        # Get selected terminals with their row indices
        selected_terminals_with_rows = self.terminal_table.get_selected_terminals()
        if not selected_terminals_with_rows:
            QMessageBox.warning(self, "Warning", "Please select terminals to apply settings")
            return
        
        # Show progress bar
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(selected_terminals_with_rows))
        self.progress_bar.setValue(0)
        
        # Connect progress signal
        self.terminal_manager.progress_updated.connect(self.update_progress)
        
        # Get settings for active tab
        tab_settings = self.sidebar.get_active_tab_settings(tab_name)
        
        # Apply settings to selected terminals
        self.terminal_manager.apply_settings_to_terminals(selected_terminals_with_rows, tab_settings, tab_name)
        
        # Hide progress bar after completion
        self.progress_bar.setVisible(False)
        self.terminal_manager.progress_updated.disconnect(self.update_progress)
    
    def update_progress(self, value, max_value):
        if max_value > 0:
            self.progress_bar.setMaximum(max_value)
            self.progress_bar.setValue(value)
            self.status_bar.showMessage(f"Progress: {value}/{max_value}")
    
    def load_config(self):
        try:
            config = self.config_manager.load_config()
            if config:
                self.sidebar.load_from_config(config)
        except Exception as e:
            print(f"Error loading config: {e}")
    
    def closeEvent(self, event):
        # Save config on close
        try:
            config = self.sidebar.get_config_for_save()
            self.config_manager.save_config(config)
        except Exception as e:
            print(f"Error saving config: {e}")
        event.accept()