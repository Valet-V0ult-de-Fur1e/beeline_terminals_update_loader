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
from datetime import datetime, timezone
import pytz # Необходимо установить: pip install pytz
import threading # Необходимо для health_check_all

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
        # self.sidebar.set_terminal_table_widget(self.terminal_table) # ПЕРЕНОСИМ ЭТУ СТРОКУ
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
        # Connect new signals
        self.sidebar.reset_password_signal.connect(self.on_reset_password)
        self.sidebar.set_password_signal.connect(self.on_set_password)
        self.sidebar.health_check_signal.connect(self.on_health_check_all)
        self.sidebar.set_individual_datetime_signal.connect(self.on_set_individual_datetime)
        self.sidebar.set_common_datetime_signal.connect(self.on_set_common_datetime)

        # ПЕРЕНОСИМ СЮДА ПОСЛЕ СОЗДАНИЯ self.terminal_table
        self.sidebar.set_terminal_table_widget(self.terminal_table) # Передаём таблицу в sidebar


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

    # --- НОВЫЕ ОБРАБОТЧИКИ ---

    def on_reset_password(self):
        selected_terminals_with_rows = self.terminal_table.get_selected_terminals()
        if not selected_terminals_with_rows:
            QMessageBox.warning(self, "Warning", "Please select terminals to reset password")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(selected_terminals_with_rows))
        self.progress_bar.setValue(0)
        completed_count = 0

        for terminal, row in selected_terminals_with_rows:
            # Use the pin code from the terminal object (updated in get_selected_terminals)
            pin_code = terminal.pin_code
            if not pin_code:
                print(f"No pin code found for terminal {terminal.device_id}, skipping reset.")
                self.terminal_table.update_terminal_status(row, f"Reset failed: No pin")
                completed_count += 1
                self.progress_bar.setValue(completed_count)
                continue

            try:
                success = terminal.reset_password(pin_code)
                if success:
                    self.terminal_table.update_terminal_status(row, f"Password reset completed")
                else:
                    self.terminal_table.update_terminal_status(row, f"Password reset failed")
            except Exception as e:
                print(f"Reset password failed for terminal {terminal.device_id}: {e}")
                self.terminal_table.update_terminal_status(row, f"Reset error: {str(e)}")
            finally:
                completed_count += 1
                self.progress_bar.setValue(completed_count)

        self.progress_bar.setVisible(False)

    def on_set_password(self):
        selected_terminals_with_rows = self.terminal_table.get_selected_terminals()
        if not selected_terminals_with_rows:
            QMessageBox.warning(self, "Warning", "Please select terminals to set password")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(selected_terminals_with_rows))
        self.progress_bar.setValue(0)
        completed_count = 0

        for terminal, row in selected_terminals_with_rows:
            try:
                # Use the password from the terminal object (from table)
                password = terminal.password
                result = terminal.set_password()
                if result: # Assuming set_password returns something on success
                    self.terminal_table.update_terminal_status(row, f"Password set completed")
                else:
                    self.terminal_table.update_terminal_status(row, f"Password set failed")
            except Exception as e:
                print(f"Set password failed for terminal {terminal.device_id}: {e}")
                self.terminal_table.update_terminal_status(row, f"Set error: {str(e)}")
            finally:
                completed_count += 1
                self.progress_bar.setValue(completed_count)

        self.progress_bar.setVisible(False)

    def on_health_check_all(self):
        # This will trigger health checks for all selected terminals
        # We can reuse the check_health logic from terminal_table but for all selected
        selected_terminals_with_rows = self.terminal_table.get_selected_terminals()
        if not selected_terminals_with_rows:
            QMessageBox.warning(self, "Warning", "Please select terminals to check health")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(selected_terminals_with_rows))
        self.progress_bar.setValue(0)
        completed_count = 0

        def health_check_thread(terminal, row):
            health_result = terminal.check_health()
            # Update status in main thread (this needs to be done carefully with threading)
            # For simplicity, we update status directly here, assuming it's safe in this context
            # or use QTimer.singleShot to schedule the update in the main thread
            if health_result is not None:
                self.terminal_table.update_terminal_status(row, f"Healthy")
            else:
                self.terminal_table.update_terminal_status(row, f"Unhealthy")

        threads = []
        for terminal, row in selected_terminals_with_rows:
            thread = threading.Thread(target=health_check_thread, args=(terminal, row))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
            completed_count += 1
            self.progress_bar.setValue(completed_count)

        self.progress_bar.setVisible(False)

    def on_set_individual_datetime(self):
        selected_terminals_with_rows = self.terminal_table.get_selected_terminals()
        if not selected_terminals_with_rows:
            QMessageBox.warning(self, "Warning", "Please select terminals to set individual datetime")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(selected_terminals_with_rows))
        self.progress_bar.setValue(0)
        completed_count = 0

        for terminal, row in selected_terminals_with_rows:
            try:
                # Get timezone from the terminal object (updated in get_selected_terminals)
                tz_str = terminal.timezone
                if not tz_str:
                    print(f"No timezone found for terminal {terminal.device_id}, skipping datetime set.")
                    self.terminal_table.update_terminal_status(row, f"DateTime set failed: No timezone")
                    completed_count += 1
                    self.progress_bar.setValue(completed_count)
                    continue

                # Set current time in Moscow first
                moscow_tz = pytz.timezone('Europe/Moscow')
                moscow_time = datetime.now(moscow_tz)
                # Then convert to the terminal's timezone
                target_tz = pytz.timezone(tz_str)
                target_time = moscow_time.astimezone(target_tz)
                formatted_datetime = target_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

                result1 = terminal.set_datetime(formatted_datetime)
                result2 = terminal.set_datetime_settings(
                    timezone=tz_str,
                    primary_ntp_server="", # Use values from sidebar if needed
                    secondary_ntp_server=""
                )

                if result1 is not None and result2 is not None:
                    self.terminal_table.update_terminal_status(row, f"Individual DateTime set completed")
                else:
                    self.terminal_table.update_terminal_status(row, f"Individual DateTime set failed")
            except Exception as e:
                print(f"Individual DateTime set failed for terminal {terminal.device_id}: {e}")
                self.terminal_table.update_terminal_status(row, f"DateTime error: {str(e)}")
            finally:
                completed_count += 1
                self.progress_bar.setValue(completed_count)

        self.progress_bar.setVisible(False)

    def on_set_common_datetime(self):
        selected_terminals_with_rows = self.terminal_table.get_selected_terminals()
        if not selected_terminals_with_rows:
            QMessageBox.warning(self, "Warning", "Please select terminals to set common datetime")
            return

        # Get timezone from sidebar
        common_timezone = self.sidebar.timezone_combo.currentText()
        primary_ntp = self.sidebar.primary_ntp.text()
        secondary_ntp = self.sidebar.secondary_ntp.text()

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(selected_terminals_with_rows))
        self.progress_bar.setValue(0)
        completed_count = 0

        # Set current time in Moscow first
        moscow_tz = pytz.timezone('Europe/Moscow')
        moscow_time = datetime.now(moscow_tz)
        # Then convert to the common timezone
        target_tz = pytz.timezone(common_timezone)
        target_time = moscow_time.astimezone(target_tz)
        formatted_datetime = target_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        for terminal, row in selected_terminals_with_rows:
            try:
                result1 = terminal.set_datetime(formatted_datetime)
                result2 = terminal.set_datetime_settings(
                    timezone=common_timezone,
                    primary_ntp_server=primary_ntp,
                    secondary_ntp_server=secondary_ntp
                )

                if result1 is not None and result2 is not None:
                    self.terminal_table.update_terminal_status(row, f"Common DateTime set completed")
                else:
                    self.terminal_table.update_terminal_status(row, f"Common DateTime set failed")
            except Exception as e:
                print(f"Common DateTime set failed for terminal {terminal.device_id}: {e}")
                self.terminal_table.update_terminal_status(row, f"DateTime error: {str(e)}")
            finally:
                completed_count += 1
                self.progress_bar.setValue(completed_count)

        self.progress_bar.setVisible(False)


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