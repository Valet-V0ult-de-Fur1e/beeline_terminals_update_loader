from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QFileDialog, QComboBox, QCheckBox
)
from PySide6.QtCore import Signal, Qt, QThread, QMutex, QMutexLocker
from PySide6.QtGui import QBrush, QColor
import threading
import os
import webbrowser # Добавляем импорт для открытия веб-ссылки

class TerminalTableWidget(QWidget):
    terminal_status_changed = Signal(int, int)  # current, total

    def __init__(self, terminal_manager, sidebar):
        super().__init__()
        self.terminal_manager = terminal_manager
        self.sidebar = sidebar # Для доступа к вкладке Client Cert, если понадобится
        # self.certificate_folder_path = "" # Больше не нужно хранить здесь
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # Create table
        self.table = QTableWidget()
        # Обновляем количество столбцов: Use, Host name, Common name, City, Org, Primary IP, Secondary IP, Local IP, Password, Pin-code, Timezone, Certificate File, Cert Path, Status, Health Check, WEB
        self.table.setColumnCount(16) # Увеличено на 1
        self.table.setHorizontalHeaderLabels([
            "Use", "Host name", "Common name", "City", "Organization",
            "Primary IP", "Secondary IP", "Local IP", "Password", "Pin-code", "Timezone",
            "Certificate File", "Cert Path", "Status", "Health Check", "WEB" # Добавлен Cert Path
        ])

        # Configure table
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)

        # Button to load new Excel file
        self.load_button = QPushButton("Load New Excel File")
        self.load_button.clicked.connect(self.on_load_new_excel)
        layout.addWidget(self.load_button)

    def on_load_new_excel(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Load Excel File", "", "Excel Files (*.xlsx *.xls)")
        if file_path:
            try:
                self.terminal_manager.load_terminals_from_excel(file_path)
                self.refresh_table()
                self.load_button.setVisible(True) # Кнопка загрузки всегда видна
            except Exception as e:
                print(f"Error loading Excel: {e}")

    def refresh_table(self):
        self.table.setRowCount(len(self.terminal_manager.terminals))

        for row, terminal in enumerate(self.terminal_manager.terminals):
            # Use checkbox
            use_checkbox = QTableWidgetItem()
            use_checkbox.setCheckState(Qt.Checked)
            self.table.setItem(row, 0, use_checkbox)

            # Original data (updated columns)
            self.table.setItem(row, 1, QTableWidgetItem(terminal.host_name))
            self.table.setItem(row, 2, QTableWidgetItem(terminal.common_name))
            self.table.setItem(row, 3, QTableWidgetItem(terminal.city))
            self.table.setItem(row, 4, QTableWidgetItem(terminal.org_name))
            self.table.setItem(row, 5, QTableWidgetItem(terminal.primary_ip))
            self.table.setItem(row, 6, QTableWidgetItem(terminal.secondary_ip))
            self.table.setItem(row, 7, QTableWidgetItem(terminal.local_ip))
            self.table.setItem(row, 8, QTableWidgetItem(terminal.password))
            # Pin-code - теперь отображаем
            self.table.setItem(row, 9, QTableWidgetItem(terminal.pin_code))
            # Timezone
            tz_combo = QComboBox()
            tz_combo.addItems(self.sidebar.timezones) # Используем таймзоны из sidebar
            tz_combo.setCurrentText(terminal.timezone) # Устанавливаем значение из терминала по умолчанию
            self.table.setCellWidget(row, 10, tz_combo)

            # Certificate file selection - NOW a file selection button
            cert_btn = QPushButton("Select File") # Изменяем текст кнопки
            cert_btn.clicked.connect(lambda _, r=row: self.select_certificate_file(r)) # Изменяем вызываемый метод
            self.table.setCellWidget(row, 11, cert_btn) # Столбец 11 - Certificate File

            # Certificate File Path - отображаем путь из объекта терминала
            cert_path_item = QTableWidgetItem(terminal.client_cert_path if hasattr(terminal, 'client_cert_path') and terminal.client_cert_path else "Not selected")
            self.table.setItem(row, 12, cert_path_item) # Столбец 12 - Cert Path

            # Status
            status_item = QTableWidgetItem("Ready")
            status_item.setBackground(QBrush(QColor(255, 255, 255))) # Default white
            self.table.setItem(row, 13, status_item) # Столбец 13 - Status

            # Health check button
            health_btn = QPushButton("Check Health")
            health_btn.clicked.connect(lambda _, r=row: self.check_health(r))
            self.table.setCellWidget(row, 14, health_btn) # Столбец 14 - Health Check

            # WEB button
            web_btn = QPushButton("ВЕБ")
            web_btn.clicked.connect(lambda _, r=row: self.open_web(r))
            self.table.setCellWidget(row, 15, web_btn) # Столбец 15 - WEB

    def select_certificate_file(self, row):
        """Открывает диалог выбора файла сертификата для конкретного терминала."""
        if row < len(self.terminal_manager.terminals):
            terminal = self.terminal_manager.terminals[row]
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select Certificate File", "", "Certificate Files (*.crt *.pem)"
            )
            if file_path:
                # Сохраняем путь к файлу в объекте терминала
                terminal.client_cert_path = file_path
                # Обновляем ячейку с путем
                cert_path_item = QTableWidgetItem(file_path)
                self.table.setItem(row, 12, cert_path_item) # Столбец 12 - Cert Path
                print(f"Certificate file selected for {terminal.device_id} ({terminal.common_name}): {file_path}")
            else:
                print(f"No file selected for terminal {terminal.device_id} ({terminal.common_name}).")

    def open_web(self, row):
        if row < len(self.terminal_manager.terminals):
            terminal = self.terminal_manager.terminals[row]
            url = f"http://{terminal.active_ip}:4011/"
            webbrowser.open(url)

    def check_health(self, row):
        if row < len(self.terminal_manager.terminals):
            terminal = self.terminal_manager.terminals[row]

            # Get IP type from combo box and set active IP
            # ip_combo = self.table.cellWidget(row, 9) # Предположим, IP type combo теперь в столбце 9, остальные сдвинулись
            # НО ВОТ ЭТО НЕВЕРНО - IP TYPE COMBO ТЕПЕРЬ В СТОЛБЦЕ 9 - НЕТ, ОН БЫЛ В 9, А СЕЙЧАС В 10 ИЛИ 11?
            # НЕТ, СТОЛБЕЦ IP TYPE УБРАЛИ, ТЕПЕРЬ ТОЛЬКО ACTIVE IP УСТАНАВЛИВАЕТСЯ В ТЕРМИНАЛЕ ПРИ ЗАПУСКЕ ОПЕРАЦИИ
            # ПОЭТОМУ МЫ БУДЕМ УСТАНАВЛИВАТЬ IP ТИП В sidebar ИЛИ main_window ПРИ ЗАПУСКЕ ОПЕРАЦИИ
            # ПОКА ОСТАВИМ ТАК, КАК ЭТОГО СТОЛБЦА НЕТ В НОВОЙ ТАБЛИЦЕ
            # ПРЕДПОЛОЖИМ, ЧТО active_ip УСТАНАВЛИВАЕТСЯ В sidebar ИЛИ main_window

            # Update status
            status_item = self.table.item(row, 13) # Столбец 13 - Status
            if status_item:
                status_item.setText("Checking...")
                status_item.setBackground(QBrush(QColor(255, 255, 0))) # Yellow for checking

            # Perform health check in a separate thread
            def health_check_thread():
                health_result = terminal.check_health()
                # Update status in main thread
                if health_result is not None:
                    status_item.setText("Healthy")
                    status_item.setBackground(QBrush(QColor(144, 238, 144))) # Light green
                else:
                    status_item.setText("Unhealthy")
                    status_item.setBackground(QBrush(QColor(255, 182, 193))) # Light pink

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

                    # Get timezone from combo box and update terminal object
                    tz_combo = self.table.cellWidget(row, 10) # Столбец 10 - Timezone
                    if tz_combo:
                        terminal.timezone = tz_combo.currentText()

                    # Get Pin-code from table item and update terminal object
                    pin_item = self.table.item(row, 9) # Столбец 9 - Pin-code
                    if pin_item:
                        terminal.pin_code = pin_item.text() # Обновляем pin_code из таблицы

                    # Add both terminal and row index
                    selected.append((terminal, row))
        return selected

    def update_terminal_status(self, row, status):
        """Update status for specific terminal row"""
        if row < self.table.rowCount():
            status_item = self.table.item(row, 13) # Столбец 13 - Status
            if status_item:
                status_item.setText(status)
                # Устанавливаем цвет фона в зависимости от статуса
                if "completed" in status.lower():
                    status_item.setBackground(QBrush(QColor(144, 238, 144))) # Light green
                elif "failed" in status.lower() or "error" in status.lower() or "unhealthy" in status.lower():
                    status_item.setBackground(QBrush(QColor(255, 182, 193))) # Light pink
                elif "checking" in status.lower():
                    status_item.setBackground(QBrush(QColor(255, 255, 0))) # Yellow
                elif "ready" in status.lower():
                    status_item.setBackground(QBrush(QColor(255, 255, 255))) # White
                else:
                    # Default color for other statuses
                    status_item.setBackground(QBrush(QColor(255, 255, 255))) # White