# ui/terminal_table.py
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QFileDialog, QComboBox
)
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import Signal, Qt, QThread, QMutex, QMutexLocker, QUrl # Добавим QUrl
import threading
import os
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
        # Увеличиваем количество колонок на 2 (для Пин-кода и Временной зоны) + 1 для WEB
        # Было: Use, Host name, Common name, City, Organization, Primary IP, Secondary IP, Local IP, Password, IP Type, Certificate, Status, Health Check (13)
        # Стало: Use, Host name, Common name, City, Organization, Primary IP, Secondary IP, Local IP, Password, IP Type, Certificate, User Certificate, Status, Health Check, WEB, Pin Code, Timezone (17)
        self.table.setColumnCount(17)
        self.table.setHorizontalHeaderLabels([
            "Use", "Host name", "Common name", "City", "Organization",
            "Primary IP", "Secondary IP", "Local IP", "Password",
            "IP Type", "Certificate", "User Certificate", "Status", "Health Check", "WEB", "Pin Code", "Timezone" # Добавлены Pin Code, Timezone
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
                # Убираем скрытие кнопки, чтобы её можно было использовать снова
                # self.load_button.setVisible(False) # Закомментируем или удалим эту строку
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
            # IP Type selection - колонка 9
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
            # Certificate file selection button (CA сертификат) - колонка 10
            cert_btn = QPushButton("Select")
            cert_btn.clicked.connect(lambda _, r=row: self.select_user_certificate(r)) # Обработчик для CA сертификата
            self.table.setCellWidget(row, 10, cert_btn) # Устанавливаем кнопку в ячейку колонки Certificate
            # User Certificate path display (пользовательский сертификат) - колонка 11
            user_cert_path = getattr(terminal, 'user_cert_path', '') # Получаем путь к пользовательскому сертификату
            self.table.setItem(row, 11, QTableWidgetItem(user_cert_path)) # Устанавливаем путь в ячейку колонки User Certificate
            # Status - колонка 12
            status_item = QTableWidgetItem("Ready")
            self.set_status_color(status_item, "Ready") # Применяем цвет при инициализации
            self.table.setItem(row, 12, status_item) # Устанавливаем ячейку в колонке Status
            # Health check button - колонка 13
            health_btn = QPushButton("Check Health")
            health_btn.clicked.connect(lambda _, r=row: self.check_health(r))
            self.table.setCellWidget(row, 13, health_btn) # Устанавливаем кнопку в ячейку колонки Health Check
            # WEB button - колонка 14
            web_btn = QPushButton("WEB")
            web_btn.clicked.connect(lambda _, r=row: self.open_web(r)) # Обработчик для открытия веб-интерфейса
            self.table.setCellWidget(row, 14, web_btn) # Устанавливаем кнопку в ячейку колонки WEB
            # Pin Code (новый столбец, индекс 15)
            # Используем str(), чтобы гарантировать строковое значение, даже если атрибут не определен (хотя теперь он должен быть)
            self.table.setItem(row, 15, QTableWidgetItem(str(terminal.pin_code)))
            # Timezone (новый столбец, индекс 16)
            # Используем str(), чтобы гарантировать строковое значение, даже если атрибут не определен (хотя теперь он должен быть)
            self.table.setItem(row, 16, QTableWidgetItem(str(terminal.timezone)))

    def select_user_certificate(self, row): # Это для User сертификата (теперь просто устанавливает путь в колонку 11)
        file_path, _ = QFileDialog.getOpenFileName(self, "Select User Certificate", "", "Certificate Files (*.crt *.pem)")
        if file_path:
            # Сохраняем путь к пользовательскому сертификату в терминале
            if row < len(self.terminal_manager.terminals):
                terminal = self.terminal_manager.terminals[row]
                if not hasattr(terminal, 'user_cert_path'):
                    terminal.user_cert_path = ""
                terminal.user_cert_path = file_path
                # Обновляем ячейку в таблице (колонка User Certificate)
                item = QTableWidgetItem(file_path)
                self.table.setItem(row, 11, item)

    def open_web(self, row):
        """Открывает веб-интерфейс терминала в браузере."""
        if row < len(self.terminal_manager.terminals):
            terminal = self.terminal_manager.terminals[row]
            # Формируем URL
            url = f"http://{terminal.active_ip}:4011"
            print(f"Opening web interface for terminal {terminal.device_id} at {url}")
            # Открываем URL в браузере по умолчанию
            QDesktopServices.openUrl(QUrl(url))

    def check_health(self, row):
        if row < len(self.terminal_manager.terminals):
            terminal = self.terminal_manager.terminals[row]
            # Get IP type from combo box and set active IP
            ip_combo = self.table.cellWidget(row, 9)
            if ip_combo:
                ip_type = ip_combo.currentText()
                terminal.set_active_ip(ip_type)
            # Update status in Status column (12) with color
            checking_item = QTableWidgetItem("Checking...")
            self.set_status_color(checking_item, "Checking...")
            self.table.setItem(row, 12, checking_item) # Обновляем ячейку в колонке Status (12) - Исправлено
            # Perform health check in a separate thread
            def health_check_thread():
                health_result = terminal.check_health()
                if health_result is not None:
                    # Update status in main thread in Status column (12) with color
                    healthy_item = QTableWidgetItem("Healthy")
                    self.set_status_color(healthy_item, "Healthy")
                    self.table.setItem(row, 12, healthy_item) # Обновляем ячейку в колонке Status (12) - Исправлено
                else:
                    unhealthy_item = QTableWidgetItem("Unhealthy")
                    self.set_status_color(unhealthy_item, "Unhealthy")
                    self.table.setItem(row, 12, unhealthy_item) # Обновляем ячейку в колонке Status (12) - Исправлено
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
                    ip_combo = self.table.cellWidget(row, 9) # Используется правильно
                    if ip_combo:
                        ip_type = ip_combo.currentText()
                        terminal.set_active_ip(ip_type)
                    # Add both terminal and row index
                    selected.append((terminal, row))
        return selected

    def set_status_color(self, item, status_text):
        """Устанавливает цвет текста для ячейки статуса."""
        status_lower = status_text.lower()
        if any(word in status_lower for word in ['failed', 'error', 'unhealthy']):
            item.setForeground(Qt.red)
        elif any(word in status_lower for word in ['completed', 'success', 'healthy']):
            item.setForeground(Qt.green)
        elif any(word in status_lower for word in ['checking', 'applying']):
            item.setForeground(Qt.blue)
        else:
            # Для "Ready", "Error: ..." и других - цвет по умолчанию
            item.setForeground(self.table.palette().text().color()) # Возвращает цвет текста по умолчанию


    def update_terminal_status(self, row, status):
        """Update status for specific terminal row"""
        if row < self.table.rowCount():
            item = QTableWidgetItem(status)
            self.set_status_color(item, status) # Применяем цвет
            self.table.setItem(row, 12, item) # Обновляем ячейку в колонке Status (12) - Исправлено

    def update_user_cert_in_table(self, terminal, cert_path):
        """Обновляет ячейку пользовательского сертификата в таблице."""
        # Найдем строку для данного терминала
        for row in range(self.table.rowCount()):
            host_name_item = self.table.item(row, 1) # Колонка Host name
            if host_name_item and host_name_item.text() == terminal.host_name:
                item = QTableWidgetItem(cert_path)
                self.table.setItem(row, 11, item) # Колонка User Certificate (11) - Исправлено
                # Также обновляем атрибут в терминале, если нужно
                if not hasattr(terminal, 'user_cert_path'):
                    terminal.user_cert_path = ""
                terminal.user_cert_path = cert_path
                break # Предполагаем уникальность host_name