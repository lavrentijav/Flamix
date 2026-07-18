"""GUI приложение для управления модулями и правилами файрвола"""

import sys
import os
import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QMessageBox,
    QProgressBar,
    QComboBox,
    QInputDialog,
    QDialog,
    QDialogButtonBox,
    QRadioButton,
    QLineEdit,
    QGroupBox,
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
import logging

# Импортируем существующие модули проекта
# Добавляем текущую директорию (где лежит flamix/) в путь для импорта
sys.path.insert(0, str(Path(__file__).parent))
from flamix.database.rules_db import RulesDB
from flamix.config import DB_PATH, ensure_directories

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# IP для работы (по умолчанию)
DEFAULT_TARGET_IP = "131.107.255.255"

def load_netsh_output_from_file(file_path: Path) -> str:
    """Загрузка вывода netsh из файла rs.txt"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Пропускаем заголовки PowerShell (первые 6 строк)
        # Ищем начало команды netsh
        start_idx = 0
        for i, line in enumerate(lines):
            if 'netsh advfirewall firewall show rule name=all' in line:
                start_idx = i + 1
                break
        
        # Пропускаем пустую строку после команды
        if start_idx < len(lines) and not lines[start_idx].strip():
            start_idx += 1
        
        # Убираем последние строки с "ОК." и "PS C:\Users\..."
        end_idx = len(lines)
        for i in range(len(lines) - 1, start_idx, -1):
            line = lines[i].strip()
            if line == "ОК." or line.startswith("PS C:\\"):
                end_idx = i
                break
        
        # Извлекаем только правила
        rules_lines = lines[start_idx:end_idx]
        return ''.join(rules_lines)
    except Exception as e:
        logger.error(f"Ошибка загрузки файла rs.txt: {e}")
        return ""


class ModuleLoaderThread(QThread):
    """Поток для загрузки модулей"""
    progress = Signal(str)
    finished = Signal(bool, str)
    plugins_loaded = Signal(list)
    
    def __init__(self, plugins_dir: Path):
        super().__init__()
        self.plugins_dir = plugins_dir
    
    def run(self):
        """Загрузка модулей"""
        try:
            self.progress.emit("Подключаем модули...")
            self.msleep(500)
            
            # Читаем плагины из папки
            self.progress.emit("Сканирование папки plugins...")
            plugins = self.scan_plugins()
            self.msleep(400)
            
            # Имитация загрузки каждого плагина
            loaded_plugins = []
            for plugin in plugins:
                plugin_name = plugin.get("name", "Unknown")
                self.progress.emit(f"Загрузка плагина: {plugin_name}...")
                self.msleep(300)
                loaded_plugins.append(plugin)
                self.progress.emit(f"Плагин {plugin_name} загружен")
                self.msleep(200)
            
            self.progress.emit("Инициализация CLI...")
            self.msleep(300)
            
            self.progress.emit("Подключение к базе данных...")
            self.msleep(400)
            
            self.progress.emit("Чтение правил с компьютера...")
            self.msleep(600)
            
            self.progress.emit("Сохранение правил в БД...")
            self.msleep(500)
            
            self.progress.emit("Модули успешно подключены!")
            self.plugins_loaded.emit(loaded_plugins)
            self.finished.emit(True, "Успешно")
        except Exception as e:
            logger.error(f"Ошибка загрузки модулей: {e}")
            self.finished.emit(False, str(e))
    
    def scan_plugins(self) -> List[Dict[str, Any]]:
        """Сканирование папки plugins для поиска плагинов"""
        plugins = []
        
        if not self.plugins_dir.exists():
            logger.warning(f"Папка plugins не найдена: {self.plugins_dir}")
            return plugins
        
        # Ищем папки с плагинами
        for plugin_folder in self.plugins_dir.iterdir():
            if not plugin_folder.is_dir():
                continue
            
            manifest_path = plugin_folder / "manifest.json"
            if manifest_path.exists():
                try:
                    with open(manifest_path, 'r', encoding='utf-8') as f:
                        manifest = json.load(f)
                    
                    plugins.append({
                        "id": manifest.get("id", plugin_folder.name),
                        "name": manifest.get("name", plugin_folder.name),
                        "version": manifest.get("version", "1.0.0"),
                        "path": str(plugin_folder),
                        "manifest": manifest
                    })
                    logger.info(f"Найден плагин: {manifest.get('name')} ({manifest.get('id')})")
                except Exception as e:
                    logger.error(f"Ошибка чтения манифеста {manifest_path}: {e}")
        
        return plugins


class MainWindow(QMainWindow):
    """Главное окно приложения"""
    
    def __init__(self):
        super().__init__()
        self.db = None
        self.loaded_plugins = []
        self.rules_loaded = False
        # Плагины лежат рядом (в _dist/app/plugins)
        self.plugins_dir = Path(__file__).parent / "plugins"
        self.current_ip = DEFAULT_TARGET_IP
        self.selected_firewall = "netsh"
        self.block_type = "full"  # "full" или "port"
        self.block_port = None
        self.init_ui()
        self.init_database()
        
    def init_ui(self):
        """Инициализация интерфейса"""
        self.setWindowTitle("Flamix - Управление IP")
        self.setGeometry(100, 100, 1000, 800)
        
        # Центральный виджет
        central_widget = QWidget()
        layout = QVBoxLayout()
        
        # Заголовок
        title = QLabel("Управление модулями и правилами файрвола")
        title.setStyleSheet("font-size: 18px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)
        
        # Выбор файрвола
        firewall_layout = QHBoxLayout()
        firewall_label = QLabel("Файрвол:")
        self.firewall_combo = QComboBox()
        self.firewall_combo.addItem("Windows Firewall (netsh)")
        self.firewall_combo.setEnabled(False)  # Пока только один вариант
        firewall_layout.addWidget(firewall_label)
        firewall_layout.addWidget(self.firewall_combo)
        firewall_layout.addStretch()
        layout.addLayout(firewall_layout)
        
        # Кнопка загрузки модулей
        self.load_btn = QPushButton("Подключить модули")
        self.load_btn.clicked.connect(self.load_modules)
        layout.addWidget(self.load_btn)
        
        # Прогресс-бар
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Текстовое поле для логов
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(150)
        layout.addWidget(QLabel("Лог операций:"))
        layout.addWidget(self.log_text)
        
        # Информация о загруженных плагинах
        self.plugins_label = QLabel("Загруженные плагины: нет")
        layout.addWidget(self.plugins_label)
        
        # Кнопки управления IP
        ip_layout = QHBoxLayout()
        self.block_btn = QPushButton("Заблокировать IP")
        self.block_btn.clicked.connect(self.block_ip)
        self.block_btn.setEnabled(False)
        
        self.unblock_btn = QPushButton("Разблокировать IP")
        self.unblock_btn.clicked.connect(self.unblock_ip)
        self.unblock_btn.setEnabled(False)
        
        self.check_btn = QPushButton("Проверить доступность")
        self.check_btn.clicked.connect(self.check_accessibility)
        self.check_btn.setEnabled(False)
        
        ip_layout.addWidget(self.block_btn)
        ip_layout.addWidget(self.unblock_btn)
        ip_layout.addWidget(self.check_btn)
        layout.addLayout(ip_layout)
        
        # Информация об IP и кнопка выбора
        ip_info_layout = QHBoxLayout()
        self.ip_label = QLabel(f"Выбранный IP: {self.current_ip}")
        select_ip_btn = QPushButton("Выбрать IP")
        select_ip_btn.clicked.connect(self.select_ip)
        ip_info_layout.addWidget(self.ip_label)
        ip_info_layout.addWidget(select_ip_btn)
        ip_info_layout.addStretch()
        layout.addLayout(ip_info_layout)
        
        # Таблица правил
        rules_label = QLabel("Текущие правила из базы данных:")
        rules_label.setStyleSheet("font-weight: bold; padding-top: 10px;")
        layout.addWidget(rules_label)
        
        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(4)
        self.rules_table.setHorizontalHeaderLabels(["ID", "Имя", "IP", "Действие"])
        self.rules_table.setColumnWidth(0, 50)
        self.rules_table.setColumnWidth(1, 200)
        self.rules_table.setColumnWidth(2, 150)
        self.rules_table.setColumnWidth(3, 100)
        layout.addWidget(self.rules_table)
        
        # Кнопка обновления правил
        refresh_btn = QPushButton("Обновить правила")
        refresh_btn.clicked.connect(self.refresh_rules)
        layout.addWidget(refresh_btn)
        
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        
    def init_database(self):
        """Инициализация базы данных"""
        try:
            ensure_directories()
            self.db = RulesDB(DB_PATH)
            self.db.initialize()
            logger.info("База данных инициализирована")
        except Exception as e:
            logger.error(f"Ошибка инициализации БД: {e}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось инициализировать БД: {e}")
    
    def log_message(self, message: str):
        """Добавление сообщения в лог"""
        self.log_text.append(f"[{self.get_timestamp()}] {message}")
        logger.info(message)
    
    def get_timestamp(self) -> str:
        """Получение временной метки"""
        from datetime import datetime
        return datetime.now().strftime("%H:%M:%S")
    
    def load_modules(self):
        """Загрузка модулей"""
        self.load_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Неопределенный прогресс
        
        self.log_message("Начинаем загрузку модулей...")
        
        # Запускаем поток загрузки
        self.loader_thread = ModuleLoaderThread(self.plugins_dir)
        self.loader_thread.progress.connect(self.on_progress)
        self.loader_thread.plugins_loaded.connect(self.on_plugins_loaded)
        self.loader_thread.finished.connect(self.on_modules_loaded)
        self.loader_thread.start()
    
    def on_progress(self, message: str):
        """Обработка прогресса загрузки"""
        self.log_message(message)
    
    def on_plugins_loaded(self, plugins: List[Dict[str, Any]]):
        """Обработка загруженных плагинов"""
        self.loaded_plugins = plugins
        if plugins:
            plugin_names = ", ".join([p.get("name", "Unknown") for p in plugins])
            self.plugins_label.setText(f"Загруженные плагины: {plugin_names}")
            self.log_message(f"Загружено плагинов: {len(plugins)}")
            for plugin in plugins:
                self.log_message(f"  - {plugin.get('name')} v{plugin.get('version')}")
        else:
            self.plugins_label.setText("Загруженные плагины: нет")
            self.log_message("Плагины не найдены")
    
    def on_modules_loaded(self, success: bool, message: str):
        """Обработка завершения загрузки"""
        self.progress_bar.setVisible(False)
        self.load_btn.setEnabled(True)
        
        if success:
            self.log_message("[OK] Модули успешно загружены!")
            self.load_rules_from_system()
            self.block_btn.setEnabled(True)
            self.unblock_btn.setEnabled(True)
            self.check_btn.setEnabled(True)
        else:
            self.log_message(f"[ERROR] Ошибка загрузки: {message}")
            QMessageBox.critical(self, "Ошибка", f"Не удалось загрузить модули: {message}")
    
    def load_rules_from_system(self):
        """Чтение правил с компьютера через netsh и сохранение в БД"""
        try:
            self.log_message("Читаем правила с компьютера через netsh...")
            
            # Используем реальный netsh для чтения правил
            cmd = [
                "netsh", "advfirewall", "firewall", "show", "rule", "name=all"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode != 0:
                # Если не удалось прочитать через netsh, пробуем файл
                self.log_message("Не удалось прочитать правила через netsh, пробуем файл rs.txt...")
                rs_file = Path(__file__).parent / "rs.txt"
                if rs_file.exists():
                    netsh_output = load_netsh_output_from_file(rs_file)
                else:
                    raise RuntimeError(f"Ошибка выполнения netsh: {result.stderr}")
            else:
                netsh_output = result.stdout
            
            if not netsh_output:
                raise ValueError("Не удалось загрузить правила")
            
            # Парсим вывод
            rules = self.parse_netsh_output(netsh_output)
            
            self.log_message(f"Найдено правил: {len(rules)}")
            
            # Сохраняем в БД (жестко записываем)
            plugin_id = "netsh_plugin"
            saved_count = 0
            
            for rule in rules:
                rule_data = {
                    "name": rule.get("name", "Unknown"),
                    "ip": rule.get("remote_ip", "Any"),
                    "remote_ip": rule.get("remote_ip", "Any"),
                    "action": rule.get("action", "block"),
                    "protocol": rule.get("protocol", "ANY"),
                    "direction": rule.get("direction", "in"),
                    "enabled": rule.get("enabled", True),
                    "local_ip": rule.get("local_ip", "Any"),
                    "local_port": rule.get("local_port", "Any"),
                    "remote_port": rule.get("remote_port", "Any")
                }
                
                # Проверяем, нет ли уже такого правила
                existing_rules = self.db.get_rules(plugin_id, limit=1000)
                rule_exists = False
                for existing in existing_rules:
                    try:
                        content = json.loads(existing.get("content", "{}"))
                        if content.get("name") == rule_data["name"]:
                            rule_exists = True
                            break
                    except:
                        pass
                
                if not rule_exists:
                    self.db.add_rule(plugin_id, json.dumps(rule_data))
                    saved_count += 1
                    if saved_count <= 5:  # Логируем только первые 5
                        self.log_message(f"Сохранено правило: {rule_data['name']}")
            
            self.log_message(f"[OK] Загружено {saved_count} новых правил в БД (всего найдено {len(rules)})")
            self.rules_loaded = True
            self.refresh_rules()
            
        except Exception as e:
            logger.error(f"Ошибка загрузки правил: {e}")
            self.log_message(f"[ERROR] Ошибка загрузки правил: {e}")
            # В случае ошибки создаем правила по умолчанию
            self.create_fallback_rules()
    
    def parse_netsh_output(self, output: str) -> List[Dict[str, Any]]:
        """Парсинг вывода netsh для извлечения правил с использованием регулярных выражений"""
        rules = []
        
        # Регулярное выражение для поиска начала правила (поддерживает русский и английский)
        rule_name_pattern = re.compile(r'^(?:Имя правила|Rule Name):\s+(.+)$', re.MULTILINE)
        
        # Регулярные выражения для полей (русский и английский форматы)
        # Используем более гибкие паттерны с учетом возможных пробелов
        patterns = {
            'name': re.compile(r'^(?:Имя правила|Rule Name):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'enabled': re.compile(r'^(?:Включен|Enabled):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'direction': re.compile(r'^(?:Направление|Direction):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'profiles': re.compile(r'^Profiles:\s+(.+?)(?:\n|$)', re.MULTILINE),
            'grouping': re.compile(r'^(?:Группировка|Grouping):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'local_ip': re.compile(r'^LocalIP:\s+(.+?)(?:\n|$)', re.MULTILINE),
            'remote_ip': re.compile(r'^(?:Удаленный IP-адрес|RemoteIP):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'protocol': re.compile(r'^(?:Протокол|Protocol):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'local_port': re.compile(r'^(?:Локальный порт|LocalPort):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'remote_port': re.compile(r'^(?:Удаленный порт|RemotePort):\s+(.+?)(?:\n|$)', re.MULTILINE),
            'action': re.compile(r'^(?:Действие|Action):\s+(.+?)(?:\n|$)', re.MULTILINE),
        }
        
        # Разделяем вывод на отдельные правила
        # Правила разделяются пустой строкой после "Действие:"
        # Используем более надежный способ: разделяем по началу нового правила
        # Сначала убираем заголовки PowerShell, если они есть
        output_clean = output.strip()
        
        # Разделяем по "Имя правила:" (начало нового правила)
        # Используем lookahead, чтобы включить разделитель в следующий блок
        rule_blocks = re.split(r'(?=\nИмя правила:)', output_clean)
        
        # Если первый блок пустой или не содержит "Имя правила:", убираем его
        if rule_blocks and not re.search(r'Имя правила:', rule_blocks[0]):
            rule_blocks = rule_blocks[1:]
        
        for block in rule_blocks:
            if not block.strip():
                continue
            
            rule = {}
            
            # Извлекаем имя правила
            name_match = patterns['name'].search(block)
            if name_match:
                rule['name'] = name_match.group(1).strip()
            else:
                continue  # Пропускаем блоки без имени правила
            
            # Извлекаем остальные поля
            enabled_match = patterns['enabled'].search(block)
            if enabled_match:
                enabled_val = enabled_match.group(1).strip().lower()
                # Поддержка русского и английского
                rule['enabled'] = enabled_val in ['да', 'yes', '1', 'true']
            
            direction_match = patterns['direction'].search(block)
            if direction_match:
                direction_val = direction_match.group(1).strip().lower()
                # Преобразуем русский в английский
                if direction_val in ['вход', 'in']:
                    rule['direction'] = 'in'
                elif direction_val in ['выход', 'out']:
                    rule['direction'] = 'out'
                else:
                    rule['direction'] = direction_val
            
            remote_ip_match = patterns['remote_ip'].search(block)
            if remote_ip_match:
                rule['remote_ip'] = remote_ip_match.group(1).strip()
            else:
                rule['remote_ip'] = 'Any'
            
            protocol_match = patterns['protocol'].search(block)
            if protocol_match:
                protocol_val = protocol_match.group(1).strip()
                # Преобразуем "Любой" в "ANY"
                if protocol_val.lower() in ['любой', 'any']:
                    rule['protocol'] = 'ANY'
                else:
                    rule['protocol'] = protocol_val.upper()
            else:
                rule['protocol'] = 'ANY'
            
            action_match = patterns['action'].search(block)
            if action_match:
                action_val = action_match.group(1).strip().lower()
                # Преобразуем русский в английский
                if action_val in ['разрешить', 'allow']:
                    rule['action'] = 'allow'
                elif action_val in ['блокировать', 'block']:
                    rule['action'] = 'block'
                else:
                    rule['action'] = action_val
            else:
                rule['action'] = 'block'
            
            # Дополнительные поля
            local_port_match = patterns['local_port'].search(block)
            if local_port_match:
                rule['local_port'] = local_port_match.group(1).strip()
            
            remote_port_match = patterns['remote_port'].search(block)
            if remote_port_match:
                rule['remote_port'] = remote_port_match.group(1).strip()
            
            local_ip_match = patterns['local_ip'].search(block)
            if local_ip_match:
                rule['local_ip'] = local_ip_match.group(1).strip()
            
            profiles_match = patterns['profiles'].search(block)
            if profiles_match:
                profiles_val = profiles_match.group(1).strip()
                rule['profiles'] = [p.strip() for p in profiles_val.split(',')]
            
            # Добавляем правило только если оно валидно
            if rule.get('name'):
                rules.append(rule)
        
        return rules
    
    def create_fallback_rules(self):
        """Создание правил по умолчанию если не удалось прочитать с системы"""
        try:
            plugin_id = "netsh_plugin"
            default_rules = [
                {"name": "Block HTTP", "ip": DEFAULT_TARGET_IP, "action": "block", "protocol": "TCP", "direction": "in"},
                {"name": "Allow DNS", "ip": "8.8.8.8", "action": "allow", "protocol": "UDP", "direction": "out"},
                {"name": "Block FTP", "ip": "10.0.0.5", "action": "block", "protocol": "TCP", "direction": "in"},
            ]
            
            for rule_data in default_rules:
                self.db.add_rule(plugin_id, json.dumps(rule_data))
            
            self.log_message("[OK] Созданы правила по умолчанию")
            self.rules_loaded = True
            self.refresh_rules()
        except Exception as e:
            logger.error(f"Ошибка создания правил по умолчанию: {e}")
    
    def refresh_rules(self):
        """Обновление таблицы правил из БД"""
        try:
            if not self.db:
                return
            
            plugin_id = "netsh_plugin"
            # Увеличиваем лимит, чтобы показать все правила
            rules = self.db.get_rules(plugin_id, limit=10000)
            
            self.rules_table.setRowCount(len(rules))
            
            for i, rule in enumerate(rules):
                try:
                    content = json.loads(rule.get("content", "{}"))
                    rule_id = rule.get("id", "")
                    name = content.get("name", "Unknown")
                    # Используем remote_ip, если есть, иначе ip
                    ip = content.get("remote_ip") or content.get("ip", "Any")
                    action = content.get("action", "block")
                    
                    self.rules_table.setItem(i, 0, QTableWidgetItem(str(rule_id)))
                    self.rules_table.setItem(i, 1, QTableWidgetItem(name))
                    self.rules_table.setItem(i, 2, QTableWidgetItem(ip))
                    self.rules_table.setItem(i, 3, QTableWidgetItem(action))
                except Exception as e:
                    logger.error(f"Ошибка парсинга правила: {e}")
                    self.rules_table.setItem(i, 0, QTableWidgetItem(str(rule.get("id", ""))))
                    self.rules_table.setItem(i, 1, QTableWidgetItem("Error"))
                    self.rules_table.setItem(i, 2, QTableWidgetItem("-"))
                    self.rules_table.setItem(i, 3, QTableWidgetItem("-"))
            
            self.log_message(f"[OK] Обновлено {len(rules)} правил")
            
        except Exception as e:
            logger.error(f"Ошибка обновления правил: {e}")
            self.log_message(f"[ERROR] Ошибка обновления: {e}")
    
    def select_ip(self):
        """Диалог выбора IP адреса и параметров блокировки"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Настройка блокировки")
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # IP адрес
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(QLabel("IP адрес:"))
        ip_input = QLineEdit(self.current_ip)
        ip_layout.addWidget(ip_input)
        layout.addLayout(ip_layout)
        
        # Тип блокировки
        block_type_group = QGroupBox("Тип блокировки")
        block_type_layout = QVBoxLayout()
        full_block_radio = QRadioButton("Полная блокировка (все порты)")
        port_block_radio = QRadioButton("Блокировка конкретного порта")
        
        if self.block_type == "full":
            full_block_radio.setChecked(True)
        else:
            port_block_radio.setChecked(True)
        
        block_type_layout.addWidget(full_block_radio)
        block_type_layout.addWidget(port_block_radio)
        block_type_group.setLayout(block_type_layout)
        layout.addWidget(block_type_group)
        
        # Порт
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Порт (для блокировки порта):"))
        port_input = QLineEdit(str(self.block_port) if self.block_port else "")
        port_input.setEnabled(port_block_radio.isChecked())
        port_layout.addWidget(port_input)
        layout.addLayout(port_layout)
        
        # Обновляем доступность поля порта
        def update_port_enabled():
            port_input.setEnabled(port_block_radio.isChecked())
        
        full_block_radio.toggled.connect(lambda: update_port_enabled())
        port_block_radio.toggled.connect(lambda: update_port_enabled())
        
        # Кнопки
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.Accepted:
            ip = ip_input.text().strip()
            # Валидация IP
            import re
            ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            if not ip_pattern.match(ip):
                QMessageBox.warning(self, "Ошибка", "Неверный формат IP адреса")
                return
            
            self.current_ip = ip
            
            if port_block_radio.isChecked():
                self.block_type = "port"
                port_str = port_input.text().strip()
                if port_str:
                    try:
                        port = int(port_str)
                        if 1 <= port <= 65535:
                            self.block_port = port
                        else:
                            QMessageBox.warning(self, "Ошибка", "Порт должен быть в диапазоне 1-65535")
                            return
                    except ValueError:
                        QMessageBox.warning(self, "Ошибка", "Порт должен быть числом")
                        return
                else:
                    QMessageBox.warning(self, "Ошибка", "Укажите порт для блокировки")
                    return
            else:
                self.block_type = "full"
                self.block_port = None
            
            # Обновляем метку
            if self.block_type == "port":
                self.ip_label.setText(f"Выбранный IP: {self.current_ip}, Порт: {self.block_port}")
            else:
                self.ip_label.setText(f"Выбранный IP: {self.current_ip} (полная блокировка)")
            
            self.log_message(f"Выбран IP: {self.current_ip}, Тип: {self.block_type}" + 
                           (f", Порт: {self.block_port}" if self.block_port else ""))
    
    def _test_connection(self, ip: str, port: int = None) -> bool:
        """Проверка подключения через ping или curl (поддержка русского вывода)"""
        try:
            # Сначала пробуем ping (4 пакета для надежности)
            self.log_message(f"Проверяем подключение к {ip} через ping...")
            ping_result = subprocess.run(
                ["ping", "-n", "4", "-w", "1000", ip],
                capture_output=True,
                text=True,
                timeout=10,
                encoding='utf-8',
                errors='replace'
            )
            
            # Парсим русский вывод ping
            output = ping_result.stdout.lower()
            # Ищем "Ответ от" (русский) или "Reply from" (английский)
            # Ищем "получено = X" или "received = X"
            # Ищем "потеряно = 0" или "lost = 0"
            
            has_reply = "ответ от" in output or "reply from" in output
            # Ищем статистику: "получено = X" или "received = X"
            received_match = re.search(r'(?:получено|received)\s*=\s*(\d+)', output)
            lost_match = re.search(r'(?:потеряно|lost)\s*=\s*(\d+)', output)
            
            if received_match and lost_match:
                received = int(received_match.group(1))
                lost = int(lost_match.group(1))
                # Если получено > 0 и потеряно < получено, значит есть ответы
                ping_success = received > 0 and lost < received
            else:
                # Fallback: проверяем наличие "Ответ от" или код возврата
                ping_success = has_reply or ping_result.returncode == 0
            
            if ping_success:
                self.log_message(f"Ping успешен: получено ответов от {ip}")
                return True
            
            # Если ping не прошел, пробуем curl (если есть порт)
            if port:
                self.log_message(f"Ping не прошел, пробуем curl к {ip}:{port}...")
                try:
                    curl_result = subprocess.run(
                        ["curl", "-m", "3", f"http://{ip}:{port}"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        encoding='utf-8',
                        errors='replace'
                    )
                    # Если curl вернул ошибку подключения, значит блокировка работает
                    if "Connection refused" in curl_result.stderr or "timed out" in curl_result.stderr.lower():
                        return False  # Блокировка работает
                    return True  # Подключение возможно
                except FileNotFoundError:
                    self.log_message("curl не найден, используем только ping")
                    return ping_success
            
            return ping_success
        except Exception as e:
            logger.error(f"Ошибка проверки подключения: {e}")
            return True  # В случае ошибки считаем, что подключение возможно
    
    def block_ip(self):
        """Блокировка IP через netsh"""
        try:
            ip = self.current_ip
            port = self.block_port if self.block_type == "port" else None
            
            if self.block_type == "port" and not port:
                QMessageBox.warning(self, "Ошибка", "Не указан порт для блокировки")
                return
            
            self.log_message(f"Блокируем IP {ip}" + (f" на порту {port}" if port else " (полная блокировка") + "...")
            
            # Проверяем подключение до блокировки
            was_accessible = self._test_connection(ip, port)
            if was_accessible:
                self.log_message(f"Подключение к {ip} было доступно до блокировки")
            else:
                self.log_message(f"Подключение к {ip} уже было недоступно")
            
            # Создаем уникальное имя правила
            if port:
                rule_name = f"Flamix_Block_{ip.replace('.', '_')}_Port_{port}"
            else:
                rule_name = f"Flamix_Block_{ip.replace('.', '_')}"
            
            # Удаляем старые правила с таким именем
            for suffix in ["_In", "_Out", ""]:
                check_name = rule_name + suffix
                check_cmd = [
                    "netsh", "advfirewall", "firewall", "show", "rule", f"name={check_name}"
                ]
                check_result = subprocess.run(
                    check_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    encoding='utf-8',
                    errors='replace'
                )
                
                if check_result.returncode == 0 and "No rules match" not in check_result.stdout:
                    self.log_message(f"Удаляем старое правило '{check_name}'...")
                    delete_cmd = [
                        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={check_name}"
                    ]
                    subprocess.run(delete_cmd, capture_output=True, timeout=10, encoding='utf-8', errors='replace')
            
            # Создаем правила блокировки
            rules_created = []
            
            if port:
                # Блокировка конкретного порта
                for direction in ["in", "out"]:
                    for protocol in ["TCP", "UDP"]:
                        cmd = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}_{direction.capitalize()}_{protocol}",
                            f"dir={direction}",
                            "action=block",
                            f"protocol={protocol}",
                            f"localport={port}" if direction == "in" else f"remoteport={port}",
                            f"remoteip={ip}",
                            "enable=yes"
                        ]
                        
                        result = subprocess.run(
                            cmd,
                            capture_output=True,
                            text=True,
                            timeout=30,
                            encoding='utf-8',
                            errors='replace'
                        )
                        
                        if result.returncode == 0:
                            rules_created.append(f"{rule_name}_{direction.capitalize()}_{protocol}")
                            self.log_message(f"Создано правило: {rule_name}_{direction.capitalize()}_{protocol}")
                        else:
                            error_msg = result.stderr or result.stdout
                            self.log_message(f"[WARNING] Ошибка создания правила {protocol} {direction}: {error_msg}")
            else:
                # Полная блокировка
                for direction in ["in", "out"]:
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}_{direction.capitalize()}",
                        f"dir={direction}",
                        "action=block",
                        f"remoteip={ip}",
                        "protocol=any",
                        "enable=yes"
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        encoding='utf-8',
                        errors='replace'
                    )
                    
                    if result.returncode == 0:
                        rules_created.append(f"{rule_name}_{direction.capitalize()}")
                        self.log_message(f"Создано правило: {rule_name}_{direction.capitalize()}")
                    else:
                        error_msg = result.stderr or result.stdout
                        self.log_message(f"[WARNING] Ошибка создания правила {direction}: {error_msg}")
            
            if rules_created:
                # Правила не сохраняем в БД автоматически - они читаются из системы
                
                # Проверяем подключение после блокировки
                self.log_message("Проверяем, применилась ли блокировка...")
                import time
                time.sleep(1)  # Даем время на применение правила
                
                is_accessible = self._test_connection(ip, port)
                
                if not is_accessible:
                    self.log_message(f"[OK] Блокировка применена успешно - подключение к {ip} недоступно")
                    QMessageBox.information(
                        self, 
                        "Успех", 
                        f"IP {ip}" + (f" на порту {port}" if port else "") + 
                        " успешно заблокирован.\nПроверка показала, что подключение недоступно."
                    )
                else:
                    self.log_message(f"[WARNING] Правило создано, но подключение к {ip} все еще доступно")
                    QMessageBox.warning(
                        self,
                        "Предупреждение",
                        f"Правило создано, но подключение к {ip} все еще доступно.\n"
                        "Возможно, требуется время на применение правила или есть другие правила, разрешающие подключение."
                    )
                
                # Обновляем правила после блокировки
                self.load_rules_from_system()
            else:
                error_msg = "Не удалось создать ни одного правила"
                self.log_message(f"[ERROR] {error_msg}")
                QMessageBox.warning(self, "Ошибка", error_msg)
                
        except Exception as e:
            logger.error(f"Ошибка блокировки IP: {e}")
            self.log_message(f"[ERROR] Исключение: {e}")
            QMessageBox.critical(self, "Ошибка", f"Исключение при блокировке: {e}")
    
    def unblock_ip(self):
        """Разблокировка IP через netsh"""
        try:
            ip = self.current_ip
            port = self.block_port if self.block_type == "port" else None
            self.log_message(f"Разблокируем IP {ip}" + (f" на порту {port}" if port else "") + "...")
            
            # Формируем имя правила
            if port:
                rule_name = f"Flamix_Block_{ip.replace('.', '_')}_Port_{port}"
                rule_patterns = [
                    f"{rule_name}_In_TCP",
                    f"{rule_name}_In_UDP",
                    f"{rule_name}_Out_TCP",
                    f"{rule_name}_Out_UDP"
                ]
            else:
                rule_name = f"Flamix_Block_{ip.replace('.', '_')}"
                rule_patterns = [
                    f"{rule_name}_In",
                    f"{rule_name}_Out"
                ]
            
            # Также ищем все правила Flamix для этого IP
            list_cmd = [
                "netsh", "advfirewall", "firewall", "show", "rule", "name=all"
            ]
            
            list_result = subprocess.run(
                list_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                encoding='utf-8',
                errors='replace'
            )
            
            # Ищем все правила Flamix для этого IP
            rules_to_delete = []
            if list_result.returncode == 0:
                output = list_result.stdout
                for line in output.split('\n'):
                    if 'Имя правила:' in line or 'Rule Name:' in line:
                        rule_name_found = line.split(':', 1)[1].strip() if ':' in line else ""
                        if rule_name_found.startswith("Flamix_Block_") and ip.replace('.', '_') in rule_name_found:
                            rules_to_delete.append(rule_name_found)
            
            # Добавляем правила из паттернов
            for pattern in rule_patterns:
                if pattern not in rules_to_delete:
                    rules_to_delete.append(pattern)
            
            # Удаляем все найденные правила
            deleted_count = 0
            for rule_to_delete in rules_to_delete:
                delete_cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_to_delete}"
                ]
                
                result = subprocess.run(
                    delete_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    encoding='utf-8',
                    errors='replace'
                )
                
                if result.returncode == 0:
                    deleted_count += 1
                    self.log_message(f"Удалено правило: {rule_to_delete}")
                elif "No rules match" not in result.stdout and "No rules match" not in result.stderr:
                    error_msg = result.stderr or result.stdout
                    self.log_message(f"[WARNING] Ошибка удаления правила {rule_to_delete}: {error_msg}")
            
            if deleted_count > 0 or len(rules_to_delete) == 0:
                # Удаляем правило из БД
                try:
                    plugin_id = "netsh_plugin"
                    deleted_from_db = self.db.delete_rules_by_ip(plugin_id, ip)
                    if deleted_from_db > 0:
                        self.log_message(f"Удалено правил из БД: {deleted_from_db}")
                    else:
                        self.log_message("Правила для этого IP не найдены в БД")
                except Exception as e:
                    logger.error(f"Ошибка удаления правила из БД: {e}")
                    self.log_message(f"[WARNING] Ошибка удаления из БД: {e}")
                
                self.log_message(f"[OK] IP {ip} разблокирован (удалено правил файрвола: {deleted_count}, из БД: {deleted_from_db if 'deleted_from_db' in locals() else 0})")
                QMessageBox.information(self, "Успех", f"IP {ip} успешно разблокирован")
                # Обновляем правила после разблокировки
                self.load_rules_from_system()
            else:
                error_msg = "Не удалось удалить правила"
                self.log_message(f"[ERROR] {error_msg}")
                QMessageBox.warning(self, "Ошибка", error_msg)
                
        except Exception as e:
            logger.error(f"Ошибка разблокировки IP: {e}")
            self.log_message(f"[ERROR] Исключение: {e}")
            QMessageBox.critical(self, "Ошибка", f"Исключение при разблокировке: {e}")
    
    def check_accessibility(self):
        """Проверка доступности IP через реальные сетевые проверки"""
        try:
            ip = self.current_ip
            port = self.block_port if self.block_type == "port" else None
            
            self.log_message(f"Проверяем доступность IP {ip}" + (f" на порту {port}" if port else "") + "...")
            
            # Используем реальную проверку подключения
            accessible = self._test_connection(ip, port)
            
            # Дополнительная проверка через telnet или Test-NetConnection (PowerShell)
            if not accessible and port:
                self.log_message(f"Проверяем доступность порта {port} через PowerShell Test-NetConnection...")
                try:
                    ps_cmd = f"Test-NetConnection -ComputerName {ip} -Port {port} -InformationLevel Quiet -WarningAction SilentlyContinue"
                    ps_result = subprocess.run(
                        ["powershell", "-Command", ps_cmd],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        encoding='utf-8',
                        errors='replace'
                    )
                    
                    if ps_result.returncode == 0:
                        # Test-NetConnection вернул True - порт доступен
                        accessible = True
                        self.log_message(f"PowerShell Test-NetConnection: порт {port} доступен")
                    else:
                        # Test-NetConnection вернул False - порт недоступен
                        accessible = False
                        self.log_message(f"PowerShell Test-NetConnection: порт {port} недоступен")
                except Exception as e:
                    logger.warning(f"Ошибка проверки через PowerShell: {e}")
                    # Продолжаем с результатом ping/curl
            
            # Формируем детальное сообщение
            if accessible:
                if port:
                    message = f"IP {ip} доступен\nПорт {port} открыт и отвечает на запросы"
                    details = f"Проверка показала, что подключение к {ip}:{port} возможно"
                else:
                    message = f"IP {ip} доступен\nХост отвечает на ping"
                    details = f"Проверка показала, что хост {ip} доступен в сети"
                
                self.log_message(f"[OK] {details}")
                QMessageBox.information(
                    self, 
                    "Результат проверки", 
                    f"{message}\n\n{details}"
                )
            else:
                if port:
                    message = f"IP {ip} недоступен\nПорт {port} закрыт или заблокирован"
                    details = f"Проверка показала, что подключение к {ip}:{port} невозможно.\nВозможно, правило блокировки активно."
                else:
                    message = f"IP {ip} недоступен\nХост не отвечает на ping"
                    details = f"Проверка показала, что хост {ip} недоступен в сети.\nВозможно, правило блокировки активно."
                
                self.log_message(f"[BLOCKED] {details}")
                QMessageBox.warning(
                    self, 
                    "Результат проверки", 
                    f"{message}\n\n{details}"
                )
                
        except Exception as e:
            logger.error(f"Ошибка проверки доступности: {e}")
            self.log_message(f"[ERROR] Исключение: {e}")
            QMessageBox.critical(self, "Ошибка", f"Исключение при проверке: {e}")


def main():
    """Главная функция"""
    app = QApplication(sys.argv)
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
