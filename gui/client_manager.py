"""Модуль управления клиентами - создание, редактирование, удаление, детали"""

import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

import dearpygui.dearpygui as dpg

logger = logging.getLogger(__name__)


def filter_numeric_input():
    """Фильтр ввода - оставляет только цифры"""
    current_value = dpg.get_value("new_client_id_input")
    # Оставляем только цифры
    filtered_value = ''.join(filter(str.isdigit, current_value))
    if filtered_value != current_value:
        dpg.set_value("new_client_id_input", filtered_value)


class ClientManager:
    """Класс для управления клиентами - все функции работы с клиентами"""

    def __init__(
        self,
        api_client,
        refresh_rules_callback=None,
        refresh_monitoring_callback=None,
        get_download_settings_callback=None
    ):
        """
        Инициализация менеджера клиентов
        
        Args:
            api_client: API клиент для работы с сервером
            refresh_rules_callback: Callback для обновления правил при выборе клиента
            refresh_monitoring_callback: Callback для обновления мониторинга
        """
        self.api_client = api_client
        self.refresh_rules_callback = refresh_rules_callback
        self.refresh_monitoring_callback = refresh_monitoring_callback
        self.get_download_settings = get_download_settings_callback or (lambda: {})
        
        # Данные клиентов
        self.clients_data: List[Dict[str, Any]] = []
        self.client_names: List[str] = []
        self.current_client_id: Optional[str] = None
        self.context_menu_client: Optional[Dict[str, Any]] = None

    def _close_delete_client_dialog(self, sender=None, app_data=None, user_data=None):
        """Закрывает окно подтверждения удаления клиента, если оно открыто."""
        if dpg.does_item_exist("delete_client_window"):
            dpg.delete_item("delete_client_window")

    def _confirm_delete_client_callback(self, sender, app_data, user_data):
        """DearPyGui callback-обертка для подтвержденного удаления клиента."""
        client_id = str(user_data) if user_data is not None else ""
        self.delete_client(client_id)

    def _show_package_result(
        self,
        filename: Path,
        client_key_password: Optional[str],
        provisioning_mode: Optional[str] = None,
    ):
        """Показывает оператору итог скачивания пакета и пароль к client.key."""
        if not dpg.does_item_exist("client_details"):
            return

        dpg.delete_item("client_details", children_only=True)
        with dpg.group(parent="client_details"):
            dpg.add_text("Package saved to:")
            dpg.add_text(str(filename))
            dpg.add_separator()
            if client_key_password:
                dpg.add_text("Password for client.key:")
                dpg.add_text(client_key_password, color=(255, 220, 120))
            elif provisioning_mode == "bootstrap":
                dpg.add_text(
                    "Bootstrap package: the client will generate its own key and enroll on first start.",
                    color=(120, 220, 255),
                )
            else:
                dpg.add_text(
                    "Password for client.key was not provided by server.",
                    color=(200, 200, 0)
                )

    def _resolve_download_target(self, client_id: str) -> Path:
        """Builds the package destination using GUI settings."""
        settings = self.get_download_settings() or {}
        directory_value = settings.get("directory") or settings.get("download_dir")
        if directory_value:
            download_dir = Path(str(directory_value)).expanduser()
        else:
            download_dir = Path.home() / "Downloads"

        try:
            download_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            if not download_dir.exists():
                download_dir = Path(".")

        prefix = str(settings.get("package_prefix") or "flamix-client").strip() or "flamix-client"
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return download_dir / f"{prefix}-{client_id}-{timestamp}.zip"

    def _maybe_open_download_folder(self, filename: Path):
        """Opens the destination folder when the setting requests it."""
        settings = self.get_download_settings() or {}
        if not settings.get("open_folder_after_download"):
            return

        try:
            folder = str(filename.parent)
            if hasattr(os, "startfile"):
                os.startfile(folder)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", folder])
        except Exception as e:
            logger.debug(f"Could not open download folder: {e}")

    def create_tab(self):
        """Создание вкладки клиентов"""
        with dpg.group(horizontal=True):
            with dpg.child_window(width=400, height=600):
                dpg.add_text("Clients", color=(100, 150, 255))
                dpg.add_separator()
                with dpg.group(horizontal=True):
                    dpg.add_button(label="Refresh", callback=self.refresh_clients)
                    dpg.add_button(label="Add Client", callback=self.show_add_client_dialog)
                dpg.add_separator()

                # Listbox
                dpg.add_listbox(
                    tag="clients_list",
                    width=-1,
                    num_items=18,
                    callback=self.on_client_selected
                )

                # Item handler для обработки правого клика
                with dpg.item_handler_registry(tag="clients_list_handler"):
                    dpg.add_item_clicked_handler(callback=self.on_client_list_clicked)
                    dpg.add_item_activated_handler(callback=self.on_client_list_activated)

                dpg.bind_item_handler_registry("clients_list", "clients_list_handler")
                dpg.add_separator()
                dpg.add_button(
                    label="Delete Selected Client",
                    callback=self.delete_selected_client,
                    tag="delete_selected_client_button"
                )
                # Устанавливаем красный цвет для кнопки удаления
                with dpg.theme() as delete_selected_theme:
                    with dpg.theme_component(dpg.mvButton):
                        dpg.add_theme_color(dpg.mvThemeCol_Button, (150, 50, 50), category=dpg.mvThemeCat_Core)
                        dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (200, 50, 50), category=dpg.mvThemeCat_Core)
                        dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (100, 30, 30), category=dpg.mvThemeCat_Core)
                dpg.bind_item_theme("delete_selected_client_button", delete_selected_theme)

            with dpg.child_window(width=-1, height=600):
                dpg.add_text("Client Details", tag="client_details_title", color=(100, 150, 255))
                dpg.add_separator()
                with dpg.group(tag="client_details"):
                    dpg.add_text("Select a client to view details")

    def refresh_clients(self):
        """Обновление списка клиентов"""
        clients = self.api_client.get_clients()
        self.apply_clients(clients)

    def apply_clients(self, clients: List[Dict[str, Any]]):
        """Применение уже загруженного списка клиентов к GUI."""
        logger.debug(f"refresh_clients: received {len(clients)} clients from API")
        if clients:
            logger.debug(f"Sample client data: {clients[0]}")
        valid_clients = []
        for c in clients:
            if c.get('id') is None:
                logger.warning(f"Skipping client with None ID: {c}")
                continue
            valid_clients.append(c)

        logger.info(f"refresh_clients: {len(valid_clients)} valid clients after filtering")
        self.clients_data = valid_clients

        self.client_names = [f"{c.get('id', 'Unknown')} - {c.get('name', 'N/A')}" for c in valid_clients]
        if dpg.does_item_exist("clients_list"):
            dpg.configure_item("clients_list", items=self.client_names)
            logger.debug(f"Updated clients_list with {len(self.client_names)} items")

        client_ids = [str(c.get('id')) for c in valid_clients if c.get('id') is not None]
        if dpg.does_item_exist("rules_client_combo"):
            dpg.configure_item("rules_client_combo", items=client_ids)
            logger.debug(f"Updated rules_client_combo with {len(client_ids)} items")
        if dpg.does_item_exist("analytics_client_combo"):
            dpg.configure_item("analytics_client_combo", items=["all"] + client_ids)
            logger.debug(f"Updated analytics_client_combo with {len(client_ids) + 1} items")

        # Обновляем глобальный выбор клиента для мониторинга
        if dpg.does_item_exist("monitoring_global_client_combo"):
            client_options = ["all"] + client_ids
            current_value = dpg.get_value("monitoring_global_client_combo")
            dpg.configure_item("monitoring_global_client_combo", items=client_options)
            # Если текущий выбор клиента больше не существует, выбираем первого или "all"
            if current_value and current_value != "all" and current_value not in client_ids:
                if client_ids:
                    dpg.set_value("monitoring_global_client_combo", client_ids[0])
                else:
                    dpg.set_value("monitoring_global_client_combo", "all")
            # Если значение пустое, но режим явно не выбран, сохраняем "all" как стабильный режим
            elif not current_value:
                dpg.set_value("monitoring_global_client_combo", "all" if "all" in client_options else "")
            # Если был выбран существующий режим, сохраняем его
            elif current_value == "all":
                dpg.set_value("monitoring_global_client_combo", "all")
            elif current_value in client_ids:
                dpg.set_value("monitoring_global_client_combo", current_value)
            elif client_ids:
                dpg.set_value("monitoring_global_client_combo", client_ids[0])

    def on_client_list_clicked(self):
        """Обработка клика мыши на списке клиентов"""
        # Проверяем, правый ли это клик
        try:
            # В dearpygui проверяем состояние правой кнопки мыши
            is_right_click = dpg.is_mouse_button_down(dpg.mvMouseButton_Right)

            if is_right_click:
                # Получаем выбранный элемент из listbox
                selected_str = dpg.get_value("clients_list")
                logger.debug(f"Right click detected. Selected: {selected_str}")

                if selected_str and selected_str in self.client_names:
                    self.show_client_context_menu(selected_str)
                elif self.current_client_id:
                    # Если элемент не выбран напрямую, используем последний выбранный элемент
                    logger.debug(f"Using current_client_id: {self.current_client_id}")
                    for client in self.clients_data:
                        if str(client.get('id')) == str(self.current_client_id):
                            client_name = f"{client.get('id', 'Unknown')} - {client.get('name', 'N/A')}"
                            if client_name in self.client_names:
                                self.show_client_context_menu(client_name)
                            break
                else:
                    logger.warning("Right click detected but no client selected")
        except Exception as e:
            logger.error(f"Error in on_client_list_clicked: {e}", exc_info=True)

    def on_client_list_activated(self, sender, app_data):
        """Обработка активации элемента списка (двойной клик или Enter)"""
        # Это может быть использовано для других действий
        pass

    def on_client_selected(self, app_data):
        """Обработка выбора клиента"""
        try:
            # app_data - это выбранная строка (например, "3 - TEST3"), а не индекс
            selected_str = str(app_data) if app_data is not None else ""

            # Находим индекс этой строки в списке
            if selected_str in self.client_names:
                selected_idx = self.client_names.index(selected_str)
                if 0 <= selected_idx < len(self.clients_data):
                    client = self.clients_data[selected_idx]
                    self.current_client_id = client.get('id')
                    self._show_client_details(client)
                    # Автоматически загружаем правила и другие данные для выбранного клиента
                    if self.refresh_rules_callback:
                        self.refresh_rules_callback()
                    # Обновляем мониторинг если вкладка открыта
                    if dpg.does_item_exist("monitoring_status_table") and self.refresh_monitoring_callback:
                        self.refresh_monitoring_callback()
            else:
                logger.warning(f"Selected client string not found: {selected_str}")
        except (ValueError, TypeError, IndexError) as e:
            logger.error(f"Error selecting client: {e}, app_data={app_data}")

    def show_client_context_menu(self, selected_str: str):
        """Показ контекстного меню для клиента"""
        try:
            if not selected_str or selected_str not in self.client_names:
                logger.warning(f"Cannot show context menu: selected_str '{selected_str}' not in client_names")
                return

            selected_idx = self.client_names.index(selected_str)
            if 0 <= selected_idx < len(self.clients_data):
                client = self.clients_data[selected_idx]

                # Проверяем, что клиент имеет валидный ID
                if client.get('id') is None:
                    logger.error(f"Cannot show context menu: client has no ID. Client data: {client}")
                    return

                # Сохраняем копию данных клиента для контекстного меню
                self.context_menu_client = {
                    'id': client.get('id'),
                    'name': client.get('name', 'N/A'),
                    'hostname': client.get('hostname'),
                    'ip_address': client.get('ip_address'),
                    'last_seen': client.get('last_seen'),
                    'enabled': client.get('enabled')
                }

                logger.debug(f"Showing context menu for client: {self.context_menu_client.get('id')}")

                # Получаем позицию мыши
                mouse_pos = dpg.get_mouse_pos()

                # Показываем контекстное меню
                dpg.configure_item("client_context_menu", pos=mouse_pos, show=True)
            else:
                logger.warning(f"Invalid client index: {selected_idx} (total: {len(self.clients_data)})")
        except Exception as e:
            logger.error(f"Error showing context menu: {e}", exc_info=True)

    def get_context_menu_client(self) -> Optional[Dict[str, Any]]:
        """Получение клиента из контекстного меню"""
        return self.context_menu_client

    def edit_client_from_menu(self):
        """Редактирование клиента из контекстного меню"""
        client = self.get_context_menu_client()
        if client:
            self.close_context_menu()
            # Пока просто показываем детали (можно добавить редактирование)
            self.current_client_id = client.get('id')
            self._show_client_details(client)
            logger.info(f"Editing client {client.get('id')}")

    def download_client_package_from_menu(self):
        """Скачивание пакета клиента из контекстного меню"""
        client = self.get_context_menu_client()
        if client:
            client_id = client.get('id')
            self.close_context_menu()
            self.download_client_package(client_id)

    def delete_client_from_menu(self):
        """Удаление клиента из контекстного меню"""
        client = self.get_context_menu_client()
        logger.debug(f"delete_client_from_menu called. Client: {client}")
        if client:
            # Проверяем, что client содержит валидный id
            client_id = client.get('id')
            logger.debug(f"Client ID from context menu: {client_id}")
            if client_id is None:
                logger.error(f"Invalid client data from context menu: {client}")
                self.close_context_menu()
                return
            self.close_context_menu()
            self.show_delete_client_dialog(client)
        else:
            logger.warning("No client selected in context menu")

    def close_context_menu(self):
        """Закрытие контекстного меню"""
        dpg.configure_item("client_context_menu", show=False)
        self.context_menu_client = None

    def _show_client_details(self, client: Dict[str, Any]):
        """Отображение деталей клиента"""
        dpg.delete_item("client_details", children_only=True)

        # Проверяем, что client содержит валидный id
        client_id = client.get('id')
        if client_id is None:
            logger.error(f"Cannot show client details: client_id is None. Client data: {client}")
            with dpg.group(parent="client_details"):
                dpg.add_text("Error: Invalid client data (missing ID)")
            return

        with dpg.group(parent="client_details"):
            dpg.add_text(f"ID: {client_id}")
            dpg.add_text(f"Name: {client.get('name', 'N/A')}")
            dpg.add_text(f"Hostname: {client.get('hostname', 'N/A')}")
            dpg.add_text(f"IP Address: {client.get('ip_address', 'N/A')}")
            dpg.add_text(f"Last Seen: {client.get('last_seen', 'N/A')}")
            dpg.add_text(f"Enabled: {'Yes' if client.get('enabled') else 'No'}")
            dpg.add_separator()
            with dpg.group(horizontal=True):
                # Сохраняем копию данных клиента для использования в lambda
                client_data = {
                    'id': client_id,
                    'name': client.get('name', 'N/A'),
                    'hostname': client.get('hostname'),
                    'ip_address': client.get('ip_address'),
                    'last_seen': client.get('last_seen'),
                    'enabled': client.get('enabled')
                }

                dpg.add_button(
                    label="Download Client Package",
                    callback=lambda s, a, cid=client_id: self.download_client_package(str(cid))
                )
                dpg.add_button(
                    label="Delete Client",
                    callback=lambda s, a, c=client_data: self.show_delete_client_dialog(c),
                    tag="delete_client_button"
                )
            # Устанавливаем красный цвет для кнопки удаления
            with dpg.theme() as delete_button_theme:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (150, 50, 50), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (200, 50, 50), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (100, 30, 30), category=dpg.mvThemeCat_Core)
            dpg.bind_item_theme("delete_client_button", delete_button_theme)

    def show_add_client_dialog(self):
        """Показ диалога добавления клиента"""
        # Удаляем существующее окно, если оно есть
        if dpg.does_item_exist("add_client_window"):
            dpg.delete_item("add_client_window")

        with dpg.window(label="Add Client", modal=True, tag="add_client_window", width=400, height=230):
            dpg.add_text("Client ID (integer only):")
            dpg.add_input_text(
                tag="new_client_id_input",
                width=-1,
                callback=filter_numeric_input
            )
            dpg.add_text("Client Name:")
            dpg.add_input_text(tag="new_client_name_input", width=-1)
            dpg.add_checkbox(
                label="Bootstrap enrollment (recommended)",
                default_value=True,
                tag="new_client_bootstrap_mode",
            )
            with dpg.group(horizontal=True):
                dpg.add_button(label="Create & Download", callback=self.create_and_download_client)
                dpg.add_button(label="Cancel", callback=lambda: dpg.delete_item("add_client_window"))

    def create_and_download_client(self):
        """Создание клиента и скачивание ZIP архива"""
        client_id_str = dpg.get_value("new_client_id_input")
        client_name = dpg.get_value("new_client_name_input") or client_id_str
        bootstrap_mode = bool(dpg.get_value("new_client_bootstrap_mode"))

        if not client_id_str:
            logger.warning("Client ID is required")
            return

        # Валидация ID как int
        try:
            client_id = int(client_id_str)
        except ValueError:
            logger.error(f"Client ID must be an integer, got: {client_id_str}")
            return

        logger.info(f"Creating client {client_id}...")

        # Создаем клиента и получаем ZIP (передаем как строку для API)
        package_result = self.api_client.create_client(
            str(client_id),
            client_name,
            provisioning_mode="bootstrap" if bootstrap_mode else "preissued",
        )

        if package_result and package_result.get('zip_data'):
            # Сохраняем ZIP файл в текущую директорию или Downloads
            filename = self._resolve_download_target(str(client_id))

            try:
                with open(filename, 'wb') as f:
                    f.write(package_result['zip_data'])
                logger.info(f"Client package saved to {filename}")
                dpg.delete_item("add_client_window")
                self.refresh_clients()
                self._show_package_result(
                    filename,
                    package_result.get('client_key_password'),
                    package_result.get('provisioning_mode'),
                )
                self._maybe_open_download_folder(filename)
            except Exception as e:
                logger.error(f"Failed to save file: {e}")
        else:
            logger.error("Failed to create client")

    def download_client_package(self, client_id: str):
        """Скачивание пакета для существующего клиента"""
        if not client_id:
            return

        logger.info(f"Downloading package for client {client_id}...")

        # Получаем пакет для существующего клиента
        package_result = self.api_client.get_client_package(client_id)

        if package_result and package_result.get('zip_data'):
            filename = self._resolve_download_target(client_id)

            try:
                with open(filename, 'wb') as f:
                    f.write(package_result['zip_data'])
                logger.info(f"Client package saved to {filename}")
                self._show_package_result(
                    filename,
                    package_result.get('client_key_password'),
                    package_result.get('provisioning_mode'),
                )
                self._maybe_open_download_folder(filename)
            except Exception as e:
                logger.error(f"Failed to save file: {e}")
        else:
            logger.error("Failed to download client package")

    def show_delete_client_dialog(self, client: Dict[str, Any]):
        """Показ диалога подтверждения удаления клиента"""
        # Проверяем, что client не None
        if client is None:
            logger.error("Cannot delete client: client is None")
            return

        # Удаляем существующее окно, если оно есть
        if dpg.does_item_exist("delete_client_window"):
            dpg.delete_item("delete_client_window")

        # Проверяем, что client_id существует и валиден
        client_id_raw = client.get('id')
        if client_id_raw is None:
            logger.error(f"Cannot delete client: client_id is None. Client data: {client}")
            return

        client_id = str(client_id_raw)
        if not client_id or client_id == 'None':
            logger.error(f"Cannot delete client: invalid client_id '{client_id}'. Client data: {client}")
            return

        client_name = client.get('name', client_id)

        with dpg.window(
                label="Delete Client",
                modal=True,
                tag="delete_client_window",
                width=400,
                height=200
        ):
            dpg.add_text(f"Are you sure you want to delete client '{client_name}' (ID: {client_id})?")
            dpg.add_separator()
            dpg.add_text("This will permanently delete:", color=(200, 100, 100))
            dpg.add_text("  • Client record")
            dpg.add_text("  • All client rules")
            dpg.add_text("  • All client sessions")
            dpg.add_text("  • All related data")
            dpg.add_text("This action cannot be undone!", color=(255, 50, 50))
            dpg.add_separator()
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Delete",
                    callback=self._confirm_delete_client_callback,
                    user_data=str(client_id),
                    tag="confirm_delete_button"
                )
                dpg.add_button(
                    label="Cancel",
                    callback=self._close_delete_client_dialog
                )
            # Устанавливаем красный цвет для кнопки подтверждения удаления
            with dpg.theme() as confirm_delete_theme:
                with dpg.theme_component(dpg.mvButton):
                    dpg.add_theme_color(dpg.mvThemeCol_Button, (200, 50, 50), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (255, 70, 70), category=dpg.mvThemeCat_Core)
                    dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (150, 30, 30), category=dpg.mvThemeCat_Core)
            dpg.bind_item_theme("confirm_delete_button", confirm_delete_theme)

    def delete_client(self, client_id: str):
        """Удаление клиента"""
        if not client_id:
            logger.warning("Cannot delete client: client_id is empty")
            return

        # Убеждаемся, что client_id - строка и не None
        client_id = str(client_id)
        if client_id == 'None' or client_id == 'null':
            logger.error(f"Cannot delete client: invalid client_id '{client_id}'")
            return

        logger.info(f"Deleting client {client_id}...")

        result = self.api_client.delete_client(client_id)

        if result and result.get('success'):
            logger.info(f"Client {client_id} deleted successfully")
            self._close_delete_client_dialog()

            # Очищаем текущий выбор клиента, если удалили выбранного
            # Сравниваем как строки для надежности
            if str(self.current_client_id) == str(client_id):
                self.current_client_id = None
                dpg.delete_item("client_details", children_only=True)
                with dpg.group(parent="client_details"):
                    dpg.add_text("Select a client to view details")

            # Обновляем список клиентов
            self.refresh_clients()
        else:
            logger.error(f"Failed to delete client {client_id}")
            # Показываем сообщение об ошибке в диалоге
            if dpg.does_item_exist("delete_client_window"):
                error_msg = result.get('detail', 'Unknown error') if result else 'Connection error'
                logger.error(f"Delete error: {error_msg}")
                error_text = f"Delete failed: {error_msg}"
                if dpg.does_item_exist("delete_client_error_text"):
                    dpg.set_value("delete_client_error_text", error_text)
                else:
                    dpg.add_text(
                        error_text,
                        color=(255, 80, 80),
                        parent="delete_client_window",
                        tag="delete_client_error_text"
                    )

    def delete_selected_client(self):
        """Удаление выбранного клиента из списка"""
        selected_str = dpg.get_value("clients_list")
        if selected_str is None or selected_str == "":
            logger.warning("No client selected")
            return

        try:
            # selected_str - это выбранная строка (например, "3 - TEST3")
            selected_str = str(selected_str)

            # Находим индекс этой строки в списке
            if selected_str in self.client_names:
                selected_idx = self.client_names.index(selected_str)
                if 0 <= selected_idx < len(self.clients_data):
                    client = self.clients_data[selected_idx]
                    # Проверяем, что client содержит валидный id
                    if not client or client.get('id') is None:
                        logger.error(f"Invalid client data at index {selected_idx}: {client}")
                        return
                    self.show_delete_client_dialog(client)
                else:
                    logger.warning(f"Invalid client index: {selected_idx} (total clients: {len(self.clients_data)})")
            else:
                logger.warning(f"Selected client string not found: {selected_str}")
        except (ValueError, TypeError, IndexError) as e:
            logger.error(f"Error deleting selected client: {e}")
