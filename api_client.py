"""Клиент для работы с веб-API сервера"""

import requests
import logging
import urllib3
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
from urllib.parse import urljoin

# Отключаем предупреждения о небезопасных HTTPS запросах для локального сервера
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
CLIENT_KEY_PASSWORD_HEADER = "X-Flamix-Client-Key-Password"


class FlamixAPIClient:
    """Клиент для работы с Flamix Server API"""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        verify_ssl: Union[bool, str] = False,
        request_timeout: Tuple[float, float] = (3.05, 10.0)
    ):
        """
        Инициализация API клиента

        Args:
            base_url: Базовый URL сервера
            verify_ssl: Проверять ли SSL сертификаты
            request_timeout: Таймауты connect/read для HTTP вызовов
        """
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = self._normalize_verify_value(verify_ssl)
        self.request_timeout = self._normalize_timeout(request_timeout)
        self.session = requests.Session()
        self.session.verify = self.verify_ssl

    @staticmethod
    def _normalize_verify_value(verify_ssl: Union[bool, str, Path, None]) -> Union[bool, str]:
        """Accept bool or a CA bundle path for certificate verification."""
        if isinstance(verify_ssl, Path):
            verify_ssl = str(verify_ssl)
        if isinstance(verify_ssl, str):
            normalized = verify_ssl.strip()
            if normalized:
                return normalized
            return False
        return bool(verify_ssl)

    @staticmethod
    def _normalize_timeout(
        timeout: Union[Tuple[float, float], float, int]
    ) -> Tuple[float, float]:
        """Normalizes timeout into a connect/read tuple."""
        if isinstance(timeout, (int, float)):
            value = float(timeout)
            return max(0.1, value), max(0.1, value)

        try:
            connect_timeout = max(0.1, float(timeout[0]))
            read_timeout = max(0.1, float(timeout[1]))
            return connect_timeout, read_timeout
        except Exception:
            return 3.05, 10.0

    def update_connection_options(
        self,
        base_url: Optional[str] = None,
        verify_ssl: Optional[Union[bool, str, Path]] = None,
        request_timeout: Optional[Union[Tuple[float, float], float, int]] = None
    ):
        """Updates base connection settings without recreating the client."""
        if base_url is not None:
            self.base_url = str(base_url).rstrip('/')
        if verify_ssl is not None:
            self.verify_ssl = self._normalize_verify_value(verify_ssl)
            self.session.verify = self.verify_ssl
        if request_timeout is not None:
            self.request_timeout = self._normalize_timeout(request_timeout)

    def _apply_timeout(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Подставляет timeout по умолчанию, если он не передан явно."""
        request_kwargs = dict(kwargs)
        request_kwargs.setdefault('timeout', self.request_timeout)
        return request_kwargs

    def _extract_package_response(self, response: requests.Response) -> Dict[str, Any]:
        """Возвращает ZIP payload и пароль из заголовка, если сервер его прислал."""
        key_password = response.headers.get(CLIENT_KEY_PASSWORD_HEADER)
        if key_password is not None:
            key_password = key_password.strip() or None
        provisioning_mode = response.headers.get("X-Flamix-Provisioning-Mode")
        if provisioning_mode is not None:
            provisioning_mode = provisioning_mode.strip() or None

        return {
            'zip_data': response.content,
            'client_key_password': key_password,
            'provisioning_mode': provisioning_mode,
        }

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Выполнение HTTP запроса

        Args:
            method: HTTP метод
            endpoint: Эндпоинт API
            **kwargs: Дополнительные параметры для requests

        Returns:
            Ответ в виде словаря или None при ошибке
        """
        url = urljoin(self.base_url + '/', endpoint.lstrip('/'))
        request_kwargs = self._apply_timeout(kwargs)
        try:
            response = self.session.request(method, url, **request_kwargs)
            response.raise_for_status()
            if response.content:
                # Try to parse as JSON, but handle non-JSON responses gracefully
                try:
                    return response.json()
                except ValueError:
                    # Response is not JSON (e.g., HTML)
                    logger.debug(f"Response from {endpoint} is not JSON")
                    return None
            return {}
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None

    def get_clients(self) -> List[Dict[str, Any]]:
        """Получение списка клиентов"""
        result = self._request('GET', '/api/clients')
        return result.get('clients', []) if result else []

    def get_client_rules(self, client_id: str) -> List[Dict[str, Any]]:
        """Получение правил клиента"""
        result = self._request('GET', f'/api/clients/{client_id}/rules')
        return result.get('rules', []) if result else []

    def create_rule(self, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Создание правила"""
        return self._request('POST', '/api/rules', json=rule_data)

    def update_rule(self, rule_id: str, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Обновление правила"""
        return self._request('PUT', f'/api/rules/{rule_id}', json=rule_data)

    def delete_rule(self, rule_id: str, client_id: str) -> Optional[Dict[str, Any]]:
        """Удаление правила"""
        return self._request('DELETE', f'/api/rules/{rule_id}', params={'client_id': client_id})

    def get_analytics(
        self,
        client_id: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Получение аналитики"""
        params = {'limit': limit}
        if client_id:
            params['client_id'] = client_id
        result = self._request('GET', '/api/analytics', params=params)
        return result.get('analytics', []) if result else []

    def get_rules_diff(self, client_id1: str, client_id2: str) -> Optional[Dict[str, Any]]:
        """Сравнение правил между клиентами"""
        return self._request(
            'GET',
            '/api/rules/diff',
            params={'client_id1': client_id1, 'client_id2': client_id2}
        )

    def get_change_requests(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Получение запросов на изменение"""
        params = {}
        if status:
            params['status'] = status
        result = self._request('GET', '/api/change-requests', params=params)
        return result.get('requests', []) if result else []

    def approve_request(self, request_id: str, reviewer: str = "admin") -> Optional[Dict[str, Any]]:
        """Одобрение запроса на изменение"""
        return self._request(
            'POST',
            f'/api/change-requests/{request_id}/approve',
            params={'reviewer': reviewer}
        )

    def reject_request(
        self,
        request_id: str,
        reason: str,
        reviewer: str = "admin"
    ) -> Optional[Dict[str, Any]]:
        """Отклонение запроса на изменение"""
        return self._request(
            'POST',
            f'/api/change-requests/{request_id}/reject',
            params={'reason': reason, 'reviewer': reviewer}
        )

    def test_connection(self) -> bool:
        """Проверка подключения к серверу"""
        url = urljoin(self.base_url + '/', '/')
        try:
            response = self.session.get(url, timeout=self.request_timeout)
            # Root endpoint returns HTML, so we just check if we got a successful response
            return response.status_code == 200
        except requests.exceptions.RequestException as e:
            logger.debug(f"Connection test failed: {e}")
            return False

    def create_client(
        self,
        client_id: str,
        name: str,
        provisioning_mode: str = "bootstrap",
    ) -> Optional[Dict[str, Any]]:
        """
        Создание клиента и получение ZIP архива с сертификатами и конфигом
        
        Args:
            client_id: ID клиента
            name: Имя клиента
            
        Returns:
            Словарь с ZIP архивом и паролем client.key или None при ошибке
        """
        url = urljoin(self.base_url + '/', '/api/clients')
        try:
            response = self.session.post(
                url,
                json={
                    "client_id": client_id,
                    "name": name,
                    "provisioning_mode": provisioning_mode,
                },
                stream=True,
                timeout=self.request_timeout
            )
            response.raise_for_status()
            return self._extract_package_response(response)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create client: {e}")
            return None

    def get_client_package(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение ZIP архива для существующего клиента
        
        Args:
            client_id: ID клиента
            
        Returns:
            Словарь с ZIP архивом и паролем client.key или None при ошибке
        """
        url = urljoin(self.base_url + '/', f'/api/clients/{client_id}/package')
        try:
            response = self.session.get(url, stream=True, timeout=self.request_timeout)
            response.raise_for_status()
            return self._extract_package_response(response)
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get client package: {e}")
            return None

    def delete_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Удаление клиента
        
        Args:
            client_id: ID клиента
            
        Returns:
            Результат удаления или None при ошибке
        """
        return self._request('DELETE', f'/api/clients/{client_id}')

    def get_client_status(self, client_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Получение системного статуса клиента
        
        Args:
            client_id: ID клиента
            limit: Максимальное количество записей
            
        Returns:
            Список статусов или пустой список при ошибке
        """
        result = self._request('GET', f'/api/clients/{client_id}/status', params={'limit': limit})
        return result.get('statuses', []) if result else []

    def get_client_status_latest(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение последнего системного статуса клиента
        
        Args:
            client_id: ID клиента
            
        Returns:
            Последний статус или None при ошибке
        """
        return self._request('GET', f'/api/clients/{client_id}/status/latest')

    def get_client_plugins(self, client_id: str) -> List[Dict[str, Any]]:
        """
        Получение статуса плагинов клиента
        
        Args:
            client_id: ID клиента
            
        Returns:
            Список плагинов или пустой список при ошибке
        """
        result = self._request('GET', f'/api/clients/{client_id}/plugins')
        return result.get('plugins', []) if result else []

    def get_client_logs(
        self,
        client_id: str,
        level: Optional[str] = None,
        limit: int = 1000,
        since: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Получение логов клиента
        
        Args:
            client_id: ID клиента
            level: Фильтр по уровню (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            limit: Максимальное количество записей
            since: ISO timestamp для фильтрации по времени
            
        Returns:
            Список логов или пустой список при ошибке
        """
        params = {'limit': limit}
        if level:
            params['level'] = level
        if since:
            params['since'] = since
        
        result = self._request('GET', f'/api/clients/{client_id}/logs', params=params)
        return result.get('logs', []) if result else []

    def get_monitoring_overview(self) -> Dict[str, Any]:
        """
        Получение обзора мониторинга всех клиентов
        
        Returns:
            Словарь с информацией о клиентах или пустой словарь при ошибке
        """
        result = self._request('GET', '/api/monitoring/overview')
        return result if result else {}

    def get_server_info(self) -> Optional[Dict[str, Any]]:
        """Returns server diagnostics and deployment information."""
        return self._request('GET', '/api/server/info')

    def get_server_health(self) -> Optional[Dict[str, Any]]:
        """Returns readiness/liveness style server health information."""
        return self._request('GET', '/api/server/health')

    def get_server_config(self) -> Optional[Dict[str, Any]]:
        """Returns the current effective server runtime configuration."""
        return self._request('GET', '/api/server/config')

    def update_server_config(self, config_patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Applies a server runtime configuration patch."""
        return self._request('PATCH', '/api/server/config', json=config_patch)

    def get_gui_connection_package(self) -> Optional[Dict[str, Any]]:
        """Downloads the GUI trust/settings bundle for self-signed server setups."""
        url = urljoin(self.base_url + '/', '/api/server/gui-package')
        try:
            response = self.session.get(url, stream=True, timeout=self.request_timeout)
            response.raise_for_status()
            return {
                'zip_data': response.content,
                'filename': 'flamix-gui-connection.zip',
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get GUI connection package: {e}")
            return None
