"""Клиент для работы с веб-API сервера"""

import requests
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class FlamixAPIClient:
    """Клиент для работы с Flamix Server API"""

    def __init__(self, base_url: str = "http://127.0.0.1:8080", verify_ssl: bool = False):
        """
        Инициализация API клиента

        Args:
            base_url: Базовый URL сервера
            verify_ssl: Проверять ли SSL сертификаты
        """
        self.base_url = base_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

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
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            if response.content:
                return response.json()
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
        result = self._request('GET', '/')
        return result is not None and 'message' in result
