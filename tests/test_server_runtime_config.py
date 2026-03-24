from datetime import datetime
import tempfile
from pathlib import Path

from flamix.server.runtime_config import ServerRuntimeConfig, load_runtime_config
from flamix.server.server import FlamixServer
from flamix.server.web_api import WebAPI


def test_runtime_config_env_and_roundtrip(monkeypatch):
    base_temp = Path("temp")
    base_temp.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(dir=str(base_temp)) as temp_dir:
        temp_path = Path(temp_dir)
        config_path = temp_path / "server-runtime.json"

        monkeypatch.setenv("FLAMIX_SERVER_HOST", "0.0.0.0")
        monkeypatch.setenv("FLAMIX_WEB_PORT", "9090")
        monkeypatch.setenv("FLAMIX_PERIODIC_TASK_INTERVAL_SECONDS", "15")
        monkeypatch.setenv("FLAMIX_SERVER_CONFIG_PATH", str(config_path))

        config = ServerRuntimeConfig.from_env()
        assert config.server_host == "0.0.0.0"
        assert config.web_port == 9090
        assert config.periodic_task_interval_seconds == 15

        saved_path = config.save()
        assert saved_path.exists()

        loaded = ServerRuntimeConfig.from_file(saved_path)
        assert loaded.server_host == "0.0.0.0"
        assert loaded.web_port == 9090
        assert loaded.periodic_task_interval_seconds == 15

        resolved = load_runtime_config(env={}, config_path=config_path)
        assert resolved.server_host == "0.0.0.0"
        assert resolved.web_port == 9090
        assert resolved.periodic_task_interval_seconds == 15


def test_server_info_health_and_config_routes():
    base_temp = Path("temp")
    base_temp.mkdir(exist_ok=True)

    with tempfile.TemporaryDirectory(dir=str(base_temp)) as temp_dir:
        base_dir = Path(temp_dir)
        runtime_config = ServerRuntimeConfig(
            server_host="127.0.0.1",
            server_port=8443,
            web_enabled=False,
            web_host="127.0.0.1",
            web_port=8080,
            db_path=base_dir / "server.db",
            cert_dir=base_dir / "certs",
            config_path=base_dir / "server-runtime.json",
        )

        server = FlamixServer(runtime_config=runtime_config)
        server.db.initialize()
        server.security.generate_ca()
        server.security.generate_server_cert(hostname="localhost", server_ip="127.0.0.1")
        server.running = True
        server.server = object()
        server.started_at = datetime.utcnow()

        web_api = WebAPI(
            rule_manager=server.rule_manager,
            rule_authorization=server.rule_authorization,
            db=server.db,
            host=runtime_config.web_host,
            port=runtime_config.web_port,
            security=server.security,
            server_host=runtime_config.server_host,
            server_port=runtime_config.server_port,
            cert_dir=runtime_config.cert_dir,
            runtime_config=server.runtime_config,
            server_instance=server,
        )

        route_paths = {
            getattr(route, "path", None)
            for route in web_api.app.routes
            if getattr(route, "path", None)
        }
        assert "/api/" in route_paths
        assert "/api/server/info" in route_paths
        assert "/api/server/health" in route_paths
        assert "/api/health" in route_paths
        assert "/api/server/config" in route_paths
        assert "/api/config" in route_paths

        info_payload = web_api._get_effective_server_info()
        assert info_payload["listen"]["host"] == "127.0.0.1"

        health_payload = web_api._get_effective_health()
        assert health_payload["checks"]["database"]["ok"] is True

        config_payload = web_api._get_runtime_config().to_public_dict()
        assert config_payload["server_host"] == "127.0.0.1"
        assert config_payload["web_port"] == 8080

        update_payload = web_api._update_runtime_config(
            {
                "server_host": "0.0.0.0",
                "periodic_task_interval_seconds": 15,
            },
            persist=True,
        )
        assert update_payload["restart_required"] is True
        assert "server_host" in update_payload["restart_required_fields"]
        assert "periodic_task_interval_seconds" in update_payload["applied_live"]
        assert server.runtime_config.periodic_task_interval_seconds == 15
        assert server.runtime_config.config_path.exists()
