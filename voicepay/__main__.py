from .config import get_settings, load_env

load_env() 

from .server import run  # noqa: E402

settings = get_settings()
run(settings.host, settings.port)