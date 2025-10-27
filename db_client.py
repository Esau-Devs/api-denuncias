import os
import re
import base64
from dotenv import load_dotenv
from supabase import create_client, AsyncClient
from postgrest.exceptions import APIError
from fastapi import HTTPException, status

# Cargar variables de entorno
load_dotenv()

# --- Configuración de Supabase ---
SUPABASE_URL: str = os.environ.get("SUPABASE_URL")
SUPABASE_KEY: str = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    # Usamos EnvironmentError para forzar la detención si faltan credenciales
    raise EnvironmentError(
        "Supabase URL o Key (SERVICE_ROLE_KEY) no encontradas. Asegúrate de tener el archivo .env")

# Inicialización global del cliente de Supabase (SÍNCRONO)
# Nota: Este cliente requiere usar run_in_threadpool en las rutas de FastAPI.
try:
    supabase: AsyncClient = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    raise RuntimeError(f"Fallo al inicializar el cliente Supabase: {e}")

# --- Funciones Auxiliares ---


def decode_base64_image(base64_string: str) -> tuple[bytes, str]:
    """Decodifica un string base64 y extrae la extensión y los datos binarios."""
    match = re.search(
        r'^data:image/(?P<ext>\w+);base64,(?P<data>.+)$', base64_string)
    if not match:
        raise ValueError(
            'String base64 inválido. Formato esperado: data:image/ext;base64,data')

    ext = match.group('ext')
    try:
        data = base64.b64decode(match.group('data'))
    except base64.binascii.Error:
        raise ValueError(
            'Los datos base64 no están codificados correctamente.')

    return data, ext


# Agregaremos más funciones de utilidad de DB aquí más tarde.
