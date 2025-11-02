import os
from dotenv import load_dotenv
from supabase import create_client, AsyncClient
from postgrest.exceptions import APIError
from fastapi import HTTPException, status

# Cargar variables de entorno
load_dotenv()

# --- Configuración de Supabase ---
SUPABASE_URL: str = os.environ.get("SUPABASE_URL")
SUPABASE_KEY: str = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

BUCKET_NAME = "user-verification-photos"

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

# Agregaremos más funciones de utilidad de DB aquí más tarde.
