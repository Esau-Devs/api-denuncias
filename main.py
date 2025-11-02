
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.responses import Response
# inicializar supabase client

# Importamos el router modular
from api.auth import auth_router
from api.denuncias import denuncias_router

# --- Configuración de FastAPI ---
app = FastAPI(
    title="API Modular de Verificación",
    description="Aplicación Backend con FastAPI y Supabase.",
)


# Ruta para servir el favicon


@app.get("/favicon.ico")
async def favicon():
    return FileResponse("favicon.svg", media_type="image/svg+xml")

# --- Configuración de CORS ---
origins = [
    "https://www.denunciasv.help",   # Ejemplo: React corriendo en 4321
    "denunciasv.help",
    "http://localhost:4321",   # El origen que estaba causando el error
    "http://localhost:8000",  # Cuando despliegues
]

app.add_middleware(
    CORSMiddleware,
    # Los orígenes permitidos
    allow_origins=origins,
    # Permitir el envío de cookies o cabeceras de autorización
    allow_credentials=True,
    # Permitir todos los métodos (GET, POST, PUT, DELETE, OPTIONS, etc.)
    allow_methods=["*"],
    # Permitir todas las cabeceras personalizadas
    allow_headers=["*"],
)
# --- Fin de la Configuración de CORS ---

# --- Conexión de Routers ---
# Montamos el router de autenticación con el prefijo /api
app.include_router(auth_router, prefix="/api")

app.include_router(denuncias_router, prefix="/denuncias", tags=["Denuncias"])
# --- Ruta de prueba ---


@app.get("/")
def read_root():
    """Ruta de prueba simple."""
    return {"message": "Server is running and CORS is configured."}


# --- Endpoints de la API ---
