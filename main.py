
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.responses import Response
import uvicorn

from fastapi import FastAPI, Request

import time
# Importamos el router modular
from api.auth import auth_router
from api.denuncias import denuncias_router
from api.usuario import usuario_router
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
app.include_router(usuario_router, prefix="/usuario", tags=["Usuario"])
# --- Ruta de prueba ---


@app.get("/")
def read_root():
    """Ruta de prueba simple."""
    return {"message": "Server is running and CORS is configured."}


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Middleware para logging detallado de peticiones"""
    start_time = time.time()

    print("\n" + "="*70)
    print(f"📨 [REQUEST] {request.method} {request.url.path}")
    print("="*70)
    print(f"🌐 Origin: {request.headers.get('origin', 'No origin header')}")
    print(f"🌐 Referer: {request.headers.get('referer', 'No referer')}")
    print(
        f"🌐 User-Agent: {request.headers.get('user-agent', 'Unknown')[:50]}...")

    # Listar cookies recibidas
    if request.cookies:
        print(f"🍪 Cookies recibidas ({len(request.cookies)}):")
        for cookie_name in request.cookies.keys():
            print(f"   - {cookie_name}")
    else:
        print(f"🍪 No se recibieron cookies")

    # Verificar header Authorization
    auth_header = request.headers.get('authorization')
    if auth_header:
        print(f"🔑 Authorization header: {auth_header[:30]}...")
    else:
        print(f"🔑 No Authorization header")

    # Procesar la petición
    try:
        response = await call_next(request)
        process_time = time.time() - start_time

        print(f"\n📤 [RESPONSE] Status: {response.status_code}")
        print(f"⏱️  Process time: {process_time:.3f}s")
        print("="*70 + "\n")

        return response
    except Exception as e:
        process_time = time.time() - start_time
        print(f"\n💥 [ERROR] Exception durante el procesamiento")
        print(f"   Error: {e.__class__.__name__}: {str(e)}")
        print(f"⏱️  Process time: {process_time:.3f}s")
        print("="*70 + "\n")
        raise

# --- Entrypoint ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8080))  # Usa el puerto que Cloud Run le pasa
    uvicorn.run("main:app", host="0.0.0.0", port=port)
