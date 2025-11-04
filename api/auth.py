
from fastapi import HTTPException, status
import numpy as np
from datetime import datetime
from starlette.concurrency import run_in_threadpool
from schemas import LoginCredentials
from db_client import supabase

import bcrypt
import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, status, Response, Request, Depends
from fastapi.concurrency import run_in_threadpool

from jose import jwt, JWTError
from dotenv import load_dotenv  # 💡 ¡NUEVA IMPORTACIÓN!

# Intentamos la importación relativa (cuando este módulo forma parte de un paquete);
# si falla (p. ej. al ejecutar como script de nivel superior), usamos la importación absoluta.
try:
    from .register import register_router
except (ImportError, ModuleNotFoundError, ValueError):
    from register import register_router  # type: ignore
# --- Carga de Variables de Entorno (CRÍTICO) ---
# Asegura que el SECRET_KEY se cargue antes de que se defina la constante
load_dotenv()

# Importamos el cliente Supabase y las utilidades

# --- Constantes de Seguridad y JWT ---

# 1. ⚠️ CRÍTICO: Leer la clave secreta y asegurar que exista
SECRET_KEY: str = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise EnvironmentError(
        "La variable de entorno 'SECRET_KEY' es obligatoria para la seguridad JWT. Asegúrate de configurarla en tu archivo .env o en el entorno.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600
SESSION_COOKIE_NAME = "session_token"

IS_PRODUCTION = os.getenv("ENVIRONMENT") == "production"
# 🛑 FORZAMOS A FALSE para el desarrollo local (HTTP)
IS_PRODUCTION = False
# -----------------------------

# --- DIAGNÓSTICO INICIAL ---
print("--- DIAGNÓSTICO DE INICIO ---")
print(
    f"DIAGNÓSTICO: SECRET_KEY cargada. Longitud: {len(SECRET_KEY)} caracteres.")
print(f"DIAGNÓSTICO: IS_PRODUCTION (secure flag) es: {IS_PRODUCTION}")
print("-----------------------------")
# -----------------------------

auth_router = APIRouter(
    prefix="/auth",
    tags=["Autenticación"]
)

# 🚀 INCLUSIÓN DEL ROUTER DE REGISTRO
# Esto hace que todas las rutas definidas en register_router (como /register)
# sean añadidas al auth_router con el mismo prefijo /auth.
auth_router.include_router(register_router)
# --- Funciones de Utilidad de JWT ---


def create_access_token(data: dict):
    """Crea un JWT con fecha de expiración."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + \
        timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> dict | None:
    """
    Decodifica y verifica el JWT. Imprime el error exacto si falla.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        # 🚨 Imprime la excepción JWT exacta
        print(f"DIAGNÓSTICO: ❌ Error al verificar token (JWTError): {e}")
        return None

# ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


@auth_router.post("/login")
async def login_user(credentials: LoginCredentials, response: Response):
    """
    Endpoint para iniciar sesión de usuario y emitir la cookie HttpOnly/Secure.
    """
    try:
        # 1. Buscar el usuario por DUI
        login_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").select(
                "id, dui, contrasena_hash, estado").eq("dui", credentials.dui).limit(1).execute()
        )

        data: List[Dict[str, Any]] = login_res.data

        if not data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas."
            )

        user_db = data[0]
        hashed_password = user_db.get("contrasena_hash")

        # 2. Verificar el estado y la contraseña
        if user_db.get("estado") != "activo":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cuenta no activa o pendiente de verificación."
            )

        password_ok = bcrypt.checkpw(
            credentials.password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )

        if not password_ok:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas."
            )

        # 3. Generar JWT y establecer la cookie segura
        user_id = user_db.get("id")
        token_data = {"sub": user_id, "dui": user_db.get("dui")}
        access_token = create_access_token(data=token_data)

        # --- DIAGNÓSTICO DE LOGIN ---
        print("\n--- DIAGNÓSTICO: LOGIN EXITOSO ---")
        print(f"DIAGNÓSTICO: Token creado para user_id: {user_id}")
        print(f"DIAGNÓSTICO: Cookie 'secure' flag es: {IS_PRODUCTION}")
        print("---------------------------------")
        # -----------------------------

        # Determinar el valor de SameSite
        # Si NO estamos en producción (HTTP), usamos 'Lax'. Si estamos en producción (HTTPS), usamos 'None' con Secure=True
        samesite_value = "None" if IS_PRODUCTION else "Lax"

        # Configuración de la Cookie Segura
        response.set_cookie(
            # Usar la constante para la cookie
            key=SESSION_COOKIE_NAME,
            value=access_token,
            # 🔒 HttpOnly: No accesible vía JavaScript (Anti-XSS)
            httponly=True,
            # 🔑 Secure: True en producción (HTTPS), False en desarrollo (HTTP)
            secure=False if not IS_PRODUCTION else True,
            # ✅ CAMBIO CLAVE: Usamos 'Lax' en desarrollo (HTTP)
            samesite=samesite_value,
            max_age=ACCESS_TOKEN_EXPIRE_SECONDS,
            path="/",
        )

        # 4. Inicio de sesión exitoso
        return {
            "user_id": user_id,
            "dui": user_db.get("dui"),
            # 💡 RETORNAR EL TOKEN PARA QUE EL FRONTEND PUEDA USARLO EN EL ENCABEZADO
            "token": access_token
        }

    # --- Manejo de Errores (para login) ---
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado durante el login: {e.__class__.__name__}: {e}"
        )


@auth_router.get("/verify-session")
async def verify_session(request: Request):
    """
    Endpoint usado por Astro Middleware para verificar si la cookie HttpOnly es válida,
    o para usar el token si es enviado en el encabezado Authorization.
    """
    # 1. Intentar obtener el token de la cabecera Authorization (Workaround)
    auth_header = request.headers.get("Authorization")
    session_token = None

    if auth_header and auth_header.startswith("Bearer "):
        session_token = auth_header.split(" ")[1]
        print(f"DIAGNÓSTICO: Token RECIBIDO de encabezado 'Authorization'.")
    else:
        # 2. Si no está en el encabezado, intentar obtenerlo de la cookie (Original)
        session_token = request.cookies.get(SESSION_COOKIE_NAME)

    # --- DIAGNÓSTICO DE VERIFY-SESSION ---
    print("\n--- DIAGNÓSTICO: VERIFY-SESSION ---")
    if session_token:
        # Muestra los primeros 10 caracteres del token
        print(
            f"DIAGNÓSTICO: Cookie/Token RECIBIDA. Token: {session_token[:10]}... Intentando verificar.")
    else:
        print(
            f"DIAGNÓSTICO: ❌ ERROR: Cookie/Token NO RECIBIDA:  Causa del 401.")
    print("-----------------------------------")
    # ------------------------------------

    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado. Cookie de sesión o encabezado no encontrados."
        )

    # 3. Verificar el token JWT
    payload = verify_token(session_token)

    if not payload:
        # 401 si el token es inválido o expiró (el error exacto se imprime en verify_token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión expirada o token inválido."
        )

    # 4. La sesión es válida y no ha expirado
    return {
        "authenticated": True,
        "user_id": payload.get("sub"),
        "dui": payload.get("dui")
    }


@auth_router.post("/logout")
async def logout(response: Response):
    """
    Endpoint para cerrar sesión, eliminando la cookie del navegador.
    """
    # Determinar el valor de SameSite
    samesite_value = "None" if IS_PRODUCTION else "Lax"

    # Eliminar la cookie de sesión
    response.delete_cookie(
        # Usar la constante para la cookie
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite=samesite_value,  # ✅ CAMBIO CLAVE
        path="/"
    )
    return {"message": "Cierre de sesión exitoso."}

# ---------------------------------------------------------------------------------------------------------------------------------------------------------------
