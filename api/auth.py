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

from fastapi import APIRouter, HTTPException, status, Response, Request
from fastapi.concurrency import run_in_threadpool

from jose import jwt, JWTError
from dotenv import load_dotenv

from .register import register_router

# Cargar variables de entorno
load_dotenv()

SECRET_KEY: str = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise EnvironmentError(
        "La variable de entorno 'SECRET_KEY' es obligatoria para la seguridad JWT. "
        "Asegúrate de configurarla en tu archivo .env o en el entorno."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 3600
SESSION_COOKIE_NAME = "session_token"  # 🔑 Debe coincidir con constants.ts

# 🔥 IMPORTANTE: En producción (Vercel/Cloud Run) debe ser True para HTTPS
IS_PRODUCTION = os.getenv("ENV") == "production"

# --- DIAGNÓSTICO INICIAL ---
print("\n" + "="*70)
print("🚀 [BACKEND INIT] Inicializando módulo de autenticación")
print("="*70)
print(f"✅ SECRET_KEY cargada - Longitud: {len(SECRET_KEY)} caracteres")
print(f"🔧 ALGORITHM: {ALGORITHM}")
print(f"⏰ ACCESS_TOKEN_EXPIRE: {ACCESS_TOKEN_EXPIRE_SECONDS} segundos")
print(f"🍪 SESSION_COOKIE_NAME: '{SESSION_COOKIE_NAME}'")
print(f"🌍 IS_PRODUCTION (secure cookies): {IS_PRODUCTION}")
print(f"🔐 ENV variable: {os.getenv('ENV', 'not set')}")
print("="*70 + "\n")

auth_router = APIRouter(
    prefix="/auth",
    tags=["Autenticación"]
)

# Montar el router de registro
auth_router.include_router(register_router)


# --- Funciones de Utilidad de JWT ---

def create_access_token(data: dict):
    """Crea un JWT con fecha de expiración."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + \
        timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    to_encode.update({"exp": expire})

    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    print(f"🔑 [JWT] Token creado exitosamente")
    print(f"   Expira en: {ACCESS_TOKEN_EXPIRE_SECONDS} segundos")
    print(f"   Timestamp expiración: {expire.isoformat()}")

    return token


def verify_token(token: str) -> dict | None:
    """
    Decodifica y verifica el JWT. Imprime el error exacto si falla.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        print(f"✅ [JWT] Token verificado correctamente")
        print(f"   User ID: {payload.get('sub')}")
        print(f"   DUI: {payload.get('dui')}")
        return payload
    except JWTError as e:
        print(f"❌ [JWT] Error al verificar token: {e.__class__.__name__}")
        print(f"   Detalle: {str(e)}")
        return None


# ----------------------------------------------------------------------
# ENDPOINTS
# ----------------------------------------------------------------------

@auth_router.post("/login")
async def login_user(credentials: LoginCredentials):
    """
    Endpoint para iniciar sesión de usuario.
    Devuelve el token en el body - Astro manejará la cookie.
    """
    print("\n" + "="*70)
    print("🔐 [LOGIN] Nueva petición de login recibida")
    print("="*70)
    print(f"📋 DUI: {credentials.dui}")
    print(f"🔒 Password length: {len(credentials.password)} caracteres")

    try:
        # 1. Buscar el usuario por DUI
        print(
            f"\n🔍 [LOGIN] Consultando base de datos para DUI: {credentials.dui}")
        login_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").select(
                "id, dui, contrasena_hash, estado"
            ).eq("dui", credentials.dui).limit(1).execute()
        )

        data: List[Dict[str, Any]] = login_res.data

        if not data:
            print(
                f"❌ [LOGIN] Usuario NO encontrado para DUI: {credentials.dui}")
            print("="*70 + "\n")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas."
            )

        user_db = data[0]
        user_id = user_db.get("id")
        estado = user_db.get("estado")
        hashed_password = user_db.get("contrasena_hash")

        print(f"✅ [LOGIN] Usuario encontrado")
        print(f"   ID: {user_id}")
        print(f"   DUI: {user_db.get('dui')}")
        print(f"   Estado: {estado}")

        # 2. Verificar el estado
        if estado != "activo":
            print(f"❌ [LOGIN] Usuario no activo. Estado actual: {estado}")
            print("="*70 + "\n")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cuenta no activa o pendiente de verificación."
            )

        # 3. Verificar contraseña
        print(f"\n🔒 [LOGIN] Verificando contraseña...")
        try:
            password_ok = bcrypt.checkpw(
                credentials.password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception as bcrypt_error:
            print(f"❌ [LOGIN] Error en bcrypt: {bcrypt_error}")
            print("="*70 + "\n")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al verificar contraseña"
            )

        if not password_ok:
            print(
                f"❌ [LOGIN] Contraseña incorrecta para DUI: {credentials.dui}")
            print("="*70 + "\n")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas."
            )

        print(f"✅ [LOGIN] Contraseña correcta")

        # 4. Generar JWT
        print(f"\n🔑 [LOGIN] Generando token JWT...")
        token_data = {"sub": user_id, "dui": user_db.get("dui")}
        access_token = create_access_token(data=token_data)

        print(f"\n✅ [LOGIN] Login exitoso para user_id: {user_id}")
        print(f"   Token generado (preview): {access_token[:30]}...")
        print(f"   Token length: {len(access_token)} caracteres")
        print(f"   Astro se encargará de establecer la cookie HttpOnly")

        # 5. Preparar respuesta
        response_data = {
            "success": True,
            "token": access_token,
            "token_type": "bearer",
            "user_id": user_id,
            "dui": user_db.get("dui"),
        }

        print(f"\n📤 [LOGIN] Enviando respuesta exitosa")
        print("="*70 + "\n")

        return response_data

    except HTTPException as http_exc:
        print(f"\n⚠️  [LOGIN] HTTPException capturada")
        print(f"   Status: {http_exc.status_code}")
        print(f"   Detail: {http_exc.detail}")
        print("="*70 + "\n")
        raise http_exc
    except Exception as e:
        print(f"\n💥 [LOGIN] Error inesperado: {e.__class__.__name__}")
        print(f"   Detalle: {str(e)}")
        import traceback
        print(f"   Traceback:\n{traceback.format_exc()}")
        print("="*70 + "\n")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado durante el login: {e.__class__.__name__}: {e}"
        )


@auth_router.get("/verify-session")
async def verify_session(request: Request):
    """
    Endpoint usado por Astro Middleware para verificar si la sesión es válida.
    Acepta el token tanto del header Authorization como de las cookies.
    """
    print("\n" + "="*70)
    print("🔐 [VERIFY] Nueva petición de verificación de sesión")
    print("="*70)

    # Información de la petición
    print(f"📡 [VERIFY] Method: {request.method}")
    print(f"📡 [VERIFY] URL: {request.url}")
    print(
        f"📡 [VERIFY] Client: {request.client.host if request.client else 'Unknown'}")

    # 1. Intentar obtener el token del header Authorization
    auth_header = request.headers.get("Authorization")
    session_token = None

    print(f"\n🔍 [VERIFY] Buscando token en header 'Authorization'...")
    if auth_header:
        print(f"   Header encontrado: {auth_header[:30]}...")
        if auth_header.startswith("Bearer "):
            session_token = auth_header.split(" ")[1]
            print(f"✅ [VERIFY] Token extraído del header Authorization")
            print(f"   Token preview: {session_token[:20]}...")
            print(f"   Token length: {len(session_token)} caracteres")
        else:
            print(f"❌ [VERIFY] Header no tiene formato 'Bearer <token>'")
    else:
        print(f"❌ [VERIFY] Header 'Authorization' no presente")

    # 2. Si no está en el header, buscar en cookies
    if not session_token:
        print(f"\n🍪 [VERIFY] Buscando cookie '{SESSION_COOKIE_NAME}'...")
        session_token = request.cookies.get(SESSION_COOKIE_NAME)

        if session_token:
            print(f"✅ [VERIFY] Cookie encontrada")
            print(f"   Token preview: {session_token[:20]}...")
            print(f"   Token length: {len(session_token)} caracteres")
        else:
            print(f"❌ [VERIFY] Cookie '{SESSION_COOKIE_NAME}' NO encontrada")

            # Listar todas las cookies disponibles
            print(f"\n📋 [VERIFY] Cookies disponibles en la petición:")
            if request.cookies:
                for cookie_name, cookie_value in request.cookies.items():
                    print(f"   - {cookie_name}: {cookie_value[:20]}...")
            else:
                print(f"   (Ninguna cookie recibida)")

            # Listar algunos headers relevantes
            print(f"\n📋 [VERIFY] Headers relevantes:")
            print(f"   Origin: {request.headers.get('origin', 'N/A')}")
            print(f"   Referer: {request.headers.get('referer', 'N/A')}")
            print(f"   Cookie: {request.headers.get('cookie', 'N/A')[:50]}...")

    # 3. Verificar que se encontró el token
    if not session_token:
        print(f"\n❌ [VERIFY] FALLO: No se encontró token en ningún lugar")
        print(f"\n🔍 [VERIFY] Diagnóstico del problema:")
        print(f"   1. Verifica que Astro esté estableciendo la cookie correctamente")
        print(
            f"   2. Verifica que el nombre de la cookie sea '{SESSION_COOKIE_NAME}'")
        print(f"   3. Verifica la configuración de SameSite y Secure")
        print(f"   4. Verifica que CORS permita credentials")
        print("="*70 + "\n")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No autenticado. Cookie de sesión o encabezado no encontrados."
        )

    # 4. Verificar el token JWT
    print(f"\n🔍 [VERIFY] Verificando validez del token JWT...")
    payload = verify_token(session_token)

    if not payload:
        print(f"❌ [VERIFY] Token inválido o expirado")
        print("="*70 + "\n")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión expirada o token inválido."
        )

    # 5. Sesión válida
    user_id = payload.get("sub")
    dui = payload.get("dui")

    print(f"\n✅ [VERIFY] Sesión verificada exitosamente")
    print(f"   User ID: {user_id}")
    print(f"   DUI: {dui}")
    print("="*70 + "\n")

    return {
        "authenticated": True,
        "user_id": user_id,
        "dui": dui
    }


@auth_router.post("/logout")
async def logout(response: Response):
    """
    Endpoint para cerrar sesión, eliminando la cookie del navegador.
    """
    print("\n" + "="*70)
    print("🚪 [LOGOUT] Petición de logout recibida")
    print("="*70)

    samesite_value = "None" if IS_PRODUCTION else "Lax"

    print(f"🍪 [LOGOUT] Eliminando cookie '{SESSION_COOKIE_NAME}'")
    print(f"   SameSite: {samesite_value}")
    print(f"   Secure: {IS_PRODUCTION}")

    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=IS_PRODUCTION,
        samesite=samesite_value,
        path="/"
    )

    print(f"✅ [LOGOUT] Cookie eliminada exitosamente")
    print("="*70 + "\n")

    return {"message": "Cierre de sesión exitoso."}
