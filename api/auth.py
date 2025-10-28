import logging
import cv2
import numpy as np  # Requerido para manejar arrays de imagen
import numpy as np  # Requerido para manejar arrays de imagen
import cv2    # Requerido para procesamiento avanzado
from fastapi import HTTPException, status
import io
import numpy as np
import face_recognition
from datetime import datetime
import re
import pytesseract
from PIL import Image
from starlette.concurrency import run_in_threadpool
from schemas import UserRegistration, LoginCredentials
from db_client import supabase, decode_base64_image
import uuid
import bcrypt
import os
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, status, Response, Request, Depends
from fastapi.concurrency import run_in_threadpool
from postgrest.exceptions import APIError
from jose import jwt, JWTError
from dotenv import load_dotenv  # 💡 ¡NUEVA IMPORTACIÓN!
import cv2  # <- NECESITAS ESTA IMPORTACIÓN
import numpy as np  # <- NECESITAS ESTA IMPORTACIÓN


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

# --- Rutas de Autenticación (El contenido de las rutas no ha cambiado, solo la carga del .env) ---
# ---------------------------------------------------------------------------------------------------------------------------------------------------------------


# Función auxiliar para extraer datos del DUI


@auth_router.post("/register")
async def register_user(user_data: UserRegistration):
    # ... (código de registro sin cambios)
    try:
        # 1. Verificar si el DUI ya existe
        existing_user_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").select(
                "dui").eq("dui", user_data.dui).execute()
        )

        if existing_user_res.data:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El número de DUI ya se encuentra registrado."
            )

        # 2. Hashear la contraseña
        pwd_bytes = user_data.password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

        user_id = str(uuid.uuid4())
        bucket_name = "user-verification-photos"

        # 3. Decodificar y subir las imágenes (asumiendo que decode_base64_image está bien)
        dui_bytes, dui_ext = decode_base64_image(user_data.duiImage)
        dui_file_path = f"user-files/{user_id}/dui_photo.{dui_ext}"
        face_bytes, face_ext = decode_base64_image(user_data.faceImage)
        face_file_path = f"user-files/{user_id}/face_photo.{face_ext}"

        # Subida al Storage de Supabase (Envuelto en run_in_threadpool)
        await run_in_threadpool(
            lambda: supabase.storage.from_(bucket_name).upload(
                path=dui_file_path,
                file=dui_bytes,
                file_options={
                    "content-type": f"image/{dui_ext}", "upsert": "true"}
            )
        )
        await run_in_threadpool(
            lambda: supabase.storage.from_(bucket_name).upload(
                path=face_file_path,
                file=face_bytes,
                file_options={
                    "content-type": f"image/{face_ext}", "upsert": "true"}
            )
        )

        # 4. Obtener URLs públicas (Síncrono)
        foto_dui_url = supabase.storage.from_(
            bucket_name).get_public_url(dui_file_path)
        foto_rostro_url = supabase.storage.from_(
            bucket_name).get_public_url(face_file_path)

        # 5. Insertar el nuevo usuario en la base de datos (Envuelto en run_in_threadpool)
        insert_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").insert({
                "id": user_id,
                "dui": user_data.dui,
                "contrasena_hash": hashed_password,
                "foto_dui_url": foto_dui_url,
                "foto_rostro_url": foto_rostro_url,
                "estado": "activo",
                "verificado": False,
            }).execute()
        )

        if not insert_res.data:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Error desconocido: Supabase no devolvió el usuario insertado.")

        return {"message": "Usuario registrado exitosamente.", "user": insert_res.data[0]}

    # --- Manejo de Errores (para register) ---
    except APIError as api_exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error en la base de datos (Supabase): {api_exc}"
        )
    except ValueError as val_exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Formato de imagen inválido: {val_exc}"
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ocurrió un error en el servidor: {e.__class__.__name__}: {e}"
        )

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
            secure=True if IS_PRODUCTION else False,
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


""" import uuid
import bcrypt
from fastapi import APIRouter, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from postgrest.exceptions import APIError

# Importamos el cliente Supabase y las utilidades desde nuestro módulo central
from db_client import supabase, decode_base64_image
# Importamos el esquema (asume que schemas.py está accesible)
from schemas import UserRegistration
from schemas import LoginCredentials
# Creamos el router para este módulo. Las rutas comenzarán con /auth (ej: /api/auth/register)
auth_router = APIRouter(
    prefix="/auth",
    tags=["Autenticación"]
)

# --- Configuración de FastAPI ---


@auth_router.post("/register")
async def register_user(user_data: UserRegistration):
    
    Endpoint para registrar un nuevo usuario, subir sus fotos y guardar en la DB.

    try:
        # 1. Verificar si el DUI ya existe
        # CORRECCIÓN: Usar run_in_threadpool para ejecutar la llamada síncrona de Supabase
        existing_user_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").select(
                "dui").eq("dui", user_data.dui).execute()
        )

        if existing_user_res.data:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El número de DUI ya se encuentra registrado."
            )

        # 2. Hashear la contraseña (Este paso es síncrono y está bien)
        pwd_bytes = user_data.password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

        user_id = str(uuid.uuid4())
        bucket_name = "user-verification-photos"

        # 3. Decodificar y subir las imágenes

        # Foto del DUI
        dui_bytes, dui_ext = decode_base64_image(user_data.duiImage)
        dui_file_path = f"user-files/{user_id}/dui_photo.{dui_ext}"

        # Subida al Storage de Supabase (CORRECCIÓN: Envolver la llamada)
        await run_in_threadpool(
            lambda: supabase.storage.from_(bucket_name).upload(
                path=dui_file_path,
                file=dui_bytes,
                file_options={
                    "content-type": f"image/{dui_ext}", "upsert": "true"}
            )
        )

        # Foto del Rostro
        face_bytes, face_ext = decode_base64_image(user_data.faceImage)
        face_file_path = f"user-files/{user_id}/face_photo.{face_ext}"

        # Subida al Storage de Supabase (CORRECCIÓN: Envolver la llamada)
        await run_in_threadpool(
            lambda: supabase.storage.from_(bucket_name).upload(
                path=face_file_path,
                file=face_bytes,
                file_options={
                    "content-type": f"image/{face_ext}", "upsert": "true"}
            )
        )

        # 4. Obtener URLs públicas (Síncrono, no necesita envoltura)
        foto_dui_url = supabase.storage.from_(
            bucket_name).get_public_url(dui_file_path)
        foto_rostro_url = supabase.storage.from_(
            bucket_name).get_public_url(face_file_path)

        # 5. Insertar el nuevo usuario en la base de datos (CORRECCIÓN: Envolver la llamada)
        insert_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").insert({
                "id": user_id,
                "dui": user_data.dui,
                "contrasena_hash": hashed_password,
                "foto_dui_url": foto_dui_url,
                "foto_rostro_url": foto_rostro_url,
                "estado": "activo",
                "verificado": False,
            }).execute()
        )

        # Manejo de respuesta de Supabase
        if not insert_res.data or len(insert_res.data) == 0:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Error desconocido: Supabase no devolvió el usuario insertado.")

        return {"message": "Usuario registrado exitosamente.", "user": insert_res.data[0]}

    # Manejar errores de Supabase
    except APIError as api_exc:
        print(f"Error de Supabase: {api_exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error en la base de datos (Supabase): {api_exc}"
        )
    # Manejar errores de Base64
    except ValueError as val_exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Formato de imagen inválido: {val_exc}"
        )
    # Manejar el re-lanzamiento de excepciones HTTP
    except HTTPException as http_exc:
        raise http_exc
    # Capturar cualquier otro error inesperado
    except Exception as e:
        print(f"Error inesperado y no capturado: {e}")
        # Retorna el tipo de error para mejor diagnóstico en el frontend
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ocurrió un error en el servidor: {e.__class__.__name__}: {e}"
        )


@auth_router.post("/login")
async def login_user(credentials: LoginCredentials):
    
    Endpoint para iniciar sesión de usuario, verificando DUI y contraseña.
    
    try:
        # 1. Buscar el usuario por DUI
        login_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").select(
                "id, dui, contrasena_hash, estado").eq("dui", credentials.dui).limit(1).execute()
        )

        # 2. Verificar si el usuario existe
        if not login_res.data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas (DUI no encontrado)."
            )

        user_db = login_res.data[0]
        hashed_password = user_db.get("contrasena_hash")

        # 3. Verificar el estado del usuario
        if user_db.get("estado") != "activo":
            # Puedes personalizar este mensaje si es 'bloqueado', 'pendiente', etc.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cuenta no activa o pendiente de verificación."
            )

        # 4. Verificar la contraseña
        # bcrypt.checkpw toma bytes, por lo que codificamos la contraseña ingresada
        password_ok = bcrypt.checkpw(
            credentials.password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )

        if not password_ok:
            # Es buena práctica dar un mensaje genérico para no revelar si existe el usuario o no
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas (contraseña incorrecta)."
            )

        # 5. Inicio de sesión exitoso
        # NOTA: En una aplicación real, aquí se generaría y devolvería un token JWT.
        return {
            "message": "Inicio de sesión exitoso.",
            "user_id": user_db.get("id"),
            "dui": user_db.get("dui")
        }

    # --- Manejo de Errores (para login) ---
    except HTTPException as http_exc:
        raise http_exc
    except APIError as api_exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error en la base de datos (Supabase): {api_exc}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado durante el login: {e.__class__.__name__}: {e}"
        )
 """
