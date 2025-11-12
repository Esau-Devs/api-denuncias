
from fastapi import APIRouter, HTTPException, status, Request
from db_client import supabase
from fastapi.concurrency import run_in_threadpool
from schemas import UsuarioResponse
from jose import jwt, JWTError
from datetime import datetime
from typing import Dict
import os
import traceback

usuario_router = APIRouter()

SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"
SESSION_COOKIE_NAME = "session_token"


async def get_current_user(request: Request) -> Dict:
    """
    Función para obtener el usuario actual desde el token JWT
    Soporta tanto cookie HttpOnly como Authorization header
    """
    auth_header = request.headers.get("Authorization")
    token = None

    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        print(f"🔑 Token obtenido del header Authorization")
    else:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if token:
            print(f"🔑 Token obtenido de la cookie HttpOnly")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado. Debes iniciar sesión."
        )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido: no contiene user_id"
            )

        print(f"✅ Usuario autenticado: {user_id}")
        return {"sub": user_id, "dui": payload.get("dui")}

    except JWTError as e:
        print(f"❌ Error al verificar token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado"
        )


@usuario_router.get("/me", response_model=UsuarioResponse)
async def get_usuario(request: Request):
    """
    Obtiene los datos del usuario por su ID (desde el token).
    """
    print("\n" + "="*60)
    print("👤 [GET /usuario/me] Iniciando petición")
    print("="*60)

    try:
        # 1. Obtener usuario del token
        print("🔐 [AUTH] Verificando token...")
        current_user = await get_current_user(request)
        user_id = current_user["sub"]
        print(f"✅ [AUTH] Usuario ID: {user_id}")

        # 2. Consultar base de datos
        print(f"📊 [DB] Consultando usuario en Supabase...")
        response = await run_in_threadpool(
            lambda: supabase.table("usuarios")
            .select("id, dui, nombre_completo, genero, fecha_registro")
            .eq("id", user_id)
            .single()
            .execute()
        )

        usuario_data = response.data
        print(f"📦 [DB] Datos recibidos:")
        print(f"   {usuario_data}")

        if not usuario_data:
            print("❌ [DB] Usuario no encontrado")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )

        # 3. Crear respuesta directamente (Pydantic maneja los alias)
        print("📤 [RESPONSE] Creando respuesta...")
        response_obj = UsuarioResponse(**usuario_data)
        print("✅ [SUCCESS] Respuesta exitosa")
        print("="*60 + "\n")
        return response_obj

    except HTTPException:
        raise

    except Exception as e:
        print(f"\n💥 [ERROR] Error en /usuario/me:")
        print(f"   {type(e).__name__}: {str(e)}")
        print(f"   Traceback: {traceback.format_exc()}")
        print("="*60 + "\n")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno: {str(e)}"
        )
