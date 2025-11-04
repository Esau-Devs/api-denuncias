from fastapi import APIRouter, HTTPException, status, Request, File, UploadFile, Form
from fastapi.concurrency import run_in_threadpool
from datetime import datetime
from typing import Dict, List, Optional
from db_client import supabase
from schemas import DenunciaResponse
from jose import jwt, JWTError
import os
import uuid

denuncias_router = APIRouter()

# Constantes JWT
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"
SESSION_COOKIE_NAME = "session_token"

# Configuración de Storage
STORAGE_BUCKET = "user-evidence-vault"
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif',
                      'webp', 'pdf', 'doc', 'docx', 'mp3', 'wav', 'ogg'}
ALLOWED_CONTENT_TYPES = {
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'audio/mpeg', 'audio/wav', 'audio/ogg'
}


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


def validate_file(file: UploadFile) -> tuple[bool, str]:
    """Valida el archivo subido"""
    if file.filename:
        extension = file.filename.split('.')[-1].lower()
        if extension not in ALLOWED_EXTENSIONS:
            return False, f"Extensión .{extension} no permitida"

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        return False, f"Tipo de archivo {file.content_type} no permitido"

    return True, ""


async def save_file_to_storage(file: UploadFile, user_id: str) -> str:
    """Guarda un archivo en Supabase Storage y retorna su URL pública"""
    # Leer contenido
    contents = await file.read()
    file_size = len(contents)

    # Validar tamaño
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Archivo {file.filename} demasiado grande (máx. 20MB)"
        )

    # Generar nombre único con ruta de usuario
    file_extension = file.filename.split('.')[-1].lower()
    unique_filename = f"{user_id}/{uuid.uuid4()}.{file_extension}"

    try:
        # Subir archivo a Supabase Storage
        print(f"📤 Subiendo archivo a Storage: {unique_filename}")

        upload_response = await run_in_threadpool(
            lambda: supabase.storage.from_(STORAGE_BUCKET).upload(
                path=unique_filename,
                file=contents,
                file_options={
                    "content-type": file.content_type,
                    "upsert": "false"
                }
            )
        )

        # Obtener URL pública del archivo
        public_url = supabase.storage.from_(
            STORAGE_BUCKET).get_public_url(unique_filename)

        print(
            f"✅ Archivo subido: {file.filename} -> {unique_filename} ({file_size / 1024:.2f} KB)")
        print(f"🔗 URL pública: {public_url}")

        return public_url

    except Exception as e:
        print(f"❌ Error al subir archivo a Storage: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al subir archivo {file.filename} a Storage: {str(e)}"
        )


@denuncias_router.post("/crear", status_code=status.HTTP_201_CREATED)
async def crear_denuncia(
    request: Request,
    category: str = Form(...),
    location: str = Form(...),
    description: str = Form(...),
    files: List[UploadFile] = File(None)  # Archivos opcionales
):
    """
    Endpoint UNIFICADO para crear denuncia con archivos
    Recibe FormData con campos y archivos
    Los archivos se guardan en Supabase Storage
    """
    # 1. Autenticar usuario
    current_user = await get_current_user(request)

    print("=" * 60)
    print("🔍 DEBUGGING - Datos recibidos:")
    print(f"Usuario autenticado: {current_user['sub']}")
    print(f"Categoría: {category}")
    print(f"Ubicación: {location}")
    print(f"Descripción: {description}")
    print(f"Archivos: {len(files) if files else 0}")
    print("=" * 60)

    # 2. Procesar archivos (si hay)
    evidencias_urls = []

    if files:
        # Limitar a 4 archivos
        if len(files) > 4:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Máximo 4 archivos por denuncia"
            )

        for file in files:
            # Validar archivo
            is_valid, error_msg = validate_file(file)
            if not is_valid:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=error_msg
                )

            # Guardar archivo en Supabase Storage y obtener URL pública
            try:
                file_url = await save_file_to_storage(file, current_user["sub"])
                evidencias_urls.append(file_url)
            except Exception as e:
                print(f"❌ Error guardando archivo {file.filename}: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error al guardar archivo {file.filename}"
                )

    print(f"📎 Evidencias procesadas: {len(evidencias_urls)} archivo(s)")

    # 3. Crear denuncia en la base de datos
    nueva_denuncia = {
        "user_id": current_user["sub"],
        "categoria": category,
        "ubicacion": location,
        "descripcion": description,
        "evidencias": evidencias_urls,  # Array de URLs públicas de Supabase Storage
        "fecha_creacion": datetime.utcnow().isoformat(),
        "estado": "pendiente"
    }

    try:
        print(f"📤 Insertando denuncia en Supabase...")

        insert_res = await run_in_threadpool(
            lambda: supabase.from_("denuncias")
            .insert(nueva_denuncia)
            .execute()
        )

        if hasattr(insert_res, 'error') and insert_res.error:
            print(f"❌ Error de Supabase: {insert_res.error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al crear la denuncia: {insert_res.error}"
            )

        if not insert_res.data or len(insert_res.data) == 0:
            print(f"❌ No se insertaron datos")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No se pudo crear la denuncia"
            )

        denuncia_creada = insert_res.data[0]

        print(f"✅ Denuncia creada exitosamente: ID {denuncia_creada['id']}")

        return {
            "message": "Denuncia creada exitosamente",
            "denuncia_id": denuncia_creada["id"],
            "data": denuncia_creada
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error inesperado al crear denuncia: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {str(e)}"
        )


@denuncias_router.get("/mis-denuncias", response_model=list[DenunciaResponse])
async def obtener_mis_denuncias(request: Request):
    """
    Obtener todas las denuncias del usuario autenticado
    """
    current_user = await get_current_user(request)

    try:
        response = await run_in_threadpool(
            lambda: supabase.from_("denuncias")
            .select("*")
            .eq("user_id", current_user["sub"])
            .order("fecha_creacion", desc=True)
            .execute()
        )

        if hasattr(response, 'error') and response.error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al obtener denuncias"
            )

        return response.data

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error al obtener denuncias: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno: {str(e)}"
        )
