from fastapi import APIRouter, HTTPException, status, Request, File, UploadFile, Form
from fastapi.concurrency import run_in_threadpool
from datetime import datetime
from typing import Dict, List, Optional
from db_client import supabase
from schemas import DenunciaResponse
from jose import jwt, JWTError
import os
import uuid

# 🔐 IMPORTAR VAULT CLIENT
print("\n" + "=" * 80)
print("📦 IMPORTANDO VAULT CLIENT EN DENUNCIAS ROUTER")
print("=" * 80)

try:
    from vault_client import vault_client

    print(f"✅ Módulo vault_client importado exitosamente")

    if vault_client is not None:
        VAULT_ENABLED = True
        print(f"✅ vault_client está disponible")
        print(
            f"   • Vault Address: {getattr(vault_client, 'vault_addr', 'N/A')}")
        print(
            f"   • Transit Engine: {getattr(vault_client, 'transit_mount_point', 'N/A')}")
        print(
            f"   • Encryption Key: {getattr(vault_client, 'key_name', 'N/A')}")
        print(f"🔐 ENCRIPTACIÓN HABILITADA para denuncias")
    else:
        VAULT_ENABLED = False
        print(f"⚠️  vault_client es None - Vault NO disponible")
        print(f"⚠️  Las denuncias se guardarán SIN ENCRIPTAR")

except ImportError as ie:
    print(f"❌ Error de importación: {str(ie)}")
    print(f"   No se encontró el módulo vault_client.py")
    VAULT_ENABLED = False
    vault_client = None

except Exception as e:
    print(f"❌ Error inesperado al importar Vault:")
    print(f"   Tipo: {type(e).__name__}")
    print(f"   Mensaje: {str(e)}")
    import traceback
    traceback.print_exc()
    VAULT_ENABLED = False
    vault_client = None

print(f"\n📊 Estado final:")
print(f"   • VAULT_ENABLED: {VAULT_ENABLED}")
print(
    f"   • vault_client: {'Disponible' if vault_client else 'No disponible'}")
print("=" * 80 + "\n")

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
    Endpoint para crear denuncia con archivos
    🔐 FIRMA Y ENCRIPTACIÓN AUTOMÁTICA CON VAULT (si está habilitado)
    """
    # 1. Autenticar usuario
    current_user = await get_current_user(request)

    print("=" * 60)
    print("🔍 DATOS RECIBIDOS:")
    print(f"Usuario: {current_user['sub']}")
    print(f"Categoría: {category}")
    print(f"Ubicación: {location}")
    print(f"Descripción: {description[:50]}..." if len(
        description) > 50 else f"Descripción: {description}")
    print(f"Archivos: {len(files) if files else 0}")
    print(f"🔐 Vault habilitado: {VAULT_ENABLED}")
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

            # Guardar archivo en Supabase Storage
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

    # 3. Preparar datos de la denuncia
    nueva_denuncia = {
        "user_id": current_user["sub"],
        "categoria": category,
        "ubicacion": location,
        "descripcion": description,
        "evidencias": evidencias_urls,
        "fecha_creacion": datetime.utcnow().isoformat(),
        "estado": "pendiente"
    }

    # 🔐 4. FIRMAR Y ENCRIPTAR CON VAULT (si está habilitado)
    if VAULT_ENABLED:
        try:
            # ✅ PASO 1: FIRMAR (datos en claro)
            print(f"🖊️  Firmando denuncia...")
            nueva_denuncia = await run_in_threadpool(
                lambda: vault_client.sign_denuncia(
                    nueva_denuncia)  # pylint: disable=no-member
            )
            print(f"✅ Firmada")

            # ✅ PASO 2: ENCRIPTAR (incluyendo firma)
            print(f"🔐 Encriptando datos...")
            nueva_denuncia = await run_in_threadpool(
                lambda: vault_client.encrypt_denuncia_fields(nueva_denuncia)
            )
            print(f"✅ Encriptada")
            print(f"   - Categoría: {nueva_denuncia['categoria'][:30]}...")
            print(f"   - Ubicación: {nueva_denuncia['ubicacion'][:30]}...")
            print(f"   - Descripción: {nueva_denuncia['descripcion'][:30]}...")
        except Exception as e:
            print(f"❌ Error al firmar/encriptar con Vault: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al procesar la denuncia: {str(e)}"
            )
    else:
        print(f"⚠️  Vault deshabilitado - guardando sin firmar ni encriptar")

    # 5. Guardar en Supabase
    try:
        print(f"📤 Guardando en Supabase...")

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

        print(f"✅ Denuncia creada: ID {denuncia_creada['id']}")
        if VAULT_ENABLED:
            print(f"🔒 Datos guardados FIRMADOS Y ENCRIPTADOS en Supabase")

        return {
            "message": "Denuncia creada exitosamente" + (" (firmada y encriptada)" if VAULT_ENABLED else ""),
            "denuncia_id": denuncia_creada["id"],
            "encrypted": VAULT_ENABLED,
            "data": denuncia_creada
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")
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
    🔓 DESENCRIPTACIÓN Y VERIFICACIÓN AUTOMÁTICA CON VAULT (si está habilitado)
    """
    current_user = await get_current_user(request)

    try:
        print(f"📥 Obteniendo denuncias de Supabase...")
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

        denuncias = response.data
        print(f"📋 {len(denuncias)} denuncia(s) encontrada(s)")

        # 🔓 DESENCRIPTAR Y VERIFICAR CON VAULT (si está habilitado)
        if VAULT_ENABLED:
            denuncias_procesadas = []

            for denuncia in denuncias:
                try:
                    denuncia_id = denuncia.get('id')

                    # ✅ PASO 1: DESENCRIPTAR
                    print(f"🔓 Desencriptando denuncia ID: {denuncia_id}...")
                    denuncia_desencriptada = await run_in_threadpool(
                        lambda d=denuncia: vault_client.decrypt_denuncia_fields(
                            d)
                    )
                    print(f"✅ Desencriptada")

                    # ✅ PASO 2: VERIFICAR FIRMA
                    es_valida = await run_in_threadpool(
                        lambda d=denuncia_desencriptada: vault_client.verify_denuncia(
                            d)
                    )

                    if not es_valida:
                        # 🚨 MENSAJE AL BACKEND - DENUNCIA COMPROMETIDA
                        print(
                            f"🚨 ═══════════════════════════════════════════════════════════")
                        print(
                            f"🚨 ALERTA: Denuncia ID {denuncia_id} FUE MODIFICADA")
                        print(f"🚨 Usuario: {current_user['sub']}")
                        print(
                            f"🚨 Fecha: {denuncia_desencriptada.get('fecha_creacion')}")
                        print(
                            f"🚨 ═══════════════════════════════════════════════════════════")
                        # Aquí puedes agregar:
                        # - Enviar email al admin
                        # - Registrar en tabla de auditoría
                        # - Enviar webhook a sistema de alertas

                    denuncias_procesadas.append(denuncia_desencriptada)

                except Exception as e:
                    print(
                        f"⚠️  Error procesando {denuncia.get('id')}: {str(e)}")
                    # Si falla, retornar datos originales
                    denuncias_procesadas.append(denuncia)

            print(f"✅ {len(denuncias_procesadas)} denuncia(s) procesada(s)")
            return denuncias_procesadas
        else:
            print(f"⚠️  Vault deshabilitado - retornando sin desencriptar")
            return denuncias

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Error al obtener denuncias: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno: {str(e)}"
        )
