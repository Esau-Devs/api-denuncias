from fastapi import APIRouter, HTTPException, status, Depends, Header
from fastapi.concurrency import run_in_threadpool
from datetime import datetime
from typing import Dict, Optional
from db_client import supabase
from schemas import DenunciaCreate, DenunciaResponse
import uuid

denuncias_router = APIRouter()


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict:
    """
    Función para obtener el usuario actual desde el token JWT
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no proporcionado"
        )

    token = authorization.replace("Bearer ", "")

    # Aquí deberías verificar el token con tu lógica de autenticación
    # Por ahora retornamos un dict básico
    # Implementa tu lógica de verificación de token aquí

    return {"sub": "user-id-placeholder"}  # Reemplaza con tu lógica real


@denuncias_router.post("/crear", status_code=status.HTTP_201_CREATED)
async def crear_denuncia(denuncia: DenunciaCreate):
    """
    Endpoint para crear una nueva denuncia (SIN AUTENTICACIÓN - TEMPORAL)
    Los nombres de campos deben coincidir con la tabla de Supabase.
    """

    # 🔍 DEBUGGING - VER QUÉ ESTÁ LLEGANDO
    print("=" * 60)
    print("🔍 DEBUGGING - Datos recibidos en el backend:")
    print(f"Type: {type(denuncia)}")
    print(f"Category: '{denuncia.category}' (type: {type(denuncia.category)})")
    print(f"Location: '{denuncia.location}' (type: {type(denuncia.location)})")
    print(
        f"Description: '{denuncia.description}' (type: {type(denuncia.description)})")
    print(f"Evidence: {denuncia.evidence} (type: {type(denuncia.evidence)})")
    print("=" * 60)

    # ⚠️ TEMPORAL: User ID de prueba (reemplazar cuando tengas autenticación)
    user_id_temporal = str(uuid.uuid4())

    print(f"📥 Recibiendo denuncia:")
    print(f"   - Categoría: {denuncia.category}")
    print(f"   - Ubicación: {denuncia.location}")
    print(f"   - Descripción: {denuncia.description}")
    print(f"   - Evidencias: {denuncia.evidence}")

    nueva_denuncia = {
        "user_id": user_id_temporal,  # ⚠️ TEMPORAL
        "categoria": denuncia.category,
        "ubicacion": denuncia.location,
        "descripcion": denuncia.description,
        "evidencias": denuncia.evidence if denuncia.evidence else [],
        "fecha_creacion": datetime.utcnow().isoformat(),
        "estado": "pendiente"
    }

    try:
        print(f"📤 Intentando insertar en Supabase...")

        # Insertar en Supabase
        insert_res = await run_in_threadpool(
            lambda: supabase.from_("denuncias")
            .insert(nueva_denuncia)
            .execute()
        )

        # Verificar si hay error
        if hasattr(insert_res, 'error') and insert_res.error:
            print(f"❌ Error de Supabase: {insert_res.error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al crear la denuncia: {insert_res.error}"
            )

        # Verificar que se insertaron datos
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


@denuncias_router.post("/crear-con-auth", status_code=status.HTTP_201_CREATED)
async def crear_denuncia_con_auth(
    denuncia: DenunciaCreate,
    current_user: Dict = Depends(get_current_user)
):
    """
    Endpoint para crear una nueva denuncia CON AUTENTICACIÓN
    Usa este endpoint cuando tengas el sistema de autenticación funcionando
    """
    nueva_denuncia = {
        "user_id": current_user["sub"],
        "categoria": denuncia.category,
        "ubicacion": denuncia.location,
        "descripcion": denuncia.description,
        "evidencias": denuncia.evidence if denuncia.evidence else [],
        "fecha_creacion": datetime.utcnow().isoformat(),
        "estado": "pendiente"
    }

    try:
        insert_res = await run_in_threadpool(
            lambda: supabase.from_("denuncias")
            .insert(nueva_denuncia)
            .execute()
        )

        if hasattr(insert_res, 'error') and insert_res.error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error al crear la denuncia: {insert_res.error}"
            )

        if not insert_res.data or len(insert_res.data) == 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No se pudo crear la denuncia"
            )

        denuncia_creada = insert_res.data[0]

        return {
            "message": "Denuncia creada exitosamente",
            "denuncia_id": denuncia_creada["id"],
            "data": denuncia_creada
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno del servidor: {str(e)}"
        )


@denuncias_router.get("/mis-denuncias", response_model=list[DenunciaResponse])
async def obtener_mis_denuncias(current_user: Dict = Depends(get_current_user)):
    """
    Obtener todas las denuncias del usuario autenticado
    """
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
