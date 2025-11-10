from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from typing import Optional


class UserRegistration(BaseModel):
    """
    Define el esquema de datos y validaciones para el registro de un nuevo usuario.
    Los campos DUI, password, duiImage y faceImage son obligatorios (Field(...)).
    """

    # DUI (Documento Único de Identidad)
    dui: str = Field(..., description="Número de DUI del usuario")

    # Contraseña con validación de longitud mínima
    password: str = Field(...,
                          min_length=6,
                          description="Contraseña del usuario (mínimo 6 caracteres)")

    # Imágenes en formato Base64 (Strings largos)
    duiImage: str = Field(..., description="Imagen del DUI en formato base64")
    faceImage: str = Field(...,
                           description="Imagen del rostro en formato base64")

    class Config:
        # Permite usar el modelo con el cliente de Supabase/FastAPI
        from_attributes = True


class LoginCredentials(BaseModel):
    """
    Define el esquema de datos para las credenciales de inicio de sesión.
    """

    dui: str = Field(..., description="Número de DUI del usuario")
    password: str = Field(..., description="Contraseña del usuario")

    class Config:
        from_attributes = True


class DenunciaCreate(BaseModel):
    """
    Schema para crear una nueva denuncia
    """
    category: str = Field(..., min_length=1, max_length=50,
                          description="Categoría de la denuncia")
    location: str = Field(..., min_length=1,
                          description="Ubicación de la denuncia")
    description: str = Field(..., min_length=10,
                             description="Descripción detallada")
    evidence: Optional[List[str]] = Field(
        default=[], description="URLs de evidencias")

    class Config:
        json_schema_extra = {
            "example": {
                "category": "Robo",
                "location": "Calle Principal #123, Apopa",
                "description": "Descripción detallada del incidente",
                "evidence": ["url1.jpg", "url2.jpg"]
            }
        }


class DenunciaResponse(BaseModel):
    """
    Schema para la respuesta de una denuncia
    """
    id: str
    user_id: str
    categoria: str
    ubicacion: str
    descripcion: str
    evidencias: Optional[str] = None
    fecha_creacion: datetime
    estado: str

    class Config:
        from_attributes = True
