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
