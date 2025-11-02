import logging
import re
import uuid
import io
import base64
from datetime import datetime
from typing import Optional

import numpy as np
import cv2
from PIL import Image
import pytesseract
import face_recognition
import bcrypt

from fastapi import APIRouter, HTTPException, status
from starlette.concurrency import run_in_threadpool

# 🔄 Importaciones a ABSOLUTAS
from db_client import supabase, BUCKET_NAME
from schemas import UserRegistration


# --- Configuración de Logging ---
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


# Inicializar el router para las rutas de registro
register_router = APIRouter()

# =========================================================================
# 🛠️ FUNCIONES DE UTILIDAD
# =========================================================================


def decode_base64_image(base64_string: str) -> tuple[bytes, str]:
    """Decodifica una imagen Base64 y extrae la extensión."""
    if "," in base64_string:
        header, encoded = base64_string.split(",", 1)
        image_bytes = base64.b64decode(encoded)
        match = re.search(r"data:image/(\w+);", header)
        extension = match.group(1).lower() if match else "jpeg"
    else:
        image_bytes = base64.b64decode(base64_string)
        extension = "jpeg"
    if extension == 'jpg':
        extension = 'jpeg'
    return image_bytes, extension


def extract_dui_data(image_bytes: bytes) -> dict:
    """
    Extrae datos de DUI salvadoreño con preprocesamiento invertido y REGEX v8.
    Basado en estrategia de captura por línea siguiente.
    """

    def preprocess_for_dui(img_gray, strategy: str):
        """Preprocesa imagen para el número DUI."""
        try:
            if strategy == 'dui_resize_ultra':
                scale_percent = 300
                w = int(img_gray.shape[1] * scale_percent / 100)
                h = int(img_gray.shape[0] * scale_percent / 100)
                resized = cv2.resize(
                    img_gray, (w, h), interpolation=cv2.INTER_CUBIC)
                denoised = cv2.fastNlMeansDenoising(
                    resized, None, h=15, templateWindowSize=7, searchWindowSize=21)
                clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(4, 4))
                enhanced = clahe.apply(denoised)
                kernel_sharpen = np.array(
                    [[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
                sharpened = cv2.filter2D(enhanced, -1, kernel_sharpen)
                _, binary = cv2.threshold(
                    sharpened, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                kernel = np.ones((2, 1), np.uint8)
                dilated = cv2.dilate(binary, kernel, iterations=1)
                return dilated

            elif strategy == 'dui_simple_scale':
                scale_percent = 250
                w = int(img_gray.shape[1] * scale_percent / 100)
                h = int(img_gray.shape[0] * scale_percent / 100)
                resized = cv2.resize(
                    img_gray, (w, h), interpolation=cv2.INTER_LANCZOS4)
                binary = cv2.adaptiveThreshold(
                    resized, 255, cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 15, 10)
                return binary

            elif strategy == 'dui_bilateral_scale':
                scale_percent = 250
                w = int(img_gray.shape[1] * scale_percent / 100)
                h = int(img_gray.shape[0] * scale_percent / 100)
                resized = cv2.resize(
                    img_gray, (w, h), interpolation=cv2.INTER_CUBIC)
                bilateral = cv2.bilateralFilter(resized, 9, 75, 75)
                _, binary = cv2.threshold(
                    bilateral, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                kernel = np.ones((2, 2), np.uint8)
                dilated = cv2.dilate(binary, kernel, iterations=1)
                return dilated

            return img_gray
        except Exception as e:
            logger.debug(f"Error en preprocesamiento DUI {strategy}: {e}")
            return img_gray

    def preprocess_full_image_inverted(img_gray):
        """
        Preprocesamiento invertido agresivo (texto blanco sobre fondo negro).
        Basado en estrategia 12_aggressive_inverted.
        """
        try:
            h, w = img_gray.shape

            # Escala agresiva 3x
            scale_factor = 3
            scaled = cv2.resize(
                img_gray,
                (w * scale_factor, h * scale_factor),
                interpolation=cv2.INTER_CUBIC
            )

            # Reducción de ruido
            denoised = cv2.fastNlMeansDenoising(
                scaled, None, h=20, templateWindowSize=7, searchWindowSize=21
            )

            # Threshold INVERTIDO: fondo negro, texto blanco
            _, binary = cv2.threshold(
                denoised, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU
            )

            return binary
        except Exception as e:
            logger.debug(f"Error en preprocesamiento invertido: {e}")
            return img_gray

    def clean_name_field_v8(raw_text: str, field_type: str) -> str:
        """
        Limpia el texto capturado eliminando etiquetas y truncando en palabras clave.
        Versión v8 mejorada.
        """
        text = raw_text.strip()

        # Etiquetas de inicio a remover
        start_keywords = {
            'APELLIDOS': ['APELLIDOS', 'APELLIDO', 'SURNAME', 'SURNAMES',
                          'ES GIEN NÁMES ESAU ALEXANDER', 'ES GIEN NÁMES', 'ES'],
            'NOMBRES': ['NOMBRES', 'NOMBRE', 'GIVEN NAMES', 'GIEN NÁMES', 'GIVEN NAME']
        }

        # Palabras clave de parada (para truncar)
        stop_keywords = [
            'CONOCIDO', 'CÓTRTOCIDO', 'CONECIDO', 'KNOWN BY', 'CÓNÉCIDO',
            'BA POR CANERO', 'GÉNERO', 'GENERO', 'GENDER', 'FECHA',
            'FECHA Y LUGAR', 'Y LUGAR', 'NOMBRES', 'NOMBRE',
            'GIVEN NAMES', 'GIEN NÁMES', 'NEMBRE'
        ]

        # Limpieza inicial: solo letras y espacios
        text = re.sub(r'[^A-ZÑÁÉÍÓÚ\s]', '', text.upper()).strip()
        text = re.sub(r'\s+', ' ', text).strip()

        # Paso 1: Truncar en palabras de parada
        for stop in stop_keywords:
            if stop in text:
                text = text.split(stop)[0].strip()
                break

        # Paso 2: Remover etiquetas de inicio
        if field_type in start_keywords:
            for keyword in start_keywords[field_type]:
                pattern = r'^\s*' + re.escape(keyword) + r'\s*'
                text = re.sub(pattern, '', text, 1).strip()

        return text

    def get_value_from_label(label_pattern: str, text: str) -> Optional[str]:
        """
        Busca el valor después de la etiqueta, priorizando la línea siguiente.
        """
        # Patrón 1: Captura en la LÍNEA SIGUIENTE
        pattern_next_line = label_pattern + r'[^\n]*\n\s*([A-ZÑÁÉÍÓÚ\s]+)'
        match = re.search(pattern_next_line, text, re.MULTILINE)
        if match:
            return match.group(1).strip()

        # Patrón 2: Fallback a captura en la misma línea
        pattern_fallback = label_pattern + r'[^\n]*?([A-ZÑÁÉÍÓÚ\s]+)'
        match_fallback = re.search(pattern_fallback, text, re.MULTILINE)
        if match_fallback:
            return match_fallback.group(1).strip()

        return None

    def extract_info_from_full_text_v8(full_text: str) -> tuple:
        """
        Extrae APELLIDOS, NOMBRES y GÉNERO usando REGEX v8.
        Retorna: (apellidos, nombres, genero)
        """
        apellidos = None
        nombres = None
        genero = None

        full_text_upper = full_text.upper()

        # 1. Buscar APELLIDOS
        apellidos_raw = get_value_from_label(
            r'(?:APELLIDOS|APELLIDO|SURNAME|SURNAMES)',
            full_text_upper
        )
        if apellidos_raw:
            apellidos = clean_name_field_v8(apellidos_raw, 'APELLIDOS')
            if len(apellidos) < 2:
                apellidos = None

        # 2. Buscar NOMBRES
        nombres_raw = get_value_from_label(
            r'(?:NOMBRES|NOMBRE|GIVEN NAMES|NEMBRE)',
            full_text_upper
        )
        if nombres_raw:
            nombres = clean_name_field_v8(nombres_raw, 'NOMBRES')
            if len(nombres) < 2:
                nombres = None

        # 3. Buscar GÉNERO
        genero_pattern = r'(?:GÉNERO|GENERO|GENDER)[\s\S]*?([MF])'
        match_genero = re.search(genero_pattern, full_text_upper)
        if match_genero:
            genero_char = match_genero.group(1).strip()
            genero = "Masculino" if genero_char == 'M' else "Femenino"
        else:
            # Corrección OCR: 'P' -> 'F'
            match_genero_p = re.search(
                r'(?:GÉNERO|GENERO|GENDER)[\s\S]*?([P])',
                full_text_upper
            )
            if match_genero_p:
                genero = "Femenino"

        return apellidos, nombres, genero

    def extract_dui_number(img_gray, strategy: str) -> Optional[str]:
        """Extrae número DUI."""
        dui_pattern = r'(\d{8}-\d)'
        try:
            processed = preprocess_for_dui(img_gray, strategy)
            pil_image = Image.fromarray(processed)
            config_line = '--psm 7 --oem 3 -c tessedit_char_whitelist=0123456789-'
            text = pytesseract.image_to_string(
                pil_image, lang='spa', config=config_line)
            cleaned = re.sub(r'[^0-9-]', '', text)
            match = re.search(dui_pattern, cleaned)
            if match:
                logger.debug(
                    f"✅ [{strategy}] DUI encontrado: {match.group(1)}")
                return match.group(1)

            config_word = '--psm 8 --oem 3 -c tessedit_char_whitelist=0123456789-'
            text_word = pytesseract.image_to_string(
                pil_image, lang='spa', config=config_word)
            cleaned_word = re.sub(r'[^0-9-]', '', text_word)
            match_word = re.search(dui_pattern, cleaned_word)
            if match_word:
                logger.debug(
                    f"✅ [{strategy}] DUI encontrado (PSM 8): {match_word.group(1)}")
                return match_word.group(1)

            config_block = '--psm 6 --oem 3 -c tessedit_char_whitelist=0123456789-'
            text_block = pytesseract.image_to_string(
                pil_image, lang='spa', config=config_block)
            cleaned_block = re.sub(r'[^0-9-]', '', text_block)
            match_block = re.search(dui_pattern, cleaned_block)
            if match_block:
                logger.debug(
                    f"✅ [{strategy}] DUI encontrado (PSM 6): {match_block.group(1)}")
                return match_block.group(1)

            logger.debug(f"❌ [{strategy}] No se encontró DUI")
            return None
        except Exception as e:
            logger.debug(f"Error extrayendo DUI con {strategy}: {e}")
            return None

    # ========================================================================
    # INICIO DE EXTRACCIÓN
    # ========================================================================
    try:
        image_pil = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        width, height = image_pil.size
        logger.info(f"📐 Dimensiones originales: {width}x{height}")

        img_array = np.array(image_pil)
        img_gray = cv2.cvtColor(img_array, cv2.COLOR_RGB2GRAY)

        # ====================================================================
        # MÉTODO 1: ESTRATEGIA INVERTIDA AGRESIVA (REGEX v8)
        # ====================================================================
        logger.info(
            "🔍 MÉTODO 1: Extracción con preprocesamiento invertido + REGEX v8...")

        apellidos = None
        nombres = None
        genero = None

        try:
            # Preprocesamiento invertido de imagen completa
            processed_inverted = preprocess_full_image_inverted(img_gray)

            # OCR de imagen completa
            full_text = pytesseract.image_to_string(
                Image.fromarray(processed_inverted),
                lang='spa',
                config='--psm 3 --oem 3'
            )

            logger.debug("--- Texto completo extraído ---")
            logger.debug(full_text[:500])  # Primeros 500 caracteres

            # Extraer información con REGEX v8
            apellidos, nombres, genero = extract_info_from_full_text_v8(
                full_text)

            if apellidos:
                logger.info(f"✅ Apellidos (v8): '{apellidos}'")
            if nombres:
                logger.info(f"✅ Nombres (v8): '{nombres}'")
            if genero:
                logger.info(f"✅ Género (v8): {genero}")

        except Exception as e:
            logger.debug(f"Error en método invertido: {e}")

        # ====================================================================
        # MÉTODO 2: FALLBACK - RECORTES ESPECÍFICOS (MÉTODO ORIGINAL)
        # ====================================================================
        if not apellidos or not nombres or not genero:
            logger.info("🔍 MÉTODO 2: Fallback a recortes específicos...")

            # RECORTE APELLIDOS
            if not apellidos:
                apellidos_crop = (
                    int(width * 0.15),
                    int(height * 0.16),
                    int(width * 0.90),
                    int(height * 0.23)
                )
                try:
                    apl_pil = image_pil.crop(apellidos_crop)
                    apl_array = np.array(apl_pil)
                    apl_gray = cv2.cvtColor(apl_array, cv2.COLOR_RGB2GRAY)

                    scale_factor = 2
                    h, w = apl_gray.shape
                    scaled = cv2.resize(
                        apl_gray, (w * scale_factor, h * scale_factor),
                        interpolation=cv2.INTER_CUBIC
                    )
                    _, binary = cv2.threshold(
                        scaled, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
                    )

                    apl_pil_proc = Image.fromarray(binary)
                    config = '--psm 6 --oem 3 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZÁÉÍÓÚÑ '
                    apl_text = pytesseract.image_to_string(
                        apl_pil_proc, lang='spa', config=config
                    )
                    apl_text = apl_text.strip().upper()
                    apl_text = re.sub(r'[^A-ZÁÉÍÓÚÑ\s]', '', apl_text)
                    apl_text = re.sub(r'\s+', ' ', apl_text).strip()

                    if 5 <= len(apl_text) <= 50:
                        apellidos = apl_text
                        logger.info(f"✅ Apellidos (fallback): '{apellidos}'")
                except Exception as e:
                    logger.debug(f"Error en fallback apellidos: {e}")

            # RECORTE NOMBRES
            if not nombres:
                nombres_crop = (
                    int(width * 0.15),
                    int(height * 0.25),
                    int(width * 0.90),
                    int(height * 0.32)
                )
                try:
                    nom_pil = image_pil.crop(nombres_crop)
                    nom_array = np.array(nom_pil)
                    nom_gray = cv2.cvtColor(nom_array, cv2.COLOR_RGB2GRAY)

                    scale_factor = 2
                    h, w = nom_gray.shape
                    scaled = cv2.resize(
                        nom_gray, (w * scale_factor, h * scale_factor),
                        interpolation=cv2.INTER_CUBIC
                    )
                    _, binary = cv2.threshold(
                        scaled, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
                    )

                    nom_pil_proc = Image.fromarray(binary)
                    config = '--psm 6 --oem 3 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZÁÉÍÓÚÑ '
                    nom_text = pytesseract.image_to_string(
                        nom_pil_proc, lang='spa', config=config
                    )
                    nom_text = nom_text.strip().upper()
                    nom_text = re.sub(r'[^A-ZÁÉÍÓÚÑ\s]', '', nom_text)
                    nom_text = re.sub(r'\s+', ' ', nom_text).strip()

                    if 5 <= len(nom_text) <= 50:
                        nombres = nom_text
                        logger.info(f"✅ Nombres (fallback): '{nombres}'")
                except Exception as e:
                    logger.debug(f"Error en fallback nombres: {e}")

            # RECORTE GÉNERO
            if not genero:
                genero_crop = (
                    int(width * 0.35),
                    int(height * 0.29),
                    int(width * 0.75),
                    int(height * 0.40)
                )
                try:
                    gen_pil = image_pil.crop(genero_crop)
                    gen_array = np.array(gen_pil)
                    gen_gray = cv2.cvtColor(gen_array, cv2.COLOR_RGB2GRAY)

                    scale_factor = 3
                    h, w = gen_gray.shape
                    scaled = cv2.resize(
                        gen_gray, (w * scale_factor, h * scale_factor),
                        interpolation=cv2.INTER_CUBIC
                    )

                    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(4, 4))
                    enhanced = clahe.apply(scaled)
                    _, binary = cv2.threshold(
                        enhanced, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU
                    )

                    gen_pil_proc = Image.fromarray(binary)

                    gen_text = ""
                    for psm in ['6', '7', '8']:
                        config = f'--psm {psm} --oem 3 -c tessedit_char_whitelist=MF'
                        temp_text = pytesseract.image_to_string(
                            gen_pil_proc, lang='spa', config=config
                        )
                        temp_text = temp_text.strip().upper()
                        if 'M' in temp_text or 'F' in temp_text:
                            gen_text = temp_text
                            break

                    if 'M' in gen_text:
                        genero = "Masculino"
                        logger.info(f"✅ Género (fallback): Masculino")
                    elif 'F' in gen_text:
                        genero = "Femenino"
                        logger.info(f"✅ Género (fallback): Femenino")
                except Exception as e:
                    logger.debug(f"Error en fallback género: {e}")

        # Construir nombre completo
        nombre_completo = None
        if apellidos and nombres:
            nombre_completo = f"{apellidos} {nombres}"
        elif apellidos or nombres:
            nombre_completo = (apellidos or nombres)

        if nombre_completo:
            logger.info(f"✅ 📝 Nombre completo: {nombre_completo}")

        # ====================================================================
        # PASO 2: EXTRAER NÚMERO DUI
        # ====================================================================
        logger.info("🔍 PASO 2: Extrayendo número de DUI...")

        crop_box = (
            0,
            int(height * 0.78),
            int(width * 0.40),
            height
        )

        logger.debug(f"✂️ Recorte DUI: {crop_box}")
        cropped_pil = image_pil.crop(crop_box)
        cropped_array = np.array(cropped_pil)
        cropped_gray = cv2.cvtColor(cropped_array, cv2.COLOR_RGB2GRAY)

        dui_strategies = [
            'dui_bilateral_scale',
            'dui_resize_ultra',
            'dui_simple_scale',
        ]

        dui_extraido = None
        for strategy in dui_strategies:
            dui_extraido = extract_dui_number(cropped_gray, strategy)
            if dui_extraido:
                logger.info(f"✅ DUI extraído: {dui_extraido}")
                break

        if not dui_extraido:
            logger.error("❌ No se pudo extraer el número de DUI")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se pudo leer el número de DUI."
            )

        # RESUMEN FINAL
        logger.info("=" * 70)
        logger.info("📊 RESUMEN DE DATOS EXTRAÍDOS:")
        logger.info(f"   🆔 DUI:          {dui_extraido}")
        logger.info(
            f"   👤 Nombre:       {nombre_completo or '❌ No detectado'}")
        logger.info(f"   ⚧️ Género:        {genero or '❌ No detectado'}")
        logger.info("=" * 70)

        return {
            "dui_extraido": dui_extraido,
            "nombre_completo": nombre_completo,
            "genero": genero
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"💥 Error crítico: {e}", exc_info=True)
        raise ValueError(f"Error al procesar imagen del DUI: {str(e)}")


'''-----------------------------------------------------------------------------------------------------------'''


def compare_faces(face_image_bytes: bytes, dui_image_bytes: bytes, tolerance: float = 0.7) -> bool:
    """Compara rostros usando face_recognition."""
    try:
        face_img = face_recognition.load_image_file(
            io.BytesIO(face_image_bytes))
        dui_img = face_recognition.load_image_file(io.BytesIO(dui_image_bytes))

        face_encodings = face_recognition.face_encodings(face_img)
        dui_encodings = face_recognition.face_encodings(dui_img)

        if not face_encodings:
            raise ValueError(
                "No se detectó ningún rostro en la foto de selfie")
        if not dui_encodings:
            raise ValueError("No se detectó ningún rostro en la foto del DUI")

        results = face_recognition.compare_faces(
            [dui_encodings[0]], face_encodings[0], tolerance=tolerance)
        return results[0]

    except Exception as e:
        logger.error("Error en comparación facial: %s", e, exc_info=True)
        raise ValueError(f"Error en comparación facial: {str(e)}")


# =========================================================================
# 🚀 ENDPOINTS
# =========================================================================

@register_router.post("/register")
async def register_user(user_data: UserRegistration):
    """
    Registra un nuevo usuario validando el DUI contra OCR y realizando
    comparación facial entre la selfie y la foto del DUI.
    """
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

        # 2. Validar formato del DUI
        if not re.match(r'^\d{8}-\d$', user_data.dui):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Formato de DUI inválido. Debe ser: 00000000-0"
            )

        # 3. Decodificar imágenes
        dui_bytes, dui_ext = decode_base64_image(user_data.duiImage)
        face_bytes, face_ext = decode_base64_image(user_data.faceImage)

        # 4. Extraer datos del DUI con OCR
        logger.info(
            f"🚀 Iniciando extracción de datos para DUI: {user_data.dui}")
        dui_data = await run_in_threadpool(extract_dui_data, dui_bytes)

        # VALIDACIÓN 1: Comparar DUI
        dui_coincide = (dui_data["dui_extraido"] == user_data.dui)
        if not dui_coincide:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"El DUI ingresado ({user_data.dui}) no coincide con el detectado ({dui_data['dui_extraido']})."
            )
        logger.info("✅ Validación DUI exitosa.")

        # VALIDACIÓN 2: Comparación facial
        try:
            rostro_coincide = await run_in_threadpool(
                compare_faces, face_bytes, dui_bytes, 0.7
            )
        except ValueError as face_error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(face_error)
            )

        if not rostro_coincide:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La selfie no coincide con el rostro en el DUI."
            )
        logger.info("✅ Validación facial exitosa.")

        # 5. Hashear contraseña
        pwd_bytes = user_data.password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

        user_id = str(uuid.uuid4())

        # 6. Subir imágenes
        dui_file_path = f"user-files/{user_id}/dui_photo.{dui_ext}"
        face_file_path = f"user-files/{user_id}/face_photo.{face_ext}"

        await run_in_threadpool(
            lambda: supabase.storage.from_(BUCKET_NAME).upload(
                path=dui_file_path, file=dui_bytes,
                file_options={
                    "content-type": f"image/{dui_ext}", "upsert": "true"}
            )
        )
        await run_in_threadpool(
            lambda: supabase.storage.from_(BUCKET_NAME).upload(
                path=face_file_path, file=face_bytes,
                file_options={
                    "content-type": f"image/{face_ext}", "upsert": "true"}
            )
        )

        # 7. URLs públicas
        foto_dui_url = supabase.storage.from_(
            BUCKET_NAME).get_public_url(dui_file_path)
        foto_rostro_url = supabase.storage.from_(
            BUCKET_NAME).get_public_url(face_file_path)

        # 8. Insertar en BD
        insert_res = await run_in_threadpool(
            lambda: supabase.from_("usuarios").insert({
                "id": user_id,
                "dui": user_data.dui,
                "contrasena_hash": hashed_password,
                "foto_dui_url": foto_dui_url,
                "foto_rostro_url": foto_rostro_url,
                "nombre_completo": dui_data["nombre_completo"],
                "genero": dui_data["genero"],
                "estado": "activo",
                "verificado": True,
            }).execute()
        )

        if not insert_res.data:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al insertar usuario en la base de datos."
            )

        # 9. Respuesta exitosa
        return {
            "message": "Usuario registrado exitosamente.",
            "user_id": user_id,
            "verificado": True,
            "datos_extraidos": {
                "dui_detectado": dui_data["dui_extraido"],
                "nombre": dui_data["nombre_completo"],
                "genero": dui_data["genero"],

            }
        }

    except ValueError as val_exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_exc)
        )
    except HTTPException as http_exc:
        raise http_exc
    except Exception as e:
        logger.critical("Error del servidor: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error del servidor: {e.__class__.__name__}: {e}"
        )
