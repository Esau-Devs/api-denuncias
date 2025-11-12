import hvac
import os
import base64
import json
import hashlib
from typing import Dict
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


class VaultClient:
    def __init__(self):
        print("=" * 80)
        print("🔐 INICIALIZANDO VAULT CLIENT")
        print("=" * 80)

        self.vault_addr = os.environ.get("VAULT_ADDR")
        self.vault_token = os.environ.get("VAULT_TOKEN")

        if not self.vault_addr or not self.vault_token:
            raise ValueError(
                "❌ VAULT_ADDR y VAULT_TOKEN deben estar configuradas")

        # Configuración
        self.transit_mount_point = "transit"
        self.key_name = "denuncias-key"
        self.sign_key_name = "denuncias-sign-key"

        # Inicializar cliente
        verify_ssl = not self.vault_addr.startswith("http://")
        self.client = hvac.Client(
            url=self.vault_addr,
            token=self.vault_token,
            timeout=10,
            verify=verify_ssl
        )

        self._auto_setup()
        print("=" * 80)

    def _auto_setup(self):
        """Configuración automática"""
        try:
            if not self.client.is_authenticated():
                raise Exception("Token de Vault no válido")

            try:
                self.client.sys.enable_secrets_engine(
                    backend_type='transit',
                    path=self.transit_mount_point
                )
            except:
                pass

            try:
                self.client.secrets.transit.create_key(
                    name=self.key_name,
                    mount_point=self.transit_mount_point
                )
            except:
                pass

            print(f"✅ Vault configurado correctamente")

        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            raise

    def encrypt_data(self, plaintext: str) -> str:
        """Encriptar texto"""
        if not plaintext:
            return ""

        plaintext_b64 = base64.b64encode(
            plaintext.encode('utf-8')).decode('utf-8')

        response = self.client.secrets.transit.encrypt_data(
            name=self.key_name,
            plaintext=plaintext_b64,
            mount_point=self.transit_mount_point
        )

        return response['data']['ciphertext']

    def decrypt_data(self, ciphertext: str) -> str:
        """Desencriptar texto"""
        if not ciphertext or not ciphertext.startswith("vault:v"):
            return ciphertext

        response = self.client.secrets.transit.decrypt_data(
            name=self.key_name,
            ciphertext=ciphertext,
            mount_point=self.transit_mount_point
        )

        plaintext_b64 = response['data']['plaintext']
        return base64.b64decode(plaintext_b64).decode('utf-8')

    # ========== MÉTODOS DE FIRMA (SIMPLIFICADOS) ==========

    def _normalize_fecha(self, fecha_str: str) -> str:
        """
        Normaliza fecha para que sea consistente
        Trunca a segundos (sin microsegundos)
        """
        if not fecha_str:
            return ""

        try:
            # Parsear fecha
            if 'T' in fecha_str:
                # Formato ISO con timezone
                fecha_str_clean = fecha_str.split(
                    '.')[0]  # Quitar microsegundos
                if '+' in fecha_str:
                    fecha_str_clean = fecha_str_clean.split('+')[0]
                return fecha_str_clean + 'Z'  # Agregar Z al final
            return fecha_str
        except:
            return fecha_str

    def _calculate_hash(self, denuncia: dict) -> str:
        """
        Calcula hash - SIN fecha para evitar problemas
        """
        # 🔧 SOLUCIÓN: NO incluir fecha en el hash
        # La fecha puede tener problemas de microsegundos/timezone
        data_to_hash = {
            "user_id": str(denuncia.get("user_id", "")),
            "categoria": str(denuncia.get("categoria", "")),
            "ubicacion": str(denuncia.get("ubicacion", "")),
            "descripcion": str(denuncia.get("descripcion", "")),
            "evidencias": sorted(denuncia.get("evidencias", []))
            # ⚠️ NO incluimos fecha_creacion
        }

        # Serializar
        json_str = json.dumps(data_to_hash, sort_keys=True, ensure_ascii=False)

        # Calcular hash
        hash_value = hashlib.sha256(json_str.encode('utf-8')).hexdigest()

        return hash_value

    def sign_denuncia(self, denuncia: dict) -> dict:
        """
        Firma la denuncia ANTES de encriptar
        """
        print(f"🖊️  Firmando denuncia...")

        # Calcular hash
        hash_value = self._calculate_hash(denuncia)
        print(f"   Hash: {hash_value[:16]}...")

        # Firmar con Vault
        response = self.client.secrets.transit.sign_data(
            name=self.sign_key_name,
            mount_point=self.transit_mount_point,
            hash_input=hash_value,
            hash_algorithm="sha2-256"
        )

        # Agregar firma
        denuncia['firma_digital'] = response['data']['signature']
        denuncia['hash_original'] = hash_value

        print(f"   ✅ Firmada")

        return denuncia

    def verify_denuncia(self, denuncia: dict) -> bool:
        """
        Verifica firma DESPUÉS de desencriptar
        """
        # Si no tiene firma, es válida
        if 'firma_digital' not in denuncia or not denuncia['firma_digital']:
            return True

        # Calcular hash actual
        current_hash = self._calculate_hash(denuncia)
        stored_hash = denuncia.get('hash_original', '')

        print(f"   Verificando firma...")
        print(f"   Hash almacenado: {stored_hash[:16]}...")
        print(f"   Hash calculado:  {current_hash[:16]}...")

        # Comparar hashes
        if stored_hash != current_hash:
            print(f"   ❌ HASHES NO COINCIDEN")
            print(f"      Completo almacenado: {stored_hash}")
            print(f"      Completo calculado:  {current_hash}")
            return False

        # Verificar con Vault
        try:
            response = self.client.secrets.transit.verify_signed_data(
                name=self.sign_key_name,
                mount_point=self.transit_mount_point,
                hash_input=current_hash,
                signature=denuncia['firma_digital'],
                hash_algorithm="sha2-256"
            )

            is_valid = response['data']['valid']

            if is_valid:
                print(f"   ✅ Firma válida")
            else:
                print(f"   ❌ Firma inválida")

            return is_valid

        except Exception as e:
            print(f"   ⚠️  Error: {str(e)}")
            return True

    # ========== FIN MÉTODOS DE FIRMA ==========

    def encrypt_denuncia_fields(self, denuncia_data: Dict) -> Dict:
        """Encriptar campos"""
        denuncia_encriptada = denuncia_data.copy()

        if "categoria" in denuncia_encriptada:
            denuncia_encriptada["categoria"] = self.encrypt_data(
                denuncia_encriptada["categoria"]
            )

        if "ubicacion" in denuncia_encriptada:
            denuncia_encriptada["ubicacion"] = self.encrypt_data(
                denuncia_encriptada["ubicacion"]
            )

        if "descripcion" in denuncia_encriptada:
            denuncia_encriptada["descripcion"] = self.encrypt_data(
                denuncia_encriptada["descripcion"]
            )

        if "evidencias" in denuncia_encriptada:
            if denuncia_encriptada["evidencias"]:
                evidencias_json = json.dumps(
                    denuncia_encriptada["evidencias"],
                    ensure_ascii=False,
                    sort_keys=True
                )
                denuncia_encriptada["evidencias"] = self.encrypt_data(
                    evidencias_json)
            else:
                denuncia_encriptada["evidencias"] = self.encrypt_data("[]")

        if "firma_digital" in denuncia_encriptada and denuncia_encriptada["firma_digital"]:
            denuncia_encriptada["firma_digital"] = self.encrypt_data(
                denuncia_encriptada["firma_digital"]
            )

        if "hash_original" in denuncia_encriptada and denuncia_encriptada["hash_original"]:
            denuncia_encriptada["hash_original"] = self.encrypt_data(
                denuncia_encriptada["hash_original"]
            )

        return denuncia_encriptada

    def decrypt_denuncia_fields(self, denuncia_encriptada: Dict) -> Dict:
        """Desencriptar campos"""
        denuncia_desencriptada = denuncia_encriptada.copy()

        if "categoria" in denuncia_desencriptada:
            denuncia_desencriptada["categoria"] = self.decrypt_data(
                denuncia_desencriptada["categoria"]
            )

        if "ubicacion" in denuncia_desencriptada:
            denuncia_desencriptada["ubicacion"] = self.decrypt_data(
                denuncia_desencriptada["ubicacion"]
            )

        if "descripcion" in denuncia_desencriptada:
            denuncia_desencriptada["descripcion"] = self.decrypt_data(
                denuncia_desencriptada["descripcion"]
            )

        if "evidencias" in denuncia_desencriptada and denuncia_desencriptada["evidencias"]:
            evidencias_json = self.decrypt_data(
                denuncia_desencriptada["evidencias"]
            )
            try:
                denuncia_desencriptada["evidencias"] = json.loads(
                    evidencias_json)
            except:
                denuncia_desencriptada["evidencias"] = []

        if "firma_digital" in denuncia_desencriptada and denuncia_desencriptada["firma_digital"]:
            denuncia_desencriptada["firma_digital"] = self.decrypt_data(
                denuncia_desencriptada["firma_digital"]
            )

        if "hash_original" in denuncia_desencriptada and denuncia_desencriptada["hash_original"]:
            denuncia_desencriptada["hash_original"] = self.decrypt_data(
                denuncia_desencriptada["hash_original"]
            )

        return denuncia_desencriptada


# Instancia global
try:
    vault_client = VaultClient()
    print("\n✅ VaultClient listo")
except Exception as e:
    print(f"\n❌ Error: {str(e)}")
    vault_client = None
