import hvac
import os
import base64
from typing import Dict
from dotenv import load_dotenv
import traceback
import sys

load_dotenv()


class VaultClient:
    def __init__(self):
        print("=" * 80)
        print("🔐 INICIALIZANDO VAULT CLIENT")
        print("=" * 80)

        # Verificar variables de entorno
        self.vault_addr = os.environ.get("VAULT_ADDR")
        self.vault_token = os.environ.get("VAULT_TOKEN")

        print(f"📋 Variables de entorno:")
        print(
            f"   VAULT_ADDR: {self.vault_addr if self.vault_addr else '❌ NO ENCONTRADA'}")
        print(
            f"   VAULT_TOKEN: {'✅ Encontrada (' + self.vault_token[:10] + '...)' if self.vault_token else '❌ NO ENCONTRADA'}")

        # Verificar todas las variables de entorno disponibles
        print(f"\n🔍 Todas las variables de entorno que contienen 'VAULT':")
        vault_vars = {k: v for k, v in os.environ.items()
                      if 'VAULT' in k.upper()}
        if vault_vars:
            for key, value in vault_vars.items():
                print(f"   {key}: {value[:20]}..." if len(
                    value) > 20 else f"   {key}: {value}")
        else:
            print(f"   ❌ No se encontraron variables con 'VAULT'")

        if not self.vault_addr or not self.vault_token:
            error_msg = "❌ VAULT_ADDR y VAULT_TOKEN deben estar configuradas"
            print(f"\n{error_msg}")
            print(f"💡 Asegúrate de configurarlas en Cloud Run:")
            print(f"   1. Ve a Cloud Run Console")
            print(f"   2. Edita tu servicio")
            print(f"   3. Variables y secretos → Agregar variable")
            print(f"   4. VAULT_ADDR = http://10.15.0.2:8200")
            print(f"   5. VAULT_TOKEN = hvs.tu_token_aqui")
            print("=" * 80)
            raise ValueError(error_msg)

        # Configuración del motor de encriptación
        self.transit_mount_point = "transit"
        self.key_name = "denuncias-key"

        # Inicializar cliente de Vault
        try:
            print(f"\n🔧 Creando cliente Vault...")
            print(f"   URL: {self.vault_addr}")
            print(f"   Token (primeros 10 chars): {self.vault_token[:10]}...")

            # Detectar si usa HTTPS
            verify_ssl = not self.vault_addr.startswith("http://")
            print(
                f"   SSL Verification: {'Enabled' if verify_ssl else 'Disabled'}")

            self.client = hvac.Client(
                url=self.vault_addr,
                token=self.vault_token,
                timeout=10,
                verify=verify_ssl
            )
            print(f"✅ Cliente Vault creado exitosamente")

        except Exception as e:
            print(f"❌ Error creando cliente Vault:")
            print(f"   Tipo de error: {type(e).__name__}")
            print(f"   Mensaje: {str(e)}")
            traceback.print_exc()
            raise

        # Auto-configurar Vault en el primer uso
        print(f"\n🚀 Iniciando auto-configuración...")
        self._auto_setup()
        print("=" * 80)

    def _auto_setup(self):
        """Configuración automática de Vault (se ejecuta una vez)"""
        try:
            print(f"\n📡 PASO 1: Verificando conectividad con Vault...")
            print(f"   Intentando conectar a: {self.vault_addr}")

            # Intentar una llamada simple para verificar conectividad
            try:
                health = self.client.sys.read_health_status(method='GET')
                print(f"✅ Vault responde - Status: {health}")
            except Exception as conn_error:
                print(f"❌ No se puede conectar a Vault:")
                print(f"   Tipo de error: {type(conn_error).__name__}")
                print(f"   Mensaje: {str(conn_error)}")
                print(f"\n💡 Posibles causas:")
                print(f"   1. Vault no está corriendo en {self.vault_addr}")
                print(f"   2. Firewall bloqueando el puerto 8200")
                print(
                    f"   3. Cloud Run no tiene acceso a la red privada (necesitas VPC Connector)")
                print(f"   4. IP incorrecta en VAULT_ADDR")
                print(f"\n🔍 Para diagnosticar desde Cloud Run, intenta:")
                print(f"   - Verificar que Vault esté corriendo: systemctl status vault")
                print(f"   - Verificar puerto abierto: netstat -tulpn | grep 8200")
                print(
                    f"   - Probar conectividad: curl {self.vault_addr}/v1/sys/health")
                raise

            print(f"\n🔑 PASO 2: Verificando autenticación...")

            if not self.client.is_authenticated():
                print(f"❌ Token de Vault inválido o expirado")
                print(f"   Token usado: {self.vault_token[:15]}...")
                print(f"\n💡 Solución:")
                print(f"   1. Conéctate a tu VM: gcloud compute ssh tu-vm")
                print(f"   2. Obtén el token root: sudo cat /opt/vault/data/root-token")
                print(f"   3. Actualiza VAULT_TOKEN en Cloud Run con ese valor")
                raise Exception("Token de Vault no válido")

            print(f"✅ Token válido y autenticado")

            # Intentar habilitar transit engine
            print(f"\n⚙️  PASO 3: Configurando Transit Engine...")
            try:
                print(
                    f"   Habilitando engine en ruta: /{self.transit_mount_point}")
                self.client.sys.enable_secrets_engine(
                    backend_type='transit',
                    path=self.transit_mount_point
                )
                print(
                    f"✅ Transit engine habilitado en /{self.transit_mount_point}")
            except Exception as e:
                error_msg = str(e).lower()
                if "path is already in use" in error_msg or "already mounted" in error_msg:
                    print(f"ℹ️  Transit engine ya está habilitado")
                else:
                    print(f"⚠️  Error habilitando transit:")
                    print(f"   {str(e)}")
                    raise e

            # Intentar crear clave de encriptación
            print(f"\n🔐 PASO 4: Configurando clave de encriptación...")
            try:
                print(f"   Creando clave: {self.key_name}")
                self.client.secrets.transit.create_key(
                    name=self.key_name,
                    mount_point=self.transit_mount_point
                )
                print(f"✅ Clave '{self.key_name}' creada exitosamente")
            except Exception as e:
                error_msg = str(e).lower()
                if "already exists" in error_msg:
                    print(f"ℹ️  Clave '{self.key_name}' ya existe")
                else:
                    print(f"⚠️  Error creando clave:")
                    print(f"   {str(e)}")
                    raise e

            print(f"\n✅ CONFIGURACIÓN COMPLETADA EXITOSAMENTE")
            print(f"   • Vault: {self.vault_addr}")
            print(f"   • Engine: /{self.transit_mount_point}")
            print(f"   • Key: {self.key_name}")

        except Exception as e:
            print(f"\n❌ ERROR EN AUTO-SETUP DE VAULT")
            print(f"   Tipo: {type(e).__name__}")
            print(f"   Mensaje: {str(e)}")
            print(f"\n📋 Información de diagnóstico:")
            print(f"   • Vault Address: {self.vault_addr}")
            print(f"   • Token (10 chars): {self.vault_token[:10]}...")
            print(f"   • Python version: {sys.version}")
            print(f"\n🔍 Stack trace completo:")
            traceback.print_exc()
            print("=" * 80)
            raise

    def check_connection(self) -> bool:
        """Verificar conexión con Vault"""
        try:
            if self.client.is_authenticated():
                print("✅ Conexión exitosa con Vault")
                return True
            else:
                print("❌ Token de Vault no válido")
                return False
        except Exception as e:
            print(f"❌ Error conectando a Vault: {str(e)}")
            return False

    def encrypt_data(self, plaintext: str) -> str:
        """
        Encriptar texto plano con Vault
        Retorna: vault:v1:abc123... (ciphertext)
        """
        try:
            if not plaintext:
                return ""

            # Convertir a base64 como requiere Vault
            plaintext_b64 = base64.b64encode(
                plaintext.encode('utf-8')).decode('utf-8')

            # Encriptar usando Vault Transit
            encrypt_response = self.client.secrets.transit.encrypt_data(
                name=self.key_name,
                plaintext=plaintext_b64,
                mount_point=self.transit_mount_point
            )

            ciphertext = encrypt_response['data']['ciphertext']
            return ciphertext

        except Exception as e:
            print(f"❌ Error encriptando: {str(e)}")
            raise Exception(f"Error en encriptación: {str(e)}")

    def decrypt_data(self, ciphertext: str) -> str:
        """
        Desencriptar ciphertext de Vault
        """
        try:
            if not ciphertext or ciphertext == "":
                return ""

            # Si no tiene el formato de Vault, retornar tal cual (dato no encriptado)
            if not ciphertext.startswith("vault:v"):
                return ciphertext

            # Desencriptar usando Vault Transit
            decrypt_response = self.client.secrets.transit.decrypt_data(
                name=self.key_name,
                ciphertext=ciphertext,
                mount_point=self.transit_mount_point
            )

            plaintext_b64 = decrypt_response['data']['plaintext']

            # Decodificar de base64
            plaintext = base64.b64decode(plaintext_b64).decode('utf-8')
            return plaintext

        except Exception as e:
            print(f"❌ Error desencriptando: {str(e)}")
            # Si falla, retornar el texto original (puede ser dato antiguo sin encriptar)
            return ciphertext

    def encrypt_denuncia_fields(self, denuncia_data: Dict) -> Dict:
        """
        Encriptar campos sensibles de la denuncia
        Incluye categoría, ubicación, descripción Y evidencias
        """
        try:
            import json
            denuncia_encriptada = denuncia_data.copy()

            # Encriptar cada campo sensible individualmente
            if "categoria" in denuncia_encriptada:
                print(f"🔐 Encriptando categoría...")
                denuncia_encriptada["categoria"] = self.encrypt_data(
                    denuncia_encriptada["categoria"]
                )

            if "ubicacion" in denuncia_encriptada:
                print(f"🔐 Encriptando ubicación...")
                denuncia_encriptada["ubicacion"] = self.encrypt_data(
                    denuncia_encriptada["ubicacion"]
                )

            if "descripcion" in denuncia_encriptada:
                print(f"🔐 Encriptando descripción...")
                denuncia_encriptada["descripcion"] = self.encrypt_data(
                    denuncia_encriptada["descripcion"]
                )

            # 🔐 ENCRIPTAR EVIDENCIAS (array de URLs)
            if "evidencias" in denuncia_encriptada and denuncia_encriptada["evidencias"]:
                print(
                    f"🔐 Encriptando {len(denuncia_encriptada['evidencias'])} evidencia(s)...")
                # Convertir array a JSON string y encriptar
                evidencias_json = json.dumps(
                    denuncia_encriptada["evidencias"], ensure_ascii=False)
                denuncia_encriptada["evidencias"] = self.encrypt_data(
                    evidencias_json)
            elif "evidencias" in denuncia_encriptada and not denuncia_encriptada["evidencias"]:
                # Si no hay evidencias, encriptar un array vacío
                denuncia_encriptada["evidencias"] = self.encrypt_data("[]")

            print(f"✅ Todos los campos encriptados exitosamente")
            return denuncia_encriptada

        except Exception as e:
            print(f"❌ Error encriptando denuncia: {str(e)}")
            raise

    def decrypt_denuncia_fields(self, denuncia_encriptada: Dict) -> Dict:
        """
        Desencriptar campos sensibles de la denuncia
        Ahora incluye las evidencias
        """
        try:
            denuncia_desencriptada = denuncia_encriptada.copy()

            # Desencriptar cada campo
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

            # 🆕 DESENCRIPTAR EVIDENCIAS
            if "evidencias_encriptadas" in denuncia_desencriptada and denuncia_desencriptada["evidencias_encriptadas"]:
                import json
                evidencias_json = self.decrypt_data(
                    denuncia_desencriptada["evidencias_encriptadas"])
                denuncia_desencriptada["evidencias"] = json.loads(
                    evidencias_json)
                # Opcional: remover el campo encriptado de la respuesta
                del denuncia_desencriptada["evidencias_encriptadas"]

            return denuncia_desencriptada

        except Exception as e:
            print(f"⚠️  Error desencriptando denuncia: {str(e)}")
            # Si falla, retornar datos originales
            return denuncia_encriptada


# Instancia global del cliente
print("\n" + "=" * 80)
print("🚀 INICIANDO CARGA DE VAULT CLIENT")
print("=" * 80)

try:
    vault_client = VaultClient()
    print("\n✅ VaultClient instanciado globalmente y funcionando")
    print("=" * 80)
except Exception as e:
    print(f"\n❌ ERROR CRÍTICO: No se pudo crear VaultClient")
    print(f"   Tipo de error: {type(e).__name__}")
    print(f"   Mensaje: {str(e)}")
    print(f"\n⚠️  La aplicación continuará SIN ENCRIPTACIÓN")
    print(f"   Las denuncias se guardarán en texto plano")
    print("\n🔍 Para solucionar:")
    print("   1. Verifica que VAULT_ADDR y VAULT_TOKEN estén en Cloud Run")
    print("   2. Verifica conectividad de red (puede necesitar VPC Connector)")
    print("   3. Revisa los logs arriba para más detalles")
    print("=" * 80)
    traceback.print_exc()
    print("=" * 80)
    vault_client = None
