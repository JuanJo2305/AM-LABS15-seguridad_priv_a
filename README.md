# App de Seguridad y Privacidad

Una aplicación Android que demuestra el manejo seguro de permisos y protección de datos personales.

## Características

### Gestión de Permisos
- **Cámara**: Captura de fotos con manejo seguro
- **Galería**: Acceso a imágenes del dispositivo
- **Micrófono**: Grabación de audio con permisos dinámicos
- **Contactos**: Lectura segura de la lista de contactos
- **Teléfono**: Funcionalidad de llamadas
- **Ubicación**: Acceso a localización del usuario

### Seguridad y Privacidad
- **Protección de Datos**: Sistema de logging encriptado
- **Almacenamiento Seguro**: Base de datos SQLCipher
- **Permisos Runtime**: Solicitud dinámica de permisos
- **Política de Privacidad**: Información transparente sobre el uso de datos

## Tecnologías Utilizadas

- **Kotlin**: Lenguaje principal
- **Android Jetpack**: Componentes modernos
- **SQLCipher**: Encriptación de base de datos
- **Camera2 API**: Manejo avanzado de cámara
- **Security Crypto**: Encriptación de datos sensibles

## Instalación

1. Clona el repositorio
2. Abre el proyecto en Android Studio
3. Sincroniza las dependencias
4. Ejecuta en dispositivo o emulador

## Estructura del Proyecto

```
app/
├── src/main/java/com/example/seguridad_priv_a/
│   ├── MainActivity.kt                 # Pantalla principal
│   ├── PermissionsApplication.kt       # Configuración global
│   ├── data/
│   │   ├── DataProtectionManager.kt    # Gestión de datos seguros
│   │   └── PermissionItem.kt          # Modelo de permisos
│   ├── adapter/
│   │   └── PermissionsAdapter.kt      # Adaptador RecyclerView
│   └── [Actividades individuales]
└── res/
    ├── layout/                        # Diseños XML
    ├── values/                        # Recursos y strings
    └── xml/                          # Configuraciones
```

## Permisos Requeridos

- `CAMERA` - Para captura de fotos
- `READ_MEDIA_IMAGES` - Acceso a galería
- `RECORD_AUDIO` - Grabación de audio
- `READ_CONTACTS` - Lectura de contactos
- `CALL_PHONE` - Realizar llamadas
- `ACCESS_COARSE_LOCATION` - Ubicación aproximada


## ACTIVIDAD

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)
Analiza el archivo `DataProtectionManager.kt` y responde:
- ¿Qué método de encriptación se utiliza para proteger datos sensibles?

    La app usa `AES-256-GCM` para el cifrado de datos, lo cual es una elección sólida porque:
    - Proporciona confidencialidad mediante AES-256.
    - Asegura integridad/autenticación gracias al modo GCM.
    > 🔐 **AES-256-GCM** = Estándar moderno y recomendado para apps móviles.


- Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging
    #### 1. Acceso sin restricción a los registros
    ```kotlin
    val logs = dataProtectionManager.getAccessLogs()
    binding.tvAccessLogs.text = logsText
    ```
    - ❗ Riesgo: Se muestra información sin verificación de identidad.
    - 🛡️ Mejora: Solicitar autenticación biométrica o pin antes de mostrar logs.
    
    #### 2. Registro excesivo o sin límites
    ```kotlin
    dataProtectionManager.logAccess("DATA_MANAGEMENT", "Todos los datos borrados por el usuario")
    ```
    - ❗ Riesgo: Puede generar fuga de información o llenar el almacenamiento.
    - 🛡️ Mejora: Implementar retención de logs, niveles de severidad y cifrado si los logs contienen datos sensibles.
    
    ---

- ¿Qué sucede si falla la inicialización del sistema de encriptación?

    Actualmente, no se maneja adecuadamente una posible falla al instanciar `DataProtectionManager`.
    
    **Consecuencias potenciales**:
    - `NullPointerException` o fallos inesperados.
    - Pérdida de registro de accesos.
    - Desprotección sin alertas al usuario.
    
    **Soluciones sugeridas**:
    - Validar la instancia del manager y capturar excepciones.
    - Mostrar advertencias si el sistema de cifrado no está disponible.
    - Bloquear acceso a secciones sensibles si el sistema no se ha inicializado correctamente.


### 1.2 Permisos y Manifiesto (2 puntos)
Examina `AndroidManifest.xml` y `MainActivity.kt`:
- Lista todos los permisos peligrosos declarados en el manifiesto
    
    ### ✅ Permisos peligrosos declarados en `AndroidManifest.xml`:
    
    ```xml
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.CALL_PHONE" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    ```
    > Todos estos permisos están categorizados como "peligrosos" por Android, ya que permiten el acceso a información sensible del usuario o a funciones críticas del dispositivo.


- ¿Qué patrón se utiliza para solicitar permisos en runtime?
    La aplicación sigue el patrón moderno de Android Jetpack para solicitar permisos en tiempo de ejecución usando ActivityResultContracts.RequestPermission():
    
    ```kotlin
        private val requestPermissionLauncher = registerForActivityResult(
            ActivityResultContracts.RequestPermission()
        ) { isGranted ->
            // Manejo del resultado
        }
    
    ```
    Además, se verifica previamente con ContextCompat.checkSelfPermission y se maneja el resultado para abrir la actividad correspondiente solo si el permiso fue otorgado:

    ```kotlin
        if (permission.status == PermissionStatus.GRANTED) {
            openActivity(permission)
        } else {
            requestPermission(permission)
        }

    
    ```
 
- Identifica qué configuración de seguridad previene backups automáticos

  En el AndroidManifest.xml, se desactiva explícitamente la funcionalidad de backup automático:
  
    ```xml
        <application
            android:allowBackup="false"
            ...
    ```

### 1.3 Gestión de Archivos (3 puntos)
Revisa `CameraActivity.kt` y `file_paths.xml`:
- ¿Cómo se implementa la compartición segura de archivos de imágenes?

    Se utiliza `FileProvider` para generar URIs seguros (`content://`) que apuntan a archivos de imagen creados en almacenamiento externo privado:

    ```kotlin
    val photoFile = createImageFile()
    currentPhotoUri = FileProvider.getUriForFile(
        this,
        "com.example.seguridad_priv_a.fileprovider",
        photoFile
    )
    takePictureLauncher.launch(currentPhotoUri)
    ```
    Además, la ruta segura está declarada en res/xml/file_paths.xml:
    ```xml
    <paths xmlns:android="http://schemas.android.com/apk/res/android">
        <external-files-path name="my_images" path="Pictures" />
    </paths>

    ```
    > Esto permite que la aplicación use el almacenamiento externo privado sin exponer rutas reales del sistema de archivos.



- ¿Qué autoridad se utiliza para el FileProvider?
    ```xml
        android:authorities="com.example.seguridad_priv_a.fileprovider"
    ```
    > Esta autoridad debe coincidir exactamente con la utilizada en FileProvider.getUriForFile().

- Explica por qué no se debe usar `file://` URIs directamente
    - Usar URIs como file:// directamente está prohibido a partir de Android 7.0 (API 24) por razones de seguridad. Si una app intenta compartir un file://, se lanza una excepción FileUriExposedException.
    
    -Riesgos de usar file://:
    
        -- Exposición del sistema de archivos al resto del sistema.
        
        -- Acceso inseguro a datos sensibles.
        
        -- Incompatibilidad con políticas de seguridad modernas (Android Nougat+).
        
        -- ✅ En su lugar, FileProvider genera content:// URIs controlados por la app, que respetan los permisos y límites del sandbox de Android.

## Parte 2: Implementación y Mejoras Intermedias (8-14 puntos)

### 2.1 Fortalecimiento de la Encriptación (3 puntos)
Modifica `DataProtectionManager.kt` para implementar:
- Rotación automática de claves maestras cada 30 días

```kotlin
fun rotateEncryptionKey(): Boolean {
    return try {
        val currentIndex = accessLogPrefs.getInt(CURRENT_KEY_INDEX, 0)
        val newIndex = currentIndex + 1
        
        // Crear nueva clave
        buildMasterKey(newIndex)
        
        // Actualizar preferencias
        accessLogPrefs.edit()
            .putInt(CURRENT_KEY_INDEX, newIndex)
            .putLong(LAST_ROTATION_TIMESTAMP, System.currentTimeMillis())
            .apply()
        
        logAccess("KEY_ROTATION", "Clave rotada: $currentIndex → $newIndex")
        true
    } catch (e: Exception) {
        logAccess("KEY_ROTATION_FAILED", "Error: ${e.message}")
        false
    }
}

private fun shouldRotateKey(): Boolean {
    val lastRotation = accessLogPrefs.getLong(LAST_ROTATION_TIMESTAMP, 0)
    if (lastRotation == 0L) return true
    
    val rotationPeriod = KEY_ROTATION_PERIOD_DAYS * 24 * 60 * 60 * 1000L
    return (System.currentTimeMillis() - lastRotation) > rotationPeriod
}
```
Características:

    - Rotación automática cada 30 días
    
    - Versionado de claves (master_key_0, master_key_1, etc.)
    
    - Registro de eventos en bitácora de seguridad
    
    - Almacenamiento seguro del último timestamp de rotación


  
- Verificación de integridad de datos encriptados usando HMAC

```kotlin
fun verifyDataIntegrity(key: String): Boolean {
    val data = encryptedPrefs.getString(key, null) ?: return false
    val storedHmac = encryptedPrefs.getString("${key}_hmac", null) ?: return false
    
    val calculatedHmac = calculateHmac(data)
    val isValid = constantTimeCompare(storedHmac, calculatedHmac)
    
    if (!isValid) {
        logAccess("DATA_TAMPERED", "Dato alterado detectado: $key")
    }
    
    return isValid
}

private fun calculateHmac(data: String): String {
    val secretKey = getHmacSecretKey()
    val mac = Mac.getInstance(HMAC_ALGORITHM)
    mac.init(secretKey)
    val hmacBytes = mac.doFinal(data.toByteArray(Charsets.UTF_8))
    return Base64.getEncoder().encodeToString(hmacBytes)
}

private fun constantTimeCompare(a: String, b: String): Boolean {
    if (a.length != b.length) return false
    var result = 0
    for (i in a.indices) {
        result = result or (a[i].code xor b[i].code)
    }
    return result == 0
}
```

Características:

    - Algoritmo HMAC-SHA256 para verificación de integridad
    
    - Almacenamiento separado de datos y sus hashes
    
    - Comparación en tiempo constante para prevenir ataques de temporización
    
    - Detección automática de datos alterados con registro de eventos


- Implementación de key derivation con salt único por usuario

```kotlin
fun deriveUserKey(username: String, masterKey: String): String {
    val salt = getOrCreateUserSalt(username)
    return deriveKey(masterKey, salt)
}

private fun getOrCreateUserSalt(username: String): ByteArray {
    val saltKey = "salt_$username"
    var salt = encryptedPrefs.getString(saltKey, null)
    
    if (salt == null) {
        salt = generateSaltBase64()
        encryptedPrefs.edit().putString(saltKey, salt).apply()
    }
    
    return Base64.getDecoder().decode(salt)
}

private fun generateSaltBase64(): String {
    val salt = ByteArray(16)
    SecureRandom().nextBytes(salt)
    return Base64.getEncoder().encodeToString(salt)
}

private fun deriveKey(password: String, salt: ByteArray): String {
    val spec = PBEKeySpec(
        password.toCharArray(),
        salt,
        KDF_ITERATIONS,
        KDF_KEY_LENGTH
    )
    
    val factory = SecretKeyFactory.getInstance(KDF_ALGORITHM)
    val secretKey = factory.generateSecret(spec)
    return Base64.getEncoder().encodeToString(secretKey.encoded)
}
```

Características:

    - Salt único generado por usuario
    
    - Función PBKDF2 con 100,000 iteraciones
    
    - Longitud de clave de 256 bits
    
    - Almacenamiento seguro de salts en almacenamiento encriptado
    
    - Generación de salt con SecureRandom


### 2.2 Sistema de Auditoría Avanzado (3 puntos)
Crea una nueva clase `SecurityAuditManager` que:
- Detecte intentos de acceso sospechosos (múltiples solicitudes en corto tiempo)
- Implemente rate limiting para operaciones sensibles
- Genere alertas cuando se detecten patrones anómalos
- Exporte logs en formato JSON firmado digitalmente

```kotlin

package com.example.seguridad_priv_a.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.Signature
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import javax.crypto.KeyGenerator

class SecurityAuditManager(private val context: Context) {

    companion object {
        // Constantes para eventos
        const val EVENT_LOGIN = "LOGIN"
        const val EVENT_SENSITIVE_OPERATION = "SENSITIVE_OPERATION"
        const val EVENT_DATA_ACCESS = "DATA_ACCESS"
        const val EVENT_PERMISSION_REQUEST = "PERMISSION_REQUEST"
        
        // Configuración de seguridad
        private const val RATE_LIMIT_WINDOW_MS = 60_000 // 1 minuto
        private const val MAX_EVENTS_PER_WINDOW = 5
        private const val SUSPICIOUS_THRESHOLD = 3
    }

    private val eventLog = mutableListOf<AuditEvent>()
    private val eventTimestamps = ConcurrentHashMap<String, MutableList<Long>>()
    private val gson = Gson()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())

    data class AuditEvent(
        val eventId: String,
        val userId: String?,
        val eventType: String,
        val timestamp: String,
        val details: Map<String, String> = emptyMap()
    )

    data class SecurityAlert(
        val alertId: String,
        val eventId: String,
        val reason: String,
        val timestamp: String,
        val severity: Int // 1: Bajo, 2: Medio, 3: Alto
    )

    // Registra un evento y verifica si es sospechoso
    fun logEvent(eventType: String, userId: String? = null, details: Map<String, String> = emptyMap()): SecurityAlert? {
        val eventId = UUID.randomUUID().toString()
        val timestamp = dateFormat.format(Date())
        val event = AuditEvent(eventId, userId, eventType, timestamp, details)
        
        eventLog.add(event)
        recordEventTimestamp(eventType, userId)
        
        return checkForSuspiciousActivity(event)
    }

    // Implementa rate limiting para una operación
    fun allowOperation(userId: String, operationType: String): Boolean {
        val key = "$userId-$operationType"
        val timestamps = eventTimestamps[key] ?: return true
        
        // Filtrar eventos dentro de la ventana de tiempo
        val currentTime = System.currentTimeMillis()
        val recentEvents = timestamps.count { currentTime - it < RATE_LIMIT_WINDOW_MS }
        
        return recentEvents < MAX_EVENTS_PER_WINDOW
    }

    // Exporta los logs en formato JSON firmado
    fun exportSignedAuditLogs(): ByteArray {
        val auditData = mapOf(
            "events" to eventLog,
            "system" to getSystemInfo(),
            "export_timestamp" to System.currentTimeMillis()
        )
        
        val jsonLog = gson.toJson(auditData).toByteArray(StandardCharsets.UTF_8)
        return signData(jsonLog)
    }

    // Verifica la firma de un log exportado
    fun verifyLogSignature(signedData: ByteArray): Boolean {
        try {
            val signature = Signature.getInstance("SHA256withECDSA")
            val publicKey = getSigningPublicKey()
            signature.initVerify(publicKey)
            signature.update(signedData.copyOfRange(128, signedData.size))
            return signature.verify(signedData.copyOfRange(0, 128))
        } catch (e: Exception) {
            return false
        }
    }

    // ==================== Métodos Privados ====================

    private fun recordEventTimestamp(eventType: String, userId: String?) {
        val key = "${userId ?: "system"}-$eventType"
        val timestamps = eventTimestamps.getOrPut(key) { mutableListOf() }
        timestamps.add(System.currentTimeMillis())
        
        // Limpiar registros antiguos
        val currentTime = System.currentTimeMillis()
        eventTimestamps[key] = timestamps.filter { currentTime - it < TimeUnit.DAYS.toMillis(1) }.toMutableList()
    }

    private fun checkForSuspiciousActivity(event: AuditEvent): SecurityAlert? {
        val key = "${event.userId ?: "system"}-${event.eventType}"
        val timestamps = eventTimestamps[key] ?: return null
        
        // Verificar actividad sospechosa
        val currentTime = System.currentTimeMillis()
        val recentEvents = timestamps.count { currentTime - it < RATE_LIMIT_WINDOW_MS }
        
        if (recentEvents >= SUSPICIOUS_THRESHOLD) {
            val alertId = UUID.randomUUID().toString()
            val reason = when {
                recentEvents >= MAX_EVENTS_PER_WINDOW -> "Actividad excesiva detectada"
                event.eventType == EVENT_LOGIN -> "Múltiples intentos de acceso"
                else -> "Patrón de actividad anómalo"
            }
            
            val severity = when {
                recentEvents >= MAX_EVENTS_PER_WINDOW -> 3
                event.eventType == EVENT_SENSITIVE_OPERATION -> 2
                else -> 1
            }
            
            val alert = SecurityAlert(
                alertId,
                event.eventId,
                reason,
                dateFormat.format(Date()),
                severity
            )
            
            // Aquí podrías agregar notificaciones o acciones adicionales
            return alert
        }
        
        return null
    }

    private fun signData(data: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        val privateKey = getSigningPrivateKey()
        signature.initSign(privateKey)
        signature.update(data)
        val signatureBytes = signature.sign()
        
        // Combinar firma + datos
        return signatureBytes + data
    }

    private fun getSigningPrivateKey(): java.security.PrivateKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        if (!keyStore.containsAlias("audit_log_signing_key")) {
            createSigningKey()
        }
        
        val entry = keyStore.getEntry("audit_log_signing_key", null) as KeyStore.PrivateKeyEntry
        return entry.privateKey
    }

    private fun getSigningPublicKey(): java.security.PublicKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getCertificate("audit_log_signing_key").publicKey
    }

    private fun createSigningKey() {
        val keyPairGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        
        val keySpec = KeyGenParameterSpec.Builder(
            "audit_log_signing_key",
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setKeySize(256)
            .build()
        
        keyPairGenerator.init(keySpec)
        keyPairGenerator.generateKeyPair()
    }

    private fun getSystemInfo(): Map<String, String> {
        return mapOf(
            "device_model" to android.os.Build.MODEL,
            "android_version" to android.os.Build.VERSION.RELEASE,
            "app_version" to context.packageManager.getPackageInfo(context.packageName, 0).versionName,
            "security_patch" to android.os.Build.VERSION.SECURITY_PATCH
        )
    }
}

```
Explicación de la Implementación

Detección de Accesos Sospechosos

- **Registro de eventos:**  
  Cada evento se registra con una marca de tiempo.

- **Análisis de patrones:**  
  - Detección de múltiples eventos del mismo tipo en corto tiempo.  
  - Umbral configurable (`SUSPICIOUS_THRESHOLD`).  
  - Se considera el contexto (usuario + tipo de evento).

- **Generación de alertas:**  
  - Niveles de severidad (1-3).  
  - Razones específicas según el patrón detectado.

---

 Rate Limiting para Operaciones Sensibles

- **Control de frecuencia:**  
  - `MAX_EVENTS_PER_WINDOW`: Límite de operaciones por ventana de tiempo.  
  - `RATE_LIMIT_WINDOW_MS`: Duración de la ventana (1 minuto por defecto).

- **Implementación:**  
  - Registro de timestamps por operación/usuario.  
  - Cálculo de eventos recientes en cada solicitud.  
  - Respuesta booleana (`allowOperation`).

---

Generación de Alertas

- **Tipos de alertas:**  
  - Actividad excesiva (nivel 3).  
  - Múltiples intentos de acceso (nivel 2).  
  - Patrones anómalos (nivel 1).

- **Metadatos:**  
  - ID único de alerta.  
  - Evento relacionado.  
  - Timestamp exacto.  
  - Razón específica.

---

Exportación de Logs Firmados

- **Formato JSON:**  
  - Incluye todos los eventos.  
  - Metadatos del sistema.  
  - Timestamp de exportación.

- **Firma Digital:**  
  - Algoritmo ECDSA con SHA-256.  
  - Claves almacenadas en Android KeyStore.  
  - Firma concatenada con los datos.

- **Verificación:**  
  - Método `verifyLogSignature` para validar integridad.  
  - Separación de firma y datos.  


### 2.3 Biometría y Autenticación (3 puntos)
Implementa autenticación biométrica en `DataProtectionActivity.kt`:

- Integra BiometricPrompt API para proteger el acceso a logs

```kotlin

private fun createBiometricPrompt(): BiometricPrompt {
    return BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            unlockSensitiveData()
            resetSessionTimer()
        }
        // ... [otros métodos del callback] ...
    })
}

private fun authenticateForAccess() {
    if (canAuthenticateWithBiometrics()) {
        biometricPrompt.authenticate(promptInfo)
    } else {
        showFallbackAuthentication()
    }
}

```

Características:

    - Uso de BiometricPrompt para autenticación moderna
    
    - Soporte para múltiples métodos biométricos (huella, rostro)
    
    - Manejo de eventos de éxito y fallo
    
    - Integración con el flujo de la aplicación

  
- Implementa fallback a PIN/Pattern si biometría no está disponible

```kotlin
private fun showFallbackAuthentication() {
        val intent = Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD)
        if (intent.resolveActivity(packageManager) != null) {
            startActivityForResult(intent, REQUEST_CODE_SET_CREDENTIALS)
        } else {
            createPinDialog()
        }
    }
    
    private fun createPinDialog() {
        val pinView = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "Ingrese su PIN"
        }
        
        AlertDialog.Builder(this)
            .setTitle("Autenticación con PIN")
            .setView(pinView)
            .setPositiveButton("Verificar") { _, _ ->
                // Aquí iría la lógica de verificación real del PIN
                unlockSensitiveData()
                resetSessionTimer()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
```

Características:

    - Detección automática de capacidades del dispositivo
    
    - Redirección al sistema para configuración de credenciales
    
    - Diálogo de PIN personalizado como último recurso
    
    - Compatibilidad con diferentes niveles de seguridad

- Añade timeout de sesión tras inactividad de 5 minutos

```kotlin

private val sessionTimeoutRunnable = Runnable {
    lockSensitiveData()
}

private fun resetSessionTimer() {
    sessionHandler.removeCallbacks(sessionTimeoutRunnable)
    sessionHandler.postDelayed(sessionTimeoutRunnable, SESSION_TIMEOUT)
}

override fun onUserInteraction() {
    super.onUserInteraction()
    resetSessionTimer()
}

```
Características:

    - Temporizador de 5 minutos de inactividad
    
    - Reinicio del temporizador con cada interacción del usuario
    
    - Bloqueo automático de datos sensibles al expirar
    
    - Uso de Handler para gestión eficiente del tiempo

Configuración Requerida

AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC"/>
<uses-permission android:name="android.permission.USE_DEVICE_CREDENTIAL"/>
```

### build.gradle

```gradle
dependencies {
    implementation "androidx.biometric:biometric:1.2.0-alpha05"
}

```
Configuración de Biometría
- Los usuarios deben tener configurado un método de autenticación biométrica o credenciales de dispositivo en:

        Configuración > Seguridad > Autenticación biométrica
        
        Configuración > Seguridad > Bloqueo de pantalla


## Licencia

Este proyecto es para fines educativos y demostrativos.
