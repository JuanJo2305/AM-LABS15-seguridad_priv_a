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

## Licencia

Este proyecto es para fines educativos y demostrativos.
