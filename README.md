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




## Licencia

Este proyecto es para fines educativos y demostrativos.
