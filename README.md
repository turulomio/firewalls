# Firewalls Configuration

Gestión centralizada de configuraciones de `firewalld` para diferentes máquinas en Gentoo Linux, empaquetado y gestionado con **Poetry**.

## Estructura del proyecto

Cada máquina tiene su propio directorio en la raíz del repositorio. Dentro de cada máquina, cuelga la estructura real a partir de `/etc`:

```text
firewalls/
├── pyproject.toml                # Configuración del paquete y dependencias con Poetry
├── firewalls/                    # Paquete Python con el comando CLI
│   ├── __init__.py
│   └── cli.py
├── deploy.py                     # Script ejecutable directo en Python
├── README.md
└── worky/                        # Configuración para la máquina "worky"
    ├── WORKY.md                  # Descripción funcional de reglas y servicios de la máquina
    └── etc/
        └── firewalld/
            ├── firewalld.conf    # Configuración principal
            ├── zones/            # Definición de zonas (p. ej. public.xml)
            ├── services/         # Definición de servicios personalizados
            ├── ipsets/           # Definición de ipsets
            ├── icmptypes/        # Definición de tipos ICMP
            ├── helpers/          # Helpers de conexión
            └── policies/         # Políticas de firewalld
```

## Uso

Puedes ejecutar el despliegue de cualquiera de las siguientes formas:

### 1. Con Poetry
```bash
poetry run firewalls_deploy <nombre_maquina>
```

### 2. Directamente con el script Python
```bash
./deploy.py <nombre_maquina>
```

Ejemplo para la máquina `worky`:
```bash
poetry run firewalls_deploy worky
# o bien
./deploy.py worky
```

### Qué hace el comando `firewalls_deploy`:
1. Valida que la configuración de la máquina especificada existe.
2. Requiere permisos de `root` (debe ser ejecutado directamente por root).
3. Sincroniza recursivamente `<nombre_maquina>/etc/` en `/etc/` preservando permisos.
4. Asigna propietario `root:root` y permisos estándar a los archivos escritos en `/etc/firewalld` (`0750` directorios, `0644` ficheros), sin alterar los permisos de `/etc`.
5. Ejecuta `firewall-cmd --reload` (o arranca el servicio si no estaba iniciado con OpenRC / systemd).

### Monitorización de Logs (`ingress` y `egress`):

Puedes monitorizar o resumir los eventos bloqueados con los siguientes comandos registrados en Poetry:

```bash
# Monitorizar conexiones entrantes bloqueadas (Ingress)
poetry run firewalls_log_ingress
poetry run firewalls_log_ingress --summary   # Muestra resumen ordenado

# Monitorizar conexiones salientes bloqueadas (Egress)
poetry run firewalls_log_egress
poetry run firewalls_log_egress --summary    # Muestra resumen ordenado

# Dashboard en tiempo real con refresco e historial de posiciones configurable
poetry run firewalls_monitor                            # Refresco por defecto (3s) y 20 posiciones
poetry run firewalls_monitor -n 2 -p 5                  # Refresco cada 2s mostrando 5 posiciones
poetry run firewalls_monitor --interval 5 --positions 50 # Refresco cada 5s mostrando 50 posiciones
```

## Configuración de Logs (`syslog-ng`)

Para que los archivos de configuración en `etc/syslog-ng/conf.d/` (como `firewalld.conf`) sean cargados por `syslog-ng` en el sistema de destino, es necesario incluir la siguiente línea en `/etc/syslog-ng/syslog-ng.conf`:

```syslog-ng
@include "/etc/syslog-ng/conf.d/*.conf"
```

## Añadir una nueva máquina

Para añadir una nueva máquina (por ejemplo `servidor1`):

1. Crea la estructura base:
   ```bash
   mkdir -p servidor1/etc/firewalld/{zones,services,ipsets,icmptypes,helpers,policies}
   cp -r worky/etc/firewalld/* servidor1/etc/firewalld/
   ```
2. Personaliza los archivos XML de zonas y configuración según las necesidades de esa máquina.
3. Despliega los cambios con `poetry run firewalls_deploy servidor1` o `./deploy.py servidor1`.
