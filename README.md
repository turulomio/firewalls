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
poetry run deploy <nombre_maquina>
```

### 2. Directamente con el script Python
```bash
./deploy.py <nombre_maquina>
```

Ejemplo para la máquina `worky`:
```bash
poetry run deploy worky
# o bien
./deploy.py worky
```

### Qué hace el comando `deploy`:
1. Valida que la configuración de la máquina especificada existe.
2. Solicita elevación automática de privilegios con `sudo` si no se ejecuta como `root`.
3. Sincroniza recursivamente `<nombre_maquina>/etc/` en `/etc/` preservando permisos.
4. Ajusta los permisos estándar de `/etc/firewalld` (`root:root`, directorios `750`, ficheros `644`).
5. Ejecuta `firewall-cmd --reload` (o arranca el servicio si no estaba iniciado con OpenRC / systemd).

## Añadir una nueva máquina

Para añadir una nueva máquina (por ejemplo `servidor1`):

1. Crea la estructura base:
   ```bash
   mkdir -p servidor1/etc/firewalld/{zones,services,ipsets,icmptypes,helpers,policies}
   cp -r worky/etc/firewalld/* servidor1/etc/firewalld/
   ```
2. Personaliza los archivos XML de zonas y configuración según las necesidades de esa máquina.
3. Despliega los cambios con `poetry run deploy servidor1` o `./deploy.py servidor1`.
