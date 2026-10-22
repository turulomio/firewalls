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
├── README.md
└── worky/                        # Configuración para la máquina "worky"
    ├── WORKY.md                  # Descripción funcional de reglas y servicios de la máquina
    ├── post_deploy.sh            # Script opcional de comandos post-despliegue
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

Puedes ejecutar el despliegue con **Poetry**:

### Desplegar una máquina
```bash
poetry run firewalls_deploy <nombre_maquina>
```

Ejemplo para la máquina `worky`:
```bash
poetry run firewalls_deploy worky
```

### Detener el servicio `firewalld`:
```bash
poetry run firewalls_deploy stop
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

# Dashboard en tiempo real con refresco, historial de posiciones y resolución DNS (PTR)
poetry run firewalls_monitor                            # Refresco por defecto (3s), 20 posiciones y resolución DNS
poetry run firewalls_monitor -n 2 -p 5                  # Refresco cada 2s mostrando 5 posiciones
poetry run firewalls_monitor --no-resolve               # Desactivar la resolución de nombres de dominio (solo IPs)
```

## 🧪 Pruebas de Conectividad (`firewalls_probes`)

El comando `firewalls_probes` permite ejecutar pruebas de conectividad tanto **salientes (egress)** como **entrantes (ingress)** para validar que el firewall está aplicando las reglas de forma esperada.

### Opciones del comando `firewalls_probes`

| Parámetro | Opción corta | Descripción | Valor por defecto |
| :--- | :--- | :--- | :--- |
| `--host` | `-H` | Host o dirección IP de destino para pruebas salientes | `kde.org` |
| `--port` | `-p` | Puerto a probar | `1555` |
| `--protocol` | `-proto` | Protocolo de transporte (`tcp` o `udp`) | `tcp` |
| `--timeout` | `-t` | Tiempo máximo de espera en segundos | `5.0` |
| `--count` | `-c` | Número de intentos a realizar | `1` |
| `--listen` | `-l` | **Modo Escucha (Entrante/Ingress)**: Abre el puerto en el PC local | Desactivado (Saliente) |
| `--bind` | `-b` | Dirección IP de interfaz local para modo escucha | `0.0.0.0` |

---

### Set de Pruebas Recomendado

A continuación se detalla un conjunto de pruebas estándar para validar el comportamiento del firewall:

#### 1. Verificación de Tráfico Saliente Permitido (Egress - Éxito esperado)

- **Navegación Web Estándar (HTTP/HTTPS)**:
  ```bash
  poetry run firewalls_probes -H kde.org -p 80 -proto tcp
  poetry run firewalls_probes -H kde.org -p 443 -proto tcp
  ```
- **Sincronización Portage de Gentoo (rsync)**:
  ```bash
  poetry run firewalls_probes -H rsync.gentoo.org -p 873 -proto tcp
  ```
- **Resolución DNS y Sincronización Horaria (NTP)**:
  ```bash
  poetry run firewalls_probes -H 1.1.1.1 -p 53 -proto udp
  poetry run firewalls_probes -H pool.ntp.org -p 123 -proto udp
  ```

#### 2. Comprobación de Bloqueo de Salida No Autorizada (Zero Trust - Bloqueo esperado)

- **Intento de conexión a puerto no autorizado (ej. TCP 1555)**:
  ```bash
  poetry run firewalls_probes -H kde.org -p 1555 -proto tcp -t 3.0
  ```
  *Resultado esperado*: `[DENEGADO/FALLO]` por `Tiempo de espera agotado (Timeout)`.

- **Intento de SSH saliente a host remoto (TCP 22)**:
  ```bash
  poetry run firewalls_probes -H github.com -p 22 -proto tcp -t 3.0
  ```
  *Resultado esperado*: `[DENEGADO/FALLO]`.

#### 3. Verificación de Tráfico Entrante (Ingress / Escucha)

- **Comprobar si un puerto local está abierto a conexiones entrantes**:
  ```bash
  # Abre el puerto 8080 local a la escucha durante 10 segundos esperando una conexión entrante
  poetry run firewalls_probes -l -p 8080 -t 10.0
  ```
- **Escucha en puerto UDP local**:
  ```bash
  poetry run firewalls_probes -l -p 51820 -proto udp -t 10.0
  ```

#### 4. Validación Integrada con el Monitor de Firewall

Para verificar visualmente que las reglas de bloqueo registran eventos correctamente:

1. Abre una terminal y ejecuta el monitor en tiempo real:
   ```bash
   poetry run firewalls_monitor -a
   ```
2. En otra terminal, lanza un sondeo bloqueado:
   ```bash
   poetry run firewalls_probes -H kde.org -p 1555
   ```
3. Comprueba cómo el monitor registra la denegación en el panel de **SALIDAS DENEGADAS (EGRESS)** resolviendo la IP a su nombre de dominio en tiempo real.


## 📊 Configuración de Logs y Aislamiento de `dmesg`

Para evitar que los descartes del firewall inunden el buffer circular del kernel (`dmesg`) y `/var/log/messages`:

1. **Activación de Logging Bajo Demanda (`LogDenied=off` por defecto)**:
   - Tradicionalmente, `LogDenied=all` en `firewalld` invoca `printk()` a nivel de kernel mediante `nf_log_syslog`, inundando `dmesg` y la consola con paquetes de descarte de red local.
   - **Solución Dinámica**: En la configuración permanente de `firewalld.conf` se establece `LogDenied=off`. De este modo, en el día a día el firewall trabaja en completo silencio y sin sobrecargar `dmesg`.
   - **Gestión Automática en los Monitores CLI**:
     - Al iniciar `firewalls_log_ingress`, `firewalls_log_egress` o `firewalls_monitor` (ejecutados como `root`), estos activan automáticamente en tiempo de ejecución:
       ```bash
       firewall-cmd --set-log-denied=all
       ```
     - Al interrumpir la ejecución con **Ctrl+C**, se intercepta la señal y se desactiva de inmediato:
       ```bash
       firewall-cmd --set-log-denied=off
       ```
     - De esta forma, solo se generan logs en el kernel mientras se esté monitorizando activamente.

2. **Canalización con `syslog-ng`**:
   - `syslog-ng` captura las trazas generadas durante la monitorización y las dirige a `/var/log/firewalld/denied.log`.
   - Cuenta con una directiva `throttle(30)` para prevenir saturación de disco (*log-flooding*).
   - El CLI `firewalls_deploy` gestiona automáticamente la inclusión de `@include "/etc/syslog-ng/conf.d/*.conf"` antes de las directivas catch-all de `/var/log/messages`, garantizando con `flags(final);` que ninguna traza del firewall se duplique en `/var/log/messages`.



## Añadir una nueva máquina

Para añadir una nueva máquina (por ejemplo `servidor1`):

1. Crea la estructura base:
   ```bash
   mkdir -p servidor1/etc/firewalld/{zones,services,ipsets,icmptypes,helpers,policies}
   cp -r worky/etc/firewalld/* servidor1/etc/firewalld/
   ```
2. Personaliza los archivos XML de zonas y configuración según las necesidades de esa máquina.
3. Despliega los cambios con: `poetry run firewalls_deploy servidor1`.
