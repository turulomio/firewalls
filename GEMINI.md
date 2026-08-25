# Proyecto Firewalls (firewalld en Gentoo)

## 📌 Objetivo del Proyecto
Este proyecto centraliza y gestiona las configuraciones de firewall basadas en `firewalld` para distintas máquinas que ejecutan **Gentoo Linux**. Permite mantener la configuración versionada en git y desplegarla fácilmente en la máquina correspondiente mediante un comando CLI en Python gestionado con **Poetry**.

---

## 🗂️ Estructura del Repositorio

- Cada máquina tiene un directorio en la raíz con su nombre (ejemplo: `worky/`).
- Dentro de la carpeta de cada máquina, existen:
  - `<NOMBRE_MAQUINA>.md` (ejemplo: `WORKY.md`): Documento en mayúsculas que describe las reglas activas de forma funcional y los servicios que se quieren configurar.
  - Subdirectorio `etc/` que reproduce fielmente la estructura real que se copiará a `/etc/` en el sistema de destino:
  ```text
  <nombre_maquina>/
  ├── <NOMBRE_MAQUINA>.md
  └── etc/
      └── firewalld/
          ├── firewalld.conf
          ├── zones/
          ├── services/
          ├── ipsets/
          ├── icmptypes/
          ├── helpers/
          └── policies/
  ```
- **Código Python**:
  - `firewalls/`: Paquete Python que contiene la lógica del CLI (`firewalls/cli.py`).
  - `deploy.py`: Punto de entrada directo en la raíz.
  - `pyproject.toml`: Configuración del proyecto, dependencias y script de consola `deploy` gestionado con **Poetry**.

---

## 🛠️ Herramientas y Convenciones

1. **Gestor de dependencias / empaquetado**:
   - Usar **Poetry** (`pyproject.toml`).
   - Dependencias de terminal: `colorama` para formateo y colores.
   - Comando disponible registrado en Poetry: `poetry run deploy <nombre_maquina>`.

2. **Sistema Operativo Destino**:
   - **Gentoo Linux**.
   - Soporta inicio tanto con **OpenRC** (`rc-service firewalld <action>`) como con **systemd** (`systemctl <action> firewalld`).

3. **Reglas de Despliegue (`deploy`)**:
   - **Parámetro obligatorio**: Nombre de la máquina a desplegar.
   - **Ejecución y Privilegios**: Se asume que el usuario ejecutará el script con permisos de `root`. No se debe incluir lógica interna de `sudo` para reejecutar o elevar privilegios.
   - **Copia**: Sincroniza recursivamente `<maquina>/etc/` a `/etc/` preservando atributos y enlaces.
   - **Permisos de archivos**: **No se cambian los permisos del directorio `/etc`**. Únicamente se asigna propietario `root:root` y permisos estándar (`0750` directorios, `0644` ficheros) a los elementos que se escriban bajo `/etc/firewalld`.
   - **Recarga automática**: Si `firewalld` está activo, ejecuta `firewall-cmd --reload`. Si está detenido, intenta arrancarlo mediante el gestor de servicios del sistema.

4. **Configuración de Logs (`syslog-ng`)**:
   - Requiere incluir la siguiente directiva en `/etc/syslog-ng/conf.d/*.conf` desde `/etc/syslog-ng/syslog-ng.conf`:
     `@include "/etc/syslog-ng/conf.d/*.conf"`

---

## ➕ Añadir una nueva máquina
Para dar de alta una nueva máquina:
1. Crear el directorio `<nueva_maquina>/etc/firewalld/` con sus respectivas subcarpetas.
2. Copiar o generar las configuraciones XML de zonas/servicios correspondientes.
3. Desplegar con: `poetry run deploy <nueva_maquina>` o `./deploy.py <nueva_maquina>`.
