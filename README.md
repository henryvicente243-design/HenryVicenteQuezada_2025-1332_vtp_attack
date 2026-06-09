#Ataque VTP — Manipulación de Base de Datos VLAN

**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** 06 de Junio 2026

---

## 🎬 Video Demostrativo

https://youtu.be/TU_LINK_AQUI

---

## 1. Objetivo del Laboratorio

Demostrar cómo el protocolo VTP (VLAN Trunking Protocol) puede ser explotado para manipular la base de datos de VLANs de toda la red, agregando o eliminando VLANs arbitrarias desde un dispositivo externo no autorizado, y aplicar la contramedida correspondiente.

---

## 2. Objetivo del Script

Construir y enviar mensajes VTP maliciosos con un número de revisión superior al del servidor legítimo, logrando que el switch acepte cambios no autorizados en la base de datos de VLANs.

### 2.1 Parámetros Usados

| Parámetro   | Descripción                                  | Valor por defecto  |
| ----------- | -------------------------------------------- | ------------------ |
| `opcion`    | 1 = Agregar VLAN \| 2 = Borrar VLAN          | Menú interactivo   |
| `vlan_id`   | ID de la VLAN objetivo                       | Requerido          |
| `vlan_name` | Nombre de la VLAN (solo para agregar)        | Requerido          |
| `IFACE`     | Interfaz de red del atacante                 | `eth0`             |

### 2.2 Requisitos

- Sistema operativo: **Kali Linux**
- Python 3.x
- Librería Scapy: `pip install scapy`
- Permisos de root: `sudo`
- Puerto conectado al trunk del switch VTP Client (SW2)

---

## 3. Funcionamiento del Script

1. Construye un frame VTP Summary con `revision=9999` (mayor al legítimo)
2. Envía el Summary Advertisement al multicast `01:00:0c:cc:cc:cc`
3. Para agregar: construye un Subset Advertisement con la info de la VLAN nueva
4. Para borrar: envía un Subset sin VLAN info, forzando la eliminación de VLANs no listadas
5. El switch acepta los cambios por tener mayor Configuration Revision Number
6. Verifica el resultado con `show vlan brief` en SW1

```
Crear y guardar el script:
bash
nano /home/kali-linux/HenryVicenteQuezada_2025-1332_vtp_attack.py

Dar permisos de ejecución:
bash
chmod +x /home/kali-linux/HenryVicenteQuezada_2025-1332_vtp_attack.py

Pasos de ejecución:

Paso 1 — SW1: Ver VLANs antes del ataque
bash
show vlan brief
show vtp status

Paso 2 — SW1: Anotar el revision number actual
bash
show vtp status

Paso 3 — Kali: Ejecutar el ataque — Agregar VLAN
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_vtp_attack.py
Selecciona opcion: 1
VLAN ID a agregar: 50
Nombre de la VLAN: ATACANTE

Paso 4 — SW1: Verificar que la VLAN fue agregada
bash
show vlan brief

Paso 5 — Kali: Ejecutar el ataque — Borrar VLAN
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_vtp_attack.py
Selecciona opcion: 2
VLAN ID a borrar: 20

Paso 6 — SW1: Verificar que la VLAN fue borrada
bash
show vlan brief

Paso 7 — SW1: Aplicar contramedida
conf t
vtp mode transparent
end
write memory

Paso 8 — Kali: Ejecutar el ataque de nuevo
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_vtp_attack.py
Selecciona opcion: 1
VLAN ID a agregar: 77
Nombre de la VLAN: BLOQUEADA

Paso 9 — SW1: Verificar que el ataque fue bloqueado
bash
show vlan brief
show vtp status

🐍 Script — HenryVicenteQuezada_2025-1332_vtp_attack.py
python
#!/usr/bin/env python3
# =============================================================
# Nombre:     Henry Vicente Quezada
# Matricula:  2025-1332
# Ataque:     VTP Attack - Agregar y Borrar VLANs
# Fecha:      2026
# =============================================================
[PEGA AQUÍ EL SCRIPT COMPLETO]

🛡️ Contramedida aplicada
SW1(config)# vtp mode transparent
SW1(config)# end
SW1# write memory
SW2(config)# vtp mode transparent
SW2(config)# end
SW2# write memory
! Verificación
SW1# show vtp status
SW2# show vtp status
SW1# show vlan brief
```

---

## 4. Documentación de la Red

### Topología

![topologia](PEGA_IMAGEN_AQUI)

### Tabla de Direccionamiento

| Dispositivo | Interfaz | VLAN | IP          | Máscara | Rol                      |
| ----------- | -------- | ---- | ----------- | ------- | ------------------------ |
| R1          | e0/0.10  | 10   | 10.13.32.1  | /24     | Gateway VLAN10 TI        |
| R1          | e0/0.20  | 20   | 10.13.33.1  | /24     | Gateway VLAN20 Gerencia  |
| R1          | e0/0.99  | 99   | 10.13.99.1  | /24     | Gateway Management       |
| SW1         | vlan 99  | 99   | 10.13.99.2  | /24     | Gestión Switch VTP Server|
| SW2         | vlan 99  | 99   | 10.13.99.3  | /24     | Gestión Switch VTP Client|
| VPC10       | eth0     | 10   | 10.13.32.11 | /24     | Cliente VLAN10           |
| VPC20       | eth0     | 20   | 10.13.33.11 | /24     | Cliente VLAN20           |
| Kali        | eth0     | 10   | 10.13.32.5  | /24     | **Atacante**             |

### VLANs

| VLAN | Nombre     | Descripción                    |
| ---- | ---------- | ------------------------------ |
| 10   | TI         | Red de usuarios TI             |
| 20   | Gerencia   | Red de Gerencia                |
| 99   | Management | Red de gestión de dispositivos |

### Interfaces SW2 (VTP Client)

| Puerto | Modo              | VLAN     | Conectado a    |
| ------ | ----------------- | -------- | -------------- |
| e0/0   | Trunk 802.1q      | 10,20,99 | SW1 e0/1       |
| e0/1   | Access            | 10       | VPC10          |
| e0/2   | Access            | 20       | VPC20          |
| e0/3   | dynamic desirable | 10       | **Kali Linux** |

---

## 5. Capturas de Pantalla

### Antes del ataque

![antes](PEGA_IMAGEN_AQUI)

📷 SW1# show vlan brief — Solo VLANs 10, 20 y 99

### Script en ejecución

![script](PEGA_IMAGEN_AQUI)

📷 Kali ejecutando vtp_attack.py — Opción agregar VLAN 50

### Durante el ataque

![durante](PEGA_IMAGEN_AQUI)

📷 SW1# show vlan brief — VLAN 50 ATACANTE agregada sin autorización

### Contramedida aplicada

![contramedida](PEGA_IMAGEN_AQUI)

📷 SW1# show vtp status — Mode: Transparent, ataque bloqueado

---

En modo Transparent el switch ignora todos los anuncios VTP recibidos y no propaga cambios al dominio. Los paquetes VTP maliciosos son descartados silenciosamente.

