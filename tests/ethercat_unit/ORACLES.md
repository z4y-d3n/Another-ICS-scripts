# Oráculos de la suite unitaria EtherCAT

Desde la raíz del repositorio, ejecutar la suite con Python 3.12 o posterior.

    python -B -m unittest discover -s tests/ethercat_unit -p 'test_*.py' -v

La carpeta carece de paquete importable para que el descubrimiento histórico
desde `tests` siga separado. `support.py` reutiliza `OfflineGuard` durante la
carga inicial y en cada método. Las pruebas usan relojes virtuales y sustituyen
la frontera del sistema antes de invocar operaciones del adaptador Linux.

## Bytes EtherCAT

- `FPRD_REQUEST` y `APRD_REQUEST` son los literales del handoff de Gate 1.
  `NATIVE_REQUEST` conserva el literal de Gate 1.1, incluida la MAC ficticia
  del vínculo y sus 31 octetos de padding. El encoder se compara con esos
  bytes. [Beckhoff ESC Technology v2.5, §§2.1–2.5](https://download.beckhoff.com/download/Document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)
- `CHAINED` reproduce el literal SM-02 de Gate 1. Tiene un LRD con payload de
  un octeto y un comando desconocido con payload vacío. Los offsets esperados,
  16 y 29, se calculan a partir de Ethernet II (14), cabecera EtherCAT (2) y
  primer datagrama (10 + 1 + 2). Los offsets de comando, índice, ADP, ADO,
  longitud y banderas, IRQ, payload y primer WKC de un datagrama en offset 16
  son 16, 17, 18, 20, 22, 24, 26 y 26 + longitud. `MIN_FRAME`, `nop_chain` y
  `single_payload` derivan del mismo layout para fronteras y truncamientos.
  El EtherType va en orden de red. Las palabras EtherCAT son little-endian.
  La cadena excluye el padding y el contrato de captura excluye FCS.
  [Beckhoff ESC Technology v2.5, figs. 2–3 y tablas 2–4](https://download.beckhoff.com/download/Document/io/ethercat-development-products/ethercat_esc_datasheet_sec1_technology_v2.5.pdf)
- `FPRD_RETURN`, `APRD_RETURN` y `NATIVE_RETURN` son literales sintéticos
  compatibles con los contratos aprobados. WKC 1 requiere también
  atribución, tiempo, estructura, posición y valor. Los valores 0x11 y 0x12
  provienen de los perfiles de referencia de los Gates. El código 9 exige
  un evento explícito de rechazo sintético.
  [Beckhoff ESC Registers v3.3, §2.1.1](https://download.beckhoff.com/download/Document/io/ethercat-development-products/ethercat_esc_datasheet_sec2_registers_v3.3.pdf)

## Metadatos Linux y plazos

- `linux_fakes.py` modela el contrato de CPython de `recvmsg`, `send`,
  `settimeout` y `sockaddr_ll`. Las trazas esperan protocolo 0 en el
  constructor y EtherType en orden de host en el `bind`. Los resultados
  provienen de un guion finito. La correlación y la entrega las calcula el
  código de producción.
  [CPython socket 3.14](https://docs.python.org/3.14/library/socket.html)
  [Conversión AF_PACKET en CPython 3.14.5](https://github.com/python/cpython/blob/v3.14.5/Modules/socketmodule.c)
  [Linux packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html)
- AUXDATA se codifica con tres u32 y cuatro u16 (20 bytes).
  `sock_extended_err` contiene u32, cuatro u8 y dos u32 (16 bytes).
  `scm_timestamping64` incluye tres pares de enteros con signo de 64 bits
  (48 bytes). Los fixtures usan orden nativo explícito y el valor simbólico
  `errno.ENOMSG` del intérprete cuando sustituyen la frontera Linux.
  El oráculo `CMSG_SPACE` da RX/TX 104/96 en LP64 y 92/88 en ILP32.
  [Linux UAPI if_packet.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_packet.h)
  [Linux UAPI errqueue.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/errqueue.h)
  [Linux net_tstamp.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/net_tstamp.h)
- La ventana local usa nanosegundos monotónicos y excluye el deadline.
  El orden TX/RX se verifica entre marcas software del reloj de sistema
  Linux, con evidencia explícita `TX_SCHED` y `RX_SOFTWARE`. Una lectura
  plausible con una marca ausente conserva incertidumbre. El banco físico
  deberá acreditar comparabilidad de relojes y comportamiento del kernel,
  NIC y driver con una captura independiente.
  [Linux Timestamping](https://docs.kernel.org/networking/timestamping.html)
  [Recepción AF_PACKET de Linux v6.12](https://github.com/torvalds/linux/blob/v6.12/net/packet/af_packet.c#L3277-L3425)
