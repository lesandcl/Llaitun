# Llaitun

Palabra en [mapudungún](https://es.wikipedia.org/wiki/Idioma_mapuche) que significa vigilar/espiar/observar/fijarse bien en algo o alguien.

Herramienta de reconocimiento pasivo, que permite identificar protocolos vulnerables dentro de una red.

## Instalación

```
git clone https://github.com/lesandcl/Llaitun.git
cd Llaitun
pip3 install -r requirements.txt
```

## Uso

Identificación de protocolos a través de un archivo PCAP:

```
python3 Llaitun.py --file <inputPcapFile>
python3 Llaitun.py -f <inputPcapFile>
```

Live mode:

```
python3 Llaitun.py --live
python3 Llaitun.py -l
```

Detalle de la enumeración:

> Actualmente solo CDP/LLDP y ARP Request.

```
python3 Llaitun.py -d -l
python3 Llaitun.py -d -f <inputPcapFile>
```

Escaneo de hosts activos en la red:

**WARNING: Llaitun es una herramienta de reconocimiento pasivo, pero la opción -a/--active-hosts realiza un escaneo activo.**

```
python3 Llaitun.py -a <network>
python3 Llaitun.py --active-host <network>
```

## Protocolos soportados

> En este momento, Llaitun solo soporta protocolos IPv4.

- OSPF
- EIGRP
- LLDP
- UDLD
- CDP
- VTP
- DTP
- DOT1Q
- PVST
- VRRP
- GLBP
- HSRP
