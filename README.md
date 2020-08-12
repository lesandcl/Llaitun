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
python Llaitun.py --file <inputPcapFile>
```

Live mode:

```
python Llaitun.py --live
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
