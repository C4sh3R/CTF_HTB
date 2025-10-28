# 🎯 HackTheBox CTF Writeups

[![HackTheBox](https://img.shields.io/badge/HackTheBox-CTF-green)](https://www.hackthebox.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Este repositorio contiene mis writeups de los CTFs que voy realizando en HackTheBox, incluyendo máquinas y desafíos.

## 📁 Estructura del Repositorio

```
CTF_HTB/
├── Machines/           # Writeups de máquinas HTB
│   ├── Easy/          # Máquinas nivel Easy
│   ├── Medium/        # Máquinas nivel Medium
│   ├── Hard/          # Máquinas nivel Hard
│   └── Insane/        # Máquinas nivel Insane
├── Challenges/        # Writeups de desafíos HTB
│   ├── Web/           # Desafíos de explotación web
│   ├── Crypto/        # Desafíos de criptografía
│   ├── Pwn/           # Desafíos de explotación binaria
│   ├── Reversing/     # Desafíos de ingeniería inversa
│   ├── Forensics/     # Desafíos de análisis forense
│   ├── Misc/          # Desafíos misceláneos
│   ├── Steganography/ # Desafíos de esteganografía
│   ├── OSINT/         # Desafíos de OSINT
│   ├── Hardware/      # Desafíos de hardware
│   └── Mobile/        # Desafíos de aplicaciones móviles
└── Templates/         # Plantillas para writeups
```

## 📊 Estadísticas

### Máquinas Completadas
- **Easy**: 0
- **Medium**: 0
- **Hard**: 0
- **Insane**: 0
- **Total**: 0

### Desafíos Completados
- **Web**: 0
- **Crypto**: 0
- **Pwn**: 0
- **Reversing**: 0
- **Forensics**: 0
- **Misc**: 0
- **Steganography**: 0
- **OSINT**: 0
- **Hardware**: 0
- **Mobile**: 0
- **Total**: 0

## 🚀 Cómo Usar Este Repositorio

### Inicio Rápido

👉 **[Lee la Guía de Inicio Rápido](QUICKSTART.md)** para comenzar a documentar tus writeups inmediatamente.

### Añadir un Nuevo Writeup

1. Copia la plantilla de `/Templates/WRITEUP_TEMPLATE.md`
2. Navega al directorio apropiado:
   - Para máquinas: `Machines/[Difficulty]/`
   - Para desafíos: `Challenges/[Category]/`
3. Crea un nuevo archivo con el nombre del desafío o máquina
4. Completa la plantilla con la información relevante

### Ejemplo

```bash
# Para una máquina Easy llamada "Lame"
cp Templates/WRITEUP_TEMPLATE.md Machines/Easy/Lame.md

# Para un desafío Web llamado "Templated"
cp Templates/WRITEUP_TEMPLATE.md Challenges/Web/Templated.md
```

## 📝 Formato de Writeup

Cada writeup incluye:

- **Información General**: Dificultad, categoría, fecha, puntos
- **Descripción**: Breve resumen del desafío
- **Reconocimiento**: Escaneos y hallazgos iniciales
- **Explotación**: Análisis de vulnerabilidades y desarrollo de exploits
- **Escalada de Privilegios**: (Solo para máquinas) Método de escalada
- **Lecciones Aprendidas**: Conocimientos adquiridos
- **Herramientas Utilizadas**: Lista de herramientas empleadas
- **Referencias**: Recursos y enlaces útiles

## 🛠️ Herramientas Comunes

Algunas de las herramientas más utilizadas en estos writeups:

- **Reconocimiento**: Nmap, Gobuster, FFuF, Wfuzz
- **Explotación Web**: Burp Suite, SQLMap, XSStrike
- **Explotación Binaria**: GDB, Ghidra, IDA Pro, pwntools
- **Criptografía**: CyberChef, John the Ripper, Hashcat
- **Análisis Forense**: Autopsy, Volatility, Wireshark
- **Post-Explotación**: LinPEAS, WinPEAS, GTFOBins

## ⚠️ Aviso Legal

Este repositorio es solo con fines educativos. Los writeups están destinados a compartir conocimientos y técnicas de seguridad informática. Por favor, usa este conocimiento de manera responsable y ética.

- Solo realiza pruebas de penetración en sistemas para los que tienes permiso explícito
- Respeta las reglas de HackTheBox y su código de conducta
- No uses estas técnicas para actividades ilegales o no autorizadas

## 📫 Contacto

Si tienes alguna pregunta o sugerencia, no dudes en abrir un issue en este repositorio.

## 📜 Licencia

Este proyecto está bajo la licencia MIT. Ver el archivo `LICENSE` para más detalles.

---

**Happy Hacking! 🔐**
