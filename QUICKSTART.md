# Guía de Inicio Rápido

Esta guía te ayudará a empezar a usar este repositorio para guardar tus writeups de HackTheBox.

## 📝 Crear tu Primer Writeup

### Paso 1: Elige la Categoría

Primero, decide si estás documentando:
- Una **máquina** → Ve a `Machines/[Difficulty]/`
- Un **desafío** → Ve a `Challenges/[Category]/`

### Paso 2: Copia la Plantilla

```bash
# Para una máquina (ejemplo: máquina Easy llamada "Lame")
cp Templates/WRITEUP_TEMPLATE.md Machines/Easy/Lame.md

# Para un desafío (ejemplo: desafío Web llamado "Templated")
cp Templates/WRITEUP_TEMPLATE.md Challenges/Web/Templated.md
```

### Paso 3: Completa la Información

Abre el archivo que acabas de crear y completa:

1. **Información General**: Dificultad, categoría, fecha, puntos
2. **Descripción**: ¿De qué trata el desafío/máquina?
3. **Reconocimiento**: ¿Qué herramientas usaste? ¿Qué encontraste?
4. **Explotación**: ¿Cómo encontraste y explotaste las vulnerabilidades?
5. **Escalada de Privilegios** (solo máquinas): ¿Cómo obtuviste root?
6. **Lecciones Aprendidas**: ¿Qué aprendiste?
7. **Herramientas y Referencias**

### Paso 4: Añade Capturas de Pantalla (Opcional)

Puedes crear una carpeta para imágenes:

```bash
mkdir -p Machines/Easy/Lame_images/
# Añade tus capturas de pantalla
# Referéncialas en el markdown: ![descripción](Lame_images/screenshot.png)
```

### Paso 5: Revisa el Ejemplo

Consulta `Machines/Easy/Example.md` para ver un ejemplo completo de cómo debe verse un writeup.

## 🎯 Consejos y Buenas Prácticas

### Durante el CTF

1. **Toma notas mientras trabajas**: No esperes hasta el final
2. **Guarda los comandos**: Copia los comandos que funcionaron
3. **Captura pantallas**: Especialmente de pasos importantes
4. **Documenta los fallos**: Lo que no funcionó también es útil

### Al Escribir

1. **Sé claro y detallado**: Alguien debería poder reproducir tus pasos
2. **Explica el "por qué"**: No solo el "qué" y el "cómo"
3. **Usa bloques de código**: Para comandos y código
4. **Formatea bien**: Usa headers, listas, y negritas apropiadamente

### Antes de Publicar

1. **Revisa ortografía y gramática**
2. **Verifica que los comandos sean correctos**
3. **Asegúrate de no exponer información sensible**
4. **Comprueba que la máquina/desafío esté retirado**

## 📚 Estructura de un Buen Writeup

```
# Título Claro
├── Información (tabla con datos clave)
├── Descripción breve
├── Reconocimiento
│   ├── Escaneos iniciales
│   └── Hallazgos
├── Explotación
│   ├── Análisis de vulnerabilidades
│   ├── Desarrollo del exploit
│   └── Primera flag
├── Escalada de privilegios (máquinas)
│   ├── Enumeración
│   ├── Explotación
│   └── Flag de root
├── Lecciones aprendidas
├── Herramientas usadas
└── Referencias
```

## 🔗 Recursos Útiles

### Herramientas de Reconocimiento
- [Nmap](https://nmap.org/) - Escaneo de red
- [Gobuster](https://github.com/OJ/gobuster) - Fuzzing de directorios
- [FFuF](https://github.com/ffuf/ffuf) - Fuzzer web

### Bases de Conocimiento
- [HackTricks](https://book.hacktricks.xyz/) - Técnicas de hacking
- [GTFOBins](https://gtfobins.github.io/) - Binarios para privilege escalation
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Payloads y bypasses

### Comunidad
- [HackTheBox Discord](https://discord.gg/hackthebox)
- [Reddit r/hackthebox](https://www.reddit.com/r/hackthebox/)

## ❓ Preguntas Frecuentes

**P: ¿Puedo publicar writeups de máquinas activas?**  
R: No. Solo publica writeups de máquinas/desafíos retirados para respetar las reglas de HTB.

**P: ¿En qué idioma debo escribir?**  
R: Puedes usar español o inglés, lo que prefieras. Mantén consistencia en cada writeup.

**P: ¿Debo incluir las flags completas?**  
R: Depende de ti, pero generalmente es mejor no incluir las flags exactas para mantener el desafío.

**P: ¿Qué hago si encuentro un error en un writeup?**  
R: Abre un issue o crea un pull request con la corrección.

## 🚀 ¡Listo para Empezar!

Ya tienes todo lo que necesitas. ¡Comienza a documentar tus aventuras en HackTheBox!

```bash
# Copia la plantilla
cp Templates/WRITEUP_TEMPLATE.md Machines/Easy/MiPrimeraMaquina.md

# Edita el archivo
nano Machines/Easy/MiPrimeraMaquina.md

# Guarda tus cambios
git add Machines/Easy/MiPrimeraMaquina.md
git commit -m "Add writeup for MiPrimeraMaquina"
git push
```

Happy Hacking! 🎯🔐
