"""The plain statement of what this audit is and is not.

Every check macverify runs reads configuration and state. None of them inspects
the *content* of an executable, so the audit can see the shape of a persistent
process but never what that process does. That distinction is the whole reason
this file exists: a reader who mistakes a clean macverify report for a clean
machine has drawn exactly the wrong conclusion.
"""

SCOPE = {
    "en": {
        "heading": "What this audit covers, and what it cannot",
        "summary": (
            "macverify reads the configuration and running state of this Mac, compares it against a "
            "fixed rule set, and prints commands for you to review. It never writes, never elevates, "
            "and never opens a network connection."
        ),
        "does_heading": "What it reads",
        "does": [
            "Toolchain and package state: which interpreters, compilers and version managers are installed, which copy actually wins on PATH, and which packages two managers both claim.",
            "Shell configuration: every profile that runs at login, the PATH it builds, world-writable or empty PATH elements, duplicate aliases, and source lines pointing at files that no longer exist.",
            "Hardware and power: memory pressure, swap, battery health, active thermal or power limits, and uptime.",
            "Storage: free space per volume, reclaimable caches and build artefacts, node_modules totals, and retained APFS local snapshots.",
            "Background execution: launchd agents and daemons in every scope, jobs whose target binary is missing, jobs set to restart forever, and crontab entries.",
            "Network exposure: which processes hold a listening socket and on which interface, the application firewall state, DNS resolvers, system proxy settings, and non-default /etc/hosts entries.",
            "macOS protections: System Integrity Protection, FileVault, Gatekeeper assessment state, installed XProtect and XProtect Remediator versions, cached pending updates, the guest account, and which remote-sharing services are enabled.",
            "Credentials and keys: SSH key algorithm, strength, file mode and passphrase state, GPG key expiry, credential-shaped strings in dotfiles and config files, and credentials embedded in git remote URLs. Values are never reported, only their location.",
            "Privacy grants: which applications hold Full Disk Access, Accessibility, Screen Recording, Input Monitoring or synthetic-event permission, read from the TCC databases when this process is already permitted to read them.",
            "Claude Code configuration: skills, agents, commands, hooks, MCP servers, permission rules and memory files, with an estimate of what each one costs in always-loaded session context.",
        ],
        "not_heading": "What it cannot see",
        "not": [
            "It does not read the contents of any executable, does not compute file hashes, and does not consult any signature database or reputation service. Because it makes no network request, nothing it finds is compared against a threat feed.",
            "It therefore cannot detect adware and browser hijackers (the Adload, Bundlore, Genieo and Pirrit families, search redirectors, and malicious browser extensions).",
            "It cannot detect infostealers that target the keychain, browser cookies and crypto wallets, such as Atomic Stealer (AMOS), Poseidon, Banshee and MacStealer, which are usually delivered by a trojanised installer or a cracked app.",
            "It cannot detect cryptominers, keyloggers, stalkerware or remote-access trojans. Where such a tool holds an Accessibility or Input Monitoring grant, macverify will report the grant and nothing more; it has no way to judge the binary behind it.",
            "It cannot detect ransomware, or any malicious payload inside an application that is correctly signed and installed in the normal place.",
            "A launchd job whose binary exists, is signed and starts at login looks identical to macverify whether it is a printer helper or a backdoor. macverify reports the shape; only a scanner that examines the binary can report the intent.",
        ],
        "av_heading": "Run an anti-malware scan as well",
        "av_intro": (
            "A configuration audit and a malware scan answer different questions and neither substitutes "
            "for the other. Run one of the following alongside this report, and treat the pair as the "
            "complete picture."
        ),
        "av_tools": [
            {
                "name": "Malwarebytes for Mac",
                "finds": "the adware, browser hijacker and potentially-unwanted-program families listed above, which is where the great majority of real macOS infections sit",
                "how": "free on-demand scan; download from malwarebytes.com and run a full scan",
            },
            {
                "name": "KnockKnock (Objective-See)",
                "finds": "everything persistently installed on this Mac, each item checked against VirusTotal; the direct complement to the launchd and login-item inventory in this report",
                "how": "download from objective-see.org; free and open source",
            },
            {
                "name": "LuLu (Objective-See)",
                "finds": "outbound connections from processes you did not expect to make them, which is what a listening-socket audit structurally cannot see",
                "how": "download from objective-see.org; free outbound firewall, runs continuously",
            },
            {
                "name": "ClamAV",
                "finds": "known file signatures across platforms; weaker on macOS-specific adware than the tools above, but scriptable and updatable offline",
                "how": "brew install clamav, then freshclam followed by clamscan -r ~",
            },
        ],
        "av_builtin": (
            "Apple's own XProtect and XProtect Remediator already run on this machine without being "
            "installed. This report lists their versions under Security; a version that has not moved "
            "in months is itself a finding worth acting on."
        ),
        "av_order": (
            "Scan first, then re-run macverify. A scanner that removes an adware LaunchAgent or revokes "
            "a privacy grant changes the very findings this report is built from."
        ),
    },
    "es": {
        "heading": "Que cubre esta auditoria y que no puede cubrir",
        "summary": (
            "macverify lee la configuracion y el estado de este Mac, lo compara con un conjunto fijo de "
            "reglas y muestra comandos para que usted los revise. Nunca escribe, nunca eleva privilegios "
            "y nunca abre una conexion de red."
        ),
        "does_heading": "Que lee",
        "does": [
            "Cadena de herramientas y paquetes: que interpretes, compiladores y gestores de versiones estan instalados, que copia gana realmente en PATH y que paquetes reclaman dos gestores a la vez.",
            "Configuracion del shell: cada perfil que se ejecuta al iniciar sesion, el PATH que construye, elementos de PATH vacios o escribibles por todos, alias duplicados y lineas source que apuntan a ficheros inexistentes.",
            "Hardware y energia: presion de memoria, swap, salud de la bateria, limites termicos o de potencia activos y tiempo encendido.",
            "Almacenamiento: espacio libre por volumen, caches y artefactos de compilacion recuperables, totales de node_modules e instantaneas locales APFS retenidas.",
            "Ejecucion en segundo plano: agentes y demonios launchd en todos los ambitos, trabajos cuyo binario ya no existe, trabajos configurados para reiniciarse siempre y entradas de crontab.",
            "Exposicion de red: que procesos mantienen un socket a la escucha y en que interfaz, el estado del cortafuegos de aplicaciones, los resolutores DNS, el proxy del sistema y entradas no predeterminadas en /etc/hosts.",
            "Protecciones de macOS: System Integrity Protection, FileVault, estado de evaluacion de Gatekeeper, versiones instaladas de XProtect y XProtect Remediator, actualizaciones pendientes en cache, la cuenta de invitado y que servicios de comparticion remota estan activos.",
            "Credenciales y claves: algoritmo, longitud, permisos y frase de paso de las claves SSH, caducidad de claves GPG, cadenas con forma de credencial en dotfiles y ficheros de configuracion, y credenciales incrustadas en URLs de remotos git. Nunca se reporta el valor, solo su ubicacion.",
            "Permisos de privacidad: que aplicaciones tienen Acceso Total al Disco, Accesibilidad, Grabacion de Pantalla, Monitorizacion de Entrada o eventos sinteticos, leidos de las bases TCC cuando este proceso ya tiene permiso para leerlas.",
            "Configuracion de Claude Code: skills, agentes, comandos, hooks, servidores MCP, reglas de permisos y ficheros de memoria, con una estimacion de lo que cada uno cuesta en contexto cargado siempre.",
        ],
        "not_heading": "Que no puede ver",
        "not": [
            "No lee el contenido de ningun ejecutable, no calcula hashes de ficheros y no consulta ninguna base de firmas ni servicio de reputacion. Como no hace ninguna peticion de red, nada de lo que encuentra se compara con una fuente de amenazas.",
            "Por tanto no puede detectar adware ni secuestradores de navegador (las familias Adload, Bundlore, Genieo y Pirrit, redirectores de busqueda y extensiones de navegador maliciosas).",
            "No puede detectar infostealers dirigidos al llavero, las cookies del navegador y las carteras de criptomonedas, como Atomic Stealer (AMOS), Poseidon, Banshee y MacStealer, que suelen llegar en un instalador troyanizado o una aplicacion pirateada.",
            "No puede detectar mineros de criptomonedas, keyloggers, stalkerware ni troyanos de acceso remoto. Si una de esas herramientas tiene un permiso de Accesibilidad o Monitorizacion de Entrada, macverify reportara el permiso y nada mas; no puede juzgar el binario que hay detras.",
            "No puede detectar ransomware ni ninguna carga maliciosa dentro de una aplicacion correctamente firmada e instalada en el lugar habitual.",
            "Un trabajo launchd cuyo binario existe, esta firmado y arranca al iniciar sesion es indistinguible para macverify tanto si es un ayudante de impresora como si es una puerta trasera. macverify reporta la forma; solo un escaner que examine el binario puede reportar la intencion.",
        ],
        "av_heading": "Ejecute tambien un analisis antimalware",
        "av_intro": (
            "Una auditoria de configuracion y un analisis de malware responden a preguntas distintas y "
            "ninguna sustituye a la otra. Ejecute una de las siguientes junto a este informe y considere "
            "el conjunto como la imagen completa."
        ),
        "av_tools": [
            {
                "name": "Malwarebytes for Mac",
                "finds": "las familias de adware, secuestradores de navegador y programas no deseados citadas arriba, donde se concentra la gran mayoria de infecciones reales en macOS",
                "how": "analisis gratuito bajo demanda; descarguelo de malwarebytes.com y ejecute un analisis completo",
            },
            {
                "name": "KnockKnock (Objective-See)",
                "finds": "todo lo instalado de forma persistente en este Mac, contrastado con VirusTotal; el complemento directo al inventario de launchd y elementos de inicio de este informe",
                "how": "descarguelo de objective-see.org; gratuito y de codigo abierto",
            },
            {
                "name": "LuLu (Objective-See)",
                "finds": "conexiones salientes de procesos que no deberian hacerlas, algo que una auditoria de sockets a la escucha no puede ver por definicion",
                "how": "descarguelo de objective-see.org; cortafuegos de salida gratuito, en ejecucion continua",
            },
            {
                "name": "ClamAV",
                "finds": "firmas de fichero conocidas en varias plataformas; mas debil con el adware especifico de macOS que las herramientas anteriores, pero automatizable y actualizable sin conexion",
                "how": "brew install clamav, despues freshclam y clamscan -r ~",
            },
        ],
        "av_builtin": (
            "XProtect y XProtect Remediator de Apple ya se ejecutan en este equipo sin necesidad de "
            "instalarlos. Este informe muestra sus versiones en Seguridad; una version que no se mueve "
            "en meses es en si misma un hallazgo que conviene atender."
        ),
        "av_order": (
            "Analice primero y vuelva a ejecutar macverify despues. Un escaner que elimina un LaunchAgent "
            "de adware o revoca un permiso de privacidad cambia los mismos hallazgos sobre los que se "
            "construye este informe."
        ),
    },
}


def scope(lang="en"):
    return SCOPE.get(lang, SCOPE["en"])
