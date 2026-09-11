/*
    Regla de detección: MAGIS TV / BrasilTV APK Dropper
    Autor: Michael Lopez
    Fecha: Septiembre 2026
    Referencia: docs/05-iocs-mitre.md

    Objetivo: detectar variantes de la familia de APKs "Magis TV / BrasilTV"
    (package com.msandroid.mobile) basándose en el módulo dropper ofuscado
    "shell" y en el binario empaquetado libexec.so identificados durante
    el análisis estático y dinámico.

    Referencia MITRE ATT&CK for Mobile:
      - T1406 / T1027.002 (Obfuscated Files or Information / Software Packing)
      - T1633.001 (Virtualization/Sandbox Evasion - System Checks)
*/

rule Magis_BrasilTV_APK_Dropper
{
    meta:
        description = "Detecta APKs de la familia Magis TV/BrasilTV con modulo dropper ofuscado 's.h.e.l.l'"
        author = "Laboratorio Seguridad de la Informacion - UTadeo"
        date = "2026-09"
        reference = "docs/05-iocs-mitre.md"
        hash_sha256 = "5d19f412085b00a44d52a218bea1f2560cd2d5736f2b77ba00424336f923e824"
        mitre_attack = "T1406, T1027.002, T1633.001"
        severity = "medium"

    strings:
        // Package y actividad principal identificados en el analisis
        $package_name = "com.msandroid.mobile" ascii
        $main_activity = "com.mobile.brasiltv.activity.SplashAty" ascii

        // Ruta del paquete ofuscado que deletrea "shell" (s/h/e/l/l)
        $shell_pkg1 = "s/h/e/l/l" ascii
        $shell_pkg2 = "s.h.e.l.l" ascii

        // Nombre del binario dropper identificado por APKiD (ELF empaquetado en ELF, UPX)
        $dropper_lib = "libexec.so" ascii wide
        $dropper_lib_main = "libexecmain.so" ascii wide

        // Firma de empaquetador comercial detectado
        $packer_marker = "Ijiami" ascii nocase

        // Identificadores de Firebase asociados a esta familia (IOC de correlacion)
        $firebase_key = "AIzaSyC-sMwGTAhbysLLyN0Zvdi4M5W8tiZ7P90" ascii
        $firebase_project = "18767524675" ascii

    condition:
        uint16(0) == 0x4b50 and  // Firma de archivo ZIP/APK (PK..)
        (
            $package_name or
            $main_activity or
            any of ($shell_pkg*) or
            any of ($dropper_lib*) or
            $packer_marker or
            $firebase_key or
            $firebase_project
        )
}

rule Magis_BrasilTV_Native_Dropper_ELF
{
    meta:
        description = "Detecta el binario nativo libexec.so usado como dropper (ELF empaquetado dentro de ELF, UPX)"
        author = "Laboratorio Seguridad de la Informacion - UTadeo"
        date = "2026-09"
        mitre_attack = "T1027.002"
        severity = "medium"

    strings:
        $elf_magic = { 7F 45 4C 46 }  // Firma de archivo ELF
        $upx_marker1 = "UPX!" ascii
        $upx_marker2 = "UPX0" ascii
        $upx_marker3 = "UPX1" ascii

    condition:
        // El archivo comienza como ELF pero contiene marcadores de UPX en su cuerpo,
        // consistente con un ELF empaquetado embebido dentro de otro ELF.
        $elf_magic at 0 and
        2 of ($upx_marker*)
}
