/*
   Reglas YARA basicas para el HoneyPI - clasificacion local de malware antes
   de gastar cuota de VirusTotal/Hybrid Analysis. NO son exhaustivas: son un
   primer filtro rapido y gratis, basado en strings/patrones comunes de las
   familias mas frecuentes en honeypots SSH/Telnet (Mirai, Gafgyt, mineros).
*/

rule Mirai_Generic
{
    meta:
        descripcion = "Strings tipicas de variantes de la botnet Mirai"
        familia = "Mirai"
    strings:
        $s1 = "/proc/net/route" ascii
        $s2 = "watchdog" ascii nocase
        $s3 = "busybox" ascii nocase
        $s4 = "GETLOCALIP" ascii
        $s5 = { 47 45 54 20 2f }
    condition:
        2 of ($s1, $s2, $s3, $s4) or $s5
}

rule Gafgyt_Bashlite
{
    meta:
        descripcion = "Strings tipicas de Gafgyt / BASHLITE"
        familia = "Gafgyt"
    strings:
        $s1 = "PING" ascii
        $s2 = "SCANNER ON" ascii nocase
        $s3 = "/bin/busybox" ascii
        $s4 = "TSource Engine Query" ascii
        $s5 = "REPORT" ascii
    condition:
        3 of them
}

rule XMRig_Miner
{
    meta:
        descripcion = "Binario o script relacionado a mineria de Monero (XMRig y derivados)"
        familia = "Cryptominer"
    strings:
        $s1 = "xmrig" ascii nocase
        $s2 = "stratum+tcp" ascii nocase
        $s3 = "monero" ascii nocase
        $s4 = "cryptonight" ascii nocase
        $s5 = "donate-level" ascii nocase
        $s6 = "pool.minexmr" ascii nocase
    condition:
        any of them
}

rule Script_Descarga_Ejecucion
{
    meta:
        descripcion = "Patron generico de shell script que descarga y ejecuta un binario (dropper)"
        familia = "Dropper generico"
    strings:
        $wget = "wget " ascii
        $curl = "curl " ascii
        $ftpget = "ftpget " ascii
        $chmod = "chmod +x" ascii
        $chmod2 = "chmod 777" ascii
        $exec = "./" ascii
    condition:
        (1 of ($wget, $curl, $ftpget)) and (1 of ($chmod, $chmod2)) and $exec
}

rule ELF_Binario_Empaquetado
{
    meta:
        descripcion = "Ejecutable ELF (Linux) - relevante porque malware IoT casi siempre es ELF, no script"
        familia = "N/A - solo indica tipo de archivo"
    condition:
        uint32(0) == 0x464c457f
}
