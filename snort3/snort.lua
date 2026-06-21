---------------------------------------------------------------------------
-- snort.lua — Configuración Snort 3 modo IDS (pasivo)
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- 1. Variables de red
---------------------------------------------------------------------------
HOME_NET     = '192.168.1.201/32'
EXTERNAL_NET = '192.168.1.25/32'

---------------------------------------------------------------------------
-- 2. Defaults del sistema (preprocesadores, codecs, inspectores)
--    Este archivo viene incluido en la imagen ciscotalos/snort3
---------------------------------------------------------------------------
include 'snort_defaults.lua'

---------------------------------------------------------------------------
-- 3. Motor IPS — modo alerta (pasivo, sin bloqueo)
---------------------------------------------------------------------------
ips =
{
    mode   = 'alert',
    rules  = [[ include /usr/local/etc/snort/rules/local.rules ]],
    enable_builtin_rules = true,
}

---------------------------------------------------------------------------
-- 4. Salida de alertas
--    Genera /var/log/snort/alert_fast.txt
--    Actualizar la ruta en Azure custom log si se migra desde Snort 2
---------------------------------------------------------------------------
alert_fast =
{
    file   = true,
    packet = false,
}

---------------------------------------------------------------------------
-- 5. Logging de paquetes (desactivado por defecto, activar si se necesita)
---------------------------------------------------------------------------
-- log_pcap = { file = 'snort.pcap' }
