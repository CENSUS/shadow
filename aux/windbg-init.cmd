!load pykd.pyd

.asm no_code_bytes 

.sympath "SRV*c:\symbols\*http://msdl.microsoft.com/download/symbols;SRV*c:\symbols\*http://symbols.mozilla.org/firefox"
.reload

bp xul!js::math_asin
bu xul!js::math_atan2 "!py c:\\tmp\\pykd_driver jeparse; !py c:\\tmp\\pykd_driver jeruns -s 256;"
bu xul!js::math_acos "!py c:\\tmp\\pykd_driver jeparse; !py c:\\tmp\\pykd_driver jeruns -s 256;"

bl

* EOF
