# Vendored code

`ntcip_ctrl/` is a verbatim subset of
[synchro-vissim-ntcip-controller](https://github.com/faysalchowdhoury/synchro-vissim-ntcip-controller) v1.0.0
(same author, MIT): the NEMA TS2 dual-ring controller, timing models and the hand-written SNMPv1 BER codec.
It is copied rather than installed so this repository builds on its own. Do not edit it here; extensions
live in `ntcip_guard/controller.py` (control inputs) and `ntcip_guard/mib.py` (phase control objects).
