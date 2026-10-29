# -*- coding: utf-8 -*-
"""ingest 解析器包：import 本包即触发全部 @register_parser 注册。"""

from . import (  # noqa: F401
    alert_cef_leef_idmef,
    generic_parsers,
    host_parsers,
    intel_parsers,
    network_pcap,
)
