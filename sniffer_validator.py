import yaml
from validator import Validator
import logging


def unflatten(flat_dict):
    """
    Convert a flattened dict with keys like "a.b.c[0].d" into a nested dict.
    """
    out = {}

    for key, value in flat_dict.items():
        parts = key.replace("]", "").split(".")
        cursor = out

        for i, part in enumerate(parts):
            # Detect list indices
            if "[" in part:
                field, idx = part.split("[")
                idx = int(idx)

                if field not in cursor:
                    cursor[field] = []

                # Expand list if needed
                while len(cursor[field]) <= idx:
                    cursor[field].append({})

                if i == len(parts) - 1:
                    cursor[field][idx] = value
                else:
                    cursor = cursor[field][idx]

            else:
                if i == len(parts) - 1:
                    cursor[part] = value
                else:
                    if part not in cursor:
                        cursor[part] = {}
                    cursor = cursor[part]

    return out


class SnifferValidator(Validator):
    def __init__(self):
        super().__init__()

        self.schema = {
            "id": str,

            "cell.band": int,
            "cell.nof_prb": int,
            "cell.scs_common": int,
            "cell.scs_ssb": int,
            "cell.ssb_period_ms": int,
            "cell.dl_arfcn": int,
            "cell.ssb_arfcn": int,

            "source.source_type": str,
            "source.source_params": str,

            "enable_recorder": bool,
            "pcap_folder": str,

            "rf.sample_rate": (float, int),
            "rf.num_channels": int,
            "rf.uplink_cfo": (float, int),
            "rf.downlink_cfo": (float, int),
            "rf.padding.front_padding": int,
            "rf.padding.back_padding": int,

            "rf.channels[0].rx_frequency": (float, int),
            "rf.channels[0].tx_frequency": (float, int),
            "rf.channels[0].rx_offset": int,
            "rf.channels[0].tx_offset": int,
            "rf.channels[0].rx_gain": int,
            "rf.channels[0].tx_gain": int,
            "rf.channels[0].enable": bool,

            "rf.channels[1].rx_frequency": (float, int),
            "rf.channels[1].tx_frequency": (float, int),
            "rf.channels[1].rx_offset": int,
            "rf.channels[1].tx_offset": int,
            "rf.channels[1].rx_gain": int,
            "rf.channels[1].tx_gain": int,
            "rf.channels[1].enable": bool,
        }

    def _json_to_config(self, json_obj):
        json_obj.pop("id", None)

        nested = unflatten(json_obj)

        nested["databases"] = [{
          "enable": "true",
          "host": "influxdb",
          "port": 8086,
          "org": "rtu",
          "token": "605bc59413b7d5457d181ccf20f9fda15693f81b068d70396cc183081b264f3b",
          "bucket": "rtusystem",
          "data_id": "test",
        }]

        nested["workers"] = {
          "pool_size": 24,
          "n_ue_dl_worker": 4,
          "n_ue_ul_worker": 4,
          "n_gnb_dl_worker": 4,
          "n_gnb_ul_worker": 4
        }

        nested["uetracker"] = {
          "close_timeout": 5000,
          "parse_messages": "true",
          "num_ues": 1,
          "enable_gpu": "false"
        }

        nested["downlink_injector"] = {
          "delay_n_slots": 5,
          "duplications": 2,
          "tx_cfo_correction": 0,
          "tx_advancement": 160,
          "pdsch_mcs": 3,
          "pdsch_prbs": 24
        }

        nested["exploit"] = "build/modules/lib_dummy_exploit.so"

        return yaml.dump(nested, sort_keys=False, indent=2)

    def validate(self, raw_str):
        logging.debug(f"Validating sniffer input: {raw_str}")
        raw_str = raw_str.strip()
        json_obj = self._extract_json(raw_str)

        if not json_obj:
            return False, self.errors

        if not self._validate_schema(json_obj):
            return False, self.errors

        component_id = json_obj.get("id")

        # Example basic sanity checks (customize as needed)
        if json_obj.get("rf.sample_rate", 0) <= 0:
            self.errors.append("rf.sample_rate must be > 0")

        if self.errors:
            return False, self.errors

        config_yaml = self._json_to_config(json_obj)
        if not config_yaml:
            self.errors.append("YAML conversion failed")
            return False, self.errors

        return True, {
            "id": component_id,
            "type": "sni5gect",
            "config_str": config_yaml
        }

