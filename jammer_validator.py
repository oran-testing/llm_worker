import yaml

from validator import Validator


class JammerValidator(Validator):
    def __init__(self):
        super().__init__()

        self.schema = {
            "id": str, "center_frequency": (float, int), "bandwidth": (float, int),
            "amplitude": (float, int), "amplitude_width": (float, int),
            "initial_phase": (float, int), "sampling_freq": (float, int),
            "num_samples": int, "output_iq_file": str, "output_csv_file": str,
            "write_iq": bool, "write_csv": bool, "tx_gain": (float, int), "device_args": str
        }

    def _json_to_config(self, json_obj):
        json_obj.pop("id", None)
        return yaml.dump(json_obj, sort_keys=False, indent=2)

    def validate(self, raw_str):
        raw_str = raw_str.strip()
        json_obj = self._extract_json(raw_str)
        if not json_obj:
            return False, self.errors

        if not self._validate_schema(json_obj, self.schema, list(self.schema.keys())):
            return False, self.errors

        component_id = json_obj.get("id")

        if json_obj.get("bandwidth", 0) <= 0:
            self.errors.append("bandwidth must be > 0")
        amp = json_obj.get("amplitude", -1)
        if not (0.0 <= amp <= 1.0):
            self.errors.append("amplitude must be between 0 and 1")
        if json_obj.get("tx_gain", -1) < 0 or json_obj.get("tx_gain", 0) > 90:
            self.errors.append("tx_gain must be between 0 and 90")

        sf = json_obj.get("sampling_freq"); bw = json_obj.get("bandwidth")
        if isinstance(sf, (int, float)) and isinstance(bw, (int, float)):
            if sf < 2.0 * bw:
                self.errors.append("sampling_freq must be at least 2x bandwidth")

        f0 = json_obj.get("center_frequency")
        if isinstance(f0, (int, float)):
            if f0 <= 0:
                self.errors.append("center_frequency must be > 0")
            else:
                in_fr1 = 410e6 <= f0 <= 7125e6
                in_fr2 = 24.25e9 <= f0 <= 52.6e9
                if not (in_fr1 or in_fr2):
                    self.errors.append("center_frequency must be inside NR FR1 (410e6–7.125e9) or FR2 (24.25e9–52.6e9)")

        dev = json_obj.get("device_args", "") or ""
        dev_lower = dev.lower()

        if "b200" in dev_lower or "b210" in dev_lower:
            if isinstance(f0, (int, float)):
                if f0 > 6e9:
                    self.errors.append("center_frequency exceeds B200-family tuning range (<= 6e9)")
                in_fr2 = 24.25e9 <= f0 <= 52.6e9
                if in_fr2:
                    self.errors.append("B200-family cannot operate in NR FR2 (24.25e9–52.6e9)")
            if isinstance(sf, (int, float)) and sf > 61.44e6:
                self.errors.append("sampling_freq exceeds B200-family practical maximum (~61.44e6)")
            if isinstance(bw, (int, float)) and bw > 56e6:
                self.errors.append("bandwidth exceeds B200-family front-end practical limit (~56e6)")

        ns = json_obj.get("num_samples", 0)
        if isinstance(ns, int) and ns <= 0:
            self.errors.append("num_samples must be > 0")

        if self.errors:
            return False, self.errors

        config_str = self._json_to_config(json_obj)
        if not config_str:
            return False, self.errors

        return True, {"id": component_id, "type": "jammer", "config_str": config_str}
