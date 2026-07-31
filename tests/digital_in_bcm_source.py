#!/usr/bin/env python3
"""Static witness for the exact BCM2838 M8 input read and bit packing."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/digital_in_bcm2838.c").read_text()


def main() -> int:
    body = SOURCE.split("int digital_in_backend_read_fixed_bank", 1)[1]
    assert body.count("read32(GPLEV0)") == 1
    assert "GPLEV1" not in body
    for pin, bit in ((5, 0), (6, 1), (13, 2), (19, 3), (26, 4)):
        term = rf"\(\(level >> {pin}\) & 1u\)" + ("" if bit == 0 else rf" << {bit}")
        assert re.search(term, body), (pin, bit)
    configure = SOURCE.split("int digital_in_backend_configure_fixed_bank", 1)[1].split("int digital_in_backend_read_fixed_bank", 1)[0]
    assert [int(value) for value in re.findall(r"configure_input\((\d+)u\)", configure)] == [5, 6, 13, 19, 26]
    print("PASS  production-input-build-source:one-GPLEV0-read-exact-pack")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
