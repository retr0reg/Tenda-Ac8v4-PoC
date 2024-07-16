# Tenda-Ac8v4-PoC

Tenda Ac8v4 Stack-Based Overflow to Remote-Code Execution via execution-flow hijacking & multiple-register manipulation exploitation; CVEs are:

* `CVE-2023-33675`
* `CVE-2023-33673`
* `CVE-2023-33672`
* `CVE-2023-33671`
* `CVE-2023-33670`
* `CVE-2023-33669`

Marked as `N1` - `N7`

## `rop.py`
* make sure you hosted `tftp` on accessible machine; specific it by `args.attacker_host`;
* make sure pre-compiled loader `rs` is hosted in `tftp`;
* reverse-shell connection will be listen in-script.
