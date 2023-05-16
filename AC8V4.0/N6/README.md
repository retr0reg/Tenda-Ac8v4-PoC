# Vulnerability Description
A stack-based overflow vulnerability that can be triggered via the `formSetFirewallCfg` function of Tenda AC8V4.0-V16.03.34.06 in the `/bin/httpd` file.
## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:

This is a buffer overflow vulnerability in the function formSetFirewallCfg which handles the firewallEn parameter. Upon receiving a POST request containing the firewallEn parameter, the function uses the strcpy function to copy the string from the firewallEn parameter into the var98 buffer. Since there is no input length restriction, if the input string's length exceeds the size of the var98 buffer, a stack overflow will occur. An attacker could exploit this vulnerability to execute arbitrary code on the target system.

<img width="574" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/e77e01a9-7347-446f-bbec-77c9fae835ac">

call chain: SetFirewallCfg->formSetFirewallCfg

# Result
This resulted a crash of the program, Verified locally


# PoC :
In Additional information
