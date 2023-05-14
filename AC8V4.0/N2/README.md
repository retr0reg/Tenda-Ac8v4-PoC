# Vulnerability Description

A stack-based overflow vulnerability can be triggered by via the in the `fromSetWifiGusetBasic` function in the `/bin/httpd` file.

## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:
This vulnerability can be attacked through a remote network. The attacker only needs to send a specially crafted POST request to the target server. In this request, the attacker can pass in a load containing specific data via the shareSpeed parameter, which causes a memory overflow. This attack does not require any user interaction.

<img width="720" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/42ad9b0e-66b4-4d7c-a363-41ecd44b5bd8">

call chain : WifiGuestSet->fromSetWifiGusetBasic

# PoC :
In Additional information
