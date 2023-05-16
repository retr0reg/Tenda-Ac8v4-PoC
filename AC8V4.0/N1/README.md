# Vulnerability Description
A stack-based overflow vulnerability can be triggered via the sub_44db3c function in the `/bin/httpd` file.
## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:
<img width="626" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/4291eaa6-9658-48f1-aaaa-061fc4b6ca93">

This is a buffer overflow vulnerability in the function sub_44db3c, which handles the timeZone parameter. Upon receiving a POST request containing the timeZone parameter, the function sub_44db3c allocates a buffer var10 of size 8 bytes on the stack, and then uses the sscanf function to attempt to read two strings from the timeZone parameter and store them in the var10 variable. Since there is no limit on the input length, if the input string is longer than 8 bytes, it will result in a stack overflow. An attacker could exploit this vulnerability to execute arbitrary code on the target system.

<img width="790" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/6ab71253-86a7-4220-b6aa-ac2b90b82144">

Call chain : fast_setting_wifi_set -> form_fast_setting_wifi_set -> sub_44db3c

# Result
Cause crash (and possible rce) by stack overflow.
<img width="1920" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/ba81e094-2a56-4a63-a9a3-caea7e39b7d9">
Core dump is in the same dir


# PoC :
In Additional information
