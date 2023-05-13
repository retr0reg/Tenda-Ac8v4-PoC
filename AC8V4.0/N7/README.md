# Vulnerability Description
A stack-based overflow vulnerability that can be triggered via the `sub_44db3c` function of Tenda AC8V4.0-V16.03.34.06.
## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:
This is a buffer overflow vulnerability in the sub_44db3c function that handles the timeZone parameter. Upon receiving a POST request containing the timeZone parameter, this function uses the sscanf function to parse the string from the timeZone parameter into the var10 buffer. Since there is no input length restriction, if the input string's length exceeds the size of the var10 buffer, a stack overflow will occur. An attacker could exploit this vulnerability to execute arbitrary code on the target system.
<img width="848" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/c503ef8b-6ad2-41d5-881b-38a5ff08e761">
To be clear, argument `ssid` needs be set to non-zero value to pass the test.

Call Chain: fast_setting_wifi_set->form_fast_setting_wifi_set->sub_44db3c

# PoC :
In Additional information
