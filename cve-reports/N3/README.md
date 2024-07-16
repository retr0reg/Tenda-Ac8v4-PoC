# Vulnerability Description
A stack-based overflow vulnerability that can be triggered via the `sub_4a79ec` function in the `/bin/httpd` file.
## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:
This is a buffer overflow vulnerability in the function that handles the time parameter. Upon receiving a POST request containing the time parameter, this function allocates several buffers on the stack (e.g. var88, var7c, etc.) and then uses the sscanf function to read several strings from the time parameter and store them in these buffers. Since there is no limit on the input length, if the length of the input string exceeds the size of these buffers, it can lead to a stack overflow. An attacker could exploit this vulnerability to execute arbitrary code on the target system.

<img width="923" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/4251fb83-b0c1-49a5-a447-f21fd2697246">
 
 Call chain: SetSysTimeCfg->fromSetSysTime->sub_4a79ec
 
# Result
This resulted a crash of the program, Verified locally
<img width="1920" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/04caf3cf-0d88-41c7-84b5-1aa26c971f63">
Core dump is in the same dir


# PoC :
In Additional information
