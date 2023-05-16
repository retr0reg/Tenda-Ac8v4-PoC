# Vulnerability Description
A stack-based overflow vulnerability that can be triggered via the `saveParentControlInfo` function in the `/bin/httpd` file.
## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:
This is a buffer overflow vulnerability in the function responsible for handling the deviceId parameter within the saveParentControlInfo function. Upon receiving a POST request containing the deviceId parameter, this function allocates a buffer (var310) and then uses the strcpy function to copy the string from the deviceId parameter into the buffer. Since there is no input length restriction, if the input string's length exceeds the size of the var310 buffer, a stack overflow will occur. An attacker could exploit this vulnerability to execute arbitrary code on the target system.

<img width="508" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/e85a64fa-a3cd-4121-a84d-ef57456d6d68">

call-chain: saveParentControlInfo -> saveParentControlInfo 

# Result
This resulted a crash of the program, Verified locally

# PoC :
In Additional information
