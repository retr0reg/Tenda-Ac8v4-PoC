# Vulnerability Description
A stack-based overflow vulnerability that can be triggered via the `get_parentControl_list_Info` function in the `/bin/httpd` file.
## Affected version:
`US_AC8V4.0si_V16.03.34.06` 

To download the firmware: https://www.tenda.com.cn/download/detail-3518.html

# Exploition details:

This is a buffer overflow vulnerability in the function responsible for handling the time parameter within the get_parentControl_list_Info function. Upon receiving a POST request containing the time parameter, this function uses the strcpy function to copy the string from the time parameter into the buffer at p1 + 34. Since there is no input length restriction, if the input string's length exceeds the size of the destination buffer, a stack overflow will occur. An attacker could exploit this vulnerability to execute arbitrary code on the target system.

<img width="717" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/b89d47a9-77f7-4f1b-87df-c427b5ff406d">

To be clear, the difference between saveParentControlInfo and get_parentControl_list_Info  is that we don't cause crash in saveParentControlInfo, but we do it in get_parentControl_list_Info by exploiting the var3c:time parameter, however, in saveParentControlInfo, we use var3c:time  only to bypass the compare_parentcontrol_time(p0)
    
Call chain : saveParentControlInfo -> saveParentControlInfo -> get_parentControl_list_Info

# Result
This resulted a crash of the program, Verified locally
<img width="1920" alt="image" src="https://github.com/DDizzzy79/Tenda-CVE/assets/72267897/14527742-8bc6-40f4-8d61-572f93698edd">
Core dump is in the same dir

# PoC :
In Additional information
