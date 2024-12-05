# CWE-7 J2EE Misconfiguration: Missing Custom Error Page

## Description

The default error page of a web application should not display sensitive information about the product.

A Web application must define a default error page for 4xx errors (e.g. 404), 5xx (e.g. 500) errors and catch java.lang.Throwable exceptions to prevent attackers from mining information from the application container's built-in error response.


When an attacker explores a web site looking for vulnerabilities, the amount of information that the site provides is crucial to the eventual success or failure of any attempted attacks.

# CWE-703 Improper Check or Handling of Exceptional Conditions

## Description

The product does not properly anticipate or handle exceptional conditions that rarely occur during normal operation of the product.

## Observed Examples

[REF-1374]: Chain: JavaScript-based cryptocurrency library can fall back to the insecure Math.random() function instead of reporting a failure (CWE-392), thus reducing the entropy (CWE-332) and leading to generation of non-unique cryptographic keys for Bitcoin wallets (CWE-1391)

CVE-2022-22224: Chain: an operating system does not properly process malformed Open Shortest Path First (OSPF) Type/Length/Value Identifiers (TLV) (CWE-703), which can cause the process to enter an infinite loop (CWE-835)

## Top 25 Examples

CVE-2022-32623: In mdp, there is a possible out of bounds write due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07342114; Issue ID: ALPS07342114.

CVE-2022-22224: An Improper Check or Handling of Exceptional Conditions vulnerability in the processing of a malformed OSPF TLV in Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated adjacent attacker to cause the periodic packet management daemon (PPMD) process to go into an infinite loop, which in turn can cause protocols and functions reliant on PPMD such as OSPF neighbor reachability to be impacted, resulting in a sustained Denial of Service (DoS) condition. The DoS condition persists until the PPMD process is manually restarted. This issue affects: Juniper Networks Junos OS: All versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S5; 19.3 versions prior to 19.3R3-S3; 19.4 versions prior to 19.4R3-S9; 20.1 versions prior to 20.1R3; 20.2 versions prior to 20.2R3-S1; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R2. Juniper Networks Junos OS Evolved: All versions prior to 20.4R3-S3-EVO; 21.1 versions prior to 21.1R2-EVO.

CVE-2021-3433: Invalid channel map in CONNECT_IND results to Deadlock. Zephyr versions >= v2.5.0 Improper Check or Handling of Exceptional Conditions (CWE-703). For more information, see https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-3c2f-w4v6-qxrp

CVE-2021-25516: An improper check or handling of exceptional conditions in Exynos baseband prior to SMR Dec-2021 Release 1 allows attackers to track locations.

CVE-2022-22265: An improper check or handling of exceptional conditions in NPU driver prior to SMR Jan-2022 Release 1 allows arbitrary memory write and code execution.

CVE-2022-39911: Improper check or handling of exceptional conditions vulnerability in Samsung Pass prior to version 4.0.06.1 allows attacker to access Samsung Pass.

CVE-2022-41777: Improper check or handling of exceptional conditions vulnerability in Nako3edit, editor component of nadesiko3 (PC Version) v3.3.74 and earlier allows a remote attacker to inject an invalid value to decodeURIComponent of nako3edit, which may lead the server to crash.

# CWE-704 Incorrect Type Conversion or Cast

## Description

The product does not correctly convert an object, resource, or structure from one type to a different type.

## Observed Examples

CVE-2021-43537: Chain: in a web browser, an unsigned 64-bit integer is forcibly cast to a 32-bit integer (CWE-681) and potentially leading to an integer overflow (CWE-190). If an integer overflow occurs, this can cause heap memory corruption (CWE-122)

CVE-2022-3979: Chain: data visualization program written in PHP uses the "!=" operator instead of the type-strict "!==" operator (CWE-480) when validating hash values, potentially leading to an incorrect type conversion (CWE-704)

## Top 25 Examples

CVE-2021-35091: Possible out of bounds read due to improper typecasting while handling page fault for global memory in Snapdragon Connectivity, Snapdragon Mobile

CVE-2021-35110: Possible buffer overflow to improper validation of hash segment of file while allocating memory in Snapdragon Connectivity, Snapdragon Mobile

CVE-2021-43537: An incorrect type conversion of sizes from 64bit to 32bit integers allowed an attacker to corrupt memory leading to a potentially exploitable crash. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.

CVE-2022-21786: In audio DSP, there is a possible memory corruption due to improper casting. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06558822; Issue ID: ALPS06558822.

CVE-2022-22102: Memory corruption in multimedia due to incorrect type conversion while adding data in Snapdragon Auto

CVE-2022-25715: Memory corruption in display driver due to incorrect type casting while accessing the fence structure fields

CVE-2022-40531: Memory corruption in WLAN due to incorrect type cast while sending WMI_SCAN_SCH_PRIO_TBL_CMDID message.

CVE-2022-3979: A vulnerability was found in NagVis up to 1.9.33 and classified as problematic. This issue affects the function checkAuthCookie of the file share/server/core/classes/CoreLogonMultisite.php. The manipulation of the argument hash leads to incorrect type conversion. The attack may be initiated remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. Upgrading to version 1.9.34 is able to address this issue. The identifier of the patch is 7574fd8a2903282c2e0d1feef5c4876763db21d5. It is recommended to upgrade the affected component. The identifier VDB-213557 was assigned to this vulnerability.

CVE-2021-39989: The HwNearbyMain module has a Exposure of Sensitive Information to an Unauthorized Actor vulnerability.Successful exploitation of this vulnerability may cause a process to restart.

# CWE-705 Incorrect Control Flow Scoping

## Description

The product does not properly return control flow to the proper location after it has completed a task or detected an unusual condition.

## Observed Examples

CVE-2023-21087: Java code in a smartphone OS can encounter a "boot loop" due to an uncaught exception

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversary-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

## Top 25 Examples

CVE-2022-2841: A vulnerability was found in CrowdStrike Falcon 6.31.14505.0/6.42.15610/6.44.15806. It has been classified as problematic. Affected is an unknown function of the component Uninstallation Handler. The manipulation leads to missing authorization. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. Upgrading to version 6.40.15409, 6.42.15611 and 6.44.15807 is able to address this issue. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-206880.

CVE-2021-41250: Python discord bot is the community bot for the Python Discord community. In affected versions when a non-blacklisted URL and an otherwise triggering filter token is included in the same message the token filter does not trigger. This means that by including any non-blacklisted URL moderation filters can be bypassed. This issue has been resolved in commit 67390298852513d13e0213870e50fb3cff1424e0

# CWE-706 Use of Incorrectly-Resolved Name or Reference

## Description

The product uses a name or reference to access a resource, but the name/reference resolves to a resource that is outside of the intended control sphere.

# CWE-707 Improper Neutralization

## Description

The product does not ensure or incorrectly ensures that structured messages or data are well-formed and that certain security properties are met before being read from an upstream component or sent to a downstream component.

If a message is malformed, it may cause the message to be incorrectly interpreted.


Neutralization is an abstract term for any technique that ensures that input (and output) conforms with expectations and is "safe." This can be done by:


  - checking that the input/output is already "safe" (e.g. validation)

  - transformation of the input/output to be "safe" using techniques such as filtering, encoding/decoding, escaping/unescaping, quoting/unquoting, or canonicalization

  - preventing the input/output from being directly provided by an attacker (e.g. "indirect selection" that maps externally-provided values to internally-controlled values)

  - preventing the input/output from being processed at all

This weakness typically applies in cases where the product prepares a control message that another process must act on, such as a command or query, and malicious input that was intended as data, can enter the control plane instead. However, this weakness also applies to more general cases where there are not always control implications.

## Top 25 Examples

CVE-2022-25809: Improper Neutralization of audio output from 3rd and 4th Generation Amazon Echo Dot devices allows arbitrary voice command execution on these devices via a malicious skill (in the case of remote attackers) or by pairing a malicious Bluetooth device (in the case of physically proximate attackers), aka an "Alexa versus Alexa (AvA)" attack.

# CWE-708 Incorrect Ownership Assignment

## Description

The product assigns an owner to a resource, but the owner is outside of the intended control sphere.

This may allow the resource to be manipulated by actors outside of the intended control sphere.

## Observed Examples

CVE-2007-5101: File system sets wrong ownership and group when creating a new file.

CVE-2007-4238: OS installs program with bin owner/group, allowing modification.

CVE-2007-1716: Manager does not properly restore ownership of a reusable resource when a user logs out, allowing privilege escalation.

CVE-2005-3148: Backup software restores symbolic links with incorrect uid/gid.

CVE-2005-1064: Product changes the ownership of files that a symlink points to, instead of the symlink itself.

CVE-2011-1551: Component assigns ownership of sensitive directory tree to a user account, which can be leveraged to perform privileged operations.

# CWE-710 Improper Adherence to Coding Standards

## Description

The product does not follow certain coding rules for development, which can lead to resultant weaknesses or increase the severity of the associated vulnerabilities.

# CWE-72 Improper Handling of Apple HFS+ Alternate Data Stream Path

## Description

The product does not properly handle special paths that may identify the data or resource fork of a file on the HFS+ file system.

If the product chooses actions to take based on the file name, then if an attacker provides the data or resource fork, the product may take unexpected actions. Further, if the product intends to restrict access to a file, then an attacker might still be able to bypass intended access restrictions by requesting the data or resource fork for that file.



The Apple HFS+ file system permits files to have multiple data input streams, accessible through special paths. The Mac OS X operating system provides a way to access the different data input streams through special paths and as an extended attribute:

```
		- Resource fork: file/..namedfork/rsrc, file/rsrc (deprecated), xattr:com.apple.ResourceFork
		- Data fork: file/..namedfork/data (only versions prior to Mac OS X v10.5)
```
Additionally, on filesystems that lack native support for multiple streams, the resource fork and file metadata may be stored in a file with "._" prepended to the name.

Forks can also be accessed through non-portable APIs.


Forks inherit the file system access controls of the file they belong to.


Programs need to control access to these paths, if the processing of a file system object is dependent on the structure of its path.


## Observed Examples

CVE-2004-1084: Server allows remote attackers to read files and resource fork content via HTTP requests to certain special file names related to multiple data streams in HFS+.

# CWE-73 External Control of File Name or Path

## Description

The product allows user input to control or influence paths or file names that are used in filesystem operations.

This could allow an attacker to access or modify system files or other files that are critical to the application.


Path manipulation errors occur when the following two conditions are met:

```
		1. An attacker can specify a path used in an operation on the filesystem.
		2. By specifying the resource, the attacker gains a capability that would not otherwise be permitted.
```
For example, the program may give the attacker the ability to overwrite the specified file or run with a configuration controlled by the attacker.

## Observed Examples

CVE-2022-45918: Chain: a learning management tool debugger uses external input to locate previous session logs (CWE-73) and does not properly validate the given path (CWE-20), allowing for filesystem path traversal using "../" sequences (CWE-24)

CVE-2008-5748: Chain: external control of values for user's desired language and theme enables path traversal.

CVE-2008-5764: Chain: external control of user's target language enables remote file inclusion.

## Top 25 Examples

CVE-2022-24900: Piano LED Visualizer is software that allows LED lights to light up as a person plays a piano connected to a computer. Version 1.3 and prior are vulnerable to a path traversal attack. The `os.path.join` call is unsafe for use with untrusted input. When the `os.path.join` call encounters an absolute path, it ignores all the parameters it has encountered till that point and starts working with the new absolute path. Since the "malicious" parameter represents an absolute path, the result of `os.path.join` ignores the static directory completely. Hence, untrusted input is passed via the `os.path.join` call to `flask.send_file` can lead to path traversal attacks. A patch with a fix is available on the `master` branch of the GitHub repository. This can also be fixed by preventing flow of untrusted data to the vulnerable `send_file` function. In case the application logic necessiates this behaviour, one can either use the `flask.safe_join` to join untrusted paths or replace `flask.send_file` calls with `flask.send_from_directory` calls.

CVE-2022-34765: A CWE-73: External Control of File Name or Path vulnerability exists that could cause loading of unauthorized firmware images when user-controlled data is written to the file path. Affected Products: X80 advanced RTU Communication Module (BMENOR2200H) (V2.01 and later), OPC UA Modicon Communication Module (BMENUA0100) (V1.10 and prior)

CVE-2022-39952: A external control of file name or path in Fortinet FortiNAC versions 9.4.0, 9.2.0 through 9.2.5, 9.1.0 through 9.1.7, 8.8.0 through 8.8.11, 8.7.0 through 8.7.6, 8.6.0 through 8.6.5, 8.5.0 through 8.5.4, 8.3.7 may allow an unauthenticated attacker to execute unauthorized code or commands via specifically crafted HTTP request.

CVE-2022-45918: ILIAS before 7.16 allows External Control of File Name or Path.

CVE-2022-23118: Jenkins Debian Package Builder Plugin 1.6.11 and earlier implements functionality that allows agents to invoke command-line `git` at an attacker-specified path on the controller, allowing attackers able to control agent processes to invoke arbitrary OS commands on the controller.

CVE-2022-25643: seatd-launch in seatd 0.6.x before 0.6.4 allows removing files with escalated privileges when installed setuid root. The attack vector is a user-supplied socket pathname.

# CWE-732 Incorrect Permission Assignment for Critical Resource

## Description

The product specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.

When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that resource by unintended parties. This is especially dangerous when the resource is related to program configuration, execution, or sensitive user data. For example, consider a misconfigured storage account for the cloud that can be read or written by a public or anonymous user.

## Observed Examples

CVE-2022-29527: Go application for cloud management creates a world-writable sudoers file that allows local attackers to inject sudo rules and escalate privileges to root by winning a race condition.

CVE-2009-3482: Anti-virus product sets insecure "Everyone: Full Control" permissions for files under the "Program Files" folder, allowing attackers to replace executables with Trojan horses.

CVE-2009-3897: Product creates directories with 0777 permissions at installation, allowing users to gain privileges and access a socket used for authentication.

CVE-2009-3489: Photo editor installs a service with an insecure security descriptor, allowing users to stop or start the service, or execute commands as SYSTEM.

CVE-2020-15708: socket created with insecure permissions

CVE-2009-3289: Library function copies a file to a new target and uses the source file's permissions for the target, which is incorrect when the source file is a symbolic link, which typically has 0777 permissions.

CVE-2009-0115: Device driver uses world-writable permissions for a socket file, allowing attackers to inject arbitrary commands.

CVE-2009-1073: LDAP server stores a cleartext password in a world-readable file.

CVE-2009-0141: Terminal emulator creates TTY devices with world-writable permissions, allowing an attacker to write to the terminals of other users.

CVE-2008-0662: VPN product stores user credentials in a registry key with "Everyone: Full Control" permissions, allowing attackers to steal the credentials.

CVE-2008-0322: Driver installs its device interface with "Everyone: Write" permissions.

CVE-2009-3939: Driver installs a file with world-writable permissions.

CVE-2009-3611: Product changes permissions to 0777 before deleting a backup; the permissions stay insecure for subsequent backups.

CVE-2007-6033: Product creates a share with "Everyone: Full Control" permissions, allowing arbitrary program execution.

CVE-2007-5544: Product uses "Everyone: Full Control" permissions for memory-mapped files (shared memory) in inter-process communication, allowing attackers to tamper with a session.

CVE-2005-4868: Database product uses read/write permissions for everyone for its shared memory, allowing theft of credentials.

CVE-2004-1714: Security product uses "Everyone: Full Control" permissions for its configuration files.

CVE-2001-0006: "Everyone: Full Control" permissions assigned to a mutex allows users to disable network connectivity.

CVE-2002-0969: Chain: database product contains buffer overflow that is only reachable through a .ini configuration file - which has "Everyone: Full Control" permissions.

## Top 25 Examples

CVE-2022-34043: Incorrect permissions for the folder C:\\ProgramData\\NoMachine\\var\\uninstall of Nomachine v7.9.2 allows attackers to perform a DLL hijacking attack and execute arbitrary code.

CVE-2022-22960: VMware Workspace ONE Access, Identity Manager and vRealize Automation contain a privilege escalation vulnerability due to improper permissions in support scripts. A malicious actor with local access can escalate privileges to 'root'.

CVE-2021-23874: Arbitrary Process Execution vulnerability in McAfee Total Protection (MTP) prior to 16.0.30 allows a local user to gain elevated privileges and execute arbitrary code bypassing MTP self-defense.

CVE-2021-25263: Local privilege vulnerability in Yandex Browser for Windows prior to 21.9.0.390 allows a local, low privileged, attacker to execute arbitary code with the SYSTEM privileges through manipulating files in directory with insecure permissions during Yandex Browser update process.

CVE-2022-0556: A local privilege escalation vulnerability caused by incorrect permission assignment in some directories of the Zyxel AP Configurator (ZAC) version 1.1.4, which could allow an attacker to execute arbitrary code as a local administrator.

CVE-2022-26526: Anaconda Anaconda3 (Anaconda Distribution) through 2021.11.0.0 and Miniconda3 through 4.11.0.0 can create a world-writable directory under %PROGRAMDATA% and place that directory into the system PATH environment variable. Thus, for example, local users can gain privileges by placing a Trojan horse file into that directory. (This problem can only happen in a non-default installation. The person who installs the product must specify that it is being installed for all users. Also, the person who installs the product must specify that the system PATH should be changed.

CVE-2022-30990: Sensitive information disclosure due to insecure folder permissions. The following products are affected: Acronis Cyber Protect 15 (Linux) before build 29240, Acronis Agent (Linux) before build 28037

CVE-2022-31464: Insecure permissions configuration in Adaware Protect v1.2.439.4251 allows attackers to escalate privileges via changing the service binary path.

CVE-2022-34457:  Dell command configuration, version 4.8 and prior, contains improper folder permission when installed not to default path but to non-secured path which leads to privilege escalation. This is critical severity vulnerability as it allows non-admin to modify the files inside installed directory and able to make application unavailable for all users. 

CVE-2022-35167: Printix Cloud Print Management v1.3.1149.0 for Windows was discovered to contain insecure permissions.

CVE-2022-37435: Apache ShenYu Admin has insecure permissions, which may allow low-privilege administrators to modify high-privilege administrator's passwords. This issue affects Apache ShenYu 2.4.2 and 2.4.3.

CVE-2022-44263: Dentsply Sirona Sidexis <= 4.3 is vulnerable to Incorrect Access Control.

CVE-2022-44732: Local privilege escalation due to insecure folder permissions. The following products are affected: Acronis Cyber Protect Home Office (Windows) before build 39900.

CVE-2022-1412: The Log WP_Mail WordPress plugin through 0.1 saves sent email in a publicly accessible directory using predictable filenames, allowing any unauthenticated visitor to obtain potentially sensitive information like generated passwords.

CVE-2022-33175: Power Distribution Units running on Powertek firmware (multiple brands) before 3.30.30 have an insecure permissions setting on the user.token field that is accessible to everyone through the /cgi/get_param.cgi HTTP API. This leads to disclosing active session ids of currently logged-in administrators. The session id can then be reused to act as the administrator, allowing reading of the cleartext password, or reconfiguring the device.

CVE-2022-0277: Incorrect Permission Assignment for Critical Resource in Packagist microweber/microweber prior to 1.2.11.

CVE-2021-0336: In onReceive of BluetoothPermissionRequest.java, there is a possible permissions bypass due to a mutable PendingIntent. This could lead to local escalation of privilege that bypasses a permission check, with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11 Android-8.1Android ID: A-158219161

CVE-2022-1316: Incorrect Permission Assignment for Critical Resource in GitHub repository zerotier/zerotierone prior to 1.8.8. Local Privilege Escalation 

CVE-2022-20218: In PermissionController, there is a possible way to get and retain permissions without user's consent due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-223907044

CVE-2022-22141: 'Long-term Data Archive Package' service implemented in the following Yokogawa Electric products creates some named pipe with imporper ACL configuration. CENTUM CS 3000 versions from R3.08.10 to R3.09.00, CENTUM VP versions from R4.01.00 to R4.03.00, from R5.01.00 to R5.04.20, and from R6.01.00 to R6.08.00, Exaopc versions from R3.72.00 to R3.79.00.

CVE-2022-22521: In Miele Benchmark Programming Tool with versions Prior to 1.2.71, executable files manipulated by attackers are unknowingly executed with users privileges. An attacker with low privileges may trick a user with administrative privileges to execute these binaries as admin. 

CVE-2022-46338: g810-led 0.4.2, a LED configuration tool for Logitech Gx10 keyboards, contained a udev rule to make supported device nodes world-readable and writable, allowing any process on the system to read traffic from keyboards, including sensitive data.

CVE-2022-23743: Check Point ZoneAlarm before version 15.8.200.19118 allows a local actor to escalate privileges during the upgrade process. In addition, weak permissions in the ProgramData\\CheckPoint\\ZoneAlarm\\Data\\Updates directory allow a local attacker the ability to execute an arbitrary file write, leading to execution of code as local system, in ZoneAlarm versions before v15.8.211.192119

CVE-2022-25010: The component /rootfs in RageFile of Stepmania v5.1b2 and below allows attackers access to the entire file system.

CVE-2021-21177: Insufficient policy enforcement in Autofill in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to obtain potentially sensitive information from process memory via a crafted HTML page.

CVE-2022-23725: PingID Windows Login prior to 2.8 does not properly set permissions on the Windows Registry entries used to store sensitive API keys under some circumstances.

CVE-2021-22648: Ovarro TBox proprietary Modbus file access functions allow attackers to read, alter, or delete the configuration file.

CVE-2022-0247: An issue exists in Fuchsia where VMO data can be modified through access to copy-on-write snapshots. A local attacker could modify objects in the VMO that they do not have permission to. We recommend upgrading past commit d97c05d2301799ed585620a9c5c739d36e7b5d3d or any of the listed versions.

CVE-2022-0483: Local privilege escalation due to insecure folder permissions. The following products are affected: Acronis VSS Doctor (Windows) before build 53

CVE-2022-1348: A vulnerability was found in logrotate in how the state file is created. The state file is used to prevent parallel executions of multiple instances of logrotate by acquiring and releasing a file lock. When the state file does not exist, it is created with world-readable permission, allowing an unprivileged user to lock the state file, stopping any rotation. This flaw affects logrotate versions before 3.20.0.

CVE-2022-1596: Incorrect Permission Assignment for Critical Resource vulnerability in ABB REX640 PCL1, REX640 PCL2, REX640 PCL3 allows an authenticated attacker to launch an attack against the user database file and try to take control of an affected system node.

CVE-2022-21819: NVIDIA distributions of Jetson Linux contain a vulnerability where an error in the IOMMU configuration may allow an unprivileged attacker with physical access to the board direct read/write access to the entire system address space through the PCI bus. Such an attack could result in denial of service, code execution, escalation of privileges, and impact to data integrity and confidentiality. The scope impact may extend to other components.

CVE-2022-22148: 'Root Service' service implemented in the following Yokogawa Electric products creates some named pipe with improper ACL configuration. CENTUM CS 3000 versions from R3.08.10 to R3.09.00, CENTUM VP versions from R4.01.00 to R4.03.00, from R5.01.00 to R5.04.20, and from R6.01.00 to R6.08.00, Exaopc versions from R3.72.00 to R3.79.00.

CVE-2022-22248: An Incorrect Permission Assignment vulnerability in shell processing of Juniper Networks Junos OS Evolved allows a low-privileged local user to modify the contents of a configuration file which could cause another user to execute arbitrary commands within the context of the follow-on user's session. If the follow-on user is a high-privileged administrator, the attacker could leverage this vulnerability to take complete control of the target system. While this issue is triggered by a user, other than the attacker, accessing the Junos shell, an attacker simply requires Junos CLI access to exploit this vulnerability. This issue affects Juniper Networks Junos OS Evolved: 20.4-EVO versions prior to 20.4R3-S1-EVO; All versions of 21.1-EVO; 21.2-EVO versions prior to 21.2R3-EVO; 21.3-EVO versions prior to 21.3R2-EVO. This issue does not affect Juniper Networks Junos OS Evolved versions prior to 19.2R1-EVO.

CVE-2022-22516: The SysDrv3S driver in the CODESYS Control runtime system on Microsoft Windows allows any system user to read and write within restricted memory space.

CVE-2022-22988: File and directory permissions have been corrected to prevent unintended users from modifying or accessing resources. It would be more difficult for an authenticated attacker to now traverse through the files and directories. This can only be exploited once an attacker has already found a way to get authenticated access to the device. 

CVE-2022-23132: During Zabbix installation from RPM, DAC_OVERRIDE SELinux capability is in use to access PID files in [/var/run/zabbix] folder. In this case, Zabbix Proxy or Server processes can bypass file read, write and execute permissions check on the file system level

CVE-2022-23143: ZTE OTCP product is impacted by a permission and access control vulnerability. Due to improper permission settings, an attacker with high permissions could use this vulnerability to maliciously delete and modify files.

CVE-2022-2332: A local unprivileged attacker may escalate to administrator privileges in Honeywell SoftMaster version 4.51, due to insecure permission assignment.

CVE-2022-23448: A vulnerability has been identified in SIMATIC Energy Manager Basic (All versions < V7.3 Update 1), SIMATIC Energy Manager PRO (All versions < V7.3 Update 1). Affected applications improperly assign permissions to critical directories and files used by the application processes. This could allow a local unprivileged attacker to achieve code execution with ADMINISTRATOR or even NT AUTHORITY/SYSTEM privileges.

CVE-2022-26236: The default privileges for the running service Normand Remisol Advance Launcher in Beckman Coulter Remisol Advance v2.0.12.1 and prior allows non-privileged users to overwrite and manipulate executables and libraries. This allows attackers to access sensitive data.

CVE-2022-26237: The default privileges for the running service Normand Viewer Service in Beckman Coulter Remisol Advance v2.0.12.1 and prior allows non-privileged users to overwrite and manipulate executables and libraries. This allows attackers to access sensitive data.

CVE-2022-26238: The default privileges for the running service Normand Service Manager in Beckman Coulter Remisol Advance v2.0.12.1 and prior allows non-privileged users to overwrite and manipulate executables and libraries. This allows attackers to access sensitive data.

CVE-2022-26239: The default privileges for the running service Normand License Manager in Beckman Coulter Remisol Advance v2.0.12.1 and prior allows unprivileged users to overwrite and manipulate executables and libraries. This allows attackers to access sensitive data.

CVE-2022-26240: The default privileges for the running service Normand Message Buffer in Beckman Coulter Remisol Advance v2.0.12.1 and prior allows non-privileged users to overwrite and manipulate executables and libraries. This allows attackers to access sensitive data.

CVE-2022-26250: Synaman v5.1 and below was discovered to contain weak file permissions which allows authenticated attackers to escalate privileges.

CVE-2022-26340: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all versions of 12.1.x and 11.6.x, and F5 BIG-IQ Centralized Management all versions of 8.x and 7.x, an authenticated, high-privileged attacker with no bash access may be able to access Certificate and Key files using Secure Copy (SCP) protocol from a remote system. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-29263: On F5 BIG-IP APM 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all versions of 12.1.x and 11.6.x, as well as F5 BIG-IP APM Clients 7.x versions prior to 7.2.1.5, the BIG-IP Edge Client Component Installer Service does not use best practice while saving temporary files. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-30700: An incorrect permission assignment vulnerability in Trend Micro Apex One and Apex One as a Service could allow a local attacker to load a DLL with escalated privileges on affected installations. Please note: an attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability.

CVE-2022-30929: Mini-Tmall v1.0 is vulnerable to Insecure Permissions via tomcat-embed-jasper.

CVE-2022-31465: A vulnerability has been identified in Xpedition Designer VX.2.10 (All versions < VX.2.10 Update 13), Xpedition Designer VX.2.11 (All versions < VX.2.11 Update 11), Xpedition Designer VX.2.12 (All versions < VX.2.12 Update 5), Xpedition Designer VX.2.13 (All versions < VX.2.13 Update 1). The affected application assigns improper access rights to the service executable. This could allow an authenticated local attacker to inject arbitrary code and escalate privileges.

CVE-2022-3258: Incorrect Permission Assignment for Critical Resource vulnerability in HYPR Workforce Access on Windows allows Authentication Abuse.

CVE-2022-33695: Use of improper permission in InputManagerService prior to SMR Jul-2022 Release 1 allows unauthorized access to the service.

CVE-2022-34314:  IBM CICS TX 11.1 could disclose sensitive information to a local user due to insecure permission settings. IBM X-Force ID: 229450. 

CVE-2022-34891: This vulnerability allows local attackers to escalate privileges on affected installations of Parallels Desktop Parallels Desktop 17.1.1. An attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability. The specific flaw exists within the update machanism. The product sets incorrect permissions on sensitive files. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of root. Was ZDI-CAN-16395.

CVE-2022-36122: The Automox Agent before 40 on Windows incorrectly sets permissions on key files.

CVE-2022-39186: EXFO - BV-10 Performance Endpoint Unit misconfiguration. System configuration file has misconfigured permissions

CVE-2022-42972: A CWE-732: Incorrect Permission Assignment for Critical Resource vulnerability exists that could cause local privilege escalation when a local attacker modifies the webroot directory. Affected Products: APC Easy UPS Online Monitoring Software (Windows 7, 10, 11 & Windows Server 2016, 2019, 2022 - Versions prior to V2.5-GA), APC Easy UPS Online Monitoring Software (Windows 11, Windows Server 2019, 2022 - Versions prior to V2.5-GA-01-22261), Schneider Electric Easy UPS Online Monitoring Software (Windows 7, 10, 11 & Windows Server 2016, 2019, 2022 - Versions prior to V2.5-GS), Schneider Electric Easy UPS Online Monitoring Software (Windows 11, Windows Server 2019, 2022 - Versions prior to V2.5-GS-01-22261)

CVE-2022-43517: A vulnerability has been identified in Simcenter STAR-CCM+ (All versions < V2306). The affected application improperly assigns file permissions to installation folders. This could allow a local attacker with an unprivileged account to override or modify the service executables and subsequently gain elevated privileges.

CVE-2022-44715: Improper File Permissions in NetScout nGeniusONE 6.3.2 build 904 allows authenticated remote users to gain permissions via a crafted payload.

CVE-2022-44725: OPC Foundation Local Discovery Server (LDS) through 1.04.403.478 uses a hard-coded file path to a configuration file. This allows a normal user to create a malicious file that is loaded by LDS (running as a high-privilege user).

CVE-2022-44733: Local privilege escalation due to insecure folder permissions. The following products are affected: Acronis Cyber Protect Home Office (Windows) before build 39900.

CVE-2022-44746: Sensitive information disclosure due to insecure folder permissions. The following products are affected: Acronis Cyber Protect Home Office (Windows) before build 40107.

CVE-2022-45193: CBRN-Analysis before 22 has weak file permissions under Public Profile, leading to disclosure of file contents or privilege escalation.

CVE-2022-45301: Insecure permissions in Chocolatey Ruby package v3.1.2.1 and below grants all users in the Authenticated Users group write privileges for the path C:\\tools\\ruby31 and all files located in that folder.

CVE-2022-45304: Insecure permissions in Chocolatey Cmder package v1.3.20 and below grants all users in the Authenticated Users group write privileges for the path C:\\tools\\Cmder and all files located in that folder.

CVE-2022-45305: Insecure permissions in Chocolatey Python3 package v3.11.0 and below grants all users in the Authenticated Users group write privileges for the subfolder C:\\Python311 and all files located in that folder.

CVE-2022-45306: Insecure permissions in Chocolatey Azure-Pipelines-Agent package v2.211.1 and below grants all users in the Authenticated Users group write privileges for the subfolder C:\\agent and all files located in that folder.

CVE-2022-45307: Insecure permissions in Chocolatey PHP package v8.1.12 and below grants all users in the Authenticated Users group write privileges for the subfolder C:\\tools\\php81 and all files located in that folder.

CVE-2022-47927: An issue was discovered in MediaWiki before 1.35.9, 1.36.x through 1.38.x before 1.38.5, and 1.39.x before 1.39.1. When installing with a pre-existing data directory that has weak permissions, the SQLite files are created with file mode 0644, i.e., world readable to local users. These files include credentials data.

CVE-2022-24886: Nextcloud Android app is the Android client for Nextcloud, a self-hosted productivity platform. In versions prior to 3.19.0, any application with notification permission can access contacts if Nextcloud has access to Contacts without applying for the Contacts permission itself. Version 3.19.0 contains a fix for this issue. There are currently no known workarounds.

CVE-2022-2188: Privilege escalation vulnerability in DXL Broker for Windows prior to 6.0.0.280 allows local users to gain elevated privileges by exploiting weak directory controls in the logs directory. This can lead to a denial-of-service attack on the DXL Broker. 

CVE-2022-22411: IBM Spectrum Scale Data Access Services (DAS) 5.1.3.1 could allow an authenticated user to insert code which could allow the attacker to manipulate cluster resources due to excessive permissions. IBM X-Force ID: 223016.

CVE-2022-41926: Nextcould talk android is the android OS implementation of the nextcloud talk chat system. In affected versions the receiver is not protected by broadcastPermission allowing malicious apps to monitor communication. It is recommended that the Nextcloud Talk Android is upgraded to 14.1.0. There are no known workarounds for this issue.

# CWE-733 Compiler Optimization Removal or Modification of Security-critical Code

## Description

The developer builds a security-critical protection mechanism into the software, but the compiler optimizes the program such that the mechanism is removed or modified.

## Observed Examples

CVE-2008-1685: C compiler optimization, as allowed by specifications, removes code that is used to perform checks to detect integer overflows.

CVE-2019-1010006: Chain: compiler optimization (CWE-733) removes or modifies code used to detect integer overflow (CWE-190), allowing out-of-bounds write (CWE-787).

## Top 25 Examples

CVE-2021-20320: A flaw was found in s390 eBPF JIT in bpf_jit_insn in arch/s390/net/bpf_jit_comp.c in the Linux kernel. In this flaw, a local attacker with special user privilege can circumvent the verifier and may lead to a confidentiality problem.

# CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')

## Description

The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.

Software or other automated logic has certain assumptions about what constitutes data and control respectively. It is the lack of verification of these assumptions for user-controlled input that leads to injection problems. Injection problems encompass a wide variety of issues -- all mitigated in very different ways and usually attempted in order to alter the control flow of the process. For this reason, the most effective way to discuss these weaknesses is to note the distinct features that classify them as injection weaknesses. The most important issue to note is that all injection problems share one thing in common -- i.e., they allow for the injection of control plane data into the user-controlled data plane. This means that the execution of the process may be altered by sending code in through legitimate data channels, using no other mechanism. While buffer overflows, and many other flaws, involve the use of some further issue to gain execution, injection problems need only for the data to be parsed.

## Observed Examples

CVE-2022-36069: Python-based dependency management tool avoids OS command injection when generating Git commands but allows injection of optional arguments with input beginning with a dash (CWE-88), potentially allowing for code execution.

CVE-1999-0067: Canonical example of OS command injection. CGI program does not neutralize "|" metacharacter when invoking a phonebook program.

CVE-2022-1509: injection of sed script syntax ("sed injection")

CVE-2020-9054: Chain: improper input validation (CWE-20) in username parameter, leading to OS command injection (CWE-78), as exploited in the wild per CISA KEV.

CVE-2021-44228: Product does not neutralize ${xyz} style expressions, allowing remote code execution. (log4shell vulnerability)

## Top 25 Examples

CVE-2022-31777: A stored cross-site scripting (XSS) vulnerability in Apache Spark 3.2.1 and earlier, and 3.3.0, allows remote attackers to execute arbitrary JavaScript in the web browser of a user, by including a malicious payload into the logs which would be returned in logs rendered in the UI.

CVE-2022-28345: The Signal app before 5.34 for iOS allows URI spoofing via RTLO injection. It incorrectly renders RTLO encoded URLs beginning with a non-breaking space, when there is a hash character in the URL. This technique allows a remote unauthenticated attacker to send legitimate looking links, appearing to be any website URL, by abusing the non-http/non-https automatic rendering of URLs. An attacker can spoof, for example, example.com, and masquerade any URL with a malicious destination. An attacker requires a subdomain such as gepj, txt, fdp, or xcod, which would appear backwards as jpeg, txt, pdf, and docx respectively.

CVE-2022-3941: A vulnerability has been found in Activity Log Plugin and classified as critical. This vulnerability affects unknown code of the component HTTP Header Handler. The manipulation of the argument X-Forwarded-For leads to improper output neutralization for logs. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-213448.

CVE-2021-36668: URL injection in Driva inSync 6.9.0 for MacOS, allows attackers to force a visit to an arbitrary url via the port parameter to the Electron App.

CVE-2022-23064: In Snipe-IT, versions v3.0-alpha to v5.3.7 are vulnerable to Host Header Injection. By sending a specially crafted host header in the reset password request, it is possible to send password reset links to users which once clicked lead to an attacker controlled server and thus leading to password reset token leak. This leads to account take over.

CVE-2022-23701: A potential remote host header injection security vulnerability has been identified in HPE Integrated Lights-Out 4 (iLO 4) firmware version(s): Prior to 2.60. This vulnerability could be remotely exploited to allow an attacker to supply invalid input to the iLO 4 webserver, causing it to respond with a redirect to an attacker-controlled domain. HPE has provided a firmware update to resolve this vulnerability in HPE Integrated Lights-Out 4 (iLO 4).

CVE-2022-25337: Ibexa DXP ezsystems/ezpublish-kernel 7.5.x before 7.5.26 and 1.3.x before 1.3.12 allows injection attacks via image filenames.

CVE-2022-31593: SAP Business One client - version 10.0 allows an attacker with low privileges, to inject code that can be executed by the application. An attacker could thereby control the behavior of the application.

CVE-2022-31658: VMware Workspace ONE Access, Identity Manager and vRealize Automation contain a remote code execution vulnerability. A malicious actor with administrator and network access can trigger a remote code execution.

CVE-2022-31665: VMware Workspace ONE Access, Identity Manager and vRealize Automation contain a remote code execution vulnerability. A malicious actor with administrator and network access can trigger a remote code execution.

CVE-2022-34773: Tabit - HTTP Method manipulation. https://bridge.tabit.cloud/configuration/addresses-query - can be POST-ed to add addresses to the DB. This is an example of OWASP:API8 – Injection.

CVE-2022-35735: In BIG-IP Versions 16.1.x before 16.1.3.1, 15.1.x before 15.1.6.1, 14.1.x before 14.1.5.1, and all versions of 13.1.x, an authenticated attacker with Resource Administrator or Manager privileges can create or modify existing monitor objects in the Configuration utility in an undisclosed manner leading to a privilege escalation. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-35954: The GitHub Actions ToolKit provides a set of packages to make creating actions easier. The `core.exportVariable` function uses a well known delimiter that attackers can use to break out of that specific variable and assign values to other arbitrary variables. Workflows that write untrusted values to the `GITHUB_ENV` file may cause the path or other environment variables to be modified without the intention of the workflow or action author. Users should upgrade to `@actions/core v1.9.1`. If you are unable to upgrade the `@actions/core` package, you can modify your action to ensure that any user input does not contain the delimiter `_GitHubActionsFileCommandDelimeter_` before calling `core.exportVariable`.

CVE-2022-46265: A vulnerability has been identified in Polarion ALM (All versions < V2304.0). The affected application contains a Host header injection vulnerability that could allow an attacker to spoof a Host header information and redirect users to malicious websites.

CVE-2022-26205: Marky commit 3686565726c65756e was discovered to contain a remote code execution (RCE) vulnerability via the Display text fields. This vulnerability allows attackers to execute arbitrary code via injection of a crafted payload.

CVE-2022-37933: A potential security vulnerability has been identified in HPE Superdome Flex and Superdome Flex 280 servers. The vulnerability could be exploited to allow local unauthorized data injection. HPE has made the following software updates to resolve the vulnerability in HPE Superdome Flex firmware 3.60.50 and below and Superdome Flex 280 servers firmware 1.40.60 and below. 

CVE-2022-38796: A Host Header Injection vulnerability in Feehi CMS 2.1.1 may allow an attacker to spoof a particular header. This can be exploited by abusing password reset emails.

CVE-2022-33011: Known v1.3.1+2020120201 was discovered to allow attackers to perform an account takeover via a host header injection attack.

CVE-2022-33012: Microweber v1.2.15 was discovered to allow attackers to perform an account takeover via a host header injection attack.

CVE-2022-37108: An injection vulnerability in the syslog-ng configuration wizard in Securonix Snypr 6.4 allows an application user with the "Manage Ingesters" permission to execute arbitrary code on remote ingesters by appending arbitrary text to text files that are executed by the system, such as users' crontab files. The patch for this was present in SNYPR version 6.4 Jun 2022 R3_[06170871], but may have been introduced sooner.

# CWE-749 Exposed Dangerous Method or Function

## Description

The product provides an Applications Programming Interface (API) or similar interface for interaction with external actors, but the interface includes a dangerous method or function that is not properly restricted.

This weakness can lead to a wide variety of resultant weaknesses, depending on the behavior of the exposed method. It can apply to any number of technologies and approaches, such as ActiveX controls, Java functions, IOCTLs, and so on.


The exposure can occur in a few different ways:


  - The function/method was never intended to be exposed to outside actors.

  - The function/method was only intended to be accessible to a limited set of actors, such as Internet-based access from a single web site.

## Observed Examples

CVE-2007-6382: arbitrary Java code execution via exposed method

CVE-2007-1112: security tool ActiveX control allows download or upload of files

## Top 25 Examples

CVE-2021-36942: Windows LSA Spoofing Vulnerability

CVE-2021-23556: The package guake before 3.8.5 are vulnerable to Exposed Dangerous Method or Function due to the exposure of execute_command and execute_command_by_uuid methods via the d-bus interface, which makes it possible for a malicious user to run an arbitrary command via the d-bus method. **Note:** Exploitation requires the user to have installed another malicious program that will be able to send dbus signals or run terminal commands.

CVE-2022-43138: Dolibarr Open Source ERP & CRM for Business before v14.0.1 allows attackers to escalate privileges via a crafted API.

# CWE-75 Failure to Sanitize Special Elements into a Different Plane (Special Element Injection)

## Description

The product does not adequately filter user-controlled input for special elements with control implications.

## Top 25 Examples

CVE-2022-3607: Failure to Sanitize Special Elements into a Different Plane (Special Element Injection) in GitHub repository octoprint/octoprint prior to 1.8.3.

# CWE-754 Improper Check for Unusual or Exceptional Conditions

## Description

The product does not check or incorrectly checks for unusual or exceptional conditions that are not expected to occur frequently during day to day operation of the product.

The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permissions, or misbehaving clients or components. However, attackers may intentionally trigger these unusual conditions, thus violating the programmer's assumptions, possibly introducing instability, incorrect behavior, or a vulnerability.


Note that this entry is not exclusively about the use of exceptions and exception handling, which are mechanisms for both checking and handling unusual or unexpected conditions.

Many functions will return some value about the success of their actions. This will alert the program whether or not to handle any errors caused by that function.

## Observed Examples

CVE-2023-49286: Chain: function in web caching proxy does not correctly check a return value (CWE-253) leading to a reachable assertion (CWE-617)

CVE-2007-3798: Unchecked return value leads to resultant integer overflow and code execution.

CVE-2006-4447: Program does not check return value when invoking functions to drop privileges, which could leave users with higher privileges than expected by forcing those functions to fail.

CVE-2006-2916: Program does not check return value when invoking functions to drop privileges, which could leave users with higher privileges than expected by forcing those functions to fail.

## Top 25 Examples

CVE-2021-21773: An out-of-bounds write vulnerability exists in the TIFF header count-processing functionality of Accusoft ImageGear 19.8. A specially crafted malformed file can lead to memory corruption. An attacker can provide a malicious file to trigger this vulnerability.

CVE-2022-20130: In transportDec_OutOfBandConfig of tpdec_lib.cpp, there is a possible out of bounds write due to a heap buffer overflow. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-224314979

CVE-2021-3560: It was found that polkit could be tricked into bypassing the credential checks for D-Bus requests, elevating the privileges of the requestor to the root user. This flaw could be used by an unprivileged local attacker to, for example, create a new local administrator. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

CVE-2022-20426: In multiple functions of many files, there is a possible obstruction of the user's ability to select a phone account due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-236263294

# CWE-755 Improper Handling of Exceptional Conditions

## Description

The product does not handle or incorrectly handles an exceptional condition.

## Observed Examples

CVE-2023-41151: SDK for OPC Unified Architecture (OPC UA) server has uncaught exception when a socket is blocked for writing but the server tries to send an error

[REF-1374]: Chain: JavaScript-based cryptocurrency library can fall back to the insecure Math.random() function instead of reporting a failure (CWE-392), thus reducing the entropy (CWE-332) and leading to generation of non-unique cryptographic keys for Bitcoin wallets (CWE-1391)

CVE-2021-3011: virtual interrupt controller in a virtualization product allows crash of host by writing a certain invalid value to a register, which triggers a fatal error instead of returning an error code

CVE-2008-4302: Chain: OS kernel does not properly handle a failure of a function call (CWE-755), leading to an unlock of a resource that was not locked (CWE-832), with resultant crash.

## Top 25 Examples

CVE-2022-20076: In ged, there is a possible memory corruption due to an incorrect error handling. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05838808; Issue ID: ALPS05839556.

CVE-2022-20111: In ion, there is a possible use after free due to incorrect error handling. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06366069; Issue ID: ALPS06366069.

CVE-2022-25795: A Memory Corruption Vulnerability in Autodesk TrueView 2022 and 2021 may lead to remote code execution through maliciously crafted DWG files.

CVE-2022-20726: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-46828: In libtirpc before 1.3.3rc1, remote attackers could exhaust the file descriptors of a process that uses libtirpc because idle TCP connections are mishandled. This can, in turn, lead to an svc_run infinite loop without accepting new connections.

CVE-2022-44698: Windows SmartScreen Security Feature Bypass Vulnerability

CVE-2021-38003: Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-22285: Improper Handling of Exceptional Conditions, Improper Check for Unusual or Exceptional Conditions vulnerability in the ABB SPIET800 and PNI800 module that allows an attacker to cause the denial of service or make the module unresponsive.

CVE-2021-25380: Improper handling of exceptional conditions in Bixby prior to version 3.0.53.02 allows attacker to execute the actions registered by the user.

CVE-2021-32066: An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. Net::IMAP does not raise an exception when StartTLS fails with an an unknown response, which might allow man-in-the-middle attackers to bypass the TLS protections by leveraging a network position between the client and the registry to block the StartTLS command, aka a "StartTLS stripping attack."

CVE-2022-35268: A denial of service vulnerability exists in the web_server hashFirst functionality of Robustel R1510 3.1.16 and 3.3.0. A specially-crafted network request can lead to denial of service. An attacker can send a sequence of requests to trigger this vulnerability.This denial of service is in the `/action/import_sdk_file/` API.

CVE-2022-32655: In Wi-Fi driver, there is a possible undefined behavior due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: GN20220705028; Issue ID: GN20220705028.

CVE-2022-32657: In Wi-Fi driver, there is a possible undefined behavior due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: GN20220705042; Issue ID: GN20220705042.

CVE-2022-32658: In Wi-Fi driver, there is a possible undefined behavior due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: GN20220705059; Issue ID: GN20220705059.

CVE-2022-32659: In Wi-Fi driver, there is a possible undefined behavior due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: GN20220705066; Issue ID: GN20220705066.

CVE-2022-41917: OpenSearch is a community-driven, open source fork of Elasticsearch and Kibana. OpenSearch allows users to specify a local file when defining text analyzers to process data for text analysis. An issue in the implementation of this feature allows certain specially crafted queries to return a response containing the first line of text from arbitrary files. The list of potentially impacted files is limited to text files with read permissions allowed in the Java Security Manager policy configuration. OpenSearch version 1.3.7 and 2.4.0 contain a fix for this issue. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-39271: Traefik (pronounced traffic) is a modern HTTP reverse proxy and load balancer that assists in deploying microservices. There is a potential vulnerability in Traefik managing HTTP/2 connections. A closing HTTP/2 server connection could hang forever because of a subsequent fatal error. This failure mode could be exploited to cause a denial of service. There has been a patch released in versions 2.8.8 and 2.9.0-rc5. There are currently no known workarounds.

CVE-2022-20748: A vulnerability in the local malware analysis process of Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on the affected device. This vulnerability is due to insufficient error handling in the local malware analysis process of an affected device. An attacker could exploit this vulnerability by sending a crafted file through the device. A successful exploit could allow the attacker to cause the local malware analysis process to crash, which could result in a DoS condition. Notes: Manual intervention may be required to recover from this situation. Malware cloud lookup and dynamic analysis will not be impacted.

CVE-2022-20854: A vulnerability in the processing of SSH connections of Cisco Firepower Management Center (FMC) and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper error handling when an SSH session fails to be established. An attacker could exploit this vulnerability by sending a high rate of crafted SSH connections to the instance. A successful exploit could allow the attacker to cause resource exhaustion, resulting in a reboot on the affected device.

# CWE-756 Missing Custom Error Page

## Description

The product does not return custom error pages to the user, possibly exposing sensitive information.

## Top 25 Examples

CVE-2022-3175: Missing Custom Error Page in GitHub repository ikus060/rdiffweb prior to 2.4.2.

# CWE-757 Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')

## Description

A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it does not select the strongest algorithm that is available to both parties.

When a security mechanism can be forced to downgrade to use a less secure algorithm, this can make it easier for attackers to compromise the product by exploiting weaker algorithm. The victim might not be aware that the less secure algorithm is being used. For example, if an attacker can force a communications channel to use cleartext instead of strongly-encrypted data, then the attacker could read the channel by sniffing, instead of going through extra effort of trying to decrypt the data using brute force techniques.

## Observed Examples

CVE-2006-4302: Attacker can select an older version of the software to exploit its vulnerabilities.

CVE-2006-4407: Improper prioritization of encryption ciphers during negotiation leads to use of a weaker cipher.

CVE-2005-2969: chain: SSL/TLS implementation disables a verification step (CWE-325) that enables a downgrade attack to a weaker protocol.

CVE-2001-1444: Telnet protocol implementation allows downgrade to weaker authentication and encryption using an Adversary-in-the-Middle AITM attack.

CVE-2002-1646: SSH server implementation allows override of configuration setting to use weaker authentication schemes. This may be a composite with CWE-642.

## Top 25 Examples

CVE-2022-36436: OSU Open Source Lab VNCAuthProxy through 1.1.1 is affected by an vncap/vnc/protocol.py VNCServerAuthenticator authentication-bypass vulnerability that could allow a malicious actor to gain unauthorized access to a VNC session or to disconnect a legitimate user from a VNC session. A remote attacker with network access to the proxy server could leverage this vulnerability to connect to VNC servers protected by the proxy server without providing any authentication credentials. Exploitation of this issue requires that the proxy server is currently accepting connections for the target VNC server.

CVE-2022-28860: An authentication downgrade in the server in Citilog 8.0 allows an attacker (in a man in the middle position between the server and its smart camera Axis M1125) to achieve HTTP access to the camera.

# CWE-758 Reliance on Undefined, Unspecified, or Implementation-Defined Behavior

## Description

The product uses an API function, data structure, or other entity in a way that relies on properties that are not always guaranteed to hold for that entity.

This can lead to resultant weaknesses when the required properties change, such as when the product is ported to a different platform or if an interaction error (CWE-435) occurs.

## Observed Examples

CVE-2006-1902: Change in C compiler behavior causes resultant buffer overflows in programs that depend on behaviors that were undefined in the C standard.

# CWE-759 Use of a One-Way Hash without a Salt

## Description

The product uses a one-way cryptographic hash against an input that should not be reversible, such as a password, but the product does not also use a salt as part of the input.

This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables.


It should be noted that, despite common perceptions, the use of a good salt with a hash does not sufficiently increase the effort for an attacker who is targeting an individual password, or who has a large amount of computing resources available, such as with cloud-based services or specialized, inexpensive hardware. Offline password cracking can still be effective if the hash function is not expensive to compute; many cryptographic functions are designed to be efficient and can be vulnerable to attacks using massive computing resources, even if the hash is cryptographically strong. The use of a salt only slightly increases the computing requirements for an attacker compared to other strategies such as adaptive hash functions. See CWE-916 for more details.

In cryptography, salt refers to some random addition of data to an input before hashing to make dictionary attacks more difficult.

## Observed Examples

CVE-2008-1526: Router does not use a salt with a hash, making it easier to crack passwords.

CVE-2006-1058: Router does not use a salt with a hash, making it easier to crack passwords.

## Top 25 Examples

CVE-2022-40295:  The application was vulnerable to an authenticated information disclosure, allowing administrators to view unsalted user passwords, which could lead to the compromise of plaintext passwords via offline attacks. 

# CWE-76 Improper Neutralization of Equivalent Special Elements

## Description

The product correctly neutralizes certain special elements, but it improperly neutralizes equivalent special elements.

The product may have a fixed list of special characters it believes is complete. However, there may be alternate encodings, or representations that also have the same meaning. For example, the product may filter out a leading slash (/) to prevent absolute path names, but does not account for a tilde (~) followed by a user name, which on some *nix systems could be expanded to an absolute pathname. Alternately, the product might filter a dangerous "-e" command-line switch when calling an external program, but it might not account for "--exec" or other switches that have the same semantics.

# CWE-760 Use of a One-Way Hash with a Predictable Salt

## Description

The product uses a one-way cryptographic hash against an input that should not be reversible, such as a password, but the product uses a predictable salt as part of the input.

This makes it easier for attackers to pre-compute the hash value using dictionary attack techniques such as rainbow tables, effectively disabling the protection that an unpredictable salt would provide.


It should be noted that, despite common perceptions, the use of a good salt with a hash does not sufficiently increase the effort for an attacker who is targeting an individual password, or who has a large amount of computing resources available, such as with cloud-based services or specialized, inexpensive hardware. Offline password cracking can still be effective if the hash function is not expensive to compute; many cryptographic functions are designed to be efficient and can be vulnerable to attacks using massive computing resources, even if the hash is cryptographically strong. The use of a salt only slightly increases the computing requirements for an attacker compared to other strategies such as adaptive hash functions. See CWE-916 for more details.

In cryptography, salt refers to some random addition of data to an input before hashing to make dictionary attacks more difficult.

## Observed Examples

CVE-2008-4905: Blogging software uses a hard-coded salt when calculating a password hash.

CVE-2002-1657: Database server uses the username for a salt when encrypting passwords, simplifying brute force attacks.

CVE-2001-0967: Server uses a constant salt when encrypting passwords, simplifying brute force attacks.

CVE-2005-0408: chain: product generates predictable MD5 hashes using a constant value combined with username, allowing authentication bypass.

## Top 25 Examples

CVE-2021-26113: A use of a one-way hash with a predictable salt vulnerability [CWE-760] in FortiWAN before 4.5.9 may allow an attacker who has previously come in possession of the password file to potentially guess passwords therein stored.

CVE-2021-38314: The Gutenberg Template Library & Redux Framework plugin <= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site’s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

# CWE-761 Free of Pointer not at Start of Buffer

## Description

The product calls free() on a pointer to a memory resource that was allocated on the heap, but the pointer is not at the start of the buffer.

This can cause the product to crash, or in some cases, modify critical program variables or execute code.


This weakness often occurs when the memory is allocated explicitly on the heap with one of the malloc() family functions and free() is called, but pointer arithmetic has caused the pointer to be in the interior or end of the buffer.

## Observed Examples

CVE-2019-11930: function "internally calls 'calloc' and returns a pointer at an index... inside the allocated buffer. This led to freeing invalid memory."

# CWE-762 Mismatched Memory Management Routines

## Description

The product attempts to return a memory resource to the system, but it calls a release function that is not compatible with the function that was originally used to allocate that resource.

This weakness can be generally described as mismatching memory management routines, such as:


  - The memory was allocated on the stack (automatically), but it was deallocated using the memory management routine free() (CWE-590), which is intended for explicitly allocated heap memory.

  - The memory was allocated explicitly using one set of memory management functions, and deallocated using a different set. For example, memory might be allocated with malloc() in C++ instead of the new operator, and then deallocated with the delete operator.

When the memory management functions are mismatched, the consequences may be as severe as code execution, memory corruption, or program crash. Consequences and ease of exploit will vary depending on the implementation of the routines and the object being managed.

# CWE-763 Release of Invalid Pointer or Reference

## Description

The product attempts to return a memory resource to the system, but it calls the wrong release function or calls the appropriate release function incorrectly.

This weakness can take several forms, such as:


  - The memory was allocated, explicitly or implicitly, via one memory management method and deallocated using a different, non-compatible function (CWE-762).

  - The function calls or memory management routines chosen are appropriate, however they are used incorrectly, such as in CWE-761.

## Observed Examples

CVE-2019-11930: function "internally calls 'calloc' and returns a pointer at an index... inside the allocated buffer. This led to freeing invalid memory."

## Top 25 Examples

CVE-2021-41073: loop_rw_iter in fs/io_uring.c in the Linux kernel 5.10 through 5.14.6 allows local users to gain privileges by using IORING_OP_PROVIDE_BUFFERS to trigger a free of a kernel buffer, as demonstrated by using /proc/<pid>/maps for exploitation.

# CWE-764 Multiple Locks of a Critical Resource

## Description

The product locks a critical resource more times than intended, leading to an unexpected state in the system.

When a product is operating in a concurrent environment and repeatedly locks a critical resource, the consequences will vary based on the type of lock, the lock's implementation, and the resource being protected. In some situations such as with semaphores, the resources are pooled and extra locking calls will reduce the size of the total available pool, possibly leading to degraded performance or a denial of service. If this can be triggered by an attacker, it will be similar to an unrestricted lock (CWE-412). In the context of a binary lock, it is likely that any duplicate locking attempts will never succeed since the lock is already held and progress may not be possible.

# CWE-765 Multiple Unlocks of a Critical Resource

## Description

The product unlocks a critical resource more times than intended, leading to an unexpected state in the system.

When the product is operating in a concurrent environment and repeatedly unlocks a critical resource, the consequences will vary based on the type of lock, the lock's implementation, and the resource being protected. In some situations such as with semaphores, the resources are pooled and extra calls to unlock will increase the count for the number of available resources, likely resulting in a crash or unpredictable behavior when the system nears capacity.

## Observed Examples

CVE-2009-0935: Attacker provides invalid address to a memory-reading function, causing a mutex to be unlocked twice

# CWE-766 Critical Data Element Declared Public

## Description

The product declares a critical variable, field, or member to be public when intended security policy requires it to be private.

This issue makes it more difficult to maintain the product, which indirectly affects security by making it more difficult or time-consuming to find and/or fix vulnerabilities. It also might make it easier to introduce vulnerabilities.

## Observed Examples

CVE-2010-3860: variables declared public allow remote read of system properties such as user name and home directory.

# CWE-767 Access to Critical Private Variable via Public Method

## Description

The product defines a public method that reads or modifies a private variable.

If an attacker modifies the variable to contain unexpected values, this could violate assumptions from other parts of the code. Additionally, if an attacker can read the private variable, it may expose sensitive information or make it easier to launch further attacks.

# CWE-768 Incorrect Short Circuit Evaluation

## Description

The product contains a conditional statement with multiple logical expressions in which one of the non-leading expressions may produce side effects. This may lead to an unexpected state in the program after the execution of the conditional, because short-circuiting logic may prevent the side effects from occurring.

Usage of short circuit evaluation, though well-defined in the C standard, may alter control flow in a way that introduces logic errors that are difficult to detect, possibly causing errors later during the product's execution. If an attacker can discover such an inconsistency, it may be exploitable to gain arbitrary control over a system.


If the first condition of an "or" statement is assumed to be true under normal circumstances, or if the first condition of an "and" statement is assumed to be false, then any subsequent conditional may contain its own logic errors that are not detected during code review or testing.


Finally, the usage of short circuit evaluation may decrease the maintainability of the code.

# CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')

## Description

The product constructs all or part of a command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended command when it is sent to a downstream component.

Many protocols and products have their own custom command language. While OS or shell command strings are frequently discovered and targeted, developers may not realize that these other command languages might also be vulnerable to attacks.

## Observed Examples

CVE-2022-1509: injection of sed script syntax ("sed injection")

CVE-2024-5184: API service using a large generative AI model allows direct prompt injection to leak hard-coded system prompts or execute other prompts.

CVE-2020-11698: anti-spam product allows injection of SNMP commands into confiuration file

CVE-2019-12921: image program allows injection of commands in "Magick Vector Graphics (MVG)" language.

CVE-2022-36069: Python-based dependency management tool avoids OS command injection when generating Git commands but allows injection of optional arguments with input beginning with a dash (CWE-88), potentially allowing for code execution.

CVE-1999-0067: Canonical example of OS command injection. CGI program does not neutralize "|" metacharacter when invoking a phonebook program.

CVE-2020-9054: Chain: improper input validation (CWE-20) in username parameter, leading to OS command injection (CWE-78), as exploited in the wild per CISA KEV.

CVE-2021-41282: injection of sed script syntax ("sed injection")

CVE-2019-13398: injection of sed script syntax ("sed injection")

## Top 25 Examples

CVE-2021-31573: In Config Manager, there is a possible command injection due to improper input validation. This could lead to remote escalation of privilege from a proximal attacker with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: A20210009; Issue ID: OSBNB00123234.

CVE-2021-31574: In Config Manager, there is a possible command injection due to improper input validation. This could lead to remote escalation of privilege from a proximal attacker with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: A20210009; Issue ID: OSBNB00123234.

CVE-2021-31575: In Config Manager, there is a possible command injection due to improper input validation. This could lead to remote escalation of privilege from a proximal attacker with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: A20210009; Issue ID: OSBNB00123234.

CVE-2022-26151: Citrix XenMobile Server 10.12 through RP11, 10.13 through RP7, and 10.14 through RP4 allows Command Injection.

CVE-2022-26536: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/setFixTools.

CVE-2022-26995: Arris TR3300 v1.0.13 was discovered to contain a command injection vulnerability in the pptp (wan_pptp.html) function via the pptp_fix_ip, pptp_fix_mask, pptp_fix_gw, and wan_dns1_stat parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26996: Arris TR3300 v1.0.13 was discovered to contain a command injection vulnerability in the pppoe function via the pppoe_username, pppoe_passwd, and pppoe_servicename parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26997: Arris TR3300 v1.0.13 was discovered to contain a command injection vulnerability in the upnp function via the upnp_ttl parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26998: Arris TR3300 v1.0.13 was discovered to contain a command injection vulnerability in the wps setting function via the wps_enrolee_pin parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26999: Arris TR3300 v1.0.13 was discovered to contain a command injection vulnerability in the static ip settings function via the wan_ip_stat, wan_mask_stat, wan_gw_stat, and wan_dns1_stat parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27000: Arris TR3300 v1.0.13 was discovered to contain a command injection vulnerability in the time and time zone function via the h_primary_ntp_server, h_backup_ntp_server, and h_time_zone parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27001: Arris TR3300 v1.0.13 were discovered to contain a command injection vulnerability in the dhcp function via the hostname parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27002: Arris TR3300 v1.0.13 were discovered to contain a command injection vulnerability in the ddns function via the ddns_name, ddns_pwd, h_ddns?ddns_host parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27076: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/delAd.

CVE-2022-27077: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /cgi-bin/uploadWeiXinPic.

CVE-2022-27078: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/setAdInfoDetail.

CVE-2022-27079: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/setPicListItem.

CVE-2022-27080: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/setWorkmode.

CVE-2022-27081: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/SetLanInfo.

CVE-2022-27082: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/SetInternetLanInfo.

CVE-2022-27083: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /cgi-bin/uploadAccessCodePic.

CVE-2022-28496: TOTOLink outdoor CPE CP900 V6.3c.566_B20171026 discovered to contain a command injection vulnerability in the setPasswordCfg function via the adminuser and adminpassparameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-28497: TOTOLink outdoor CPE CP900 V6.3c.566_B20171026 is discovered to contain a command injection vulnerability in the mtd_write_bootloader function via the filename parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-30321: go-getter up to 1.5.11 and 2.0.2 allowed arbitrary host access via go-getter path traversal, symlink processing, and command injection flaws. Fixed in 1.6.1 and 2.1.0.

CVE-2022-40765: A vulnerability in the Edge Gateway component of Mitel MiVoice Connect through 19.3 (22.22.6100.0) could allow an authenticated attacker with internal network access to conduct a command-injection attack, due to insufficient restriction of URL parameters.

CVE-2021-22899: A command injection vulnerability exists in Pulse Connect Secure before 9.1R11.4 allows a remote authenticated attacker to perform remote code execution via Windows Resource Profiles Feature

CVE-2022-22688: Improper neutralization of special elements used in a command ('Command Injection') vulnerability in File service functionality in Synology DiskStation Manager (DSM) before 6.2.4-25556-2 allows remote authenticated users to execute arbitrary commands via unspecified vectors.

CVE-2022-2323: Improper neutralization of special elements used in a user input allows an authenticated malicious user to perform remote code execution in the host system. This vulnerability impacts SonicWall Switch 1.1.1.0-2s and earlier versions

CVE-2022-46421: Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in Apache Software Foundation Apache Airflow Hive Provider.This issue affects Apache Airflow Hive Provider: before 5.0.0. 

CVE-2022-39265: MyBB is a free and open source forum software. The _Mail Settings_ ? Additional Parameters for PHP's mail() function mail_parameters setting value, in connection with the configured mail program's options and behavior, may allow access to sensitive information and Remote Code Execution (RCE). The vulnerable module requires Admin CP access with the `_Can manage settings?_` permission and may depend on configured file permissions. MyBB 1.8.31 resolves this issue with the commit `0cd318136a`. Users are advised to upgrade. There are no known workarounds for this vulnerability.

CVE-2022-4009: In affected versions of Octopus Deploy it is possible for a user to introduce code via offline package creation

CVE-2021-40043: The laser command injection vulnerability exists on AIS-BW80H-00 versions earlier than AIS-BW80H-00 9.0.3.4(H100SP13C00). The devices cannot effectively defend against external malicious interference. Attackers need the device to be visually exploitable and successful triggering of this vulnerability could execute voice commands on the device.

CVE-2021-4304: A vulnerability was found in eprintsug ulcc-core. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file cgi/toolbox/toolbox. The manipulation of the argument password leads to command injection. The attack can be launched remotely. The patch is named 811edaae81eb044891594f00062a828f51b22cb1. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-217447.

CVE-2021-4329: A vulnerability, which was classified as critical, has been found in json-logic-js 2.0.0. Affected by this issue is some unknown functionality of the file logic.js. The manipulation leads to command injection. Upgrading to version 2.0.1 is able to address this issue. The patch is identified as c1dd82f5b15d8a553bb7a0cfa841ab8a11a9c227. It is recommended to upgrade the affected component. VDB-222266 is the identifier assigned to this vulnerability.

CVE-2022-21941: All versions of iSTAR Ultra prior to version 6.8.9.CU01 are vulnerable to a command injection that could allow an unauthenticated user root access to the system.

CVE-2022-24144: Tenda AX3 v16.03.12.10_CN was discovered to contain a command injection vulnerability in the function WanParameterSetting. This vulnerability allows attackers to execute arbitrary commands via the gateway, dns1, and dns2 parameters.

CVE-2022-24148: Tenda AX3 v16.03.12.10_CN was discovered to contain a command injection vulnerability in the function mDMZSetCfg. This vulnerability allows attackers to execute arbitrary commands via the dmzIp parameter.

CVE-2022-24150: Tenda AX3 v16.03.12.10_CN was discovered to contain a command injection vulnerability in the function formSetSafeWanWebMan. This vulnerability allows attackers to execute arbitrary commands via the remoteIp parameter.

CVE-2022-24165: Tenda routers G1 and G3 v15.11.0.17(9502)_CN were discovered to contain a command injection vulnerability in the function formSetQvlanList. This vulnerability allows attackers to execute arbitrary commands via the qvlanIP parameter.

CVE-2022-24167: Tenda routers G1 and G3 v15.11.0.17(9502)_CN were discovered to contain a command injection vulnerability in the function formSetDMZ. This vulnerability allows attackers to execute arbitrary commands via the dmzHost1 parameter.

CVE-2022-24168: Tenda routers G1 and G3 v15.11.0.17(9502)_CN were discovered to contain a command injection vulnerability in the function formSetIpGroup. This vulnerability allows attackers to execute arbitrary commands via the IPGroupStartIP and IPGroupEndIP parameters.

CVE-2022-24170: Tenda routers G1 and G3 v15.11.0.17(9502)_CN were discovered to contain a command injection vulnerability in the function formSetIpSecTunnel. This vulnerability allows attackers to execute arbitrary commands via the IPsecLocalNet and IPsecRemoteNet parameters.

CVE-2022-24171: Tenda routers G1 and G3 v15.11.0.17(9502)_CN were discovered to contain a command injection vulnerability in the function formSetPppoeServer. This vulnerability allows attackers to execute arbitrary commands via the pppoeServerIP, pppoeServerStartIP, and pppoeServerEndIP parameters.

CVE-2022-25130: A command injection vulnerability in the function updateWifiInfo of TOTOLINK Technology routers T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 and T10 V2_Firmware V4.1.8cu.5207_B20210320 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25131: A command injection vulnerability in the function recvSlaveCloudCheckStatus of TOTOLINK Technology routers T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 and T10 V2_Firmware V4.1.8cu.5207_B20210320 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25132: A command injection vulnerability in the function meshSlaveDlfw of TOTOLINK Technology router T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25133: A command injection vulnerability in the function isAssocPriDevice of TOTOLINK Technology router T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25134: A command injection vulnerability in the function setUpgradeFW of TOTOLINK Technology router T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25135: A command injection vulnerability in the function recv_mesh_info_sync of TOTOLINK Technology router T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25136: A command injection vulnerability in the function meshSlaveUpdate of TOTOLINK Technology routers T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 and T10 V2_Firmware V4.1.8cu.5207_B20210320 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-25137: A command injection vulnerability in the function recvSlaveUpgstatus of TOTOLINK Technology routers T6 V3_Firmware T6_V3_V4.1.5cu.748_B20211015 and T10 V2_Firmware V4.1.8cu.5207_B20210320 allows attackers to execute arbitrary commands via a crafted MQTT packet.

CVE-2022-26186: TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via the exportOvpn interface at cstecgi.cgi.

CVE-2022-26187: TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via the pingCheck function.

CVE-2022-26188: TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via /setting/NTPSyncWithHost.

CVE-2022-26189: TOTOLINK N600R V4.3.0cu.7570_B20200620 was discovered to contain a command injection vulnerability via the langType parameter in the login interface.

CVE-2022-26415: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all versions of 12.1.x, when running in Appliance mode, an authenticated user assigned the Administrator role may be able to bypass Appliance mode restrictions, utilizing an undisclosed iControl REST endpoint. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-27588: We have already fixed this vulnerability in the following versions of QVR: QVR 5.1.6 build 20220401 and later

CVE-2022-27806: On all versions of 16.1.x, 15.1.x, 14.1.x, 13.1.x, 12.1.x, and 11.6.x of F5 BIG-IP Advanced WAF, ASM, and ASM, and F5 BIG-IP Guided Configuration (GC) all versions prior to 9.0, when running in Appliance mode, an authenticated attacker assigned the Administrator role may be able to bypass Appliance mode restrictions, utilizing command injection vulnerabilities in undisclosed URIs in F5 BIG-IP Guided Configuration. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-28220: Apache James prior to release 3.6.3 and 3.7.1 is vulnerable to a buffering attack relying on the use of the STARTTLS command. Fix of CVE-2021-38542, which solved similar problem fron Apache James 3.6.1, is subject to a parser differential and do not take into account concurrent requests.

CVE-2022-3086: Cradlepoint IBR600 NCOS versions 6.5.0.160bc2e and prior are vulnerable to shell escape, which enables local attackers with non-superuser credentials to gain full, unrestrictive shell access which may allow an attacker to execute arbitrary code. 

CVE-2022-32262: A vulnerability has been identified in SINEMA Remote Connect Server (All versions < V3.1). The affected application contains a file upload server that is vulnerable to command injection. An attacker could use this to achieve arbitrary code execution.

CVE-2022-32449: TOTOLINK EX300_V2 V4.0.3c.7484 was discovered to contain a command injection vulnerability via the langType parameter in the setLanguageCfg function. This vulnerability is exploitable via a crafted MQTT data packet.

CVE-2022-34592: Wavlink WL-WN575A3 RPT75A3.V4300.201217 was discovered to contain a command injection vulnerability via the function obtw. This vulnerability allows attackers to execute arbitrary commands via a crafted POST request.

CVE-2022-34660: A vulnerability has been identified in Teamcenter V12.4 (All versions < V12.4.0.15), Teamcenter V13.0 (All versions < V13.0.0.10), Teamcenter V13.1 (All versions < V13.1.0.10), Teamcenter V13.2 (All versions < V13.2.0.9), Teamcenter V13.3 (All versions < V13.3.0.5), Teamcenter V14.0 (All versions < V14.0.0.2). File Server Cache service in Teamcenter consist of a functionality that is vulnerable to command injection. This could potentially allow an attacker to perform remote code execution.

CVE-2022-34974: D-Link DIR810LA1_FW102B22 was discovered to contain a command injection vulnerability via the Ping_addr function.

CVE-2022-36523: D-Link Go-RT-AC750 GORTAC750_revA_v101b03 & GO-RT-AC750_revB_FWv200b02 is vulnerable to command injection via /htdocs/upnpinc/gena.php.

CVE-2022-36553: Hytec Inter HWL-2511-SS v1.05 and below was discovered to contain a command injection vulnerability via the component /www/cgi-bin/popen.cgi.

CVE-2022-36554: A command injection vulnerability in the CLI (Command Line Interface) implementation of Hytec Inter HWL-2511-SS v1.05 and below allows attackers to execute arbitrary commands with root privileges.

CVE-2022-36556: Seiko SkyBridge MB-A100/A110 v4.2.0 and below was discovered to contain a command injection vulnerability via the ipAddress parameter at 07system08execute_ping_01.

CVE-2022-36559: Seiko SkyBridge MB-A200 v01.00.04 and below was discovered to contain a command injection vulnerability via the Ping parameter at ping_exec.cgi.

CVE-2022-36786: DLINK - DSL-224 Post-auth RCE. DLINK router version 3.0.8 has an interface where you can configure NTP servers (Network Time Protocol) via jsonrpc API. It is possible to inject a command through this interface that will run with ROOT permissions on the router. 

CVE-2022-40021: QVidium Technologies Amino A140 (prior to firmware version 1.0.0-283) was discovered to contain a command injection vulnerability.

CVE-2022-40022: Microchip Technology (Microsemi) SyncServer S650 was discovered to contain a command injection vulnerability.

CVE-2022-40100: Tenda i9 v1.0.0.8(3828) was discovered to contain a command injection vulnerability via the FormexeCommand function.

CVE-2022-40770: Zoho ManageEngine ServiceDesk Plus versions 13010 and prior are vulnerable to authenticated command injection. This can be exploited by high-privileged users.

CVE-2022-40881: SolarView Compact 6.00 was discovered to contain a command injection vulnerability via network_test.php

CVE-2022-41617: In versions 16.1.x before 16.1.3.1, 15.1.x before 15.1.6.1, 14.1.x before 14.1.5.1, and 13.1.x before 13.1.5.1, When the Advanced WAF / ASM module is provisioned, an authenticated remote code execution vulnerability exists in the BIG-IP iControl REST interface.

CVE-2022-41800:  In all versions of BIG-IP, when running in Appliance mode, an authenticated user assigned the Administrator role may be able to bypass Appliance mode restrictions, utilizing an undisclosed iControl REST endpoint. A successful exploit can allow the attacker to cross a security boundary. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated. 

CVE-2022-42156: D-Link COVR 1200,1203 v1.08 was discovered to contain a command injection vulnerability via the tomography_ping_number parameter at function SetNetworkTomographySettings.

CVE-2022-42160: D-Link COVR 1200,1202,1203 v1.08 was discovered to contain a command injection vulnerability via the system_time_timezone parameter at function SetNTPServerSettings.

CVE-2022-42161: D-Link COVR 1200,1202,1203 v1.08 was discovered to contain a command injection vulnerability via the /SetTriggerWPS/PIN parameter at function SetTriggerWPS.

CVE-2022-42897: Array Networks AG/vxAG with ArrayOS AG before 9.4.0.469 allows unauthenticated command injection that leads to privilege escalation and control of the system. NOTE: ArrayOS AG 10.x is unaffected.

CVE-2022-43109: D-Link DIR-823G v1.0.2 was found to contain a command injection vulnerability in the function SetNetworkTomographySettings. This vulnerability allows attackers to execute arbitrary commands via a crafted packet.

CVE-2022-43367: IP-COM EW9 V15.11.0.14(9732) was discovered to contain a command injection vulnerability in the formSetDebugCfg function.

CVE-2022-43781: There is a command injection vulnerability using environment variables in Bitbucket Server and Data Center. An attacker with permission to control their username can exploit this issue to execute arbitrary code on the system. This vulnerability can be unauthenticated if the Bitbucket Server and Data Center instance has enabled “Allow public signup”.

CVE-2022-44621: Diagnosis Controller miss parameter validation, so user may attacked by command injection via HTTP Request.

CVE-2022-44832: D-Link DIR-3040 device with firmware 120B03 was discovered to contain a command injection vulnerability via the SetTriggerLEDBlink function.

CVE-2022-45094: A vulnerability has been identified in SINEC INS (All versions < V1.0 SP2 Update 1). An authenticated remote attacker with access to the Web Based Management (443/tcp) of the affected product, could potentially inject commands into the dhcpd configuration of the affected product. An attacker might leverage this to trigger remote code execution on the affected component.

CVE-2022-45095:  Dell PowerScale OneFS, 8.2.x-9.4.x, contain a command injection vulnerability. An authenticated user having access local shell and having the privilege to gather logs from the cluster could potentially exploit this vulnerability, leading to execute arbitrary commands, denial of service, information disclosure, and data deletion. 

CVE-2022-45462: Alarm instance management has command injection when there is a specific command configured. It is only for logged-in users. We recommend you upgrade to version 2.0.6 or higher

CVE-2022-45796: Command injection vulnerability in nw_interface.html in SHARP multifunction printers (MFPs)'s Digital Full-color Multifunctional System 202 or earlier, 120 or earlier, 600 or earlier, 121 or earlier, 500 or earlier, 402 or earlier, 790 or earlier, and Digital Multifunctional System (Monochrome) 200 or earlier, 211 or earlier, 102 or earlier, 453 or earlier, 400 or earlier, 202 or earlier, 602 or earlier, 500 or earlier, 401 or earlier allows remote attackers to execute arbitrary commands via unspecified vectors.

CVE-2022-4616: The webserver in Delta DX-3021 versions prior to 1.24 is vulnerable to command injection through the network diagnosis page. This vulnerability could allow a remote unauthenticated user to add files, delete files, and change file permissions. 

CVE-2022-46404: A command injection vulnerability has been identified in Atos Unify OpenScape 4000 Assistant and Unify OpenScape 4000 Manager (8 before R2.22.18, 10 before 0.28.13, and 10 R1 before R1.34.4) that may allow an unauthenticated attacker to upload arbitrary files and achieve administrative access to the system.

CVE-2022-46641: D-Link DIR-846 A1_FW100A43 was discovered to contain a command injection vulnerability via the lan(0)_dhcps_staticlist parameter in the SetIpMacBindSettings function.

CVE-2022-46642: D-Link DIR-846 A1_FW100A43 was discovered to contain a command injection vulnerability via the auto_upgrade_hour parameter in the SetAutoUpgradeInfo function.

CVE-2022-48255: There is a system command injection vulnerability in BiSheng-WNM FW 3.0.0.325. A Huawei printer has a system command injection vulnerability. Successful exploitation could lead to remote code execution.

CVE-2022-48259: There is a system command injection vulnerability in BiSheng-WNM FW 3.0.0.325. Successful exploitation could allow attackers to gain higher privileges.

CVE-2022-28618: A command injection security vulnerability has been identified in HPE Nimble Storage Hybrid Flash Arrays, HPE Nimble Storage All Flash Arrays and HPE Nimble Storage Secondary Flash Arrays that could allow an attacker to execute arbitrary commands on a Nimble appliance. HPE has made the following software updates to resolve the vulnerability in HPE Nimble Storage: 5.0.10.100 or later, 5.2.1.0 or later, 6.0.0.100 or later.

CVE-2022-31702: vRealize Network Insight (vRNI) contains a command injection vulnerability present in the vRNI REST API. A malicious actor with network access to the vRNI REST API can execute commands without authentication.

CVE-2022-31874: ASUS RT-N53 3.0.0.4.376.3754 has a command injection vulnerability in the SystemCmd parameter of the apply.cgi interface.

CVE-2022-45063: xterm before 375 allows code execution via font ops, e.g., because an OSC 50 response may have Ctrl-g and therefore lead to command execution within the vi line-editing mode of Zsh. NOTE: font ops are not allowed in the xterm default configurations of some Linux distributions.

# CWE-770 Allocation of Resources Without Limits or Throttling

## Description

The product allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated, in violation of the intended security policy for that actor.

Code frequently has to work with limited resources, so programmers must be careful to ensure that resources are not consumed too quickly, or too easily. Without use of quotas, resource limits, or other protection mechanisms, it can be easy for an attacker to consume many resources by rapidly making many requests, or causing larger resources to be used than is needed. When too many resources are allocated, or if a single resource is too large, then it can prevent the code from working correctly, possibly leading to a denial of service.

## Observed Examples

CVE-2022-21668: Chain: Python library does not limit the resources used to process images that specify a very large number of bands (CWE-1284), leading to excessive memory consumption (CWE-789) or an integer overflow (CWE-190).

CVE-2009-4017: Language interpreter does not restrict the number of temporary files being created when handling a MIME request with a large number of parts..

CVE-2009-2726: Driver does not use a maximum width when invoking sscanf style functions, causing stack consumption.

CVE-2009-2540: Large integer value for a length property in an object causes a large amount of memory allocation.

CVE-2009-2054: Product allows exhaustion of file descriptors when processing a large number of TCP packets.

CVE-2008-5180: Communication product allows memory consumption with a large number of SIP requests, which cause many sessions to be created.

CVE-2008-1700: Product allows attackers to cause a denial of service via a large number of directives, each of which opens a separate window.

CVE-2005-4650: CMS does not restrict the number of searches that can occur simultaneously, leading to resource exhaustion.

CVE-2020-15100: web application scanner attempts to read an excessively large file created by a user, causing process termination

CVE-2020-7218: Go-based workload orchestrator does not limit resource usage with unauthenticated connections, allowing a DoS by flooding the service

## Top 25 Examples

CVE-2021-44988: Jerryscript v3.0.0 and below was discovered to contain a stack overflow via ecma_find_named_property in ecma-helpers.c.

CVE-2021-46050: A Stack Overflow vulnerability exists in Binaryen 103 via the printf_common function.

CVE-2022-29503: A memory corruption vulnerability exists in the libpthread linuxthreads functionality of uClibC 0.9.33.2 and uClibC-ng 1.0.40. Thread allocation can lead to memory corruption. An attacker can create threads to trigger this vulnerability.

CVE-2022-35107: SWFTools commit 772e55a2 was discovered to contain a stack overflow via vfprintf at /stdio-common/vfprintf.c.

CVE-2022-35111: SWFTools commit 772e55a2 was discovered to contain a stack overflow via __sanitizer::StackDepotNode::hash(__sanitizer::StackTrace const&) at /sanitizer_common/sanitizer_stackdepot.cpp.

CVE-2022-21716: Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 22.2.0, Twisted SSH client and server implement is able to accept an infinite amount of data for the peer's SSH version identifier. This ends up with a buffer using all the available memory. The attach is a simple as `nc -rv localhost 22 < /dev/zero`. A patch is available in version 22.2.0. There are currently no known workarounds.

CVE-2022-41288: A vulnerability has been identified in JT2Go (All versions < V14.1.0.6), Teamcenter Visualization V13.2 (All versions < V13.2.0.12), Teamcenter Visualization V13.3 (All versions < V13.3.0.8), Teamcenter Visualization V14.0 (All versions < V14.0.0.4), Teamcenter Visualization V14.1 (All versions < V14.1.0.6). The CGM_NIST_Loader.dll contains stack exhaustion vulnerability when parsing a CGM file. An attacker could leverage this vulnerability to crash the application causing denial of service condition.

CVE-2022-32559: An issue was discovered in Couchbase Server before 7.0.4. Random HTTP requests lead to leaked metrics.

CVE-2022-3273: Allocation of Resources Without Limits or Throttling in GitHub repository ikus060/rdiffweb prior to 2.5.0a4.

CVE-2021-3669: A flaw was found in the Linux kernel. Measuring usage of the shared memory does not scale with large shared memory segment counts which could lead to resource exhaustion and DoS.

CVE-2021-3759: A memory overflow vulnerability was found in the Linux kernel’s ipc functionality of the memcg subsystem, in the way a user calls the semget function multiple times, creating semaphores. This flaw allows a local user to starve the resources, causing a denial of service. The highest threat from this vulnerability is to system availability.

CVE-2022-1708: A vulnerability was found in CRI-O that causes memory or disk space exhaustion on the node for anyone with access to the Kube API. The ExecSync request runs commands in a container and logs the output of the command. This output is then read by CRI-O after command execution, and it is read in a manner where the entire file corresponding to the output of the command is read in. Thus, if the output of the command is large it is possible to exhaust the memory or the disk space of the node when CRI-O reads the output of the command. The highest threat from this vulnerability is system availability.

CVE-2022-20143: In addAutomaticZenRule of ZenModeHelper.java, there is a possible permanent denial of service due to resource exhaustion. This could lead to local denial of service with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-220735360

CVE-2022-20478: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-241764135

CVE-2022-20479: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-241764340

CVE-2022-20480: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-241764350

CVE-2022-20484: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-242702851

CVE-2022-20485: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-242702935

CVE-2022-20486: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-242703118

CVE-2022-20487: In NotificationChannel of NotificationChannel.java, there is a possible failure to persist permissions settings due to resource exhaustion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-242703202

CVE-2022-21952: A Missing Authentication for Critical Function vulnerability in spacewalk-java of SUSE Manager Server 4.1, SUSE Manager Server 4.2 allows remote attackers to easily exhaust available disk resources leading to DoS. This issue affects: SUSE Manager Server 4.1 spacewalk-java versions prior to 4.1.46. SUSE Manager Server 4.2 spacewalk-java versions prior to 4.2.37. 

CVE-2022-23487: js-libp2p is the official javascript Implementation of libp2p networking stack. Versions older than `v0.38.0` of js-libp2p are vulnerable to targeted resource exhaustion attacks. These attacks target libp2p’s connection, stream, peer, and memory management. An attacker can cause the allocation of large amounts of memory, ultimately leading to the process getting killed by the host’s operating system. While a connection manager tasked with keeping the number of connections within manageable limits has been part of js-libp2p, this component was designed to handle the regular churn of peers, not a targeted resource exhaustion attack. Users are advised to update their js-libp2p dependency to `v0.38.0` or greater. There are no known workarounds for this vulnerability.

CVE-2022-23492: go-libp2p is the offical libp2p implementation in the Go programming language. Version `0.18.0` and older of go-libp2p are vulnerable to targeted resource exhaustion attacks. These attacks target libp2p’s connection, stream, peer, and memory management. An attacker can cause the allocation of large amounts of memory, ultimately leading to the process getting killed by the host’s operating system. While a connection manager tasked with keeping the number of connections within manageable limits has been part of go-libp2p, this component was designed to handle the regular churn of peers, not a targeted resource exhaustion attack. Users are advised to upgrade their version of go-libp2p to version `0.18.1` or newer. Users unable to upgrade may consult the denial of service (dos) mitigation page for more information on how to incorporate mitigation strategies, monitor your application, and respond to attacks.

CVE-2022-23913: In Apache ActiveMQ Artemis prior to 2.20.0 or 2.19.1, an attacker could partially disrupt availability (DoS) through uncontrolled resource consumption of memory.

CVE-2022-2406: The legacy Slack import feature in Mattermost version 6.7.0 and earlier fails to properly limit the sizes of imported files, which allows an authenticated attacker to crash the server by importing large files via the Slack import REST API.

CVE-2022-28871: A Denial-of-Service (DoS) vulnerability was discovered in F-Secure Atlant whereby the fsicapd component used in certain F-Secure products while scanning larger packages/fuzzed files consume too much memory eventually can crash the scanning engine. The exploit can be triggered remotely by an attacker.

CVE-2022-31075: KubeEdge is an open source system for extending native containerized application orchestration capabilities to hosts at Edge. Prior to versions 1.11.1, 1.10.2, and 1.9.4, EdgeCore may be susceptible to a DoS attack on CloudHub if an attacker was to send a well-crafted HTTP request to `/edge.crt`. If an attacker can send a well-crafted HTTP request to CloudHub, and that request has a very large body, that request can crash the HTTP service through a memory exhaustion vector. The request body is being read into memory, and a body that is larger than the available memory can lead to a successful attack. Because the request would have to make it through authorization, only authorized users may perform this attack. The consequence of the exhaustion is that CloudHub will be in denial of service. KubeEdge is affected only when users enable the CloudHub module in the file `cloudcore.yaml`. This bug has been fixed in Kubeedge 1.11.1, 1.10.2, and 1.9.4. As a workaround, disable the CloudHub switch in the config file `cloudcore.yaml`.

CVE-2022-31078: KubeEdge is an open source system for extending native containerized application orchestration capabilities to hosts at Edge. Prior to versions 1.11.1, 1.10.2, and 1.9.4, the CloudCore Router does not impose a limit on the size of responses to requests made by the REST handler. An attacker could use this weakness to make a request that will return an HTTP response with a large body and cause DoS of CloudCore. In the HTTP Handler API, the rest handler makes a request to a pre-specified handle. The handle will return an HTTP response that is then read into memory. The consequence of the exhaustion is that CloudCore will be in a denial of service. Only an authenticated user of the cloud can make an attack. It will be affected only when users enable `router` module in the config file `cloudcore.yaml`. This bug has been fixed in Kubeedge 1.11.1, 1.10.2, and 1.9.4. As a workaround, disable the router switch in the config file `cloudcore.yaml`.

CVE-2022-31079: KubeEdge is an open source system for extending native containerized application orchestration capabilities to hosts at Edge. Prior to versions 1.11.1, 1.10.2, and 1.9.4, the Cloud Stream server and the Edge Stream server reads the entire message into memory without imposing a limit on the size of this message. An attacker can exploit this by sending a large message to exhaust memory and cause a DoS. The Cloud Stream server and the Edge Stream server are under DoS attack in this case. The consequence of the exhaustion is that the CloudCore and EdgeCore will be in a denial of service. Only an authenticated user can cause this issue. It will be affected only when users enable `cloudStream` module in the config file `cloudcore.yaml` and enable `edgeStream` module in the config file `edgecore.yaml`. This bug has been fixed in Kubeedge 1.11.1, 1.10.2, and 1.9.4. As a workaround, disable cloudStream module in the config file `cloudcore.yaml` and disable edgeStream module in the config file `edgecore.yaml`.

CVE-2022-3147: Mattermost version 7.0.x and earlier fails to sufficiently limit the in-memory sizes of concurrently uploaded JPEG images, which allows authenticated users to cause resource exhaustion on specific system configurations, resulting in server-side Denial of Service.

CVE-2022-33749: XAPI open file limit DoS It is possible for an unauthenticated client on the network to cause XAPI to hit its file-descriptor limit. This causes XAPI to be unable to accept new requests for other (trusted) clients, and blocks XAPI from carrying out any tasks that require the opening of file descriptors.

CVE-2022-3423: Allocation of Resources Without Limits or Throttling in GitHub repository nocodb/nocodb prior to 0.92.0. 

CVE-2022-35915: OpenZeppelin Contracts is a library for secure smart contract development. The target contract of an EIP-165 `supportsInterface` query can cause unbounded gas consumption by returning a lot of data, while it is generally assumed that this operation has a bounded cost. The issue has been fixed in v4.7.2. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-41932: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. It's possible to make XWiki create many new schemas and fill them with tables just by using a crafted user identifier in the login form. This may lead to degraded database performance. The problem has been patched in XWiki 13.10.8, 14.6RC1 and 14.4.2. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-2134: Allocation of Resources Without Limits or Throttling in GitHub repository inventree/inventree prior to 0.8.0.

CVE-2022-43686: In Concrete CMS (formerly concrete5) below 8.5.10 and between 9.0.0 and 9.1.2, the authTypeConcreteCookieMap table can be filled up causing a denial of service (high load).

CVE-2022-41725: A denial of service is possible from excessive resource consumption in net/http and mime/multipart. Multipart form parsing with mime/multipart.Reader.ReadForm can consume largely unlimited amounts of memory and disk files. This also affects form parsing in the net/http package with the Request methods FormFile, FormValue, ParseMultipartForm, and PostFormValue. ReadForm takes a maxMemory parameter, and is documented as storing "up to maxMemory bytes +10MB (reserved for non-file parts) in memory". File parts which cannot be stored in memory are stored on disk in temporary files. The unconfigurable 10MB reserved for non-file parts is excessively large and can potentially open a denial of service vector on its own. However, ReadForm did not properly account for all memory consumed by a parsed form, such as map entry overhead, part names, and MIME headers, permitting a maliciously crafted form to consume well over 10MB. In addition, ReadForm contained no limit on the number of disk files created, permitting a relatively small request body to create a large number of disk temporary files. With fix, ReadForm now properly accounts for various forms of memory overhead, and should now stay within its documented limit of 10MB + maxMemory bytes of memory consumption. Users should still be aware that this limit is high and may still be hazardous. In addition, ReadForm now creates at most one on-disk temporary file, combining multiple form parts into a single temporary file. The mime/multipart.File interface type's documentation states, "If stored on disk, the File's underlying concrete type will be an *os.File.". This is no longer the case when a form contains more than one file part, due to this coalescing of parts into a single file. The previous behavior of using distinct files for each form part may be reenabled with the environment variable GODEBUG=multipartfiles=distinct. Users should be aware that multipart.ReadForm and the http.Request methods that call it do not limit the amount of disk consumed by temporary files. Callers can limit the size of form data with http.MaxBytesReader.

# CWE-771 Missing Reference to Active Allocated Resource

## Description

The product does not properly maintain a reference to a resource that has been allocated, which prevents the resource from being reclaimed.

This does not necessarily apply in languages or frameworks that automatically perform garbage collection, since the removal of all references may act as a signal that the resource is ready to be reclaimed.

# CWE-772 Missing Release of Resource after Effective Lifetime

## Description

The product does not release a resource after its effective lifetime has ended, i.e., after the resource is no longer needed.

When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release. Frequently-affected resources include memory, CPU, disk space, power or battery, etc.

## Observed Examples

CVE-2007-0897: Chain: anti-virus product encounters a malformed file but returns from a function without closing a file descriptor (CWE-775) leading to file descriptor consumption (CWE-400) and failed scans.

CVE-2001-0830: Sockets not properly closed when attacker repeatedly connects and disconnects from server.

CVE-1999-1127: Does not shut down named pipe connections if malformed data is sent.

CVE-2009-2858: Chain: memory leak (CWE-404) leads to resource exhaustion.

CVE-2009-2054: Product allows exhaustion of file descriptors when processing a large number of TCP packets.

CVE-2008-2122: Port scan triggers CPU consumption with processes that attempt to read data from closed sockets.

CVE-2007-4103: Product allows resource exhaustion via a large number of calls that do not complete a 3-way handshake.

CVE-2002-1372: Chain: Return values of file/socket operations are not checked (CWE-252), allowing resultant consumption of file descriptors (CWE-772).

## Top 25 Examples

CVE-2022-31222: Dell BIOS versions contain a Missing Release of Resource after Effective Lifetime vulnerability. A local authenticated administrator user could potentially exploit this vulnerability by consuming excess memory in order to cause the application to crash.

CVE-2022-41952: Synapse before 1.52.0 with URL preview functionality enabled will attempt to generate URL previews for media stream URLs without properly limiting connection time. Connections will only be terminated after `max_spider_size` (default: 10M) bytes have been downloaded, which can in some cases lead to long-lived connections towards the streaming media server (for instance, Icecast). This can cause excessive traffic and connections toward such servers if their stream URL is, for example, posted to a large room with many Synapse instances with URL preview enabled. Version 1.52.0 implements a timeout mechanism which will terminate URL preview connections after 30 seconds. Since generating URL previews for media streams is not supported and always fails, 1.53.0 additionally implements an allow list for content types for which Synapse will even attempt to generate a URL preview. Upgrade to 1.53.0 to fully resolve the issue. As a workaround, turn off URL preview functionality by setting `url_preview_enabled: false` in the Synapse configuration file.

# CWE-773 Missing Reference to Active File Descriptor or Handle

## Description

The product does not properly maintain references to a file descriptor or handle, which prevents that file descriptor/handle from being reclaimed.

This can cause the product to consume all available file descriptors or handles, which can prevent other processes from performing critical file processing operations.

# CWE-774 Allocation of File Descriptors or Handles Without Limits or Throttling

## Description

The product allocates file descriptors or handles on behalf of an actor without imposing any restrictions on how many descriptors can be allocated, in violation of the intended security policy for that actor.

This can cause the product to consume all available file descriptors or handles, which can prevent other processes from performing critical file processing operations.

# CWE-775 Missing Release of File Descriptor or Handle after Effective Lifetime

## Description

The product does not release a file descriptor or handle after its effective lifetime has ended, i.e., after the file descriptor/handle is no longer needed.

When a file descriptor or handle is not released after use (typically by explicitly closing it), attackers can cause a denial of service by consuming all available file descriptors/handles, or otherwise preventing other system processes from obtaining their own file descriptors/handles.

## Observed Examples

CVE-2007-0897: Chain: anti-virus product encounters a malformed file but returns from a function without closing a file descriptor (CWE-775) leading to file descriptor consumption (CWE-400) and failed scans.

## Top 25 Examples

CVE-2022-22215: A Missing Release of File Descriptor or Handle after Effective Lifetime vulnerability in plugable authentication module (PAM) of Juniper Networks Junos OS and Junos OS Evolved allows a locally authenticated attacker with low privileges to cause a Denial of Service (DoS). It is possible that after the termination of a gRPC connection the respective/var/run/<pid>.env file is not getting deleted which if occurring repeatedly can cause inode exhaustion. Inode exhaustion can present itself in two different ways: 1. The following log message can be observed: host kernel: pid <pid> (<process>), uid <uid> inumber <number> on /.mount/var: out of inodes which by itself is a clear indication. 2. The following log message can be observed: host <process>[<pid>]: ... : No space left on device which is not deterministic and just a representation of a write error which could have several reasons. So the following check needs to be done: user@host> show system storage no-forwarding Filesystem Size Used Avail Capacity Mounted on /dev/ada1p1 475M 300M 137M 69% /.mount/var which indicates that the write error is not actually due to a lack of disk space. If either 1. or 2. has been confirmed, then the output of: user@host> file list /var/run/*.env | count need to be checked and if it indicates a high (>10000) number of files the system has been affected by this issue. This issue affects: Juniper Networks Junos OS All versions prior to 19.1R3-S8; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to 19.4R2-S6, 19.4R3-S7; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S4; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-EVO; 21.1 versions prior to 21.1R3-S1-EVO; 21.2 versions prior to 21.2R1-S1-EVO, 21.2R2-EVO.

# CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')

## Description

The product uses XML documents and allows their structure to be defined with a Document Type Definition (DTD), but it does not properly control the number of recursive definitions of entities.

If the DTD contains a large number of nested or recursive entities, this can lead to explosive growth of data when parsed, causing a denial of service.

## Observed Examples

CVE-2008-3281: XEE in XML-parsing library.

CVE-2011-3288: XML bomb / XEE in enterprise communication product.

CVE-2011-1755: "Billion laughs" attack in XMPP server daemon.

CVE-2009-1955: XML bomb in web server module

CVE-2003-1564: Parsing library allows XML bomb

## Top 25 Examples

CVE-2022-0217: It was discovered that an internal Prosody library to load XML based on libexpat does not properly restrict the XML features allowed in parsed XML data. Given suitable attacker input, this results in expansion of recursive entity references from DTDs (CWE-776). In addition, depending on the libexpat version used, it may also allow injections using XML External Entity References (CWE-611).

CVE-2022-23640: Excel-Streaming-Reader is an easy-to-use implementation of a streaming Excel reader using Apache POI. Prior to xlsx-streamer 2.1.0, the XML parser that was used did apply all the necessary settings to prevent XML Entity Expansion issues. Upgrade to version 2.1.0 to receive a patch. There is no known workaround.

CVE-2021-41559: Silverstripe silverstripe/framework 4.8.1 has a quadratic blowup in Convert::xml2array() that enables a remote attack via a crafted XML document.

CVE-2022-25857: The package org.yaml:snakeyaml from 0 and before 1.31 are vulnerable to Denial of Service (DoS) due missing to nested depth limitation for collections.

# CWE-777 Regular Expression without Anchors

## Description

The product uses a regular expression to perform neutralization, but the regular expression is not anchored and may allow malicious or malformed data to slip through.

When performing tasks such as validating against a set of allowed inputs (allowlist), data is examined and possibly modified to ensure that it is well-formed and adheres to a list of safe values. If the regular expression is not anchored, malicious or malformed data may be included before or after any string matching the regular expression. The type of malicious data that is allowed will depend on the context of the application and which anchors are omitted from the regular expression.

Regular expressions are typically used to match a pattern of text. Anchors are used in regular expressions to specify where the pattern should match: at the beginning, the end, or both (the whole input).

## Observed Examples

CVE-2022-30034: Chain: Web UI for a Python RPC framework does not use regex anchors to validate user login emails (CWE-777), potentially allowing bypass of OAuth (CWE-1390).

## Top 25 Examples

CVE-2021-28965: The REXML gem before 3.2.5 in Ruby before 2.6.7, 2.7.x before 2.7.3, and 3.x before 3.0.1 does not properly address XML round-trip issues. An incorrect document can be produced after parsing and serializing.

CVE-2022-30688: needrestart 0.8 through 3.5 before 3.6 is prone to local privilege escalation. Regexes to detect the Perl, Python, and Ruby interpreters are not anchored, allowing a local user to escalate privileges when needrestart tries to detect if interpreters are using old source files.

# CWE-778 Insufficient Logging

## Description

When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

When security-critical events are not logged properly, such as a failed login attempt, this can make malicious behavior more difficult to detect and may hinder forensic analysis after an attack succeeds.


As organizations adopt cloud storage resources, these technologies often require configuration changes to enable detailed logging information, since detailed logging can incur additional costs. This could lead to telemetry gaps in critical audit logs. For example, in Azure, the default value for logging is disabled.

## Observed Examples

CVE-2008-4315: server does not log failed authentication attempts, making it easier for attackers to perform brute force password guessing without being detected

CVE-2008-1203: admin interface does not log failed authentication attempts, making it easier for attackers to perform brute force password guessing without being detected

CVE-2007-3730: default configuration for POP server does not log source IP or username for login attempts

CVE-2007-1225: proxy does not log requests without "http://" in the URL, allowing web surfers to access restricted web content without detection

CVE-2003-1566: web server does not log requests for a non-standard request type

## Top 25 Examples

CVE-2022-30305: An insufficient logging [CWE-778] vulnerability in FortiSandbox versions 4.0.0 to 4.0.2, 3.2.0 to 3.2.3 and 3.1.0 to 3.1.5 and FortiDeceptor versions 4.2.0, 4.1.0 through 4.1.1, 4.0.0 through 4.0.2, 3.3.0 through 3.3.3, 3.2.0 through 3.2.2,3.1.0 through 3.1.1 and 3.0.0 through 3.0.2 may allow a remote attacker to repeatedly enter incorrect credentials without causing a log entry, and with no limit on the number of failed authentication attempts.

CVE-2022-25783: Insufficient Logging vulnerability in web server of Secomea GateManager allows logged in user to issue improper queries without logging. This issue affects: Secomea GateManager versions prior to 9.7.

# CWE-779 Logging of Excessive Data

## Description

The product logs too much information, making log files hard to process and possibly hindering recovery efforts or forensic analysis after an attack.

While logging is a good practice in general, and very high levels of logging are appropriate for debugging stages of development, too much logging in a production environment might hinder a system administrator's ability to detect anomalous conditions. This can provide cover for an attacker while attempting to penetrate a system, clutter the audit trail for forensic analysis, or make it more difficult to debug problems in a production environment.

## Observed Examples

CVE-2007-0421: server records a large amount of data to the server log when it receives malformed headers

CVE-2002-1154: chain: application does not restrict access to front-end for updates, which allows attacker to fill the error log

## Top 25 Examples

CVE-2022-22291: Logging of excessive data vulnerability in telephony prior to SMR Feb-2022 Release 1 allows privileged attackers to get Cell Location Information through log of user device.

CVE-2022-25779: Logging of Excessive Data vulnerability in audit log of Secomea GateManager allows logged in user to write text entries in audit log. This issue affects: Secomea GateManager versions prior to 9.7.

# CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

## Description

The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.

This weakness can lead to a vulnerability in environments in which the attacker does not have direct access to the operating system, such as in web applications. Alternately, if the weakness occurs in a privileged program, it could allow the attacker to specify commands that normally would not be accessible, or to call alternate commands with privileges that the attacker does not have. The problem is exacerbated if the compromised process does not follow the principle of least privilege, because the attacker-controlled commands may run with special system privileges that increases the amount of damage.


There are at least two subtypes of OS command injection:


  - The application intends to execute a single, fixed program that is under its own control. It intends to use externally-supplied inputs as arguments to that program. For example, the program might use system("nslookup [HOSTNAME]") to run nslookup and allow the user to supply a HOSTNAME, which is used as an argument. Attackers cannot prevent nslookup from executing. However, if the program does not remove command separators from the HOSTNAME argument, attackers could place the separators into the arguments, which allows them to execute their own program after nslookup has finished executing.

  - The application accepts an input that it uses to fully select which program to run, as well as which commands to use. The application simply redirects this entire command to the operating system. For example, the program might use "exec([COMMAND])" to execute the [COMMAND] that was supplied by the user. If the COMMAND is under attacker control, then the attacker can execute arbitrary commands or programs. If the command is being executed using functions like exec() and CreateProcess(), the attacker might not be able to combine multiple commands together in the same line.

From a weakness standpoint, these variants represent distinct programmer errors. In the first variant, the programmer clearly intends that input from untrusted parties will be part of the arguments in the command to be executed. In the second variant, the programmer does not intend for the command to be accessible to any untrusted party, but the programmer probably has not accounted for alternate ways in which malicious attackers can provide input.

## Observed Examples

CVE-2020-10987: OS command injection in Wi-Fi router, as exploited in the wild per CISA KEV.

CVE-2020-10221: Template functionality in network configuration management tool allows OS command injection, as exploited in the wild per CISA KEV.

CVE-2020-9054: Chain: improper input validation (CWE-20) in username parameter, leading to OS command injection (CWE-78), as exploited in the wild per CISA KEV.

CVE-1999-0067: Canonical example of OS command injection. CGI program does not neutralize "|" metacharacter when invoking a phonebook program.

CVE-2001-1246: Language interpreter's mail function accepts another argument that is concatenated to a string used in a dangerous popen() call. Since there is no neutralization of this argument, both OS Command Injection (CWE-78) and Argument Injection (CWE-88) are possible.

CVE-2002-0061: Web server allows command execution using "|" (pipe) character.

CVE-2003-0041: FTP client does not filter "|" from filenames returned by the server, allowing for OS command injection.

CVE-2008-2575: Shell metacharacters in a filename in a ZIP archive

CVE-2002-1898: Shell metacharacters in a telnet:// link are not properly handled when the launching application processes the link.

CVE-2008-4304: OS command injection through environment variable.

CVE-2008-4796: OS command injection through https:// URLs

CVE-2007-3572: Chain: incomplete denylist for OS command injection

CVE-2012-1988: Product allows remote users to execute arbitrary commands by creating a file whose pathname contains shell metacharacters.

## Top 25 Examples

CVE-2022-41525: TOTOLINK NR1800X V9.1.0u.6279_B20210910 was discovered to contain a command injection vulnerability via the OpModeCfg function at /cgi-bin/cstecgi.cgi.

CVE-2022-46597: TRENDnet TEW755AP 1.13B01 was discovered to contain a command injection vulnerability via the sys_service parameter in the setup_wizard_mydlink (sub_4104B8) function.

CVE-2022-46598: TRENDnet TEW755AP 1.13B01 was discovered to contain a command injection vulnerability via the wps_sta_enrollee_pin parameter in the action set_sta_enrollee_pin_5g function.

CVE-2021-36667: Command injection vulnerability in Druva inSync 6.9.0 for MacOS, allows attackers to execute arbitrary commands via crafted payload to the local HTTP server due to un-sanitized call to the python os.system library.

CVE-2021-42232: TP-Link Archer A7 Archer A7(US)_V5_210519 is affected by a command injection vulnerability in /usr/bin/tddp. The vulnerability is caused by the program taking part of the received data packet as part of the command. This will cause an attacker to execute arbitrary commands on the router.

CVE-2021-42872: TOTOLINK EX1200T V4.1.2cu.5215 is affected by a command injection vulnerability that can remotely execute arbitrary code.

CVE-2021-44080: A Command Injection vulnerability in httpd web server (setup.cgi) in SerComm h500s, FW: lowi-h500s-v3.4.22 allows logged in administrators to arbitrary OS commands as root in the device via the connection_type parameter of the statussupport_diagnostic_tracing.json endpoint.

CVE-2022-1262: A command injection vulnerability in the protest binary allows an attacker with access to the remote command line interface to execute arbitrary commands as root.

CVE-2022-2068: In addition to the c_rehash shell command injection identified in CVE-2022-1292, further circumstances where the c_rehash script does not properly sanitise shell metacharacters to prevent command injection were found by code review. When the CVE-2022-1292 was fixed it was not discovered that there are other places in the script where the file names of certificates being hashed were possibly passed to a command executed through the shell. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.4 (Affected 3.0.0,3.0.1,3.0.2,3.0.3). Fixed in OpenSSL 1.1.1p (Affected 1.1.1-1.1.1o). Fixed in OpenSSL 1.0.2zf (Affected 1.0.2-1.0.2ze).

CVE-2022-20718: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-22997: Addressed a remote code execution vulnerability by resolving a command injection vulnerability and closing an AWS S3 bucket that potentially allowed an attacker to execute unsigned code on My Cloud Home devices.

CVE-2022-23611: iTunesRPC-Remastered is a Discord Rich Presence for iTunes on Windows utility. In affected versions iTunesRPC-Remastered did not properly sanitize image file paths leading to OS level command injection. This issue has been patched in commit cdcd48b. Users are advised to upgrade.

CVE-2022-23661: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23662: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23663: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23664: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23665: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23666: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23667: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23681: Multiple vulnerabilities exist in the AOS-CX command line interface that could lead to authenticated command injection. A successful exploit could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete switch compromise in ArubaOS-CX version(s): AOS-CX 10.09.xxxx: 10.09.1030 and below, AOS-CX 10.08.xxxx: 10.08.1030 and below, AOS-CX 10.06.xxxx: 10.06.0180 and below. Aruba has released upgrades for ArubaOS-CX Switch Devices that address these security vulnerabilities.

CVE-2022-23682: Multiple vulnerabilities exist in the AOS-CX command line interface that could lead to authenticated command injection. A successful exploit could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete switch compromise in ArubaOS-CX version(s): AOS-CX 10.09.xxxx: 10.09.1030 and below, AOS-CX 10.08.xxxx: 10.08.1030 and below, AOS-CX 10.06.xxxx: 10.06.0180 and below. Aruba has released upgrades for ArubaOS-CX Switch Devices that address these security vulnerabilities.

CVE-2022-23683: Authenticated command injection vulnerabilities exist in the AOS-CX Network Analytics Engine via NAE scripts. Successful exploitation of these vulnerabilities result in the ability to execute arbitrary commands as a privileged user on the underlying operating system, leading to a complete compromise of the switch running AOS-CX in ArubaOS-CX Switches version(s): AOS-CX 10.10.xxxx: 10.10.0002 and below, AOS-CX 10.09.xxxx: 10.09.1030 and below, AOS-CX 10.08.xxxx: 10.08.1070 and below, AOS-CX 10.06.xxxx: 10.06.0210 and below. Aruba has released upgrades for ArubaOS-CX Switch Devices that address these security vulnerabilities.

CVE-2022-24065: The package cookiecutter before 2.1.1 are vulnerable to Command Injection via hg argument injection. When calling the cookiecutter function from Python code with the checkout parameter, it is passed to the hg checkout command in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-24193: CasaOS before v0.2.7 was discovered to contain a command injection vulnerability.

CVE-2022-24697: Kylin's cube designer function has a command injection vulnerability when overwriting system parameters in the configuration overwrites menu. RCE can be implemented by closing the single quotation marks around the parameter value of “-- conf=” to inject any operating system command into the command line parameters. This vulnerability affects Kylin 2 version 2.6.5 and earlier, Kylin 3 version 3.1.2 and earlier, and Kylin 4 version 4.0.1 and earlier.

CVE-2022-25017: Hitron CHITA 7.2.2.0.3b6-CD devices contain a command injection vulnerability via the Device/DDNS ddnsUsername field.

CVE-2022-25048: Command injection vulnerability in CWP v0.9.8.1126 that allows normal users to run commands as the root user.

CVE-2022-25168: Apache Hadoop's FileUtil.unTar(File, File) API does not escape the input file name before being passed to the shell. An attacker can inject arbitrary commands. This is only used in Hadoop 3.3 InMemoryAliasMap.completeBootstrapTransfer, which is only ever run by a local user. It has been used in Hadoop 2.x for yarn localization, which does enable remote code execution. It is used in Apache Spark, from the SQL command ADD ARCHIVE. As the ADD ARCHIVE command adds new binaries to the classpath, being able to execute shell scripts does not confer new permissions to the caller. SPARK-38305. "Check existence of file before untarring/zipping", which is included in 3.3.0, 3.1.4, 3.2.2, prevents shell commands being executed, regardless of which version of the hadoop libraries are in use. Users should upgrade to Apache Hadoop 2.10.2, 3.2.4, 3.3.3 or upper (including HADOOP-18136).

CVE-2022-25906: All versions of the package is-http2 are vulnerable to Command Injection due to missing input sanitization or other checks, and sandboxes being employed to the isH2 function. 

CVE-2022-26289: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/exeCommand.

CVE-2022-26290: Tenda M3 1.10 V1.0.0.12(4856) was discovered to contain a command injection vulnerability via the component /goform/WriteFacMac.

CVE-2022-26413: A command injection vulnerability in the CGI program of Zyxel VMG3312-T20A firmware version 5.30(ABFX.5)C0 could allow a local authenticated attacker to execute arbitrary OS commands on a vulnerable device via a LAN interface.

CVE-2022-26481: An issue was discovered in Poly Studio before 3.7.0. Command Injection can occur via the CN field of a Create Certificate Signing Request (CSR) action.

CVE-2022-26482: An issue was discovered in Poly EagleEye Director II before 2.2.2.1. os.system command injection can be achieved by an admin.

CVE-2022-26580: PAX A930 device with PayDroid_7.1.1_Virgo_V04.3.26T1_20210419 can allow the execution of specific command injections on selected binaries in the ADB daemon shell service. The attacker must have physical USB access to the device in order to exploit this vulnerability.

CVE-2022-26670: D-Link DIR-878 has inadequate filtering for special characters in the webpage input field. An unauthenticated LAN attacker can perform command injection attack to execute arbitrary system commands to control the system or disrupt service.

CVE-2022-26868: Dell EMC PowerStore versions 2.0.0.x, 2.0.1.x, and 2.1.0.x are vulnerable to a command injection flaw. An authenticated attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the application's underlying OS, with the privileges of the vulnerable application. Exploitation may lead to a system takeover by an attacker.

CVE-2022-28374: Verizon 5G Home LVSKIHP OutDoorUnit (ODU) 3.33.101.0 does not property sanitize user-controlled parameters within the DMACC URLs on the Settings page of the Engineering portal. An authenticated remote attacker on the local network can inject shell metacharacters into /usr/lib/lua/5.1/luci/controller/admin/settings.lua to achieve remote code execution as root.

CVE-2022-28375: Verizon 5G Home LVSKIHP OutDoorUnit (ODU) 3.33.101.0 does not property sanitize user-controlled parameters within the crtcswitchsimprofile function of the crtcrpc JSON listener. A remote attacker on the local network can inject shell metacharacters into /usr/lib/lua/5.1/luci/controller/rpc.lua to achieve remote code execution as root,

CVE-2022-28491: TOTOLink outdoor CPE CP900 V6.3c.566_B20171026 contains a command injection vulnerability in the NTPSyncWithHost function via the host_name parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-28494: TOTOLink outdoor CPE CP900 V6.3c.566_B20171026 is discovered to contain a command injection vulnerability in the setUpgradeFW function via the filename parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-28495: TOTOLink outdoor CPE CP900 V6.3c.566_B20171026 is discovered to contain a command injection vulnerability in the setWebWlanIdx function via the webWlanIdx parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-29080: The npm-dependency-versions package through 0.3.0 for Node.js allows command injection if an attacker is able to call dependencyVersions with a JSON object in which pkgs is a key, and there are shell metacharacters in a value.

CVE-2022-29520: An OS command injection vulnerability exists in the console_main_loop :sys functionality of Abode Systems, Inc. iota All-In-One Security Kit 6.9Z. A specially-crafted XCMD can lead to arbitrary command execution. An attacker can send an XML payload to trigger this vulnerability.

CVE-2022-29843: A command injection vulnerability in the DDNS service configuration of Western Digital My Cloud OS 5 devices running firmware versions prior to 5.26.119 allows an attacker to execute code in the context of the root user.

CVE-2022-30078: NETGEAR R6200_V2 firmware versions through R6200v2-V1.0.3.12_10.1.11 and R6300_V2 firmware versions through R6300v2-V1.0.4.52_10.0.93 allow remote authenticated attackers to execute arbitrary command via shell metacharacters in the ipv6_fix.cgi ipv6_wan_ipaddr, ipv6_lan_ipaddr, ipv6_wan_length, or ipv6_lan_length parameters.

CVE-2022-30105: In Belkin N300 Firmware 1.00.08, the script located at /setting_hidden.asp, which is accessible before and after configuring the device, exhibits multiple remote command injection vulnerabilities. The following parameters in the [form name] form; [list vulnerable parameters], are not properly sanitized after being submitted to the web interface in a POST request. With specially crafted parameters, it is possible to inject a an OS command which will be executed with root privileges, as the web interface, and all processes on the device, run as root.

CVE-2022-30425: Tenda Technology Co.,Ltd HG6 3.3.0-210926 was discovered to contain a command injection vulnerability via the pingAddr and traceAddr parameters. This vulnerability is exploited via a crafted POST request.

CVE-2022-31479: An unauthenticated attacker can update the hostname with a specially crafted name that will allow for shell commands to be executed during the core collection process. This vulnerability impacts products based on HID Mercury Intelligent Controllers LP1501, LP1502, LP2500, LP4502, and EP4502 which contain firmware versions prior to 1.302 for the LP series and 1.296 for the EP series. An attacker with this level of access on the device can monitor all communications sent to and from this device, modify onboard relays, change configuration files, or cause the device to become unstable. The injected commands only get executed during start up or when unsafe calls regarding the hostname are used. This allows the attacker to gain remote access to the device and can make their persistence permanent by modifying the filesystem.

CVE-2022-31814: pfSense pfBlockerNG through 2.1.4_26 allows remote attackers to execute arbitrary OS commands as root via shell metacharacters in the HTTP Host header. NOTE: 3.x is unaffected.

CVE-2022-32534: The Bosch Ethernet switch PRA-ES8P2S with software version 1.01.05 and earlier was found to be vulnerable to command injection through its diagnostics web interface. This allows execution of shell commands.

CVE-2022-32765: An OS command injection vulnerability exists in the sysupgrade command injection functionality of Robustel R1510 3.1.16 and 3.3.0. A specially-crafted network request can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger this vulnerability.

CVE-2022-33312: Multiple command injection vulnerabilities exist in the web_server action endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network request can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/action/import_cert_file/` API is affected by command injection vulnerability.

CVE-2022-33313: Multiple command injection vulnerabilities exist in the web_server action endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network request can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/action/import_https_cert_file/` API is affected by command injection vulnerability.

CVE-2022-33314: Multiple command injection vulnerabilities exist in the web_server action endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network request can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/action/import_sdk_file/` API is affected by command injection vulnerability.

CVE-2022-33325: Multiple command injection vulnerabilities exist in the web_server ajax endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network packets can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/ajax/clear_tools_log/` API is affected by command injection vulnerability.

CVE-2022-33326: Multiple command injection vulnerabilities exist in the web_server ajax endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network packets can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/ajax/config_rollback/` API is affected by a command injection vulnerability.

CVE-2022-33327: Multiple command injection vulnerabilities exist in the web_server ajax endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network packets can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/ajax/remove_sniffer_raw_log/` API is affected by a command injection vulnerability.

CVE-2022-33328: Multiple command injection vulnerabilities exist in the web_server ajax endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network packets can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/ajax/remove/` API is affected by a command injection vulnerability.

CVE-2022-33329: Multiple command injection vulnerabilities exist in the web_server ajax endpoints functionalities of Robustel R1510 3.3.0. A specially-crafted network packets can lead to arbitrary command execution. An attacker can send a sequence of requests to trigger these vulnerabilities.The `/ajax/set_sys_time/` API is affected by a command injection vulnerability.

CVE-2022-34769: Michlol - rashim web interface Insecure direct object references (IDOR). First of all, the attacker needs to login. After he performs log into the system there are some functionalities that the specific user is not allowed to perform. However all the attacker needs to do in order to achieve his goals is to change the value of the ptMsl parameter and then the attacker can access sensitive data that he not supposed to access because its belong to another user.

CVE-2022-35132: Usermin through 1.850 allows a remote authenticated user to execute OS commands via command injection in a filename for the GPG module.

CVE-2022-36309: Airspan AirVelocity 1500 software versions prior to 15.18.00.2511 have a root command injection vulnerability in the ActiveBank parameter of the recoverySubmit.cgi script running on the eNodeB's web management UI. This issue may affect other AirVelocity and AirSpeed models.

CVE-2022-36566: Rengine v1.3.0 was discovered to contain a command injection vulnerability via the scan engine function.

CVE-2022-38132: Command injection vulnerability in Linksys MR8300 router while Registration to DDNS Service. By specifying username and password, an attacker connected to the router's web interface can execute arbitrary OS commands. The username and password fields are not sanitized correctly and are used as URL construction arguments, allowing URL redirection to an arbitrary server, downloading an arbitrary script file, and eventually executing the file in the device. This issue affects: Linksys MR8300 Router 1.0.

CVE-2022-38547: A post-authentication command injection vulnerability in the CLI command of Zyxel ZyWALL/USG series firmware versions 4.20 through 4.72, VPN series firmware versions 4.30 through 5.32, USG FLEX series firmware versions 4.50 through 5.32, and ATP series firmware versions 4.32 through 5.32, which could allow an authenticated attacker with administrator privileges to execute OS commands.

CVE-2022-40005: Intelbras WiFiber 120AC inMesh before 1-1-220826 allows command injection by authenticated users, as demonstrated by the /boaform/formPing6 and /boaform/formTracert URIs for ping and traceroute.

CVE-2022-40764: Snyk CLI before 1.996.0 allows arbitrary command execution, affecting Snyk IDE plugins and the snyk npm package. Exploitation could follow from the common practice of viewing untrusted files in the Visual Studio Code editor, for example. The original demonstration was with shell metacharacters in the vendor.json ignore field, affecting snyk-go-plugin before 1.19.1. This affects, for example, the Snyk TeamCity plugin (which does not update automatically) before 20220930.142957.

CVE-2022-40847: In Tenda AC1200 Router model W15Ev2 V15.11.0.10(1576), there exists a command injection vulnerability in the function formSetFixTools. This vulnerability allows attackers to run arbitrary commands on the server via the hostname parameter.

CVE-2022-41395: Tenda AC1200 Router Model W15Ev2 V15.11.0.10(1576) was discovered to contain a command injection vulnerability via the dmzHost parameter in the setDMZ function.

CVE-2022-41396: Tenda AC1200 Router Model W15Ev2 V15.11.0.10(1576) was discovered to contain multiple command injection vulnerabilities in the function setIPsecTunnelList via the IPsecLocalNet and IPsecRemoteNet parameters.

CVE-2022-42053: Tenda AC1200 Router Model W15Ev2 V15.11.0.10(1576) was discovered to contain a command injection vulnerability via the PortMappingServer parameter in the setPortMapping function.

CVE-2022-42055: Multiple command injection vulnerabilities in GL.iNet GoodCloud IoT Device Management System Version 1.00.220412.00 via the ping and traceroute tools allow attackers to read arbitrary files on the system.

CVE-2022-42139: Delta Electronics DVW-W02W2-E2 1.5.0.10 is vulnerable to Command Injection via Crafted URL.

CVE-2022-42140: Delta Electronics DX-2100-L1-CN 2.42 is vulnerable to Command Injection via lform/net_diagnose.

CVE-2022-43325: An unauthenticated command injection vulnerability in the product license validation function of Telos Alliance Omnia MPX Node 1.3.* - 1.4.* allows attackers to execute arbitrary commands via a crafted payload injected into the license input.

CVE-2022-43390: A command injection vulnerability in the CGI program of Zyxel NR7101 firmware prior to V1.15(ACCC.3)C0, which could allow an authenticated attacker to execute some OS commands on a vulnerable device by sending a crafted HTTP request.

CVE-2022-44019: In Total.js 4 before 0e5ace7, /api/common/ping can achieve remote command execution via shell metacharacters in the host parameter.

CVE-2022-44567: A command injection vulnerability exists in Rocket.Chat-Desktop <3.8.14 that could allow an attacker to pass a malicious url of openInternalVideoChatWindow to shell.openExternal(), which may lead to remote code execution (internalVideoChatWindow.ts#L17). To exploit the vulnerability, the internal video chat window must be disabled or a Mac App Store build must be used (internalVideoChatWindow.ts#L14). The vulnerability may be exploited by an XSS attack because the function openInternalVideoChatWindow is exposed in the Rocket.Chat-Desktop-API.

CVE-2022-45709: IP-COM M50 V15.11.0.33(10768) was discovered to contain multiple command injection vulnerabilities via the pEnable, pLevel, and pModule parameters in the formSetDebugCfg function.

CVE-2022-45711: IP-COM M50 V15.11.0.33(10768) was discovered to contain a command injection vulnerability via the hostname parameter in the formSetNetCheckTools function.

CVE-2022-46304: ChangingTec ServiSign component has insufficient filtering for special characters in the connection response parameter. An unauthenticated remote attacker can host a malicious website for the component user to access, which triggers command injection and allows the attacker to execute arbitrary system command to perform arbitrary system operation or disrupt service.

CVE-2022-48070: Phicomm K2 v22.6.534.263 was discovered to contain a command injection vulnerability via the autoUpTime parameter in the automatic upgrade function.

CVE-2022-48072: Phicomm K2G v22.6.3.20 was discovered to contain a command injection vulnerability via the autoUpTime parameter in the automatic upgrade function.

CVE-2022-48337: GNU Emacs through 28.2 allows attackers to execute commands via shell metacharacters in the name of a source-code file, because lib-src/etags.c uses the system C library function in its implementation of the etags program. For example, a victim may use the "etags -u *" command (suggested in the etags documentation) in a situation where the current working directory has contents that depend on untrusted input.

CVE-2022-24725: Shescape is a shell escape package for JavaScript. An issue in versions 1.4.0 to 1.5.1 allows for exposure of the home directory on Unix systems when using Bash with the `escape` or `escapeAll` functions from the _shescape_ API with the `interpolation` option set to `true`. Other tested shells, Dash and Zsh, are not affected. Depending on how the output of _shescape_ is used, directory traversal may be possible in the application using _shescape_. The issue was patched in version 1.5.1. As a workaround, manually escape all instances of the tilde character (`~`) using `arg.replace(/~/g, "\\\\~")`.

CVE-2022-33891: The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

CVE-2021-1497: Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-1498: Multiple vulnerabilities in the web-based management interface of Cisco HyperFlex HX could allow an unauthenticated, remote attacker to perform command injection attacks against an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-21315: The System Information Library for Node.JS (npm package "systeminformation") is an open source collection of functions to retrieve detailed hardware, system and OS information. In systeminformation before version 5.3.1 there is a command injection vulnerability. Problem was fixed in version 5.3.1. As a workaround instead of upgrading, be sure to check or sanitize service parameters that are passed to si.inetLatency(), si.inetChecksite(), si.services(), si.processLoad() ... do only allow strings, reject any arrays. String sanitation works as expected.

CVE-2021-27561: Yealink Device Management (DM) 3.6.0.20 allows command injection as root via the /sm/api/v1/firewall/zone/services URI, without authentication.

CVE-2021-36260: A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.

CVE-2021-45382: A Remote Command Execution (RCE) vulnerability exists in all series H/W revisions D-link DIR-810L, DIR-820L/LW, DIR-826L, DIR-830L, and DIR-836L routers via the DDNS function in ncc2 binary file. Note: DIR-810L, DIR-820L, DIR-830L, DIR-826L, DIR-836L, all hardware revisions, have reached their End of Life ("EOL") /End of Service Life ("EOS") Life-Cycle and as such this issue will not be patched.

CVE-2022-26258: D-Link DIR-820L 1.05B03 was discovered to contain remote command execution (RCE) vulnerability via HTTP POST to get set ccp.

CVE-2022-28810: Zoho ManageEngine ADSelfService Plus before build 6122 allows a remote authenticated administrator to execute arbitrary operating OS commands as SYSTEM via the policy custom script feature. Due to the use of a default administrator password, attackers may be able to abuse this functionality with minimal effort. Additionally, a remote and partially authenticated attacker may be able to inject arbitrary commands into the custom script due to an unsanitized password field.

CVE-2022-30525: A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

CVE-2022-44877: login/index.php in CWP (aka Control Web Panel or CentOS Web Panel) 7 before 0.9.8.1147 allows remote attackers to execute arbitrary OS commands via shell metacharacters in the login parameter.

CVE-2022-46169: Cacti is an open source platform which provides a robust and extensible operational monitoring and fault management framework for users. In affected versions a command injection vulnerability allows an unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can be accessed without authentication. This function retrieves the IP address of the client via `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the resolved hostname. If such an entry was found, the function returns `true` and the client is authorized. This authorization can be bypassed due to the implementation of the `get_client_addr` function. The function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker. Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an attacker can bypass the authentication e.g. by providing the header `Forwarded-For: <TARGETIP>`. This way the function `get_client_addr` returns the IP address of the server running Cacti. The following call to `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller` hostname check because of the default entry. After the authorization of the `remote_agent.php` file is bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item` entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call, the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP` action exists. This is very likely on a productive instance because this action is added by some predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept for compatibility reasons it should at least be prevented to fake the IP address of the server running Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23` being the first release containing the patch.

CVE-2021-42759: A violation of secure design principles in Fortinet Meru AP version 8.6.1 and below, version 8.5.5 and below allows attacker to execute unauthorized code or commands via crafted cli commands.

CVE-2021-43073: A improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiWeb version 6.4.1 and 6.4.0, version 6.3.15 and below, version 6.2.6 and below allows attacker to execute unauthorized code or commands via crafted HTTP requests.

CVE-2021-43075: A improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiWLM version 8.6.2 and below, version 8.5.2 and below, version 8.4.2 and below, version 8.3.2 and below allows attacker to execute unauthorized code or commands via crafted HTTP requests to the alarm dashboard and controller config handlers.

CVE-2021-43928: Improper neutralization of special elements used in an OS command ('OS Command Injection') vulnerability in mail sending and receiving component in Synology Mail Station before 20211105-10315 allows remote authenticated users to execute arbitrary commands via unspecified vectors.

CVE-2021-44171: A improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiOS version 6.0.0 through 6.0.14, FortiOS version 6.2.0 through 6.2.10, FortiOS version 6.4.0 through 6.4.8, FortiOS version 7.0.0 through 7.0.3 allows attacker to execute privileged commands on a linked FortiSwitch via diagnostic CLI commands.

CVE-2022-1703: Improper neutralization of special elements in the SonicWall SSL-VPN SMA100 series management interface allows a remote authenticated attacker to inject OS Commands which potentially leads to remote command execution vulnerability or denial of service (DoS) attack.

CVE-2022-22273: Improper neutralization of Special Elements leading to OS Command Injection vulnerability impacting end-of-life Secure Remote Access (SRA) products and older firmware versions of Secure Mobile Access (SMA) 100 series products, specifically the SRA appliances running all 8.x, 9.0.0.5-19sv and earlier versions and Secure Mobile Access (SMA) 100 series products running older firmware 9.0.0.9-26sv and earlier versions

CVE-2022-22301: An improper neutralization of special elements used in an OS Command vulnerability [CWE-78] in FortiAP-C console 5.4.0 through 5.4.3, 5.2.0 through 5.2.1 may allow an authenticated attacker to execute unauthorized commands by running CLI commands with specifically crafted arguments.

CVE-2022-22684: Improper neutralization of special elements used in an OS command ('OS Command Injection') vulnerability in task management component in Synology DiskStation Manager (DSM) before 6.2.4-25553 allows remote authenticated users to execute arbitrary commands via unspecified vectors.

CVE-2022-2185: A critical issue has been discovered in GitLab affecting all versions starting from 14.0 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 where an authenticated user authorized to import projects could import a maliciously crafted project leading to remote code execution.

CVE-2022-4257: A vulnerability was found in C-DATA Web Management System. It has been rated as critical. This issue affects some unknown processing of the file cgi-bin/jumpto.php of the component GET Parameter Handler. The manipulation of the argument hostname leads to argument injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214631.

CVE-2022-23389: PublicCMS v4.0 was discovered to contain a remote code execution (RCE) vulnerability via the cmdarray parameter.

CVE-2022-24441: The package snyk before 1.1064.0 are vulnerable to Code Injection when analyzing a project. An attacker who can convince a user to scan a malicious project can include commands in a build file such as build.gradle or gradle-wrapper.jar, which will be executed with the privileges of the application. This vulnerability may be triggered when running the the CLI tool directly, or when running a scan with one of the IDE plugins that invoke the Snyk CLI. Successful exploitation of this issue would likely require some level of social engineering - to coerce an untrusted project to be downloaded and analyzed via the Snyk CLI or opened in an IDE where a Snyk IDE plugin is installed and enabled. Additionally, if the IDE has a Trust feature then the target folder must be marked as ‘trusted’ in order to be vulnerable. **NOTE:** This issue is independent of the one reported in [CVE-2022-40764](https://security.snyk.io/vuln/SNYK-JS-SNYK-3037342), and upgrading to a fixed version for this addresses that issue as well. The affected IDE plugins and versions are: - VS Code - Affected: <=1.8.0, Fixed: 1.9.0 - IntelliJ - Affected: <=2.4.47, Fixed: 2.4.48 - Visual Studio - Affected: <=1.1.30, Fixed: 1.1.31 - Eclipse - Affected: <=v20221115.132308, Fixed: All subsequent versions - Language Server - Affected: <=v20221109.114426, Fixed: All subsequent versions

CVE-2022-32054: Tenda AC10 US_AC10V1.0RTL_V15.03.06.26_multi_TD01 was discovered to contain a remote code execution (RCE) vulnerability via the lanIp parameter.

CVE-2022-39327: Azure CLI is the command-line interface for Microsoft Azure. In versions previous to 2.40.0, Azure CLI contains a vulnerability for potential code injection. Critical scenarios are where a hosting machine runs an Azure CLI command where parameter values have been provided by an external source. The vulnerability is only applicable when the Azure CLI command is run on a Windows machine and with any version of PowerShell and when the parameter value contains the `&` or `|` symbols. If any of these prerequisites are not met, this vulnerability is not applicable. Users should upgrade to version 2.40.0 or greater to receive a a mitigation for the vulnerability.

CVE-2022-45942: A Remote Code Execution (RCE) vulnerability was found in includes/baijiacms/common.inc.php in baijiacms v4.

CVE-2021-41738: ZeroShell 3.9.5 has a command injection vulnerability in /cgi-bin/kerbynet IP parameter, which may allow an authenticated attacker to execute system commands.

CVE-2021-42875: TOTOLINK EX1200T V4.1.2cu.5215 contains a remote command injection vulnerability in the function setDiagnosisCfg of the file lib/cste_modules/system.so to control the ipDoamin.

CVE-2021-42884: TOTOLINK EX1200T V4.1.2cu.5215 contains a remote command injection vulnerability in function setDeviceName of the file global.so which can control thedeviceName to attack.

CVE-2021-42885: TOTOLINK EX1200T V4.1.2cu.5215 contains a remote command injection vulnerability in function setDeviceMac of the file global.so which can control deviceName to attack.

CVE-2021-42888: TOTOLINK EX1200T V4.1.2cu.5215 contains a remote command injection vulnerability in function setLanguageCfg of the file global.so which can control langType to attack.

CVE-2021-42890: TOTOLINK EX1200T V4.1.2cu.5215 contains a remote command injection vulnerability in function NTPSyncWithHost of the file system.so which can control hostTime to attack.

CVE-2022-1030: Okta Advanced Server Access Client for Linux and macOS prior to version 1.58.0 was found to be vulnerable to command injection via a specially crafted URL. An attacker, who has knowledge of a valid team name for the victim and also knows a valid target host where the user has access, can execute commands on the local system.

CVE-2022-2234: An authenticated mySCADA myPRO 8.26.0 user may be able to modify parameters to run commands directly in the operating system.

CVE-2022-22454: IBM InfoSphere Information Server 11.7 could allow a locally authenticated attacker to execute arbitrary commands on the system by sending a specially crafted request.

CVE-2022-2251: Improper sanitization of branch names in GitLab Runner affecting all versions prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allows a user who creates a branch with a specially crafted name and gets another user to trigger a pipeline to execute commands in the runner as that other user.

CVE-2022-22984: The package snyk before 1.1064.0; the package snyk-mvn-plugin before 2.31.3; the package snyk-gradle-plugin before 3.24.5; the package @snyk/snyk-cocoapods-plugin before 2.5.3; the package snyk-sbt-plugin before 2.16.2; the package snyk-python-plugin before 1.24.2; the package snyk-docker-plugin before 5.6.5; the package @snyk/snyk-hex-plugin before 1.1.6 are vulnerable to Command Injection due to an incomplete fix for [CVE-2022-40764](https://security.snyk.io/vuln/SNYK-JS-SNYK-3037342). A successful exploit allows attackers to run arbitrary commands on the host system where the Snyk CLI is installed by passing in crafted command line flags. In order to exploit this vulnerability, a user would have to execute the snyk test command on untrusted files. In most cases, an attacker positioned to control the command line arguments to the Snyk CLI would already be positioned to execute arbitrary commands. However, this could be abused in specific scenarios, such as continuous integration pipelines, where developers can control the arguments passed to the Snyk CLI to leverage this component as part of a wider attack against an integration/build pipeline. This issue has been addressed in the latest Snyk Docker images available at https://hub.docker.com/r/snyk/snyk as of 2022-11-29. Images downloaded and built prior to that date should be updated. The issue has also been addressed in the Snyk TeamCity CI/CD plugin as of version v20221130.093605.

CVE-2022-23672: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23673: A authenticated remote command injection vulnerability was discovered in Aruba ClearPass Policy Manager version(s): 6.10.4 and below, 6.9.9 and below, 6.8.9-HF2 and below, 6.7.x and below. Aruba has released updates to ClearPass Policy Manager that address this security vulnerability.

CVE-2022-23900: A command injection vulnerability in the API of the Wavlink WL-WN531P3 router, version M31G3.V5030.201204, allows an attacker to achieve unauthorized remote code execution via a malicious POST request through /cgi-bin/adm.cgi.

CVE-2022-23935: lib/Image/ExifTool.pm in ExifTool before 12.38 mishandles a $file =~ /\\|$/ check, leading to command injection.

CVE-2022-24237: The snaptPowered2 component of Snapt Aria v12.8 was discovered to contain a command injection vulnerability. This vulnerability allows authenticated attackers to execute arbitrary commands.

CVE-2022-24377: The package cycle-import-check before 1.3.2 are vulnerable to Command Injection via the writeFileToTmpDirAndOpenIt function due to improper user-input sanitization.

CVE-2022-24388: Vulnerability in rconfig “date” enables an attacker with user level access to the CLI to inject root level commands into Fidelis Network and Deception CommandPost, Collector, Sensor, and Sandbox components as well as neighboring Fidelis components. The vulnerability is present in Fidelis Network and Deception versions prior to 9.4.5. Patches and updates are available to address this vulnerability.

CVE-2022-24389: Vulnerability in rconfig “cert_utils” enables an attacker with user level access to the CLI to inject root level commands into Fidelis Network and Deception CommandPost, Collector, Sensor, and Sandbox components as well as neighboring Fidelis components. The vulnerability is present in Fidelis Network and Deception versions prior to 9.4.5. Patches and updates are available to address this vulnerability.

CVE-2022-24390: Vulnerability in rconfig “remote_text_file” enables an attacker with user level access to the CLI to inject user level commands into Fidelis Network and Deception CommandPost, Collector, Sensor, and Sandbox components as well as neighboring Fidelis components. The vulnerability is present in Fidelis Network and Deception versions prior to 9.4.5. Patches and updates are available to address this vulnerability.

CVE-2022-24392: Vulnerability in Fidelis Network and Deception CommandPost enables authenticated command injection through the web interface using the “feed_comm_test” value for the “feed” parameter. The vulnerability could allow a specially crafted HTTP request to execute system commands on the CommandPost and return results in an HTTP response via an authenticated session. The vulnerability is present in Fidelis Network and Deception versions prior to 9.4.5. Patches and updates are available to address this vulnerability.

CVE-2022-24393: Vulnerability in Fidelis Network and Deception CommandPost enables authenticated command injection through the web interface using the “check_vertica_upgrade” value for the “cpIp” parameter. The vulnerability could allow a specially crafted HTTP request to execute system commands on the CommandPost and return results in an HTTP response via an authenticated session. The vulnerability is present in Fidelis Network and Deception versions prior to 9.4.5. Patches and updates are available to address this vulnerability.

CVE-2022-24394: Vulnerability in Fidelis Network and Deception CommandPost enables authenticated command injection through the web interface using the “update_checkfile” value for the “filename” parameter. The vulnerability could allow a specially crafted HTTP request to execute system commands on the CommandPost and return results in an HTTP response via an authenticated session. The vulnerability is present in Fidelis Network and Deception versions prior to 9.4.5. Patches and updates are available to address this vulnerability.

CVE-2022-24431: All versions of package abacus-ext-cmdline are vulnerable to Command Injection via the execute function due to improper user-input sanitization.

CVE-2022-25060: TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a command injection vulnerability via the component oal_startPing.

CVE-2022-25061: TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a command injection vulnerability via the component oal_setIp6DefaultRoute.

CVE-2022-25064: TP-LINK TL-WR840N(ES)_V6.20_180709 was discovered to contain a remote code execution (RCE) vulnerability via the function oal_wan6_setIpAddr.

CVE-2022-25075: TOTOLink A3000RU V5.9c.2280_B20180512 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25076: TOTOLink A800R V4.1.2cu.5137_B20200730 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25077: TOTOLink A3100R V4.1.2cu.5050_B20200504 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25078: TOTOLink A3600R V4.1.2cu.5182_B20201102 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25079: TOTOLink A810R V4.1.2cu.5182_B20201026 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25080: TOTOLink A830R V5.9c.4729_B20191112 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25081: TOTOLink T10 V5.9c.5061_B20200511 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25082: TOTOLink A950RG V5.9c.4050_B20190424 and V4.1.2cu.5204_B20210112 were discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25083: TOTOLink A860R V4.1.2cu.5182_B20201027 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25084: TOTOLink T6 V5.9c.4085_B20190428 was discovered to contain a command injection vulnerability in the "Main" function. This vulnerability allows attackers to execute arbitrary commands via the QUERY_STRING parameter.

CVE-2022-25171: The package p4 before 0.0.7 are vulnerable to Command Injection via the run() function due to improper input sanitization

CVE-2022-25438: Tenda AC9 v15.03.2.21 was discovered to contain a remote command execution (RCE) vulnerability via the SetIPTVCfg function.

CVE-2022-25441: Tenda AC9 v15.03.2.21 was discovered to contain a remote command execution (RCE) vulnerability via the vlanid parameter in the SetIPTVCfg function.

CVE-2022-25912: The package simple-git before 3.15.0 are vulnerable to Remote Code Execution (RCE) when enabling the ext transport protocol, which makes it exploitable via clone() method. This vulnerability exists due to an incomplete fix of [CVE-2022-24066](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-2434306).

CVE-2022-26206: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function setLanguageCfg, via the langType parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26990: Arris routers SBR-AC1900P 1.0.7-B05, SBR-AC3200P 1.0.7-B05 and SBR-AC1200P 1.0.5-B05 were discovered to contain a command injection vulnerability in the firewall-local log function via the EmailAddress, SmtpServerName, SmtpUsername, and SmtpPassword parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26991: Arris routers SBR-AC1900P 1.0.7-B05, SBR-AC3200P 1.0.7-B05 and SBR-AC1200P 1.0.5-B05 were discovered to contain a command injection vulnerability in the ntp function via the TimeZone parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27268: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the component get_cgi_from_memory. This vulnerability is triggered via a crafted packet.

CVE-2022-27269: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the component config_ovpn. This vulnerability is triggered via a crafted packet.

CVE-2022-27270: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the component ipsec_secrets. This vulnerability is triggered via a crafted packet.

CVE-2022-27271: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the component python-lib. This vulnerability is triggered via a crafted packet.

CVE-2022-27272: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the function sub_1791C. This vulnerability is triggered via a crafted packet.

CVE-2022-27273: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the function sub_12168. This vulnerability is triggered via a crafted packet.

CVE-2022-27274: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the function sub_12028. This vulnerability is triggered via a crafted packet.

CVE-2022-27275: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the function sub_122D0. This vulnerability is triggered via a crafted packet.

CVE-2022-27276: InHand Networks InRouter 900 Industrial 4G Router before v1.0.0.r11700 was discovered to contain a remote code execution (RCE) vulnerability via the function sub_10F2C. This vulnerability is triggered via a crafted packet.

CVE-2022-27373: Shanghai Feixun Data Communication Technology Co., Ltd router fir302b A2 was discovered to contain a remote command execution (RCE) vulnerability via the Ping function.

CVE-2022-28055: Fusionpbx v4.4 and below contains a command injection vulnerability via the download email logs function.

CVE-2022-28557: There is a command injection vulnerability at the /goform/setsambacfg interface of Tenda AC15 US_AC15V1.0BR_V15.03.05.20_multi_TDE01.bin device web, which can also cooperate with CVE-2021-44971 to cause unconditional arbitrary command execution

CVE-2022-28571: D-link 882 DIR882A1_FW130B06 was discovered to contain a command injection vulnerability in`/usr/bin/cli.

CVE-2022-28572: Tenda AX1806 v1.0.0.1 was discovered to contain a command injection vulnerability in `SetIPv6Status` function

CVE-2022-28573: D-Link DIR-823-Pro v1.0.2 was discovered to contain a command injection vulnerability in the function SetNTPserverSeting. This vulnerability allows attackers to execute arbitrary commands via the system_time_timezone parameter.

CVE-2022-28575: It is found that there is a command injection vulnerability in the setopenvpnclientcfg interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows attackers to execute arbitrary commands through a carefully constructed payload

CVE-2022-28577: It is found that there is a command injection vulnerability in the delParentalRules interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28578: It is found that there is a command injection vulnerability in the setOpenVpnCfg interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28579: It is found that there is a command injection vulnerability in the setParentalRules interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28580: It is found that there is a command injection vulnerability in the setL2tpServerCfg interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28581: It is found that there is a command injection vulnerability in the setWiFiAdvancedCfg interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28582: It is found that there is a command injection vulnerability in the setWiFiSignalCfg interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28583: It is found that there is a command injection vulnerability in the setWiFiWpsCfg interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28584: It is found that there is a command injection vulnerability in the setWiFiWpsStart interface in TOTOlink A7100RU (v7.4cu.2313_b20191024) router, which allows an attacker to execute arbitrary commands through a carefully constructed payload.

CVE-2022-28895: A command injection vulnerability in the component /setnetworksettings/IPAddress of D-Link DIR882 DIR882A1_FW130B06 allows attackers to escalate privileges to root via a crafted payload.

CVE-2022-28896: A command injection vulnerability in the component /setnetworksettings/SubnetMask of D-Link DIR882 DIR882A1_FW130B06 allows attackers to escalate privileges to root via a crafted payload.

CVE-2022-29013: A command injection in the command parameter of Razer Sila Gaming Router v2.0.441_api-2.0.418 allows attackers to execute arbitrary commands via a crafted POST request.

CVE-2022-29256: sharp is an application for Node.js image processing. Prior to version 0.30.5, there is a possible vulnerability in logic that is run only at `npm install` time when installing versions of `sharp` prior to the latest v0.30.5. If an attacker has the ability to set the value of the `PKG_CONFIG_PATH` environment variable in a build environment then they might be able to use this to inject an arbitrary command at `npm install` time. This is not part of any runtime code, does not affect Windows users at all, and is unlikely to affect anyone that already cares about the security of their build environment. This problem is fixed in version 0.30.5.

CVE-2022-29303: SolarView Compact ver.6.00 was discovered to contain a command injection vulnerability via conf_mail.php.

CVE-2022-29337: C-DATA FD702XW-X-R430 v2.1.13_X001 was discovered to contain a command injection vulnerability via the va_cmd parameter in formlanipv6. This vulnerability allows attackers to execute arbitrary commands via a crafted HTTP request.

CVE-2022-30023: Tenda ONT GPON AC1200 Dual band WiFi HG9 v1.0.1 is vulnerable to Command Injection via the Ping function.

CVE-2022-30079: Command injection vulnerability was discovered in Netgear R6200 v2 firmware through R6200v2-V1.0.3.12 via binary /sbin/acos_service that could allow remote authenticated attackers the ability to modify values in the vulnerable parameter.

CVE-2022-3008: The tinygltf library uses the C library function wordexp() to perform file path expansion on untrusted paths that are provided from the input file. This function allows for command injection by using backticks. An attacker could craft an untrusted path input that would result in a path expansion. We recommend upgrading to 2.6.0 or past commit 52ff00a38447f06a17eab1caa2cf0730a119c751

CVE-2022-31311: An issue in adm.cgi of WAVLINK AERIAL X 1200M M79X3.V5030.180719 allows attackers to execute arbitrary commands via a crafted POST request.

CVE-2022-32092: D-Link DIR-645 v1.03 was discovered to contain a command injection vulnerability via the QUERY_STRING parameter at __ajax_explorer.sgi.

CVE-2022-33941: PowerCMS XMLRPC API provided by Alfasado Inc. contains a command injection vulnerability. Sending a specially crafted message by POST method to PowerCMS XMLRPC API may allow arbitrary Perl script execution, and an arbitrary OS command may be executed through it. Affected products/versions are as follows: PowerCMS 6.021 and earlier (PowerCMS 6 Series), PowerCMS 5.21 and earlier (PowerCMS 5 Series), and PowerCMS 4.51 and earlier (PowerCMS 4 Series). Note that all versions of PowerCMS 3 Series and earlier which are unsupported (End-of-Life, EOL) are also affected by this vulnerability.

CVE-2022-34527: D-Link DSL-3782 v1.03 and below was discovered to contain a command injection vulnerability via the function byte_4C0160.

CVE-2022-34538: Digital Watchdog DW MEGApix IP cameras A7.2.2_20211029 was discovered to contain a command injection vulnerability in the component /admin/vca/bia/addacph.cgi. This vulnerability is exploitable via a crafted POST request.

CVE-2022-34539: Digital Watchdog DW MEGApix IP cameras A7.2.2_20211029 was discovered to contain a command injection vulnerability in the component /admin/curltest.cgi. This vulnerability is exploitable via a crafted POST request.

CVE-2022-34540: Digital Watchdog DW MEGApix IP cameras A7.2.2_20211029 was discovered to contain a command injection vulnerability in the component /admin/vca/license/license_tok.cgi. This vulnerability is exploitable via a crafted POST request.

CVE-2022-34595: Tenda AX1803 v1.0.0.1_2890 was discovered to contain a command injection vulnerability via the function setipv6status.

CVE-2022-34596: Tenda AX1803 v1.0.0.1_2890 was discovered to contain a command injection vulnerability via the function WanParameterSetting.

CVE-2022-34597: Tenda AX1806 v1.0.0.1 was discovered to contain a command injection vulnerability via the function WanParameterSetting.

CVE-2022-35555: A command injection vulnerability exists in /goform/exeCommand in Tenda W6 V1.0.0.9(4122), which allows attackers to construct cmdinput parameters for arbitrary command execution.

CVE-2022-36273: Tenda AC9 V15.03.2.21_cn is vulnerable to command injection via goform/SetSysTimeCfg.

CVE-2022-36455: TOTOLink A3600R V4.1.2cu.5182_B20201102 was discovered to contain a command injection vulnerability via the username parameter in /cstecgi.cgi.

CVE-2022-36456: TOTOLink A720R V4.1.5cu.532_B20210610 was discovered to contain a command injection vulnerability via the username parameter in /cstecgi.cgi.

CVE-2022-36458: TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the command parameter in the function setTracerouteCfg.

CVE-2022-36459: TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the host_time parameter in the function NTPSyncWithHost.

CVE-2022-36460: TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the FileName parameter in the function UploadFirmwareFile.

CVE-2022-36461: TOTOLINK A3700R V9.1.2u.6134_B20201202 was discovered to contain a command injection vulnerability via the hostName parameter in the function setOpModeCfg.

CVE-2022-36479: TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the host_time parameter in the function NTPSyncWithHost.

CVE-2022-36481: TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the ip parameter in the function setDiagnosisCfg.

CVE-2022-36485: TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the hostName parameter in the function setOpModeCfg.

CVE-2022-36486: TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the FileName parameter in the function UploadFirmwareFile.

CVE-2022-36487: TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the command parameter in the function setTracerouteCfg.

CVE-2022-36509: H3C GR3200 MiniGR1B0V100R014 was discovered to contain a command injection vulnerability via the param parameter at DelL2tpLNSList.

CVE-2022-36510: H3C GR2200 MiniGR1A0V100R014 was discovered to contain a command injection vulnerability via the param parameter at DelL2tpLNSList.

CVE-2022-36633: Teleport 9.3.6 is vulnerable to Command injection leading to Remote Code Execution. An attacker can craft a malicious ssh agent installation link by URL encoding a bash escape with carriage return line feed. This url encoded payload can be used in place of a token and sent to a user in a social engineering attack. This is fully unauthenticated attack utilizing the trusted teleport server to deliver the payload.

CVE-2022-36749: RPi-Jukebox-RFID v2.3.0 was discovered to contain a command injection vulnerability via the component /htdocs/utils/Files.php. This vulnerability is exploited via a crafted payload injected into the file name of an uploaded file.

CVE-2022-36962: SolarWinds Platform was susceptible to Command Injection. This vulnerability allows a remote adversary with complete control over the SolarWinds database to execute arbitrary commands.

CVE-2022-37056: D-Link GO-RT-AC750 GORTAC750_revA_v101b03 and GO-RT-AC750_revB_FWv200b02 is vulnerable to Command Injection via /cgibin, hnap_main,

CVE-2022-37057: D-Link Go-RT-AC750 GORTAC750_revA_v101b03 and GO-RT-AC750_revB_FWv200b02 are vulnerable to Command Injection via cgibin, ssdpcgi_main.

CVE-2022-37070: H3C GR-1200W MiniGRW1A0V100R006 was discovered to contain a command injection vulnerability via the param parameter at DelL2tpLNSList.

CVE-2022-37076: TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the FileName parameter in the function UploadFirmwareFile.

CVE-2022-37079: TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the hostName parameter in the function setOpModeCfg.

CVE-2022-37081: TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the command parameter at setting/setTracerouteCfg.

CVE-2022-37082: TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the host_time parameter at the function NTPSyncWithHost.

CVE-2022-37083: TOTOLINK A7000R V9.1.0u.6115_B20201022 was discovered to contain a command injection vulnerability via the ip parameter at the function setDiagnosisCfg.

CVE-2022-37123: D-link DIR-816 A2_v1.10CNB04.img is vulnerable to Command injection via /goform/form2userconfig.cgi.

CVE-2022-37129: D-Link DIR-816 A2_v1.10CNB04.img is vulnerable to Command Injection via /goform/SystemCommand. After the user passes in the command parameter, it will be spliced into byte_4836B0 by snprintf, and finally doSystem(&byte_4836B0); will be executed, resulting in a command injection.

CVE-2022-37130: In D-Link DIR-816 A2_v1.10CNB04, DIR-878 DIR_878_FW1.30B08.img a command injection vulnerability occurs in /goform/Diagnosis, after the condition is met, setnum will be spliced into v10 by snprintf, and the system will be executed, resulting in a command injection vulnerability

CVE-2022-37149: WAVLINK WL-WN575A3 RPT75A3.V4300.201217 was discovered to contain a command injection vulnerability when operating the file adm.cgi. This vulnerability allows attackers to execute arbitrary commands via the username parameter.

CVE-2022-37718: The management portal component of JetNexus/EdgeNexus ADC 4.2.8 was discovered to contain a command injection vulnerability. This vulnerability allows authenticated attackers to execute arbitrary commands through a specially crafted payload. This vulnerability can also be exploited from an unauthenticated context via unspecified vectors

CVE-2022-37810: Tenda AC1206 V15.03.06.23 was discovered to contain a command injection vulnerability via the mac parameter in the function formWriteFacMac.

CVE-2022-37860: The web configuration interface of the TP-Link M7350 V3 with firmware version 190531 is affected by a pre-authentication command injection vulnerability.

CVE-2022-37878: Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. A successful exploit could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): 6.10.x: 6.10.6 and below; 6.9.x: 6.9.11 and below. Aruba has released upgrades for Aruba ClearPass Policy Manager that address these security vulnerabilities.

CVE-2022-37893: An authenticated command injection vulnerability exists in the Aruba InstantOS and ArubaOS 10 command line interface. Successful exploitation of this vulnerability results in the ability to execute arbitrary commands as a privileged user on the underlying operating system of Aruba InstantOS 6.4.x: 6.4.4.8-4.2.4.20 and below; Aruba InstantOS 6.5.x: 6.5.4.23 and below; Aruba InstantOS 8.6.x: 8.6.0.18 and below; Aruba InstantOS 8.7.x: 8.7.1.9 and below; Aruba InstantOS 8.10.x: 8.10.0.1 and below; ArubaOS 10.3.x: 10.3.1.0 and below; Aruba has released upgrades for Aruba InstantOS that address this security vulnerability.

CVE-2022-37897: There is a command injection vulnerability that could lead to unauthenticated remote code execution by sending specially crafted packets destined to the PAPI (Aruba Networks AP management protocol) UDP port (8211). Successful exploitation of this vulnerability results in the ability to execute arbitrary code as a privileged user on the underlying operating system. 

CVE-2022-37898: Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities results in the ability to execute arbitrary commands as a privileged user on the underlying operating system. 

CVE-2022-37899: Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities results in the ability to execute arbitrary commands as a privileged user on the underlying operating system. 

CVE-2022-37900: Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities results in the ability to execute arbitrary commands as a privileged user on the underlying operating system. 

CVE-2022-37901: Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities results in the ability to execute arbitrary commands as a privileged user on the underlying operating system. 

CVE-2022-37902: Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities results in the ability to execute arbitrary commands as a privileged user on the underlying operating system. 

CVE-2022-37912: Authenticated command injection vulnerabilities exist in the ArubaOS command line interface. Successful exploitation of these vulnerabilities results in the ability to execute arbitrary commands as a privileged user on the underlying operating system. 

CVE-2022-38308: TOTOLink A700RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the lang parameter in the function cstesystem. This vulnerability allows attackers to execute arbitrary commands via a crafted payload.

CVE-2022-38511: TOTOLINK A810R V5.9c.4050_B20190424 was discovered to contain a command injection vulnerability via the component downloadFile.cgi.

CVE-2022-38531: FPT G-97RG6M R4.2.98.035 and G-97RG3 R4.2.43.078 are vulnerable to Remote Command Execution in the ping function.

CVE-2022-38534: TOTOLINK-720R v4.1.5cu.374 was discovered to contain a remote code execution (RCE) vulnerability via the setdiagnosicfg function.

CVE-2022-38535: TOTOLINK-720R v4.1.5cu.374 was discovered to contain a remote code execution (RCE) vulnerability via the setTracerouteCfg function.

CVE-2022-38826: In TOTOLINK T6 V4.1.5cu.709_B20210518, there is an execute arbitrary command in cstecgi.cgi.

CVE-2022-38828: TOTOLINK T6 V4.1.5cu.709_B20210518 is vulnerable to command injection via cstecgi.cgi

CVE-2022-40475: TOTOLINK A860R V4.1.2cu.5182_B20201027 was discovered to contain a command injection via the component /cgi-bin/downloadFile.cgi.

CVE-2022-40929: XXL-JOB 2.2.0 has a Command execution vulnerability in background tasks. NOTE: this is disputed because the issues/4929 report is about an intended and supported use case (running arbitrary Bash scripts on behalf of users).

CVE-2022-41518: TOTOLINK NR1800X V9.1.0u.6279_B20210910 was discovered to contain a command injection vulnerability via the UploadFirmwareFile function at /cgi-bin/cstecgi.cgi.

CVE-2022-41955: Autolab is a course management service, initially developed by a team of students at Carnegie Mellon University, that enables instructors to offer autograded programming assignments to their students over the Web. A remote code execution vulnerability was discovered in Autolab's MOSS functionality, whereby an instructor with access to the feature might be able to execute code on the server hosting Autolab. This vulnerability has been patched in version 2.10.0. As a workaround, disable the MOSS feature if it is unneeded by replacing the body of `run_moss` in `app/controllers/courses_controller.rb` with `render(plain: "Feature disabled", status: :bad_request) && return`.

CVE-2022-42999: D-Link DIR-816 A2 1.10 B05 was discovered to contain multiple command injection vulnerabilities via the admuser and admpass parameters at /goform/setSysAdm.

CVE-2022-43184: D-Link DIR878 1.30B08 Hotfix_04 was discovered to contain a command injection vulnerability via the component /bin/proc.cgi.

CVE-2022-43536: Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. Successful exploits could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below. 

CVE-2022-43537: Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. Successful exploits could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below. 

CVE-2022-43538: Vulnerabilities in the ClearPass Policy Manager web-based management interface allow remote authenticated users to run arbitrary commands on the underlying host. Successful exploits could allow an attacker to execute arbitrary commands as root on the underlying operating system leading to complete system compromise in Aruba ClearPass Policy Manager version(s): ClearPass Policy Manager 6.10.x: 6.10.7 and below and ClearPass Policy Manager 6.9.x: 6.9.12 and below. 

CVE-2022-4364: A vulnerability classified as critical has been found in Teledyne FLIR AX8 up to 1.46.16. Affected is an unknown function of the file palette.php of the component Web Service Handler. The manipulation of the argument palette leads to command injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-215118 is the identifier assigned to this vulnerability.

CVE-2022-44249: TOTOLINK NR1800X V9.1.0u.6279_B20210910 contains a command injection via the FileName parameter in the UploadFirmwareFile function.

CVE-2022-44250: TOTOLINK NR1800X V9.1.0u.6279_B20210910 contains a command injection via the hostName parameter in the setOpModeCfg function.

CVE-2022-44251: TOTOLINK NR1800X V9.1.0u.6279_B20210910 contains a command injection via the ussd parameter in the setUssd function.

CVE-2022-44252: TOTOLINK NR1800X V9.1.0u.6279_B20210910 contains a command injection via the FileName parameter in the setUploadSetting function.

CVE-2022-44843: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the port parameter in the setting/setOpenVpnClientCfg function.

CVE-2022-44844: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the pass parameter in the setting/setOpenVpnCfg function.

CVE-2022-44928: D-Link DVG-G5402SP GE_1.03 was discovered to contain a command injection vulnerability via the Maintenance function.

CVE-2022-44930: D-Link DHP-W310AV 3.10EU was discovered to contain a command injection vulnerability via the System Checks function.

CVE-2022-45005: IP-COM EW9 V15.11.0.14(9732) was discovered to contain a command injection vulnerability in the cmd_get_ping_output function.

CVE-2022-45025: Markdown Preview Enhanced v0.6.5 and v0.19.6 for VSCode and Atom was discovered to contain a command injection vulnerability via the PDF file import function.

CVE-2022-45043: Tenda AX12 V22.03.01.16_cn is vulnerable to command injection via goform/fast_setting_internet_set.

CVE-2022-45497: Tenda W6-S v1.0.0.4(510) was discovered to contain a command injection vulnerability in the tpi_get_ping_output function at /goform/exeCommand.

CVE-2022-45506: Tenda W30E v1.0.1.25(633) was discovered to contain a command injection vulnerability via the fileNameMit parameter at /goform/delFileName.

CVE-2022-45699: Command injection in the administration interface in APSystems ECU-R version 5203 allows a remote unauthenticated attacker to execute arbitrary commands as root using the timezone parameter.

CVE-2022-45717: IP-COM M50 V15.11.0.33(10768) was discovered to contain a command injection vulnerability via the usbPartitionName parameter in the formSetUSBPartitionUmount function. This vulnerability is exploited via a crafted GET request.

CVE-2022-45768: Command Injection vulnerability in Edimax Technology Co., Ltd. Wireless Router N300 Firmware BR428nS v3 allows attacker to execute arbitrary code via the formWlanMP function.

CVE-2022-45977: Tenda AX12 V22.03.01.21_CN was found to have a command injection vulnerability via /goform/setMacFilterCfg function.

CVE-2022-45996: Tenda W20E V16.01.0.6(3392) is vulnerable to Command injection via cmd_get_ping_output.

CVE-2022-46476: D-Link DIR-859 A1 1.05 was discovered to contain a command injection vulnerability via the service= variable in the soapcgi_main function.

CVE-2022-46538: Tenda F1203 V2.0.1.6 was discovered to contain a command injection vulnerability via the mac parameter at /goform/WriteFacMac.

CVE-2022-46631: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the wscDisabled parameter in the setting/setWiFiSignalCfg function.

CVE-2022-46634: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the wscDisabled parameter in the setting/setWiFiWpsCfg function.

CVE-2022-47210: The default console presented to users over telnet (when enabled) is restricted to a subset of commands. Commands issued at this console, however, appear to be fed directly into a system call or other similar function. This allows any authenticated user to execute arbitrary commands on the device.

CVE-2022-47853: TOTOlink A7100RU V7.4cu.2313_B20191024 is vulnerable to Command Injection Vulnerability in the httpd service. An attacker can obtain a stable root shell through a specially constructed payload.

CVE-2022-48107: D-Link DIR_878_FW1.30B08 was discovered to contain a command injection vulnerability via the component /setnetworksettings/IPAddress. This vulnerability allows attackers to escalate privileges to root via a crafted payload.

CVE-2022-48108: D-Link DIR_878_FW1.30B08 was discovered to contain a command injection vulnerability via the component /SetNetworkSettings/SubnetMask. This vulnerability allows attackers to escalate privileges to root via a crafted payload.

CVE-2022-48121: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the rsabits parameter in the setting/delStaticDhcpRules function.

CVE-2022-48122: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the dayvalid parameter in the setting/delStaticDhcpRules function.

CVE-2022-48123: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the servername parameter in the setting/delStaticDhcpRules function.

CVE-2022-48124: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the FileName parameter in the setting/setOpenVpnCertGenerationCfg function.

CVE-2022-48125: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the password parameter in the setting/setOpenVpnCertGenerationCfg function.

CVE-2022-48126: TOTOlink A7100RU V7.4cu.2313_B20191024 was discovered to contain a command injection vulnerability via the username parameter in the setting/setOpenVpnCertGenerationCfg function.

CVE-2022-28901: A command injection vulnerability in the component /SetTriggerLEDBlink/Blink of D-Link DIR882 DIR882A1_FW130B06 allows attackers to escalate privileges to root via a crafted payload.

CVE-2022-28905: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the devicemac parameter in /setting/setDeviceName.

CVE-2022-28906: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the langtype parameter in /setting/setLanguageCfg.

CVE-2022-28907: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the hosttime function in /setting/NTPSyncWithHost.

CVE-2022-28908: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the ipdoamin parameter in /setting/setDiagnosisCfg.

CVE-2022-28909: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the webwlanidx parameter in /setting/setWebWlanIdx.

CVE-2022-28910: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the devicename parameter in /setting/setDeviceName.

CVE-2022-28911: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the filename parameter in /setting/CloudACMunualUpdate.

CVE-2022-28912: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the filename parameter in /setting/setUpgradeFW.

CVE-2022-28913: TOTOLink N600R V5.3c.7159_B20190425 was discovered to contain a command injection vulnerability via the filename parameter in /setting/setUploadSetting.

CVE-2022-28915: D-Link DIR-816 A2_v1.10CNB04 was discovered to contain a command injection vulnerability via the admuser and admpass parameters in /goform/setSysAdm.

CVE-2022-31446: Tenda AC18 router V15.03.05.19 and V15.03.05.05 was discovered to contain a remote code execution (RCE) vulnerability via the Mac parameter at ip/goform/WriteFacMac.

CVE-2022-3492: A vulnerability classified as critical was found in SourceCodester Human Resource Management System 1.0. This vulnerability affects unknown code of the component Profile Photo Handler. The manipulation of the argument parameter leads to os command injection. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210772.

CVE-2022-26207: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function setDiagnosisCfg, via the ipDoamin parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26208: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function setWebWlanIdx, via the webWlanIdx parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26209: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function setUploadSetting, via the FileName parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26210: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function setUpgradeFW, via the FileName parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26211: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function CloudACMunualUpdate, via the deviceMac and deviceName parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26212: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function setDeviceName, via the deviceMac and deviceName parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26213: Totolink X5000R_Firmware v9.1.0u.6118_B20201102 was discovered to contain a command injection vulnerability in the function setNtpCfg, via the tz parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26214: Totolink A830R V5.9c.4729_B20191112, A3100R V4.1.2cu.5050_B20200504, A950RG V4.1.2cu.5161_B20200903, A800R V4.1.2cu.5137_B20200730, A3000RU V5.9c.5185_B20201128, and A810R V4.1.2cu.5182_B20201026 were discovered to contain a command injection vulnerability in the function NTPSyncWithHost. This vulnerability allows attackers to execute arbitrary commands via the host_time parameter.

CVE-2022-26265: Contao Managed Edition v1.5.0 was discovered to contain a remote command execution (RCE) vulnerability via the component php_cli parameter.

CVE-2022-26992: Arris routers SBR-AC1900P 1.0.7-B05, SBR-AC3200P 1.0.7-B05 and SBR-AC1200P 1.0.5-B05 were discovered to contain a command injection vulnerability in the ddns function via the DdnsUserName, DdnsHostName, and DdnsPassword parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26993: Arris routers SBR-AC1900P 1.0.7-B05, SBR-AC3200P 1.0.7-B05 and SBR-AC1200P 1.0.5-B05 were discovered to contain a command injection vulnerability in the pppoe function via the pppoeUserName, pppoePassword, and pppoe_Service parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-26994: Arris routers SBR-AC1900P 1.0.7-B05, SBR-AC3200P 1.0.7-B05 and SBR-AC1200P 1.0.5-B05 were discovered to contain a command injection vulnerability in the pptp function via the pptpUserName and pptpPassword parameters. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27003: Totolink routers s X5000R V9.1.0u.6118_B20201102 and A7000R V9.1.0u.6115_B20201022 were discovered to contain a command injection vulnerability in the Tunnel 6rd function via the relay6rd parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27004: Totolink routers s X5000R V9.1.0u.6118_B20201102 and A7000R V9.1.0u.6115_B20201022 were discovered to contain a command injection vulnerability in the Tunnel 6in4 function via the remote6in4 parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2022-27005: Totolink routers s X5000R V9.1.0u.6118_B20201102 and A7000R V9.1.0u.6115_B20201022 were discovered to contain a command injection vulnerability in the setWanCfg function via the hostName parameter. This vulnerability allows attackers to execute arbitrary commands via a crafted request.

CVE-2021-43033: An issue was discovered in Kaseya Unitrends Backup Appliance before 10.5.5. Multiple functions in the bpserverd daemon were vulnerable to arbitrary remote code execution as root. The vulnerability was caused by untrusted input (received by the server) being passed to system calls.

CVE-2022-26582: PAX A930 device with PayDroid_7.1.1_Virgo_V04.3.26T1_20210419 can allow an attacker to gain root access through command injection in systool client. The attacker must have shell access to the device in order to exploit this vulnerability.

# CWE-780 Use of RSA Algorithm without OAEP

## Description

The product uses the RSA algorithm but does not incorporate Optimal Asymmetric Encryption Padding (OAEP), which might weaken the encryption.

Padding schemes are often used with cryptographic algorithms to make the plaintext less predictable and complicate attack efforts. The OAEP scheme is often used with RSA to nullify the impact of predictable common text.

## Top 25 Examples

CVE-2022-25218: The use of the RSA algorithm without OAEP, or any other padding scheme, in telnetd_startup, allows an unauthenticated attacker on the local area network to achieve a significant degree of control over the "plaintext" to which an arbitrary blob of ciphertext will be decrypted by OpenSSL's RSA_public_decrypt() function. This weakness allows the attacker to manipulate the various iterations of the telnetd startup state machine and eventually obtain a root shell on the device, by means of an exchange of crafted UDP packets. In all versions but K2 22.5.9.163 and K3C 32.1.15.93 a successful attack also requires the exploitation of a null-byte interaction error (CVE-2022-25219).

# CWE-781 Improper Address Validation in IOCTL with METHOD_NEITHER I/O Control Code

## Description

The product defines an IOCTL that uses METHOD_NEITHER for I/O, but it does not validate or incorrectly validates the addresses that are provided.

When an IOCTL uses the METHOD_NEITHER option for I/O control, it is the responsibility of the IOCTL to validate the addresses that have been supplied to it. If validation is missing or incorrect, attackers can supply arbitrary memory addresses, leading to code execution or a denial of service.

## Observed Examples

CVE-2006-2373: Driver for file-sharing and messaging protocol allows attackers to execute arbitrary code.

CVE-2009-0686: Anti-virus product does not validate addresses, allowing attackers to gain SYSTEM privileges.

CVE-2009-0824: DVD software allows attackers to cause a crash.

CVE-2008-5724: Personal firewall allows attackers to gain SYSTEM privileges.

CVE-2007-5756: chain: device driver for packet-capturing software allows access to an unintended IOCTL with resultant array index error.

# CWE-782 Exposed IOCTL with Insufficient Access Control

## Description

The product implements an IOCTL with functionality that should be restricted, but it does not properly enforce access control for the IOCTL.

When an IOCTL contains privileged functionality and is exposed unnecessarily, attackers may be able to access this functionality by invoking the IOCTL. Even if the functionality is benign, if the programmer has assumed that the IOCTL would only be accessed by a trusted process, there may be little or no validation of the incoming data, exposing weaknesses that would never be reachable if the attacker cannot call the IOCTL directly.


The implementations of IOCTLs will differ between operating system types and versions, so the methods of attack and prevention may vary widely.

## Observed Examples

CVE-2009-2208: Operating system does not enforce permissions on an IOCTL that can be used to modify network settings.

CVE-2008-3831: Device driver does not restrict ioctl calls to its direct rendering manager.

CVE-2008-3525: ioctl does not check for a required capability before processing certain requests.

CVE-2008-0322: Chain: insecure device permissions allows access to an IOCTL, allowing arbitrary memory to be overwritten.

CVE-2007-4277: Chain: anti-virus product uses weak permissions for a device, leading to resultant buffer overflow in an exposed IOCTL.

CVE-2007-1400: Chain: sandbox allows opening of a TTY device, enabling shell commands through an exposed ioctl.

CVE-2006-4926: Anti-virus product uses insecure security descriptor for a device driver, allowing access to a privileged IOCTL.

CVE-1999-0728: Unauthorized user can disable keyboard or mouse by directly invoking a privileged IOCTL.

## Top 25 Examples

CVE-2021-21551: Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required. 

CVE-2022-38582: Incorrect access control in the anti-virus driver wsdkd.sys of Watchdog Antivirus v1.4.158 allows attackers to write arbitrary files.

CVE-2021-44852: An issue was discovered in BS_RCIO64.sys in Biostar RACING GT Evo 2.1.1905.1700. A low-integrity process can open the driver's device object and issue IOCTLs to read or write to arbitrary physical memory locations (or call an arbitrary address), leading to execution of arbitrary code. This is associated with 0x226040, 0x226044, and 0x226000.

# CWE-783 Operator Precedence Logic Error

## Description

The product uses an expression in which operator precedence causes incorrect logic to be used.

While often just a bug, operator precedence logic errors can have serious consequences if they are used in security-critical code, such as making an authentication decision.

## Observed Examples

CVE-2008-2516: Authentication module allows authentication bypass because it uses "(x = call(args) == SUCCESS)" instead of "((x = call(args)) == SUCCESS)".

CVE-2008-0599: Chain: Language interpreter calculates wrong buffer size (CWE-131) by using "size = ptr ? X : Y" instead of "size = (ptr ? X : Y)" expression.

CVE-2001-1155: Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence (CWE-783), allowing bypass of DNS-based access restrictions.

# CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision

## Description

The product uses a protection mechanism that relies on the existence or values of a cookie, but it does not properly ensure that the cookie is valid for the associated user.

Attackers can easily modify cookies, within the browser or by implementing the client-side code outside of the browser. Attackers can bypass protection mechanisms such as authorization and authentication by modifying the cookie to contain an expected value.

## Observed Examples

CVE-2009-1549: Attacker can bypass authentication by setting a cookie to a specific value.

CVE-2009-1619: Attacker can bypass authentication and gain admin privileges by setting an "admin" cookie to 1.

CVE-2009-0864: Content management system allows admin privileges by setting a "login" cookie to "OK."

CVE-2008-5784: e-dating application allows admin privileges by setting the admin cookie to 1.

CVE-2008-6291: Web-based email list manager allows attackers to gain admin privileges by setting a login cookie to "admin."

## Top 25 Examples

CVE-2022-38297: UCMS v1.6.0 contains an authentication bypass vulnerability which is exploited via cookie poisoning.

CVE-2022-3083: All versions of Landis+Gyr E850 (ZMQ200) are vulnerable to CWE-784: Reliance on Cookies Without Validation and Integrity. The device's web application navigation depends on the value of the session cookie. The web application could become inaccessible for the user if an attacker changes the cookie values. 

CVE-2022-30620: On Cellinx Camera with guest enabled, attacker with web access can elevate privileges to administrative: "1" to "0" privileges by changing the following cookie values from "is_admin", "showConfig". Administrative Privileges which allows changing various configuration in the camera.

CVE-2022-29248: Guzzle is a PHP HTTP client. Guzzle prior to versions 6.5.6 and 7.4.3 contains a vulnerability with the cookie middleware. The vulnerability is that it is not checked if the cookie domain equals the domain of the server which sets the cookie via the Set-Cookie header, allowing a malicious server to set cookies for unrelated domains. The cookie middleware is disabled by default, so most library consumers will not be affected by this issue. Only those who manually add the cookie middleware to the handler stack or construct the client with ['cookies' => true] are affected. Moreover, those who do not use the same Guzzle client to call multiple domains and have disabled redirect forwarding are not affected by this vulnerability. Guzzle versions 6.5.6 and 7.4.3 contain a patch for this issue. As a workaround, turn off the cookie middleware.

# CWE-785 Use of Path Manipulation Function without Maximum-sized Buffer

## Description

The product invokes a function for normalizing paths or file names, but it provides an output buffer that is smaller than the maximum possible size, such as PATH_MAX.

Passing an inadequately-sized output buffer to a path manipulation function can result in a buffer overflow. Such functions include realpath(), readlink(), PathAppend(), and others.

Windows provides a large number of utility functions that manipulate buffers containing filenames. In most cases, the result is returned in a buffer that is passed in as input. (Usually the filename is modified in place.) Most functions require the buffer to be at least MAX_PATH bytes in length, but you should check the documentation for each function individually. If the buffer is not large enough to store the result of the manipulation, a buffer overflow can occur.

# CWE-786 Access of Memory Location Before Start of Buffer

## Description

The product reads or writes to a buffer using an index or pointer that references a memory location prior to the beginning of the buffer.

This typically occurs when a pointer or its index is decremented to a position before the buffer, when pointer arithmetic results in a position before the beginning of the valid memory location, or when a negative index is used.

## Observed Examples

CVE-2002-2227: Unchecked length of SSLv2 challenge value leads to buffer underflow.

CVE-2007-4580: Buffer underflow from a small size value with a large buffer (length parameter inconsistency, CWE-130)

CVE-2007-1584: Buffer underflow from an all-whitespace string, which causes a counter to be decremented before the buffer while looking for a non-whitespace character.

CVE-2007-0886: Buffer underflow resultant from encoded data that triggers an integer overflow.

CVE-2006-6171: Product sets an incorrect buffer size limit, leading to "off-by-two" buffer underflow.

CVE-2006-4024: Negative value is used in a memcpy() operation, leading to buffer underflow.

CVE-2004-2620: Buffer underflow due to mishandled special characters

## Top 25 Examples

CVE-2022-0351: Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.

# CWE-787 Out-of-bounds Write

## Description

The product writes data past the end, or before the beginning, of the intended buffer.

## Observed Examples

CVE-2021-21220: Chain: insufficient input validation (CWE-20) in browser allows heap corruption (CWE-787), as exploited in the wild per CISA KEV.

CVE-2021-28664: GPU kernel driver allows memory corruption because a user can obtain read/write access to read-only pages, as exploited in the wild per CISA KEV.

CVE-2020-17087: Chain: integer truncation (CWE-197) causes small buffer allocation (CWE-131) leading to out-of-bounds write (CWE-787) in kernel pool, as exploited in the wild per CISA KEV.

CVE-2020-1054: Out-of-bounds write in kernel-mode driver, as exploited in the wild per CISA KEV.

CVE-2020-0041: Escape from browser sandbox using out-of-bounds write due to incorrect bounds check, as exploited in the wild per CISA KEV.

CVE-2020-0968: Memory corruption in web browser scripting engine, as exploited in the wild per CISA KEV.

CVE-2020-0022: chain: mobile phone Bluetooth implementation does not include offset when calculating packet length (CWE-682), leading to out-of-bounds write (CWE-787)

CVE-2019-1010006: Chain: compiler optimization (CWE-733) removes or modifies code used to detect integer overflow (CWE-190), allowing out-of-bounds write (CWE-787).

CVE-2009-1532: malformed inputs cause accesses of uninitialized or previously-deleted objects, leading to memory corruption

CVE-2009-0269: chain: -1 value from a function call was intended to indicate an error, but is used as an array index instead.

CVE-2002-2227: Unchecked length of SSLv2 challenge value leads to buffer underflow.

CVE-2007-4580: Buffer underflow from a small size value with a large buffer (length parameter inconsistency, CWE-130)

CVE-2007-4268: Chain: integer signedness error (CWE-195) passes signed comparison, leading to heap overflow (CWE-122)

CVE-2009-2550: Classic stack-based buffer overflow in media player using a long entry in a playlist

CVE-2009-2403: Heap-based buffer overflow in media player using a long entry in a playlist

## Top 25 Examples

CVE-2021-0679: In apusys, there is a possible memory corruption due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05687781.

CVE-2021-21782: An out-of-bounds write vulnerability exists in the SGI format buffer size processing functionality of Accusoft ImageGear 19.8. A specially crafted malformed file can lead to memory corruption. An attacker can provide a malicious file to trigger this vulnerability.

CVE-2021-26384: A malformed SMI (System Management Interface) command may allow an attacker to establish a corrupted SMI Trigger Info data structure, potentially leading to out-of-bounds memory reads and writes when triggering an SMI resulting in a potential loss of resources.

CVE-2021-26386: A malicious or compromised UApp or ABL may be used by an attacker to issue a malformed system call to the Stage 2 Bootloader potentially leading to corrupt memory and code execution.

CVE-2021-38014: Out of bounds write in Swiftshader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-40161: A Memory Corruption vulnerability may lead to code execution through maliciously crafted DLL files through PDFTron earlier than 9.0.7 version.

CVE-2021-40393: An out-of-bounds write vulnerability exists in the RS-274X aperture macro variables handling functionality of Gerbv 2.7.0 and dev (commit b5f1eacd) and the forked version of Gerbv (commit 71493260). A specially-crafted gerber file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

CVE-2021-4129: Mozilla developers and community members Julian Hector, Randell Jesup, Gabriele Svelto, Tyson Smith, Christian Holler, and Masayuki Nakano reported memory safety bugs present in Firefox 94. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 95, Firefox ESR < 91.4.0, and Thunderbird < 91.4.0.

CVE-2021-42554: An issue was discovered in Insyde InsydeH2O with Kernel 5.0 before 05.08.42, Kernel 5.1 before 05.16.42, Kernel 5.2 before 05.26.42, Kernel 5.3 before 05.35.42, Kernel 5.4 before 05.42.51, and Kernel 5.5 before 05.50.51. An SMM memory corruption vulnerability in FvbServicesRuntimeDxe allows a possible attacker to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2021-42727: Adobe Bridge 11.1.1 (and earlier) is affected by a stack overflow vulnerability due to insecure handling of a crafted file, potentially resulting in arbitrary code execution in the context of the current user. Exploitation requires user interaction in that a victim must open a crafted file in Bridge.

CVE-2021-43215: iSNS Server Memory Corruption Vulnerability Can Lead to Remote Code Execution

CVE-2021-43522: An issue was discovered in Insyde InsydeH2O with kernel 5.1 through 2021-11-08, 5.2 through 2021-11-08, and 5.3 through 2021-11-08. A StorageSecurityCommandDxe SMM memory corruption vulnerability allows an attacker to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2021-43615: An issue was discovered in HddPassword in Insyde InsydeH2O with kernel 5.1 before 05.16.23, 5.2 before 05.26.23, 5.3 before 05.35.23, 5.4 before 05.43.22, and 5.5 before 05.51.22. An SMM memory corruption vulnerability allows an attacker to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2021-44488: An issue was discovered in YottaDB through r1.32 and V7.0-000. Using crafted input, attackers can control the size and input to calls to memcpy in op_fnfnumber in sr_port/op_fnfnumber.c in order to corrupt memory or crash the application.

CVE-2021-44828: Arm Mali GPU Kernel Driver (Midgard r26p0 through r30p0, Bifrost r0p0 through r34p0, and Valhall r19p0 through r34p0) allows a non-privileged user to achieve write access to read-only memory, and possibly obtain root privileges, corrupt memory, and modify the memory of other processes.

CVE-2022-0500: A flaw was found in unrestricted eBPF usage by the BPF_BTF_LOAD, leading to a possible out-of-bounds memory write in the Linux kernel’s BPF subsystem due to the way a user loads BTF. This flaw allows a local user to crash or escalate their privileges on the system.

CVE-2022-0797: Out of bounds memory access in Mojo in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page.

CVE-2022-20203: In multiple locations of the nanopb library, there is a possible way to corrupt memory when decoding untrusted protobuf files. This could lead to local escalation of privilege,with no additional execution privileges needed. User interaction is not needed for exploitation.

CVE-2022-20235: The PowerVR GPU kernel driver maintains an "Information Page" used by its cache subsystem. This page can only be written by the GPU driver itself, but prior to DDK 1.18 however, a user-space program could write arbitrary data to the page, leading to memory corruption issues.Product: AndroidVersions: Android SoCAndroid ID: A-259967780

CVE-2022-20600: In TBD of TBD, there is a possible out of bounds write due to memory corruption. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-239847859References: N/A

CVE-2022-21217: An out-of-bounds write vulnerability exists in the device TestEmail functionality of reolink RLC-410W v3.0.0.136_20121102. A specially-crafted network request can lead to an out-of-bounds write. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-21796: A memory corruption vulnerability exists in the netserver parse_command_list functionality of reolink RLC-410W v3.0.0.136_20121102. A specially-crafted HTTP request can lead to an out-of-bounds write. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-22088: Memory corruption in Bluetooth HOST due to buffer overflow while parsing the command response received from remote

CVE-2022-22100: Memory corruption in multimedia due to improper check on received export descriptors in Snapdragon Auto

CVE-2022-22610: A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.3, Safari 15.4, watchOS 8.5, iOS 15.4 and iPadOS 15.4, tvOS 15.4. Processing maliciously crafted web content may lead to code execution.

CVE-2022-22764: Mozilla developers Paul Adenot and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 96 and Firefox ESR 91.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 97, Thunderbird < 91.6, and Firefox ESR < 91.6.

CVE-2022-24030: An issue was discovered in AhciBusDxe in Insyde InsydeH2O with kernel 5.1 through 5.5. An SMM memory corruption vulnerability allows an attacker to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2022-24031: An issue was discovered in NvmExpressDxe in Insyde InsydeH2O with kernel 5.1 through 5.5. An SMM memory corruption vulnerability allows an attacker to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2022-24063: This vulnerability allows remote attackers to execute arbitrary code on affected installations of Sante DICOM Viewer Pro 13.2.0.21165. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of JP2 files. The issue results from the lack of proper validation of user-supplied data, which can result in a memory corruption condition. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-15105.

CVE-2022-24936: Out-of-Bounds error in GBL parser in Silicon Labs Gecko Bootloader version 4.0.1 and earlier allows attacker to overwrite flash Sign key and OTA decryption key via malicious bootloader upgrade.

CVE-2022-25959: Omron CX-Position (versions 2.5.3 and prior) is vulnerable to memory corruption while processing a specific project file, which may allow an attacker to execute arbitrary code.

CVE-2022-26700: A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 15.5, watchOS 8.6, iOS 15.5 and iPadOS 15.5, macOS Monterey 12.4, Safari 15.5. Processing maliciously crafted web content may lead to code execution.

CVE-2022-26716: A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, watchOS 8.6, macOS Monterey 12.4, Safari 15.5. Processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-26719: A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, watchOS 8.6, macOS Monterey 12.4, Safari 15.5. Processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2022-26762: A memory corruption issue was addressed with improved memory handling. This issue is fixed in macOS Monterey 12.4, iOS 15.5 and iPadOS 15.5. A malicious application may be able to execute arbitrary code with system privileges.

CVE-2022-29465: An out-of-bounds write vulnerability exists in the PSD Header processing memory allocation functionality of Accusoft ImageGear 20.0. A specially-crafted malformed file can lead to memory corruption. An attacker can provide a malicious file to trigger this vulnerability.

CVE-2022-30937: A vulnerability has been identified in EN100 Ethernet module DNP3 IP variant (All versions), EN100 Ethernet module IEC 104 variant (All versions), EN100 Ethernet module IEC 61850 variant (All versions < V4.37), EN100 Ethernet module Modbus TCP variant (All versions), EN100 Ethernet module PROFINET IO variant (All versions). Affected applications contains a memory corruption vulnerability while parsing specially crafted HTTP packets to /txtrace endpoint. This could allow an attacker to crash the affected application leading to a denial of service condition.

CVE-2022-30938: A vulnerability has been identified in EN100 Ethernet module DNP3 IP variant (All versions), EN100 Ethernet module IEC 104 variant (All versions), EN100 Ethernet module IEC 61850 variant (All versions < V4.40), EN100 Ethernet module Modbus TCP variant (All versions), EN100 Ethernet module PROFINET IO variant (All versions). Affected applications contains a memory corruption vulnerability while parsing specially crafted HTTP packets to /txtrace endpoint manupulating a specific argument. This could allow an attacker to crash the affected application leading to a denial of service condition

CVE-2022-31696: VMware ESXi contains a memory corruption vulnerability that exists in the way it handles a network socket. A malicious actor with local access to ESXi may exploit this issue to corrupt memory leading to an escape of the ESXi sandbox.

CVE-2022-31747: Mozilla developers Andrew McCreight, Nicolas B. Pierron, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 100 and Firefox ESR 91.9. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Thunderbird < 91.10, Firefox < 101, and Firefox ESR < 91.10.

CVE-2022-32796: A memory corruption issue was addressed with improved state management. This issue is fixed in macOS Monterey 12.5. An app may be able to execute arbitrary code with kernel privileges.

CVE-2022-32827: A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 16, macOS Ventura 13. An app may be able to cause a denial-of-service.

CVE-2022-32944: A memory corruption issue was addressed with improved state management. This issue is fixed in tvOS 16.1, iOS 15.7.1 and iPadOS 15.7.1, macOS Ventura 13, watchOS 9.1, iOS 16.1 and iPadOS 16, macOS Monterey 12.6.1, macOS Big Sur 11.7.1. An app may be able to execute arbitrary code with kernel privileges.

CVE-2022-33234: Memory corruption in video due to configuration weakness. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-37937: Pre-auth memory corruption in HPE Serviceguard

CVE-2022-40962: Mozilla developers Nika Layzell, Timothy Nikkel, Sebastian Hengst, Andreas Pehrson, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105.

CVE-2022-42820: A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 16.1 and iPadOS 16, macOS Ventura 13. An app may cause unexpected app termination or arbitrary code execution.

CVE-2022-42932: Mozilla developers Ashley Hale and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 105 and Firefox ESR 102.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 106, Firefox ESR < 102.4, and Thunderbird < 102.4.

CVE-2022-44789: A logical issue in O_getOwnPropertyDescriptor() in Artifex MuJS 1.0.0 through 1.3.x before 1.3.2 allows an attacker to achieve Remote Code Execution through memory corruption, via the loading of a crafted JavaScript file.

CVE-2022-45421: Mozilla developers Andrew McCreight and Gabriele Svelto reported memory safety bugs present in Thunderbird 102.4. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107.

CVE-2022-46878: Mozilla developers Randell Jesup, Valentin Gosu, Olli Pettay, and the Mozilla Fuzzing Team reported memory safety bugs present in Thunderbird 102.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 108, Firefox ESR < 102.6, and Thunderbird < 102.6.

CVE-2022-46879: Mozilla developers and community members Lukas Bernhard, Gabriele Svelto, Randell Jesup, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 107. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 108.

CVE-2022-46883: Mozilla developers Gabriele Svelto, Yulia Startsev, Andrew McCreight and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 106. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.<br />*Note*: This advisory was added on December 13th, 2022 after discovering it was inadvertently left out of the original advisory. The fix was included in the original release of Firefox 107. This vulnerability affects Firefox < 107.

CVE-2022-47935: A vulnerability has been identified in JT Open (All versions < V11.1.1.0), JT Utilities (All versions < V13.1.1.0), Solid Edge (All versions < V2023). The Jt1001.dll contains a memory corruption vulnerability while parsing specially crafted JT files. An attacker could leverage this vulnerability to execute code in the context of the current process. (ZDI-CAN-19078)

CVE-2022-47967: A vulnerability has been identified in Solid Edge (All versions < V2023 MP1). The DOCMGMT.DLL contains a memory corruption vulnerability that could be triggered while parsing files in different file formats such as PAR, ASM, DFT. This could allow an attacker to execute code in the context of the current process.

CVE-2022-47977: A vulnerability has been identified in JT Open (All versions < V11.2.3.0), JT Utilities (All versions < V13.2.3.0). The affected application contains a memory corruption vulnerability while parsing specially crafted JT files. This could allow an attacker to execute code in the context of the current process.

CVE-2021-1942: Improper handling of permissions of a shared memory region can lead to memory corruption in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables, Snapdragon Wired Infrastructure and Networking

CVE-2022-21882: Win32k Elevation of Privilege Vulnerability

CVE-2021-1732: Windows Win32k Elevation of Privilege Vulnerability

CVE-2021-28310: Win32k Elevation of Privilege Vulnerability

CVE-2021-30665: A memory corruption issue was addressed with improved state management. This issue is fixed in watchOS 7.4.1, iOS 14.5.1 and iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, macOS Big Sur 11.3.1. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-30761: A memory corruption issue was addressed with improved state management. This issue is fixed in iOS 12.5.4. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-30807: A memory corruption issue was addressed with improved memory handling. This issue is fixed in macOS Big Sur 11.5.1, iOS 14.7.1 and iPadOS 14.7.1, watchOS 7.6.1. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited.

CVE-2021-30883: A memory corruption issue was addressed with improved memory handling. This issue is fixed in iOS 15.0.2 and iPadOS 15.0.2, macOS Monterey 12.0.1, iOS 14.8.1 and iPadOS 14.8.1, tvOS 15.1, watchOS 8.1, macOS Big Sur 11.6.1. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-34448: Scripting Engine Memory Corruption Vulnerability

CVE-2021-39793: In kbase_jd_user_buf_pin_pages of mali_kbase_mem.c, there is a possible out of bounds write due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-210470189References: N/A

CVE-2022-41073: Windows Print Spooler Elevation of Privilege Vulnerability

CVE-2022-41125: Windows CNG Key Isolation Service Elevation of Privilege Vulnerability

CVE-2022-41128: Windows Scripting Languages Remote Code Execution Vulnerability

CVE-2021-35211: Microsoft discovered a remote code execution (RCE) vulnerability in the SolarWinds Serv-U product utilizing a Remote Memory Escape Vulnerability. If exploited, a threat actor may be able to gain privileged access to the machine hosting Serv-U Only. SolarWinds Serv-U Managed File Transfer and Serv-U Secure FTP for Windows before 15.2.3 HF2 are affected by this vulnerability.

CVE-2022-32266: DMA attacks on the parameter buffer used by a software SMI handler used by the driver PcdSmmDxe could lead to a TOCTOU attack on the SMI handler and lead to corruption of other ACPI fields and adjacent memory fields. DMA attacks on the parameter buffer used by a software SMI handler used by the driver PcdSmmDxe could lead to a TOCTOU attack on the SMI handler and lead to corruption of other ACPI fields and adjacent memory fields. The attack would require detailed knowledge of the PCD database contents on the current platform. This issue was discovered by Insyde engineering during a security review. This issue is fixed in Kernel 5.3: 05.36.23, Kernel 5.4: 05.44.23, Kernel 5.5: 05.52.23. Kernel 5.2 is unaffected. CWE-787 An issue was discovered in Insyde InsydeH2O with kernel 5.0 through 5.5. DMA attacks on the parameter buffer that is used by a software SMI handler (used by the PcdSmmDxe driver) could lead to a TOCTOU race-condition attack on the SMI handler, and lead to corruption of other ACPI fields and adjacent memory fields. The attack would require detailed knowledge of the PCD database contents on the current platform.

CVE-2021-37571: MediaTek microchips, as used in NETGEAR devices through 2021-11-11 and other devices, mishandle IEEE 1905 protocols. (Affected Chipsets MT7603E, MT7613, MT7615, MT7622, MT7628, MT7629, MT7915; Affected Software Versions 2.0.2; Out-of-bounds write).

CVE-2022-35086: SWFTools commit 772e55a2 was discovered to contain a segmentation violation via /multiarch/memmove-vec-unaligned-erms.S.

CVE-2022-35101: SWFTools commit 772e55a2 was discovered to contain a segmentation violation via /multiarch/memset-vec-unaligned-erms.S.

# CWE-788 Access of Memory Location After End of Buffer

## Description

The product reads or writes to a buffer using an index or pointer that references a memory location after the end of the buffer.

This typically occurs when a pointer or its index is incremented to a position after the buffer; or when pointer arithmetic results in a position after the buffer.

## Observed Examples

CVE-2009-2550: Classic stack-based buffer overflow in media player using a long entry in a playlist

CVE-2009-2403: Heap-based buffer overflow in media player using a long entry in a playlist

CVE-2009-0689: large precision value in a format string triggers overflow

CVE-2009-0558: attacker-controlled array index leads to code execution

CVE-2008-4113: OS kernel trusts userland-supplied length value, allowing reading of sensitive information

CVE-2007-4268: Chain: integer signedness error (CWE-195) passes signed comparison, leading to heap overflow (CWE-122)

## Top 25 Examples

CVE-2021-39820: Adobe InDesign versions 16.3 (and earlier), and 16.3.1 (and earlier) is affected by an Out-of-bounds Write vulnerability due to insecure handling of a malicious TIFF file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40734: Adobe Audition version 14.4 (and earlier) is affected by a memory corruption vulnerability when parsing a SVG file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40735: Adobe Audition version 14.4 (and earlier) is affected by a memory corruption vulnerability, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40736: Adobe Audition version 14.4 (and earlier) is affected by a memory corruption vulnerability, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40738: Adobe Audition version 14.4 (and earlier) is affected by a memory corruption vulnerability when parsing a WAV file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40739: Adobe Audition version 14.4 (and earlier) is affected by a memory corruption vulnerability when parsing a M4A file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40740: Adobe Audition version 14.4 (and earlier) is affected by a memory corruption vulnerability when parsing a M4A file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40763: Adobe Character Animator version 4.4 (and earlier) is affected by a memory corruption vulnerability when parsing a WAF file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40764: Adobe Character Animator version 4.4 (and earlier) is affected by a memory corruption vulnerability when parsing a M4A file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40765: Adobe Character Animator version 4.4 (and earlier) is affected by a memory corruption vulnerability when parsing a M4A file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40777: Adobe Media Encoder version 15.4.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40779: Adobe Media Encoder version 15.4.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40780: Adobe Media Encoder version 15.4.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40783: Adobe Premiere Rush version 1.5.16 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious WAV file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40784: Adobe Premiere Rush version 1.5.16 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious WAV file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40786: Adobe Premiere Elements 20210809.daily.2242976 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40787: Adobe Premiere Elements 20210809.daily.2242976 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40792: Adobe Premiere Pro version 15.4.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40793: Adobe Premiere Pro version 15.4.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-40794: Adobe Premiere Pro version 15.4.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-42526: Adobe Premiere Elements 20210809.daily.2242976 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-42527: Adobe Premiere Elements 20210809.daily.2242976 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-42724: Adobe Bridge version 11.1.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-42725: Adobe Bridge version 11.1.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious M4A file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-42729: Adobe Bridge version 11.1.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious WAV file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-42730: Adobe Bridge version 11.1.1 (and earlier) is affected by a memory corruption vulnerability due to insecure handling of a malicious PSD file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-43754: Adobe Prelude version 22.1.1 (and earlier) is affected by an Out-of-bounds Write vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-43755: Adobe After Effects versions 22.0 (and earlier) and 18.4.2 (and earlier) are affected by an Out-of-bounds Write vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code execution in the context of the current user. User interaction is required to exploit this vulnerability.

CVE-2021-43756: Adobe Media Encoder versions 22.0, 15.4.2 (and earlier) are affected by an Out-of-bounds Write vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2022-0521: Access of Memory Location After End of Buffer in GitHub repository radareorg/radare2 prior to 5.6.2.

# CWE-789 Memory Allocation with Excessive Size Value

## Description

The product allocates memory based on an untrusted, large size value, but it does not ensure that the size is within expected limits, allowing arbitrary amounts of memory to be allocated.

## Observed Examples

CVE-2022-21668: Chain: Python library does not limit the resources used to process images that specify a very large number of bands (CWE-1284), leading to excessive memory consumption (CWE-789) or an integer overflow (CWE-190).

CVE-2010-3701: program uses ::alloca() for encoding messages, but large messages trigger segfault

CVE-2008-1708: memory consumption and daemon exit by specifying a large value in a length field

CVE-2008-0977: large value in a length field leads to memory consumption and crash when no more memory is available

CVE-2006-3791: large key size in game program triggers crash when a resizing function cannot allocate enough memory

CVE-2004-2589: large Content-Length HTTP header value triggers application crash in instant messaging application due to failure in memory allocation

## Top 25 Examples

CVE-2022-23524: Helm is a tool for managing Charts, pre-configured Kubernetes resources. Versions prior to 3.10.3 are subject to Uncontrolled Resource Consumption, resulting in Denial of Service. Input to functions in the _strvals_ package can cause a stack overflow. In Go, a stack overflow cannot be recovered from. Applications that use functions from the _strvals_ package in the Helm SDK can have a Denial of Service attack when they use this package and it panics. This issue has been patched in 3.10.3. SDK users can validate strings supplied by users won't create large arrays causing significant memory usage before passing them to the _strvals_ functions.

CVE-2021-46877: jackson-databind 2.10.x through 2.12.x before 2.12.6 and 2.13.x before 2.13.1 allows attackers to cause a denial of service (2 GB transient heap usage per read) in uncommon situations involving JsonNode JDK serialization.

CVE-2022-22226: In VxLAN scenarios on EX4300-MP, EX4600, QFX5000 Series devices an Uncontrolled Memory Allocation vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an unauthenticated adjacently located attacker sending specific packets to cause a Denial of Service (DoS) condition by crashing one or more PFE's when they are received and processed by the device. Upon automatic restart of the PFE, continued processing of these packets will cause the memory leak to reappear. Depending on the volume of packets received the attacker may be able to create a sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS on EX4300-MP, EX4600, QFX5000 Series: 17.1 version 17.1R1 and later versions prior to 17.3R3-S12; 17.4 versions prior to 17.4R2-S13, 17.4R3-S5; 18.1 versions prior to 18.1R3-S13; 18.2 versions prior to 18.2R3-S8; 18.3 versions prior to 18.3R3-S5; 18.4 versions prior to 18.4R1-S8, 18.4R2-S6, 18.4R3-S6; 19.1 versions prior to 19.1R3-S4; 19.2 versions prior to 19.2R1-S7, 19.2R3-S1; 19.3 versions prior to 19.3R2-S6, 19.3R3-S1; 19.4 versions prior to 19.4R1-S4, 19.4R2-S4, 19.4R3-S1; 20.1 versions prior to 20.1R2; 20.2 versions prior to 20.2R2-S3, 20.2R3; 20.3 versions prior to 20.3R2. This issue does not affect Junos OS versions prior to 17.1R1.

CVE-2022-27819: SWHKD 1.1.5 allows unsafe parsing via the -c option. An information leak might occur but there is a simple denial of service (memory exhaustion) upon an attempt to parse a large or infinite file (such as a block or character device).

CVE-2022-3212: <bytes::Bytes as axum_core::extract::FromRequest>::from_request would not, by default, set a limit for the size of the request body. That meant if a malicious peer would send a very large (or infinite) body your server might run out of memory and crash. This also applies to these extractors which used Bytes::from_request internally: axum::extract::Form axum::extract::Json String

CVE-2021-28714: Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is ready to process them. There are some measures taken for avoiding to pile up too much data, but those can be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default). Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time. (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in its RX queue ring page and the next package would require more than one free slot, which may be the case when using GSO, XDP, or software hashing. (CVE-2021-28714)

CVE-2021-28715: Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is ready to process them. There are some measures taken for avoiding to pile up too much data, but those can be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default). Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time. (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in its RX queue ring page and the next package would require more than one free slot, which may be the case when using GSO, XDP, or software hashing. (CVE-2021-28714)

CVE-2022-40762: A Memory Allocation with Excessive Size Value vulnerablity in the TEE_Realloc function in Samsung mTower through 0.3.0 allows a trusted application to trigger a Denial of Service (DoS) by invoking the function TEE_Realloc with an excessive number for the parameter len.

CVE-2021-39670: In setStream of WallpaperManager.java, there is a possible way to cause a permanent DoS due to improper input validation. This could lead to local denial of service with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-204087139

CVE-2022-1337: The image proxy component in Mattermost version 6.4.1 and earlier allocates memory for multiple copies of a proxied image, which allows an authenticated attacker to crash the server via links to very large image files.

CVE-2022-24741: Nextcloud server is an open source, self hosted cloud style services platform. In affected versions an attacker can cause a denial of service by uploading specially crafted files which will cause the server to allocate too much memory / CPU. It is recommended that the Nextcloud Server is upgraded to 21.0.8 , 22.2.4 or 23.0.1. Users unable to upgrade should disable preview generation with the `'enable_previews'` config flag.

CVE-2022-31016: Argo CD is a declarative continuous deployment for Kubernetes. Argo CD versions v0.7.0 and later are vulnerable to an uncontrolled memory consumption bug, allowing an authorized malicious user to crash the repo-server service, resulting in a Denial of Service. The attacker must be an authenticated Argo CD user authorized to deploy Applications from a repository which contains (or can be made to contain) a large file. The fix for this vulnerability is available in versions 2.3.5, 2.2.10, 2.1.16, and later. There are no known workarounds. Users are recommended to upgrade.

CVE-2022-31080: KubeEdge is an open source system for extending native containerized application orchestration capabilities to hosts at Edge. Prior to versions 1.11.1, 1.10.2, and 1.9.4, a large response received by the viaduct WSClient can cause a DoS from memory exhaustion. The entire body of the response is being read into memory which could allow an attacker to send a request that returns a response with a large body. The consequence of the exhaustion is that the process which invokes a WSClient will be in a denial of service. The software is affected If users who are authenticated to the edge side connect to `cloudhub` from the edge side through WebSocket protocol. This bug has been fixed in Kubeedge 1.11.1, 1.10.2, and 1.9.4. There are currently no known workarounds.

CVE-2022-35922: Rust-WebSocket is a WebSocket (RFC6455) library written in Rust. In versions prior to 0.26.5 untrusted websocket connections can cause an out-of-memory (OOM) process abort in a client or a server. The root cause of the issue is during dataframe parsing. Affected versions would allocate a buffer based on the declared dataframe size, which may come from an untrusted source. When `Vec::with_capacity` fails to allocate, the default Rust allocator will abort the current process, killing all threads. This affects only sync (non-Tokio) implementation. Async version also does not limit memory, but does not use `with_capacity`, so DoS can happen only when bytes for oversized dataframe or message actually got delivered by the attacker. The crashes are fixed in version 0.26.5 by imposing default dataframe size limits. Affected users are advised to update to this version. Users unable to upgrade are advised to filter websocket traffic externally or to only accept trusted traffic.

CVE-2022-41727: An attacker can craft a malformed TIFF image which will consume a significant amount of memory when passed to DecodeConfig. This could lead to a denial of service.

# CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## Description

The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

Cross-site scripting (XSS) vulnerabilities occur when:


  1. Untrusted data enters a web application, typically from a web request.

  1. The web application dynamically generates a web page that contains this untrusted data.

  1. During page generation, the application does not prevent the data from containing content that is executable by a web browser, such as JavaScript, HTML tags, HTML attributes, mouse events, Flash, ActiveX, etc.

  1. A victim visits the generated web page through a web browser, which contains malicious script that was injected using the untrusted data.

  1. Since the script comes from a web page that was sent by the web server, the victim's web browser executes the malicious script in the context of the web server's domain.

  1. This effectively violates the intention of the web browser's same-origin policy, which states that scripts in one domain should not be able to access resources or run code in a different domain.

There are three main kinds of XSS:

  -  **Type 1: Reflected XSS (or Non-Persistent)**  - The server reads data directly from the HTTP request and reflects it back in the HTTP response. Reflected XSS exploits occur when an attacker causes a victim to supply dangerous content to a vulnerable web application, which is then reflected back to the victim and executed by the web browser. The most common mechanism for delivering malicious content is to include it as a parameter in a URL that is posted publicly or e-mailed directly to the victim. URLs constructed in this manner constitute the core of many phishing schemes, whereby an attacker convinces a victim to visit a URL that refers to a vulnerable site. After the site reflects the attacker's content back to the victim, the content is executed by the victim's browser.

  -  **Type 2: Stored XSS (or Persistent)**  - The application stores dangerous data in a database, message forum, visitor log, or other trusted data store. At a later time, the dangerous data is subsequently read back into the application and included in dynamic content. From an attacker's perspective, the optimal place to inject malicious content is in an area that is displayed to either many users or particularly interesting users. Interesting users typically have elevated privileges in the application or interact with sensitive data that is valuable to the attacker. If one of these users executes malicious content, the attacker may be able to perform privileged operations on behalf of the user or gain access to sensitive data belonging to the user. For example, the attacker might inject XSS into a log message, which might not be handled properly when an administrator views the logs. 

  -  **Type 0: DOM-Based XSS**  - In DOM-based XSS, the client performs the injection of XSS into the page; in the other types, the server performs the injection. DOM-based XSS generally involves server-controlled, trusted script that is sent to the client, such as Javascript that performs sanity checks on a form before the user submits it. If the server-supplied script processes user-supplied data and then injects it back into the web page (such as with dynamic HTML), then DOM-based XSS is possible. 

Once the malicious script is injected, the attacker can perform a variety of malicious activities. The attacker could transfer private information, such as cookies that may include session information, from the victim's machine to the attacker. The attacker could send malicious requests to a web site on behalf of the victim, which could be especially dangerous to the site if the victim has administrator privileges to manage that site. Phishing attacks could be used to emulate trusted web sites and trick the victim into entering a password, allowing the attacker to compromise the victim's account on that web site. Finally, the script could exploit a vulnerability in the web browser itself possibly taking over the victim's machine, sometimes referred to as "drive-by hacking."

In many cases, the attack can be launched without the victim even being aware of it. Even with careful users, attackers frequently use a variety of methods to encode the malicious portion of the attack, such as URL encoding or Unicode, so the request looks less suspicious.



The Same Origin Policy states that browsers should limit the resources accessible to scripts running on a given web site, or "origin", to the resources associated with that web site on the client-side, and not the client-side resources of any other sites or "origins". The goal is to prevent one site from being able to modify or read the contents of an unrelated site. Since the World Wide Web involves interactions between many sites, this policy is important for browsers to enforce.


When referring to XSS, the Domain of a website is roughly equivalent to the resources associated with that website on the client-side of the connection. That is, the domain can be thought of as all resources the browser is storing for the user's interactions with this particular site.


## Observed Examples

CVE-2021-25926: Python Library Manager did not sufficiently neutralize a user-supplied search term, allowing reflected XSS.

CVE-2021-25963: Python-based e-commerce platform did not escape returned content on error pages, allowing for reflected Cross-Site Scripting attacks.

CVE-2021-1879: Universal XSS in mobile operating system, as exploited in the wild per CISA KEV.

CVE-2020-3580: Chain: improper input validation (CWE-20) in firewall product leads to XSS (CWE-79), as exploited in the wild per CISA KEV.

CVE-2014-8958: Admin GUI allows XSS through cookie.

CVE-2017-9764: Web stats program allows XSS through crafted HTTP header.

CVE-2014-5198: Web log analysis product allows XSS through crafted HTTP Referer header.

CVE-2008-5080: Chain: protection mechanism failure allows XSS

CVE-2006-4308: Chain: incomplete denylist (CWE-184) only checks "javascript:" tag, allowing XSS (CWE-79) using other tags

CVE-2007-5727: Chain: incomplete denylist (CWE-184) only removes SCRIPT tags, enabling XSS (CWE-79)

CVE-2008-5770: Reflected XSS using the PATH_INFO in a URL

CVE-2008-4730: Reflected XSS not properly handled when generating an error message

CVE-2008-5734: Reflected XSS sent through email message.

CVE-2008-0971: Stored XSS in a security product.

CVE-2008-5249: Stored XSS using a wiki page.

CVE-2006-3568: Stored XSS in a guestbook application.

CVE-2006-3211: Stored XSS in a guestbook application using a javascript: URI in a bbcode img tag.

CVE-2006-3295: Chain: library file is not protected against a direct request (CWE-425), leading to reflected XSS (CWE-79).

## Top 25 Examples

CVE-2021-20543: IBM Jazz Team Server 6.0.6, 6.0.6.1, 7.0, 7.0.1, and 7.0.2 is vulnerable to HTML injection. A remote attacker could inject malicious HTML code, which when viewed, would be executed in the victim's Web browser within the security context of the hosting site. IBM X-Force ID: 198929.

CVE-2021-31676: A reflected XSS was discovered in PESCMS-V2.3.3. When combined with CSRF in the same file, they can cause bigger destruction.

CVE-2021-39024: IBM Guardium Data Encryption (GDE) 4.0.0.0 and 5.0.0.0 is vulnerable to cross-site scripting. This vulnerability allows users to embed arbitrary JavaScript code in the Web UI thus altering the intended functionality potentially leading to credentials disclosure within a trusted session. IBM X-Force ID: 213862.

CVE-2021-40658: Textpattern 4.8.7 is affected by a HTML injection vulnerability through “Content>Write>Body”.

CVE-2021-41421: A PHP code injection vulnerability in MaianAffiliate v.1.0 allows an authenticated attacker to gain RCE through the MaianAffiliate admin panel.

CVE-2021-4267: A vulnerability classified as problematic was found in tad_discuss. Affected by this vulnerability is an unknown functionality. The manipulation of the argument DiscussTitle leads to cross site scripting. The attack can be launched remotely. The name of the patch is af94d034ff8db642d05fd8788179eab05f433958. It is recommended to apply a patch to fix this issue. The identifier VDB-216469 was assigned to this vulnerability.

CVE-2022-1059: Aethon TUG Home Base Server versions prior to version 24 are affected by un unauthenticated attacker who can freely access hashed user credentials.

CVE-2022-23068: ToolJet versions v0.6.0 to v1.10.2 are vulnerable to HTML injection where an attacker can inject malicious code inside the first name and last name field while inviting a new user which will be reflected in the invitational e-mail.

CVE-2022-23367: Fulusso v1.1 was discovered to contain a DOM-based cross-site scripting (XSS) vulnerability in /BindAccount/SuccessTips.js. This vulnerability allows attackers to inject malicious code into a victim user's device via open redirection.

CVE-2022-23474: Editor.js is a block-style editor with clean JSON output. Versions prior to 2.26.0 are vulnerable to Code Injection via pasted input. The processHTML method passes pasted input into wrapper’s innerHTML. This issue is patched in version 2.26.0.

CVE-2022-23599: Products.ATContentTypes are the core content types for Plone 2.1 - 4.3. Versions of Plone that are dependent on Products.ATContentTypes prior to version 3.0.6 are vulnerable to reflected cross site scripting and open redirect when an attacker can get a compromised version of the image_view_fullscreen page in a cache, for example in Varnish. The technique is known as cache poisoning. Any later visitor can get redirected when clicking on a link on this page. Usually only anonymous users are affected, but this depends on the user's cache settings. Version 3.0.6 of Products.ATContentTypes has been released with a fix. This version works on Plone 5.2, Python 2 only. As a workaround, make sure the image_view_fullscreen page is not stored in the cache. More information about the vulnerability and cvmitigation measures is available in the GitHub Security Advisory.

CVE-2022-24917: An authenticated user can create a link with reflected Javascript code inside it for services’ page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict. Malicious code has access to all the same objects as the rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a victim during social engineering attacks.

CVE-2022-24918: An authenticated user can create a link with reflected Javascript code inside it for items’ page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict. Malicious code has access to all the same objects as the rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a victim during social engineering attacks.

CVE-2022-24919: An authenticated user can create a link with reflected Javascript code inside it for graphs’ page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict. Malicious code has access to all the same objects as the rest of the web page and can make arbitrary modifications to the contents of the page being displayed to a victim during social engineering attacks.

CVE-2022-26088: An issue was discovered in BMC Remedy before 22.1. Email-based Incident Forwarding allows remote authenticated users to inject HTML (such as an SSRF payload) into the Activity Log by placing it in the To: field. This affects rendering that occurs upon a click in the "number of recipients" field. NOTE: the vendor's position is that "no real impact is demonstrated."

CVE-2022-26136: A vulnerability in multiple Atlassian products allows a remote, unauthenticated attacker to bypass Servlet Filters used by first and third party apps. The impact depends on which filters are used by each app, and how the filters are used. This vulnerability can result in authentication bypass and cross-site scripting. Atlassian has released updates that fix the root cause of this vulnerability, but has not exhaustively enumerated all potential consequences of this vulnerability. Atlassian Bamboo versions are affected before 8.0.9, from 8.1.0 before 8.1.8, and from 8.2.0 before 8.2.4. Atlassian Bitbucket versions are affected before 7.6.16, from 7.7.0 before 7.17.8, from 7.18.0 before 7.19.5, from 7.20.0 before 7.20.2, from 7.21.0 before 7.21.2, and versions 8.0.0 and 8.1.0. Atlassian Confluence versions are affected before 7.4.17, from 7.5.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and version 7.21.0. Atlassian Crowd versions are affected before 4.3.8, from 4.4.0 before 4.4.2, and version 5.0.0. Atlassian Fisheye and Crucible versions before 4.8.10 are affected. Atlassian Jira versions are affected before 8.13.22, from 8.14.0 before 8.20.10, and from 8.21.0 before 8.22.4. Atlassian Jira Service Management versions are affected before 4.13.22, from 4.14.0 before 4.20.10, and from 4.21.0 before 4.22.4.

CVE-2022-29816: In JetBrains IntelliJ IDEA before 2022.1 HTML injection into IDE messages was possible

CVE-2022-30991: HTML injection via report name. The following products are affected: Acronis Cyber Protect 15 (Linux, Windows) before build 29240

CVE-2022-31102: Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Argo CD starting with 2.3.0 and prior to 2.3.6 and 2.4.5 is vulnerable to a cross-site scripting (XSS) bug which could allow an attacker to inject arbitrary JavaScript in the `/auth/callback` page in a victim's browser. This vulnerability only affects Argo CD instances which have single sign on (SSO) enabled. The exploit also assumes the attacker has 1) access to the API server's encryption key, 2) a method to add a cookie to the victim's browser, and 3) the ability to convince the victim to visit a malicious `/auth/callback` link. The vulnerability is classified as low severity because access to the API server's encryption key already grants a high level of access. Exploiting the XSS would allow the attacker to impersonate the victim, but would not grant any privileges which the attacker could not otherwise gain using the encryption key. A patch for this vulnerability has been released in the following Argo CD versions 2.4.5 and 2.3.6. There is currently no known workaround.

CVE-2022-3242: Code Injection in GitHub repository microweber/microweber prior to 1.3.2.

CVE-2022-32763: A cross-site scripting (xss) sanitization vulnerability bypass exists in the SanitizeHtml functionality of Lansweeper lansweeper 10.1.1.0. A specially-crafted HTTP request can lead to arbitrary Javascript code injection. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-34009: Fossil 2.18 on Windows allows attackers to cause a denial of service (daemon crash) via an XSS payload in a ticket. This occurs because the ticket data is stored in a temporary file, and the product does not properly handle the absence of this file after Windows Defender has flagged it as malware.

CVE-2022-34160: IBM CICS TX Standard and Advanced 11.1 is vulnerable to HTML injection. A remote attacker could inject malicious HTML code, which when viewed, would be executed in the victim's Web browser within the security context of the hosting site. IBM X-Force ID: 229330.

CVE-2022-34966: OpenTeknik LLC OSSN OPEN SOURCE SOCIAL NETWORK v6.3 LTS was discovered to contain an HTML injection vulnerability via the location parameter at http://ip_address/:port/ossn/home.

CVE-2022-35229: An authenticated user can create a link with reflected Javascript code inside it for the discovery page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict.

CVE-2022-35230: An authenticated user can create a link with reflected Javascript code inside it for the graphs page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict.

CVE-2022-38191: There is an HTML injection issue in Esri Portal for ArcGIS versions 10.9.0 and below which may allow a remote, authenticated attacker to inject HTML into some locations in the home application.

CVE-2022-3869: Code Injection in GitHub repository froxlor/froxlor prior to 0.10.38.2.

CVE-2022-38802: Zkteco BioTime < 8.5.3 Build:20200816.447 is vulnerable to Incorrect Access Control via resign, private message, manual log, time interval, attshift, and holiday. An authenticated administrator can read local files by exploiting XSS into a pdf generator when exporting data as a PDF

CVE-2022-38803: Zkteco BioTime < 8.5.3 Build:20200816.447 is vulnerable to Incorrect Access Control via Leave, overtime, Manual log. An authenticated employee can read local files by exploiting XSS into a pdf generator when exporting data as a PDF

CVE-2022-38845: Cross Site Scripting in Import feature in EspoCRM 7.1.8 allows remote users to run malicious JavaScript in victim s browser via sending crafted csv file containing malicious JavaScript to authenticated user. Any authenticated user importing the crafted CSV file may end up running the malicious JavaScripting in the browser.

CVE-2022-40248: An HTML injection vulnerability exists in CERT/CC VINCE software prior to 1.50.4. An authenticated attacker can inject arbitrary HTML via form using the "Product Affected" field.

CVE-2022-40257: An HTML injection vulnerability exists in CERT/CC VINCE software prior to 1.50.4. An authenticated attacker can inject arbitrary HTML via a crafted email with HTML content in the Subject field.

CVE-2022-40434: Softr v2.0 was discovered to be vulnerable to HTML injection via the Name field of the Account page.

CVE-2022-4105: A stored XSS in a kiwi Test Plan can run malicious javascript which could be chained with an HTML injection to perform a UI redressing attack (clickjacking) and an HTML injection which disables the use of the history page.

CVE-2022-42187: Hustoj 22.09.22 has a XSS Vulnerability in /admin/problem_judge.php.

CVE-2022-43695: Concrete CMS (formerly concrete5) below 8.5.10 and between 9.0.0 and 9.1.2 is vulnerable to Stored Cross-Site Scripting (XSS) in dashboard/system/express/entities/associations because Concrete CMS allows association with an entity name that doesn’t exist or, if it does exist, contains XSS since it was not properly sanitized. Remediate by updating to Concrete CMS 9.1.3+ or 8.5.10+.

CVE-2022-43754: An Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to embed Javascript code via /rhn/audit/scap/Search.do This issue affects: SUSE Linux Enterprise Module for SUSE Manager Server 4.2 hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-formula-0.3-150300.3.3.2, py27-compat-salt-3000.3-150300.7.7.26.2, python-urlgrabber-3.10.2.1py2_3-150300.3.3.2, spacecmd-4.2.20-150300.4.30.2, spacewalk-backend-4.2.25-150300.4.32.4, spacewalk-client-tools-4.2.21-150300.4.27.3, spacewalk-java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2, spacewalk-web-4.2.30-150300.3.30.3, susemanager-4.2.38-150300.3.44.3, susemanager-doc-indexes-4.2-150300.12.36.3, susemanager-docs_en-4.2-150300.12.36.2, susemanager-schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to 4.2.28. SUSE Linux Enterprise Module for SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39. SUSE Manager Server 4.2 release-notes-susemanager versions prior to 4.2.10.

CVE-2022-44012: An issue was discovered in /DS/LM_API/api/SelectionService/InsertQueryWithActiveRelationsReturnId in Simmeth Lieferantenmanager before 5.6. An attacker can execute JavaScript code in the browser of the victim if a site is loaded. The victim's encrypted password can be stolen and most likely be decrypted.

CVE-2022-45004: Gophish through 0.12.1 was discovered to contain a cross-site scripting (XSS) vulnerability via a crafted landing page.

CVE-2022-45411: Cross-Site Tracing occurs when a server will echo a request back via the Trace method, allowing an XSS attack to access to authorization headers and cookies inaccessible to JavaScript (such as cookies protected by HTTPOnly). To mitigate this attack, browsers placed limits on <code>fetch()</code> and XMLHttpRequest; however some webservers have implemented non-standard headers such as <code>X-Http-Method-Override</code> that override the HTTP method, and made this attack possible again. Thunderbird has applied the same mitigations to the use of this and similar headers. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107.

CVE-2022-39207: Onedev is an open source, self-hosted Git Server with CI/CD and Kanban. During CI/CD builds, it is possible to save build artifacts for later retrieval. They can be accessed through OneDev's web UI after the successful run of a build. These artifact files are served by the webserver in the same context as the UI without any further restrictions. This leads to Cross-Site Scripting (XSS) when a user creates a build artifact that contains HTML. When accessing the artifact, the content is rendered by the browser, including any JavaScript that it contains. Since all cookies (except for the rememberMe one) do not set the HttpOnly flag, an attacker could steal the session of a victim and use it to impersonate them. To exploit this issue, attackers need to be able to modify the content of artifacts, which usually means they need to be able to modify a project's build spec. The exploitation requires the victim to click on an attacker's link. It can be used to elevate privileges by targeting admins of a OneDev instance. In the worst case, this can lead to arbitrary code execution on the server, because admins can create Server Shell Executors and use them to run any command on the server. This issue has been patched in version 7.3.0. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-3033: If a Thunderbird user replied to a crafted HTML email containing a <code>meta</code> tag, with the <code>meta</code> tag having the <code>http-equiv="refresh"</code> attribute, and the content attribute specifying an URL, then Thunderbird started a network request to that URL, regardless of the configuration to block remote content. In combination with certain other HTML elements and attributes in the email, it was possible to execute JavaScript code included in the message in the context of the message compose document. The JavaScript code was able to perform actions including, but probably not limited to, read and modify the contents of the message compose document, including the quoted original message, which could potentially contain the decrypted plaintext of encrypted data in the crafted email. The contents could then be transmitted to the network, either to the URL specified in the META refresh tag, or to a different URL, as the JavaScript code could modify the URL specified in the document. This bug doesn't affect users who have changed the default Message Body display setting to 'simple html' or 'plain text'. This vulnerability affects Thunderbird < 102.2.1 and Thunderbird < 91.13.1.

CVE-2021-1879: This issue was addressed by improved management of object lifetimes. This issue is fixed in iOS 12.5.2, iOS 14.4.2 and iPadOS 14.4.2, watchOS 7.3.3. Processing maliciously crafted web content may lead to universal cross site scripting. Apple is aware of a report that this issue may have been actively exploited..

CVE-2022-29444: Plugin Settings Change leading to Cross-Site Scripting (XSS) vulnerability in Cloudways Breeze plugin <= 2.0.2 on WordPress allows users with a subscriber or higher user role to execute any of the wp_ajax_* actions in the class Breeze_Configuration which includes the ability to change any of the plugin's settings including CDN setting which could be further used for XSS attack.

CVE-2021-36176: Multiple uncontrolled resource consumption vulnerabilities in the web interface of FortiPortal before 6.0.6 may allow a single low-privileged user to induce a denial of service via multiple HTTP requests.

CVE-2021-43929: Improper neutralization of special elements in output used by a downstream component ('Injection') vulnerability in work flow management in Synology DiskStation Manager (DSM) before 7.0.1-42218-2 allows remote authenticated users to inject arbitrary web script or HTML via unspecified vectors.

CVE-2022-2178: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in Saysis Computer Starcities allows Cross-Site Scripting (XSS).This issue affects Starcities: before 1.1. 

CVE-2022-38628: Nortek Linear eMerge E3-Series 0.32-08f, 0.32-07p, 0.32-07e, 0.32-09c, 0.32-09b, 0.32-09a, and 0.32-08e were discovered to contain a cross-site scripting (XSS) vulnerability which is chained with a local session fixation. This vulnerability allows attackers to escalate privileges via unspecified vectors.

CVE-2022-1021: Insecure Storage of Sensitive Information in GitHub repository chatwoot/chatwoot prior to 2.6.0.

CVE-2021-38295: In Apache CouchDB, a malicious user with permission to create documents in a database is able to attach a HTML attachment to a document. If a CouchDB admin opens that attachment in a browser, e.g. via the CouchDB admin interface Fauxton, any JavaScript code embedded in that HTML attachment will be executed within the security context of that admin. A similar route is available with the already deprecated _show and _list functionality. This privilege escalation vulnerability allows an attacker to add or remove data in any database or make configuration changes. This issue affected Apache CouchDB prior to 3.1.2

CVE-2022-2861: Inappropriate implementation in Extensions API in Google Chrome prior to 104.0.5112.101 allowed an attacker who convinced a user to install a malicious extension to inject arbitrary scripts into WebUI via a crafted HTML page.

CVE-2022-31744: An attacker could have injected CSS into stylesheets accessible via internal URIs, such as resource:, and in doing so bypass a page's Content Security Policy. This vulnerability affects Firefox ESR < 91.11, Thunderbird < 102, Thunderbird < 91.11, and Firefox < 101.

CVE-2021-4251: A vulnerability classified as problematic was found in as. This vulnerability affects the function getFullURL of the file include.cdn.php. The manipulation leads to cross site scripting. The attack can be initiated remotely. The name of the patch is 4acad1e3d2c34c017473ceea442fb3e3e078b2bd. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216208.

CVE-2021-4252: A vulnerability, which was classified as problematic, has been found in WP-Ban. This issue affects the function toggle_checkbox of the file ban-options.php. The manipulation of the argument $_SERVER["HTTP_USER_AGENT"] leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 13e0b1e922f3aaa3f8fcb1dd6d50200dd693fd76. It is recommended to apply a patch to fix this issue. The identifier VDB-216209 was assigned to this vulnerability.

CVE-2021-4253: A vulnerability, which was classified as problematic, was found in ctrlo lenio. Affected is an unknown function in the library lib/Lenio.pm of the component Ticket Handler. The manipulation of the argument site_id leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is 7a1f90bd2a0ce95b8338ec0926902da975ec64d9. It is recommended to apply a patch to fix this issue. VDB-216210 is the identifier assigned to this vulnerability.

CVE-2021-4254: A vulnerability has been found in ctrlo lenio and classified as problematic. Affected by this vulnerability is an unknown functionality of the file views/layouts/main.tt of the component Notice Handler. The manipulation of the argument notice.notice.text leads to cross site scripting. The attack can be launched remotely. The name of the patch is aa300555343c1c081951fcb68bfb6852fbba7451. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-216211.

CVE-2021-4255: A vulnerability was found in ctrlo lenio and classified as problematic. Affected by this issue is some unknown functionality of the file views/contractor.tt. The manipulation of the argument contractor.name leads to cross site scripting. The attack may be launched remotely. The name of the patch is e1646d5cd0a2fbab9eb505196dd2ca1c9e4cdd97. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216212.

CVE-2021-4257: A vulnerability was found in ctrlo lenio. It has been declared as problematic. This vulnerability affects unknown code of the file views/task.tt of the component Task Handler. The manipulation of the argument site.org.name/check.name/task.tasktype.name/task.name leads to cross site scripting. The attack can be initiated remotely. The name of the patch is 698c5fa465169d6f23c6a41ca4b1fc9a7869013a. It is recommended to apply a patch to fix this issue. VDB-216214 is the identifier assigned to this vulnerability.

CVE-2022-28368: Dompdf 1.2.1 allows remote code execution via a .php file in the src:url field of an @font-face Cascading Style Sheets (CSS) statement (within an HTML input file).

CVE-2022-29269: In Nagios XI through 5.8.5, in the schedule report function, an authenticated attacker is able to inject HTML tags that lead to the reformatting/editing of emails from an official email address.

CVE-2022-31108: Mermaid is a JavaScript based diagramming and charting tool that uses Markdown-inspired text definitions and a renderer to create and modify complex diagrams. An attacker is able to inject arbitrary `CSS` into the generated graph allowing them to change the styling of elements outside of the generated graph, and potentially exfiltrate sensitive information by using specially crafted `CSS` selectors. The following example shows how an attacker can exfiltrate the contents of an input field by bruteforcing the `value` attribute one character at a time. Whenever there is an actual match, an `http` request will be made by the browser in order to "load" a background image that will let an attacker know what's the value of the character. This issue may lead to `Information Disclosure` via CSS selectors and functions able to generate HTTP requests. This also allows an attacker to change the document in ways which may lead a user to perform unintended actions, such as clicking on a link, etc. This issue has been resolved in version 9.1.3. Users are advised to upgrade. Users unable to upgrade should ensure that user input is adequately escaped before embedding it in CSS blocks.

CVE-2022-32269: In Real Player 20.0.8.310, the G2 Control allows injection of unsafe javascript: URIs in local HTTP error pages (displayed by Internet Explorer core). This leads to arbitrary code execution.

CVE-2022-3333: A vulnerability, which was classified as problematic, was found in Zephyr Project Manager up to 3.2.4. Affected is an unknown function of the file /v1/tasks/create/ of the component REST Call Handler. The manipulation of the argument onanimationstart leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 3.2.5 is able to address this issue. It is recommended to upgrade the affected component. VDB-209370 is the identifier assigned to this vulnerability.

CVE-2022-3452: A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /category.php. The manipulation of the argument category_name leads to cross site scripting. The attack can be initiated remotely. The identifier of this vulnerability is VDB-210436.

CVE-2022-3453: A vulnerability was found in SourceCodester Book Store Management System 1.0. It has been rated as problematic. This issue affects some unknown processing of the file /transcation.php. The manipulation of the argument buyer_name leads to cross site scripting. The attack may be initiated remotely. The identifier VDB-210437 was assigned to this vulnerability.

CVE-2022-39016:  Javascript injection in PDFtron in M-Files Hubshare before 3.3.10.9 allows authenticated attackers to perform an account takeover via a crafted PDF upload.

CVE-2022-3975: A vulnerability, which was classified as problematic, has been found in NukeViet CMS. Affected by this issue is the function filterAttr of the file vendor/vinades/nukeviet/Core/Request.php of the component Data URL Handler. The manipulation of the argument attrSubSet leads to cross site scripting. The attack may be launched remotely. Upgrading to version 4.5 is able to address this issue. The name of the patch is 0b3197fad950bb3383e83039a8ee4c9509b3ce02. It is recommended to upgrade the affected component. VDB-213554 is the identifier assigned to this vulnerability.

CVE-2022-4091: A vulnerability was found in SourceCodester Canteen Management System. It has been classified as problematic. This affects the function query of the file food.php. The manipulation of the argument product_name leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214359.

CVE-2022-4234: A vulnerability was found in SourceCodester Canteen Management System. It has been rated as problematic. This issue affects the function builtin_echo of the file youthappam/brand.php. The manipulation of the argument brand_name leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214595.

CVE-2022-4250: A vulnerability has been found in Movie Ticket Booking System and classified as problematic. Affected by this vulnerability is an unknown functionality of the file booking.php. The manipulation of the argument id leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214627.

CVE-2022-4251: A vulnerability was found in Movie Ticket Booking System and classified as problematic. Affected by this issue is some unknown functionality of the file editBooking.php. The manipulation leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-214628.

CVE-2022-4252: A vulnerability was found in SourceCodester Canteen Management System. It has been classified as problematic. This affects the function builtin_echo of the file categories.php. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-214629 was assigned to this vulnerability.

CVE-2022-4253: A vulnerability was found in SourceCodester Canteen Management System. It has been declared as problematic. This vulnerability affects the function builtin_echo of the file customer.php. The manipulation leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-214630 is the identifier assigned to this vulnerability.

CVE-2022-4347: A vulnerability was found in xiandafu beetl-bbs. It has been declared as problematic. Affected by this vulnerability is an unknown functionality of the file WebUtils.java. The manipulation of the argument user leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-215107.

CVE-2022-4348: A vulnerability was found in y_project RuoYi-Cloud. It has been rated as problematic. Affected by this issue is some unknown functionality of the component JSON Handler. The manipulation leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-215108.

CVE-2022-4350: A vulnerability, which was classified as problematic, was found in Mingsoft MCMS 5.2.8. Affected is an unknown function of the file search.do. The manipulation of the argument content_title leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-215112.

CVE-2022-4353: A vulnerability has been found in LinZhaoguan pb-cms 2.0 and classified as problematic. Affected by this vulnerability is the function IpUtil.getIpAddr. The manipulation leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-215113 was assigned to this vulnerability.

CVE-2022-4522: A vulnerability classified as problematic was found in CalendarXP up to 10.0.1. This vulnerability affects unknown code. The manipulation leads to cross site scripting. The attack can be initiated remotely. Upgrading to version 10.0.2 is able to address this issue. The name of the patch is e3715b2228ddefe00113296069969f9e184836da. It is recommended to upgrade the affected component. VDB-215902 is the identifier assigned to this vulnerability.

CVE-2022-4523: A vulnerability, which was classified as problematic, has been found in vexim2. This issue affects some unknown processing. The manipulation leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 21c0a60d12e9d587f905cd084b2c70f9b1592065. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-215903.

CVE-2022-4556: A vulnerability was found in Alinto SOGo up to 5.7.1 and classified as problematic. Affected by this issue is the function _migrateMailIdentities of the file SoObjects/SOGo/SOGoUserDefaults.m of the component Identity Handler. The manipulation of the argument fullName leads to cross site scripting. The attack may be launched remotely. Upgrading to version 5.8.0 is able to address this issue. The name of the patch is efac49ae91a4a325df9931e78e543f707a0f8e5e. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-215960.

CVE-2022-4558: A vulnerability was found in Alinto SOGo up to 5.7.1. It has been classified as problematic. This affects an unknown part of the file SoObjects/SOGo/NSString+Utilities.m of the component Folder/Mail Handler. The manipulation leads to cross site scripting. It is possible to initiate the attack remotely. Upgrading to version 5.8.0 is able to address this issue. The name of the patch is 1e0f5f00890f751e84d67be4f139dd7f00faa5f3. It is recommended to upgrade the affected component. The identifier VDB-215961 was assigned to this vulnerability.

CVE-2022-4559: A vulnerability was found in INEX IPX-Manager up to 6.2.0. It has been declared as problematic. This vulnerability affects unknown code of the file resources/views/customer/list.foil.php. The manipulation leads to cross site scripting. The attack can be initiated remotely. Upgrading to version 6.3.0 is able to address this issue. The name of the patch is bc9b14c6f70cccdb89b559e8bc3a7318bfe9c243. It is recommended to upgrade the affected component. VDB-215962 is the identifier assigned to this vulnerability.

CVE-2022-4561: A vulnerability classified as problematic has been found in SemanticDrilldown Extension. Affected is the function printFilterLine of the file includes/specials/SDBrowseDataPage.php of the component GET Parameter Handler. The manipulation of the argument value leads to cross site scripting. It is possible to launch the attack remotely. The name of the patch is 6e18cf740a4548166c1d95f6d3a28541d298a3aa. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-215964.

CVE-2022-4581: A vulnerability was found in 1j01 mind-map and classified as problematic. This issue affects some unknown processing of the file app.coffee. The manipulation of the argument html leads to cross site scripting. The attack may be initiated remotely. The name of the patch is 9617e6084dfeccd92079ab4d7f439300a4b24394. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-216167.

CVE-2022-4582: A vulnerability was found in starter-public-edition-4 up to 4.6.10. It has been classified as problematic. Affected is an unknown function. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. Upgrading to version 4.6.11 is able to address this issue. The name of the patch is 2606983c20f6ea3430ac4b36b3d2e88aafef45da. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-216168.

CVE-2022-4595: A vulnerability classified as problematic has been found in django-openipam. This affects an unknown part of the file openipam/report/templates/report/exposed_hosts.html. The manipulation of the argument description leads to cross site scripting. It is possible to initiate the attack remotely. The name of the patch is a6223a1150d60cd036106ba6a8e676c1bfc3cc85. It is recommended to apply a patch to fix this issue. The identifier VDB-216189 was assigned to this vulnerability.

CVE-2022-4596: A vulnerability, which was classified as problematic, has been found in Shoplazza 1.1. This issue affects some unknown processing of the file /admin/api/admin/articles/ of the component Add Blog Post Handler. The manipulation of the argument Title leads to cross site scripting. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-216191.

CVE-2022-4597: A vulnerability, which was classified as problematic, was found in Shoplazza LifeStyle 1.1. Affected is an unknown function of the file /admin/api/admin/v2_products of the component Create Product Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-216192.

CVE-2022-46162: discourse-bbcode is the official BBCode plugin for Discourse. Prior to commit 91478f5, CSS injection can occur when rendering content generated with the discourse-bccode plugin. This vulnerability only affects sites which have the discourse-bbcode plugin installed and enabled. This issue is patched in commit 91478f5. As a workaround, ensure that the Content Security Policy is enabled and monitor any posts that contain bbcode.

CVE-2022-4640: A vulnerability has been found in Mingsoft MCMS 5.2.9 and classified as problematic. Affected by this vulnerability is the function save of the component Article Handler. The manipulation leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216499.

CVE-2022-0282: Cross-site Scripting in Packagist microweber/microweber prior to 1.2.11. 

CVE-2022-23008: On NGINX Controller API Management versions 3.18.0-3.19.0, an authenticated attacker with access to the "user" or "admin" role can use undisclosed API endpoints on NGINX Controller API Management to inject JavaScript code that is executed on managed NGINX data plane instances. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-26255: Clash for Windows v0.19.8 was discovered to allow arbitrary code execution via a crafted payload injected into the Proxies name column.

CVE-2022-36036: mdx-mermaid provides plug and play access to Mermaid in MDX. There is a potential for an arbitrary javascript injection in versions less than 1.3.0 and 2.0.0-rc1. Modify any mermaid code blocks with arbitrary code and it will execute when the component is loaded by MDXjs. This vulnerability was patched in version(s) 1.3.0 and 2.0.0-rc2. There are currently no known workarounds.

CVE-2022-3493: A vulnerability, which was classified as problematic, has been found in SourceCodester Human Resource Management System 1.0. This issue affects some unknown processing of the component Add Employee Handler. The manipulation of the argument First Name/Middle Name/Last Name leads to cross site scripting. The attack may be initiated remotely. The identifier VDB-210773 was assigned to this vulnerability.

CVE-2022-3502: A vulnerability was found in Human Resource Management System 1.0. It has been classified as problematic. This affects an unknown part of the component Leave Handler. The manipulation of the argument Reason leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-210831.

CVE-2022-3503: A vulnerability was found in SourceCodester Purchase Order Management System 1.0. It has been declared as problematic. This vulnerability affects unknown code of the component Supplier Handler. The manipulation of the argument Supplier Name/Address/Contact person/Contact leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-210832.

CVE-2022-3518: A vulnerability classified as problematic has been found in SourceCodester Sanitization Management System 1.0. Affected is an unknown function of the component User Creation Handler. The manipulation of the argument First Name/Middle Name/Last Name leads to cross site scripting. It is possible to launch the attack remotely. VDB-211014 is the identifier assigned to this vulnerability.

CVE-2022-3519: A vulnerability classified as problematic was found in SourceCodester Sanitization Management System 1.0. Affected by this vulnerability is an unknown functionality of the component Quote Requests Tab. The manipulation of the argument Manage Remarks leads to cross site scripting. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-211015.

CVE-2022-3580: A vulnerability, which was classified as problematic, has been found in SourceCodester Cashier Queuing System 1.0.1. This issue affects some unknown processing of the component User Creation Handler. The manipulation leads to cross site scripting. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-211187.

CVE-2022-3581: A vulnerability, which was classified as problematic, was found in SourceCodester Cashier Queuing System 1.0. Affected is an unknown function of the component Cashiers Tab. The manipulation of the argument Name leads to cross site scripting. It is possible to launch the attack remotely. The identifier of this vulnerability is VDB-211188.

CVE-2022-3716: A vulnerability classified as problematic was found in SourceCodester Online Medicine Ordering System 1.0. Affected by this vulnerability is an unknown functionality of the file /omos/admin/?page=user/list. The manipulation of the argument First Name/Middle Name/Last Name leads to cross site scripting. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-212347.

CVE-2022-4092: An issue has been discovered in GitLab EE affecting all versions starting from 15.6 before 15.6.1. It was possible to create a malicious README page due to improper neutralisation of user supplied input.

CVE-2022-0748: The package post-loader from 0.0.0 are vulnerable to Arbitrary Code Execution which uses a markdown parser in an unsafe way so that any javascript code inside the markdown input files gets evaluated and executed.

CVE-2022-0121: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in hoppscotch hoppscotch/hoppscotch.This issue affects hoppscotch/hoppscotch before 2.1.1. 

# CWE-790 Improper Filtering of Special Elements

## Description

The product receives data from an upstream component, but does not filter or incorrectly filters special elements before sending it to a downstream component.

## Top 25 Examples

CVE-2022-0895: Static Code Injection in GitHub repository microweber/microweber prior to 1.3.

CVE-2022-40145: This vulnerable is about a potential code injection when an attacker has control of the target LDAP server using in the JDBC JNDI URL. The function jaas.modules.src.main.java.porg.apache.karaf.jass.modules.jdbc.JDBCUtils#doCreateDatasource use InitialContext.lookup(jndiName) without filtering. An user can modify `options.put(JDBCUtils.DATASOURCE, "osgi:" + DataSource.class.getName());` to `options.put(JDBCUtils.DATASOURCE,"jndi:rmi://x.x.x.x:xxxx/Command");` in JdbcLoginModuleTest#setup. This is vulnerable to a remote code execution (RCE) attack when a configuration uses a JNDI LDAP data source URI when an attacker has control of the target LDAP server.This issue affects all versions of Apache Karaf up to 4.4.1 and 4.3.7. We encourage the users to upgrade to Apache Karaf at least 4.4.2 or 4.3.8

CVE-2022-40740: Realtek GPON router has insufficient filtering for special characters. A remote attacker authenticated as an administrator can exploit this vulnerability to perform command injection attacks, to execute arbitrary system command, manipulate system or disrupt service.

CVE-2021-35587: Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: OpenSSO Agent). Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Access Manager. Successful attacks of this vulnerability can result in takeover of Oracle Access Manager. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

CVE-2022-24300: Minetest before 5.4.0 allows attackers to add or modify arbitrary meta fields of the same item stack as saved user input, aka ItemStack meta injection.

CVE-2022-24888: Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Prior to versions 20.0.14.4, 21.0.8, 22.2.4, and 23.0.1, it is possible to create files and folders that have leading and trailing \\n, \\r, \\t, and \\v characters. The server rejects files and folders that have these characters in the middle of their names, so this might be an opportunity for injection. This issue is fixed in versions 20.0.14.4, 21.0.8, 22.2.4, and 23.0.1. There are currently no known workarounds.

CVE-2022-0578: Code Injection in GitHub repository publify/publify prior to 9.2.8.

CVE-2022-22985: The absence of filters when loading some sections in the web application of the vulnerable device allows attackers to inject malicious code that will be interpreted when a legitimate user accesses the specific web section where the information is displayed. Injection can be done on specific parameters. The injected code is executed when a legitimate user attempts to review history.

CVE-2022-24915: The absence of filters when loading some sections in the web application of the vulnerable device allows attackers to inject malicious code that will be interpreted when a legitimate user accesses the web section where the information is displayed. Injection can be done on specific parameters. The injected code is executed when a legitimate user attempts to upload, copy, download, or delete an existing configuration (Administrative Services).

CVE-2022-26198: Notable v1.8.4 does not filter text editing, allowing attackers to execute arbitrary code via a crafted payload injected into the Title text field.

CVE-2022-26272: A remote code execution (RCE) vulnerability in Ionize v1.0.8.1 allows attackers to execute arbitrary code via a crafted string written to the file application/config/config.php.

CVE-2022-28096: Skycaiji v2.4 was discovered to contain a remote code execution (RCE) vulnerability via /SkycaijiApp/admin/controller/Develop.php.

CVE-2022-3383: The Ultimate Member plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 2.5.0 via the get_option_value_from_callback function that accepts user supplied input and passes it through call_user_func(). This makes it possible for authenticated attackers, with administrative capabilities, to execute code on the server.

CVE-2022-3384: The Ultimate Member plugin for WordPress is vulnerable to Remote Code Execution in versions up to, and including, 2.5.0 via the populate_dropdown_options function that accepts user supplied input and passes it through call_user_func(). This is restricted to non-parameter PHP functions like phpinfo(); since user supplied parameters are not passed through the function. This makes it possible for authenticated attackers, with administrative privileges, to execute code on the server.

CVE-2022-36215: DedeBIZ v6 was discovered to contain a remote code execution vulnerability in sys_info.php.

CVE-2022-41945: super-xray is a vulnerability scanner (xray) GUI launcher. In version 0.1-beta, the URL is not filtered and directly spliced ??into the command, resulting in a possible RCE vulnerability. Users should upgrade to super-xray 0.2-beta.

CVE-2022-23881: ZZZCMS zzzphp v2.1.0 was discovered to contain a remote command execution (RCE) vulnerability via danger_key() at zzz_template.php.

CVE-2022-27411: TOTOLINK N600R v5.3c.5507_B20171031 was discovered to contain a command injection vulnerability via the QUERY_STRING parameter in the "Main" function.

CVE-2022-35517: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 adm.cgi has no filtering on parameters: web_pskValue, wl_Method, wlan_ssid, EncrypType, rwan_ip, rwan_mask, rwan_gateway, ppp_username, ppp_passwd and ppp_setver, which leads to command injection in page /wizard_router_mesh.shtml.

CVE-2022-35518: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 nas.cgi has no filtering on parameters: User1Passwd and User1, which leads to command injection in page /nas_disk.shtml.

CVE-2022-35519: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 firewall.cgi has no filtering on parameter add_mac, which leads to command injection in page /cli_black_list.shtml.

CVE-2022-35520: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 api.cgi has no filtering on parameter ufconf, and this is a hidden parameter which doesn't appear in POST body, but exist in cgi binary. This leads to command injection in page /ledonoff.shtml.

CVE-2022-35521: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 firewall.cgi has no filtering on parameters: remoteManagementEnabled, blockPortScanEnabled, pingFrmWANFilterEnabled and blockSynFloodEnabled, which leads to command injection in page /man_security.shtml.

CVE-2022-35522: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 adm.cgi has no filtering on parameters: ppp_username, ppp_passwd, rwan_gateway, rwan_mask and rwan_ip, which leads to command injection in page /wan.shtml.

CVE-2022-35523: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 firewall.cgi has no filtering on parameter del_mac and parameter flag, which leads to command injection in page /cli_black_list.shtml.

CVE-2022-35524: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 adm.cgi has no filtering on parameters: wlan_signal, web_pskValue, sel_EncrypTyp, sel_Automode, wlan_bssid, wlan_ssid and wlan_channel, which leads to command injection in page /wizard_rep.shtml.

CVE-2022-35525: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 adm.cgi has no filtering on parameter led_switch, which leads to command injection in page /ledonoff.shtml.

CVE-2022-35526: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 login.cgi has no filtering on parameter key, which leads to command injection in page /login.shtml.

CVE-2022-35533: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 qos.cgi has no filtering on parameters: cli_list and cli_num, which leads to command injection in page /qos.shtml.

CVE-2022-35534: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 wireless.cgi has no filtering on parameter hiddenSSID32g and SSID2G2, which leads to command injection in page /wifi_multi_ssid.shtml.

CVE-2022-35535: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 wireless.cgi has no filtering on parameter macAddr, which leads to command injection in page /wifi_mesh.shtml.

CVE-2022-35536: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 qos.cgi has no filtering on parameters: qos_bandwith and qos_dat, which leads to command injection in page /qos.shtml.

CVE-2022-35537: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 wireless.cgi has no filtering on parameters: mac_5g and Newname, which leads to command injection in page /wifi_mesh.shtml.

CVE-2022-35538: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 wireless.cgi has no filtering on parameters: delete_list, delete_al_mac, b_delete_list and b_delete_al_mac, which leads to command injection in page /wifi_mesh.shtml.

CVE-2022-37843: In TOTOLINK A860R V4.1.2cu.5182_B20201027 in cstecgi.cgi, the acquired parameters are directly put into the system for execution without filtering, resulting in a command injection vulnerability.

CVE-2022-29639: TOTOLINK A3100R V4.1.2cu.5050_B20200504 and V4.1.2cu.5247_B20211129 were discovered to contain a command injection vulnerability via the magicid parameter in the function uci_cloudupdate_config.

CVE-2022-32228: An information disclosure vulnerability exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 since the getReadReceipts Meteor server method does not properly filter user inputs that are passed to MongoDB queries, allowing $regex queries to enumerate arbitrary Message IDs.

# CWE-791 Incomplete Filtering of Special Elements

## Description

The product receives data from an upstream component, but does not completely filter special elements before sending it to a downstream component.

## Top 25 Examples

CVE-2022-25597: ASUS RT-AC86U’s LPD service has insufficient filtering for special characters in the user request, which allows an unauthenticated LAN attacker to perform command injection attack, execute arbitrary commands and disrupt or terminate service.

CVE-2022-39057: RAVA certificate validation system has insufficient filtering for special parameter of the web page input field. A remote attacker with administrator privilege can exploit this vulnerability to perform arbitrary system command and disrupt service.

CVE-2022-27176: Incomplete filtering of special elements vulnerability exists in RevoWorks SCVX using 'File Sanitization Library' 1.043 and prior versions, RevoWorks Browser 2.2.67 and prior versions (when using 'File Sanitization Option'), and RevoWorks Desktop 2.1.84 and prior versions (when using 'File Sanitization Option'), which may allow an attacker to execute a malicious macro by having a user to download, import, and open a specially crafted file in the local environment.

# CWE-792 Incomplete Filtering of One or More Instances of Special Elements

## Description

The product receives data from an upstream component, but does not completely filter one or more instances of special elements before sending it to a downstream component.

Incomplete filtering of this nature involves either:


  - only filtering a single instance of a special element when more exist, or

  - not filtering all instances or all elements where multiple special elements exist.

## Top 25 Examples

CVE-2022-22297: An incomplete filtering of one or more instances of special elements vulnerability [CWE-792] in the command line interpreter of FortiWeb version 6.4.0 through 6.4.1, FortiWeb version 6.3.0 through 6.3.17, FortiWeb all versions 6.2, FortiWeb all versions 6.1, FortiWeb all versions 6.0, FortiRecorder version 6.4.0 through 6.4.3, FortiRecorder all versions 6.0, FortiRecorder all versions 2.7 may allow an authenticated user to read arbitrary files via specially crafted command arguments.

# CWE-793 Only Filtering One Instance of a Special Element

## Description

The product receives data from an upstream component, but only filters a single instance of a special element before sending it to a downstream component.

Incomplete filtering of this nature may be location-dependent, as in only the first or last element is filtered.

# CWE-794 Incomplete Filtering of Multiple Instances of Special Elements

## Description

The product receives data from an upstream component, but does not filter all instances of a special element before sending it to a downstream component.

Incomplete filtering of this nature may be applied to:


  - sequential elements (special elements that appear next to each other) or

  - non-sequential elements (special elements that appear multiple times in different locations).

# CWE-795 Only Filtering Special Elements at a Specified Location

## Description

The product receives data from an upstream component, but only accounts for special elements at a specified location, thereby missing remaining special elements that may exist before sending it to a downstream component.

A filter might only account for instances of special elements when they occur:


  - relative to a marker (e.g. "at the beginning/end of string; the second argument"), or

  - at an absolute position (e.g. "byte number 10").

This may leave special elements in the data that did not match the filter position, but still may be dangerous.

# CWE-796 Only Filtering Special Elements Relative to a Marker

## Description

The product receives data from an upstream component, but only accounts for special elements positioned relative to a marker (e.g. "at the beginning/end of a string; the second argument"), thereby missing remaining special elements that may exist before sending it to a downstream component.

# CWE-797 Only Filtering Special Elements at an Absolute Position

## Description

The product receives data from an upstream component, but only accounts for special elements at an absolute position (e.g. "byte number 10"), thereby missing remaining special elements that may exist before sending it to a downstream component.

# CWE-798 Use of Hard-coded Credentials

## Description

The product contains hard-coded credentials, such as a password or cryptographic key.

There are two main variations:


  - Inbound: the product contains an authentication mechanism that checks the input credentials against a hard-coded set of credentials. In this variant, a default administration account is created, and a simple password is hard-coded into the product and associated with that account. This hard-coded password is the same for each installation of the product, and it usually cannot be changed or disabled by system administrators without manually modifying the program, or otherwise patching the product. It can also be difficult for the administrator to detect.

  - Outbound: the product connects to another system or component, and it contains hard-coded credentials for connecting to that component. This variant applies to front-end systems that authenticate with a back-end service. The back-end service may require a fixed password that can be easily discovered. The programmer may simply hard-code those back-end credentials into the front-end product.

## Observed Examples

CVE-2022-29953: Condition Monitor firmware has a maintenance interface with hard-coded credentials

CVE-2022-29960: Engineering Workstation uses hard-coded cryptographic keys that could allow for unathorized filesystem access and privilege escalation

CVE-2022-29964: Distributed Control System (DCS) has hard-coded passwords for local shell access

CVE-2022-30997: Programmable Logic Controller (PLC) has a maintenance service that uses undocumented, hard-coded credentials

CVE-2022-30314: Firmware for a Safety Instrumented System (SIS) has hard-coded credentials for access to boot configuration

CVE-2022-30271: Remote Terminal Unit (RTU) uses a hard-coded SSH private key that is likely to be used in typical deployments

CVE-2021-37555: Telnet service for IoT feeder for dogs and cats has hard-coded password [REF-1288]

CVE-2021-35033: Firmware for a WiFi router uses a hard-coded password for a BusyBox shell, allowing bypass of authentication through the UART port

CVE-2012-3503: Installation script has a hard-coded secret token value, allowing attackers to bypass authentication

CVE-2010-2772: SCADA system uses a hard-coded password to protect back-end database containing authorization information, exploited by Stuxnet worm

CVE-2010-2073: FTP server library uses hard-coded usernames and passwords for three default accounts

CVE-2010-1573: Chain: Router firmware uses hard-coded username and password for access to debug functionality, which can be used to execute arbitrary code

CVE-2008-2369: Server uses hard-coded authentication key

CVE-2008-0961: Backup product uses hard-coded username and password, allowing attackers to bypass authentication via the RPC interface

CVE-2008-1160: Security appliance uses hard-coded password allowing attackers to gain root access

CVE-2006-7142: Drive encryption product stores hard-coded cryptographic keys for encrypted configuration files in executable programs

CVE-2005-3716: VoIP product uses hard-coded public credentials that cannot be changed, which allows attackers to obtain sensitive information

CVE-2005-3803: VoIP product uses hard coded public and private SNMP community strings that cannot be changed, which allows remote attackers to obtain sensitive information

CVE-2005-0496: Backup product contains hard-coded credentials that effectively serve as a back door, which allows remote attackers to access the file system

## Top 25 Examples

CVE-2022-31460: Owl Labs Meeting Owl 5.2.0.15 allows attackers to activate Tethering Mode with hard-coded hoothoot credentials via a certain c 150 value.

CVE-2022-22765: BD Viper LT system, versions 2.0 and later, contains hardcoded credentials. If exploited, threat actors may be able to access, modify or delete sensitive information, including electronic protected health information (ePHI), protected health information (PHI) and personally identifiable information (PII). BD Viper LT system versions 4.0 and later utilize Microsoft Windows 10 and have additional Operating System hardening configurations which increase the attack complexity required to exploit this vulnerability.

CVE-2022-26476: A vulnerability has been identified in Spectrum Power 4 (All versions using Shared HIS), Spectrum Power 7 (All versions using Shared HIS), Spectrum Power MGMS (All versions using Shared HIS). An unauthenticated attacker could log into the component Shared HIS used in Spectrum Power systems by using an account with default credentials. A successful exploitation could allow the attacker to access the component Shared HIS with administrative privileges.

CVE-2022-28371: On Verizon 5G Home LVSKIHP InDoorUnit (IDU) 3.4.66.162 and OutDoorUnit (ODU) 3.33.101.0 devices, the CRTC and ODU RPC endpoints rely on a static certificate for access control. This certificate is embedded in the firmware, and is identical across the fleet of devices. An attacker need only download this firmware and extract the private components of these certificates (from /etc/lighttpd.d/ca.pem and /etc/lighttpd.d/server.pem) to gain access. (The firmware download location is shown in a device's upgrade logs.)

CVE-2022-29477: An authentication bypass vulnerability exists in the web interface /action/factory* functionality of Abode Systems, Inc. iota All-In-One Security Kit 6.9X and 6.9Z. A specially-crafted HTTP header can lead to authentication bypass. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-34151: Use of hard-coded credentials vulnerability exists in Machine automation controller NJ series all models V 1.48 and earlier, Machine automation controller NX7 series all models V1.28 and earlier, Machine automation controller NX1 series all models V1.48 and earlier, Automation software 'Sysmac Studio' all models V1.49 and earlier, and Programmable Terminal (PT) NA series NA5-15W/NA5-12W/NA5-9W/NA5-7W models Runtime V1.15 and earlier, which may allow a remote attacker who successfully obtained the user credentials by analyzing the affected product to access the controller.

CVE-2022-40263: BD Totalys MultiProcessor, versions 1.70 and earlier, contain hardcoded credentials. If exploited, threat actors may be able to access, modify or delete sensitive information, including electronic protected health information (ePHI), protected health information (PHI) and personally identifiable information (PII). Customers using BD Totalys MultiProcessor version 1.70 with Microsoft Windows 10 have additional operating system hardening configurations which increase the attack complexity required to exploit this vulnerability.

CVE-2021-45841: In Terramaster F4-210, F2-210 TOS 4.2.X (4.2.15-2107141517), an attacker can self-sign session cookies by knowing the target's MAC address and the user's password hash. Guest users (disabled by default) can be abused using a null/empty hash and allow an unauthenticated attacker to login as guest.

CVE-2022-20868: A vulnerability in the web-based management interface of Cisco Email Security Appliance, Cisco Secure Email and Web Manager and Cisco Secure Web Appliance could allow an authenticated, remote attacker to elevate privileges on an affected system. The attacker needs valid credentials to exploit this vulnerability. This vulnerability is due to the use of a hardcoded value to encrypt a token used for certain APIs calls . An attacker could exploit this vulnerability by authenticating to the device and sending a crafted HTTP request. A successful exploit could allow the attacker to impersonate another valid user and execute commands with the privileges of that user account. 

CVE-2022-25213: Improper physical access control and use of hard-coded credentials in /etc/passwd permits an attacker with physical access to obtain a root shell via an unprotected UART port on the device. The same port exposes an unauthenticated Das U-Boot BIOS shell.

CVE-2022-34907: An authentication bypass vulnerability exists in FileWave before 14.6.3 and 14.7.x before 14.7.2. Exploitation could allow an unauthenticated actor to gain access to the system with the highest authority possible and gain full control over the FileWave platform.

CVE-2022-43978: There is an improper authentication vulnerability in Pandora FMS v764. The application verifies that the user has a valid session when he is not trying to do a login. Since the secret is static in generatePublicHash function, an attacker with knowledge of a valid session can abuse this in order to pass the authentication check.

CVE-2022-35582: Penta Security Systems Inc WAPPLES 4.0.*, 5.0.0.*, 5.0.12.* are vulnerable to Incorrect Access Control. The operating system that WAPPLES runs on has a built-in non-privileged user penta with a predefined password. The password for this user, as well as its existence, is not disclosed in the documentation. Knowing the credentials, attackers can use this feature to gain uncontrolled access to the device and therefore are considered an undocumented possibility for remote control.

# CWE-799 Improper Control of Interaction Frequency

## Description

The product does not properly limit the number or frequency of interactions that it has with an actor, such as the number of incoming requests.

This can allow the actor to perform actions more frequently than expected. The actor could be a human or an automated process such as a virus or bot. This could be used to cause a denial of service, compromise program logic (such as limiting humans to a single vote), or other consequences. For example, an authentication routine might not limit the number of times an attacker can guess a password. Or, a web site might conduct a poll but only expect humans to vote a maximum of once a day.

## Observed Examples

CVE-2002-1876: Mail server allows attackers to prevent other users from accessing mail by sending large number of rapid requests.

## Top 25 Examples

CVE-2021-20414: IBM Guardium Data Encryption (GDE) 3.0.0.2 could allow a user to bruce force sensitive information due to not properly limiting the number of interactions. IBM X-Force ID: 196216.

CVE-2022-0823: An improper control of interaction frequency vulnerability in Zyxel GS1200 series switches could allow a local attacker to guess the password by using a timing side-channel attack.

CVE-2021-3172: An issue in Php-Fusion v9.03.90 fixed in v9.10.00 allows authenticated attackers to cause a Distributed Denial of Service via the Polling feature.

CVE-2022-37458: Discourse through 2.8.7 allows admins to send invitations to arbitrary email addresses at an unlimited rate.

CVE-2021-34735: Multiple vulnerabilities in the Cisco ATA 190 Series Analog Telephone Adapter Software could allow an attacker to perform a command injection attack resulting in remote code execution or cause a denial of service (DoS) condition on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-1624: A vulnerability in the Rate Limiting Network Address Translation (NAT) feature of Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause high CPU utilization in the Cisco QuantumFlow Processor of an affected device, resulting in a denial of service (DoS) condition. This vulnerability is due to mishandling of the rate limiting feature within the QuantumFlow Processor. An attacker could exploit this vulnerability by sending large amounts of traffic that would be subject to NAT and rate limiting through an affected device. A successful exploit could allow the attacker to cause the QuantumFlow Processor utilization to reach 100 percent on the affected device, resulting in a DoS condition.

CVE-2022-21689: OnionShare is an open source tool that lets you securely and anonymously share files, host websites, and chat with friends using the Tor network. In affected versions the receive mode limits concurrent uploads to 100 per second and blocks other uploads in the same second, which can be triggered by a simple script. An adversary with access to the receive mode can block file upload for others. There is no way to block this attack in public mode due to the anonymity properties of the tor network.

CVE-2022-40306: The login form /Login in ECi Printanista Hub (formerly FMAudit Printscout) through 2022-06-27 performs expensive RSA key-generation operations, which allows attackers to cause a denial of service (DoS) by requesting that form repeatedly.

