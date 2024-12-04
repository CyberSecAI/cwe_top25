# CWE-9 J2EE Misconfiguration: Weak Access Permissions for EJB Methods

## Description

If elevated access rights are assigned to EJB methods, then an attacker can take advantage of the permissions to exploit the product.

If the EJB deployment descriptor contains one or more method permissions that grant access to the special ANYONE role, it indicates that access control for the application has not been fully thought through or that the application is structured in such a way that reasonable access control restrictions are impossible.

# CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

## Description

The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.

## Observed Examples

CVE-2021-41232: Chain: authentication routine in Go-based agile development product does not escape user name (CWE-116), allowing LDAP injection (CWE-90)

CVE-2005-2301: Server does not properly escape LDAP queries, which allows remote attackers to cause a DoS and possibly conduct an LDAP injection attack.

## Top 25 Examples

CVE-2022-22360: IBM Sterling Partner Engagement Manager 6.1.2, 6.2, and Cloud/SasS 22.2 could allow a remote authenticated attacker to conduct an LDAP injection. By using a specially crafted request, an attacker could exploit this vulnerability and could result in in granting permission to unauthorized resources. IBM X-Force ID: 220782.

CVE-2022-45910: Improper neutralization of special elements used in an LDAP query ('LDAP Injection') vulnerability in ActiveDirectory and Sharepoint ActiveDirectory authority connectors of Apache ManifoldCF allows an attacker to manipulate the LDAP search queries (DoS, additional queries, filter manipulation) during user lookup, if the username or the domain string are passed to the UserACLs servlet without validation. This issue affects Apache ManifoldCF version 2.23 and prior versions.

CVE-2022-24832: GoCD is an open source a continuous delivery server. The bundled gocd-ldap-authentication-plugin included with the GoCD Server fails to correctly escape special characters when using the username to construct LDAP queries. While this does not directly allow arbitrary LDAP data exfiltration, it can allow an existing LDAP-authenticated GoCD user with malicious intent to construct and execute malicious queries, allowing them to deduce facts about other users or entries within the LDAP database (e.g alternate fields, usernames, hashed passwords etc) through brute force mechanisms. This only affects users who have a working LDAP authorization configuration enabled on their GoCD server, and only is exploitable by users authenticating using such an LDAP configuration. This issue has been fixed in GoCD 22.1.0, which is bundled with gocd-ldap-authentication-plugin v2.2.0-144.

CVE-2022-22975: An issue was discovered in the Pinniped Supervisor with either LADPIdentityProvider or ActiveDirectoryIdentityProvider resources. An attack would involve the malicious user changing the common name (CN) of their user entry on the LDAP or AD server to include special characters, which could be used to perform LDAP query injection on the Supervisor's LDAP query which determines their Kubernetes group membership.

CVE-2022-31088: LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings) stored in an LDAP directory. In versions prior to 8.0 the user name field at login could be used to enumerate LDAP data. This is only the case for LDAP search configuration. This issue has been fixed in version 8.0.

# CWE-908 Use of Uninitialized Resource

## Description

The product uses or accesses a resource that has not been initialized.

When a resource has not been properly initialized, the product may behave unexpectedly. This may lead to a crash or invalid memory access, but the consequences vary depending on the type of resource and how it is used within the product.

## Observed Examples

CVE-2019-9805: Chain: Creation of the packet client occurs before initialization is complete (CWE-696) resulting in a read from uninitialized memory (CWE-908), causing memory corruption.

CVE-2008-4197: Use of uninitialized memory may allow code execution.

CVE-2008-2934: Free of an uninitialized pointer leads to crash and possible code execution.

CVE-2008-0063: Product does not clear memory contents when generating an error message, leading to information leak.

CVE-2008-0062: Lack of initialization triggers NULL pointer dereference or double-free.

CVE-2008-0081: Uninitialized variable leads to code execution in popular desktop application.

CVE-2008-3688: Chain: Uninitialized variable leads to infinite loop.

CVE-2008-3475: Chain: Improper initialization leads to memory corruption.

CVE-2005-1036: Chain: Bypass of access restrictions due to improper authorization (CWE-862) of a user results from an improperly initialized (CWE-909) I/O permission bitmap

CVE-2008-3597: Chain: game server can access player data structures before initialization has happened leading to NULL dereference

CVE-2009-2692: Chain: uninitialized function pointers can be dereferenced allowing code execution

CVE-2009-0949: Chain: improper initialization of memory can lead to NULL dereference

CVE-2009-3620: Chain: some unprivileged ioctls do not verify that a structure has been initialized before invocation, leading to NULL dereference

## Top 25 Examples

CVE-2021-39671: In code generated by aidl_const_expressions.cpp, there is a possible out of bounds read due to uninitialized data. This could lead to information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-206718630

CVE-2022-26437: In httpclient, there is a possible out of bounds write due to uninitialized data. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: WSAP00103831; Issue ID: WSAP00103831.

CVE-2022-2949:  Altair HyperView Player versions 2021.1.0.27 and prior are vulnerable to the use of uninitialized memory vulnerability during parsing of H3D files. A DWORD is extracted from an uninitialized buffer and, after sign extension, is used as an index into a stack variable to increment a counter leading to memory corruption. 

CVE-2022-2950:  Altair HyperView Player versions 2021.1.0.27 and prior are vulnerable to the use of uninitialized memory vulnerability during parsing of H3D files. A DWORD is extracted from an uninitialized buffer and, after sign extension, is used as an index into a stack variable to increment a counter leading to memory corruption. 

CVE-2022-32615: In ccd, there is a possible out of bounds write due to uninitialized data. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07326559; Issue ID: ALPS07326559.

CVE-2022-32616: In isp, there is a possible out of bounds write due to uninitialized data. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07341258; Issue ID: ALPS07341258.

CVE-2022-39283: FreeRDP is a free remote desktop protocol library and clients. All FreeRDP based clients when using the `/video` command line switch might read uninitialized data, decode it as audio/video and display the result. FreeRDP based server implementations are not affected. This issue has been patched in version 2.8.1. If you cannot upgrade do not use the `/video` switch.

CVE-2022-20015: In kd_camera_hw driver, there is a possible information disclosure due to uninitialized data. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05862966; Issue ID: ALPS05862966.

CVE-2022-20357: In writeToParcel of SurfaceControl.cpp, there is a possible information disclosure due to uninitialized data. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-214999987

CVE-2022-38668: HTTP applications (servers) based on Crow through 1.0+4 may reveal potentially sensitive uninitialized data from stack memory when fulfilling a request for a static file smaller than 16 KB.

CVE-2022-0494: A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or CAP_SYS_RAWIO) to create issues with confidentiality.

# CWE-909 Missing Initialization of Resource

## Description

The product does not initialize a critical resource.

Many resources require initialization before they can be properly used. If a resource is not initialized, it could contain unpredictable or expired data, or it could be initialized to defaults that are invalid. This can have security implications when the resource is expected to have certain properties or values.

## Observed Examples

CVE-2020-20739: A variable that has its value set in a conditional statement is sometimes used when the conditional fails, sometimes causing data leakage

CVE-2005-1036: Chain: Bypass of access restrictions due to improper authorization (CWE-862) of a user results from an improperly initialized (CWE-909) I/O permission bitmap

## Top 25 Examples

CVE-2022-1016: A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel information leak problem caused by a local, unprivileged attacker.

CVE-2022-0175: A flaw was found in the VirGL virtual OpenGL renderer (virglrenderer). The virgl did not properly initialize memory when allocating a host-backed memory resource. A malicious guest could use this flaw to mmap from the guest kernel and read this uninitialized memory from the host, possibly leading to information disclosure.

CVE-2022-0382: An information leak flaw was found due to uninitialized memory in the Linux kernel's TIPC protocol subsystem, in the way a user sends a TIPC datagram to one or more destinations. This flaw allows a local user to read some kernel memory. This issue is limited to no more than 7 bytes, and the user cannot control what is read. This flaw affects the Linux kernel versions prior to 5.17-rc1.

CVE-2021-0946: The method PVRSRVBridgePMRPDumpSymbolicAddr allocates puiMemspaceNameInt on the heap, fills the contents of the buffer via PMR_PDumpSymbolicAddr, and then copies the buffer to userspace. The method PMR_PDumpSymbolicAddr may fail, and if it does the buffer will be left uninitialized and despite the error will still be copied to userspace. Kernel leak of uninitialized heap data with no privs required.Product: AndroidVersions: Android SoCAndroid ID: A-236846966

CVE-2021-0947: The method PVRSRVBridgeTLDiscoverStreams allocates puiStreamsInt on the heap, fills the contents of the buffer via TLServerDiscoverStreamsKM, and then copies the buffer to userspace. The method TLServerDiscoverStreamsKM may fail for several reasons including invalid sizes. If this method fails the buffer will be left uninitialized and despite the error will still be copied to userspace. Kernel leak of uninitialized heap data with no privs required.Product: AndroidVersions: Android SoCAndroid ID: A-236838960

# CWE-91 XML Injection (aka Blind XPath Injection)

## Description

The product does not properly neutralize special elements that are used in XML, allowing attackers to modify the syntax, content, or commands of the XML before it is processed by an end system.

Within XML, special elements could include reserved words or characters such as "<", ">", """, and "&", which could then be used to add new data or modify XML syntax.

# CWE-910 Use of Expired File Descriptor

## Description

The product uses or accesses a file descriptor after it has been closed.

After a file descriptor for a particular file or device has been released, it can be reused. The code might not write to the original file, since the reused file descriptor might reference a different file or device.

# CWE-911 Improper Update of Reference Count

## Description

The product uses a reference count to manage a resource, but it does not update or incorrectly updates the reference count.

Reference counts can be used when tracking how many objects contain a reference to a particular resource, such as in memory management or garbage collection. When the reference count reaches zero, the resource can be de-allocated or reused because there are no more objects that use it. If the reference count accidentally reaches zero, then the resource might be released too soon, even though it is still in use. If all objects no longer use the resource, but the reference count is not zero, then the resource might not ever be released.

## Observed Examples

CVE-2002-0574: chain: reference count is not decremented, leading to memory leak in OS by sending ICMP packets.

CVE-2004-0114: Reference count for shared memory not decremented when a function fails, potentially allowing unprivileged users to read kernel memory.

CVE-2006-3741: chain: improper reference count tracking leads to file descriptor consumption

CVE-2007-1383: chain: integer overflow in reference counter causes the same variable to be destroyed twice.

CVE-2007-1700: Incorrect reference count calculation leads to improper object destruction and code execution.

CVE-2008-2136: chain: incorrect update of reference count leads to memory leak.

CVE-2008-2785: chain/composite: use of incorrect data type for a reference counter allows an overflow of the counter, leading to a free of memory that is still in use.

CVE-2008-5410: Improper reference counting leads to failure of cryptographic operations.

CVE-2009-1709: chain: improper reference counting in a garbage collection routine leads to use-after-free

CVE-2009-3553: chain: reference count not correctly maintained when client disconnects during a large operation, leading to a use-after-free.

CVE-2009-3624: Reference count not always incremented, leading to crash or code execution.

CVE-2010-0176: improper reference counting leads to expired pointer dereference.

CVE-2010-0623: OS kernel increments reference count twice but only decrements once, leading to resource consumption and crash.

CVE-2010-2549: OS kernel driver allows code execution

CVE-2010-4593: improper reference counting leads to exhaustion of IP addresses

CVE-2011-0695: Race condition causes reference counter to be decremented prematurely, leading to the destruction of still-active object and an invalid pointer dereference.

CVE-2012-4787: improper reference counting leads to use-after-free

## Top 25 Examples

CVE-2022-3304: Use after free in CSS in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-20109: In ion, there is a possible use after free due to improper update of reference count. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06399915; Issue ID: ALPS06399915.

CVE-2022-29581: Improper Update of Reference Count vulnerability in net/sched of Linux Kernel allows local attacker to cause privilege escalation to root. This issue affects: Linux Kernel versions prior to 5.18; version 4.14 and later versions.

CVE-2022-38999: The AOD module has the improper update of reference count vulnerability. Successful exploitation of this vulnerability may affect data integrity, confidentiality, and availability.

CVE-2022-3910: Use After Free vulnerability in Linux Kernel allows Privilege Escalation. An improper Update of Reference Count in io_uring leads to Use-After-Free and Local Privilege Escalation. When io_msg_ring was invoked with a fixed file, it called io_fput_file() which improperly decreased its reference count (leading to Use-After-Free and Local Privilege Escalation). Fixed files are permanently registered to the ring, and should not be put separately. We recommend upgrading past commit https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 https://github.com/torvalds/linux/commit/fc7222c3a9f56271fba02aabbfbae999042f1679 

# CWE-912 Hidden Functionality

## Description

The product contains functionality that is not documented, not part of the specification, and not accessible through an interface or command sequence that is obvious to the product's users or administrators.

Hidden functionality can take many forms, such as intentionally malicious code, "Easter Eggs" that contain extraneous functionality such as games, developer-friendly shortcuts that reduce maintenance or support costs such as hard-coded accounts, etc. From a security perspective, even when the functionality is not intentionally malicious or damaging, it can increase the product's attack surface and expose additional weaknesses beyond what is already exposed by the intended functionality. Even if it is not easily accessible, the hidden functionality could be useful for attacks that modify the control flow of the application.

## Observed Examples

CVE-2022-31260: Chain: a digital asset management program has an undisclosed backdoor in the legacy version of a PHP script (CWE-912) that could allow an unauthenticated user to export metadata (CWE-306)

CVE-2022-3203: A wireless access point manual specifies that the only method of configuration is via web interface (CWE-1059), but there is an undisclosed telnet server that was activated by default (CWE-912).

## Top 25 Examples

CVE-2022-3203: On ORing net IAP-420(+) with FW version 2.0m a telnet server is enabled by default and cannot permanently be disabled. You can connect to the device via LAN or WiFi with hardcoded credentials and get an administrative shell. These credentials are reset to defaults with every reboot.

CVE-2021-20716: Hidden functionality in multiple Buffalo network devices (BHR-4RV firmware Ver.2.55 and prior, FS-G54 firmware Ver.2.04 and prior, WBR2-B11 firmware Ver.2.32 and prior, WBR2-G54 firmware Ver.2.32 and prior, WBR2-G54-KD firmware Ver.2.32 and prior, WBR-B11 firmware Ver.2.23 and prior, WBR-G54 firmware Ver.2.23 and prior, WBR-G54L firmware Ver.2.20 and prior, WHR2-A54G54 firmware Ver.2.25 and prior, WHR2-G54 firmware Ver.2.23 and prior, WHR2-G54V firmware Ver.2.55 and prior, WHR3-AG54 firmware Ver.2.23 and prior, WHR-G54 firmware Ver.2.16 and prior, WHR-G54-NF firmware Ver.2.10 and prior, WLA2-G54 firmware Ver.2.24 and prior, WLA2-G54C firmware Ver.2.24 and prior, WLA-B11 firmware Ver.2.20 and prior, WLA-G54 firmware Ver.2.20 and prior, WLA-G54C firmware Ver.2.20 and prior, WLAH-A54G54 firmware Ver.2.54 and prior, WLAH-AM54G54 firmware Ver.2.54 and prior, WLAH-G54 firmware Ver.2.54 and prior, WLI2-TX1-AG54 firmware Ver.2.53 and prior, WLI2-TX1-AMG54 firmware Ver.2.53 and prior, WLI2-TX1-G54 firmware Ver.2.20 and prior, WLI3-TX1-AMG54 firmware Ver.2.53 and prior, WLI3-TX1-G54 firmware Ver.2.53 and prior, WLI-T1-B11 firmware Ver.2.20 and prior, WLI-TX1-G54 firmware Ver.2.20 and prior, WVR-G54-NF firmware Ver.2.02 and prior, WZR-G108 firmware Ver.2.41 and prior, WZR-G54 firmware Ver.2.41 and prior, WZR-HP-G54 firmware Ver.2.41 and prior, WZR-RS-G54 firmware Ver.2.55 and prior, and WZR-RS-G54HP firmware Ver.2.55 and prior) allows a remote attacker to enable the debug option and to execute arbitrary code or OS commands, change the configuration, and cause a denial of service (DoS) condition.

CVE-2022-21173: Hidden functionality vulnerability in ELECOM LAN routers (WRH-300BK3 firmware v1.05 and earlier, WRH-300WH3 firmware v1.05 and earlier, WRH-300BK3-S firmware v1.05 and earlier, WRH-300DR3-S firmware v1.05 and earlier, WRH-300LB3-S firmware v1.05 and earlier, WRH-300PN3-S firmware v1.05 and earlier, WRH-300WH3-S firmware v1.05 and earlier, and WRH-300YG3-S firmware v1.05 and earlier) allows an attacker on the adjacent network to execute an arbitrary OS command via unspecified vectors.

CVE-2022-39044: Hidden functionality vulnerability in multiple Buffalo network devices allows a network-adjacent attacker with an administrative privilege to execute an arbitrary OS command. The affected products/versions are as follows: WCR-300 firmware Ver. 1.87 and earlier, WHR-HP-G300N firmware Ver. 2.00 and earlier, WHR-HP-GN firmware Ver. 1.87 and earlier, WPL-05G300 firmware Ver. 1.88 and earlier, WZR-300HP firmware Ver. 2.00 and earlier, WZR-450HP firmware Ver. 2.00 and earlier, WZR-600DHP firmware Ver. 2.00 and earlier, WZR-900DHP firmware Ver. 1.15 and earlier, WZR-HP-AG300H firmware Ver. 1.76 and earlier, WZR-HP-G302H firmware Ver. 1.86 and earlier, WLAE-AG300N firmware Ver. 1.86 and earlier, FS-600DHP firmware Ver. 3.40 and earlier, FS-G300N firmware Ver. 3.14 and earlier, FS-HP-G300N firmware Ver. 3.33 and earlier, FS-R600DHP firmware Ver. 3.40 and earlier, BHR-4GRV firmware Ver. 2.00 and earlier, DWR-HP-G300NH firmware Ver. 1.84 and earlier, DWR-PG firmware Ver. 1.83 and earlier, HW-450HP-ZWE firmware Ver. 2.00 and earlier, WER-A54G54 firmware Ver. 1.43 and earlier, WER-AG54 firmware Ver. 1.43 and earlier, WER-AM54G54 firmware Ver. 1.43 and earlier, WER-AMG54 firmware Ver. 1.43 and earlier, WHR-300 firmware Ver. 2.00 and earlier, WHR-300HP firmware Ver. 2.00 and earlier, WHR-AM54G54 firmware Ver. 1.43 and earlier, WHR-AMG54 firmware Ver. 1.43 and earlier, WHR-AMPG firmware Ver. 1.52 and earlier, WHR-G firmware Ver. 1.49 and earlier, WHR-G300N firmware Ver. 1.65 and earlier, WHR-G301N firmware Ver. 1.87 and earlier, WHR-G54S firmware Ver. 1.43 and earlier, WHR-G54S-NI firmware Ver. 1.24 and earlier, WHR-HP-AMPG firmware Ver. 1.43 and earlier, WHR-HP-G firmware Ver. 1.49 and earlier, WHR-HP-G54 firmware Ver. 1.43 and earlier, WLI-H4-D600 firmware Ver. 1.88 and earlier, WLI-TX4-AG300N firmware Ver. 1.53 and earlier, WS024BF firmware Ver. 1.60 and earlier, WS024BF-NW firmware Ver. 1.60 and earlier, WZR2-G108 firmware Ver. 1.33 and earlier, WZR2-G300N firmware Ver. 1.55 and earlier, WZR-450HP-CWT firmware Ver. 2.00 and earlier, WZR-450HP-UB firmware Ver. 2.00 and earlier, WZR-600DHP2 firmware Ver. 1.15 and earlier, WZR-AGL300NH firmware Ver. 1.55 and earlier, WZR-AMPG144NH firmware Ver. 1.49 and earlier, WZR-AMPG300NH firmware Ver. 1.51 and earlier, WZR-D1100H firmware Ver. 2.00 and earlier, WZR-G144N firmware Ver. 1.48 and earlier, WZR-G144NH firmware Ver. 1.48 and earlier, WZR-HP-G300NH firmware Ver. 1.84 and earlier, WZR-HP-G301NH firmware Ver. 1.84 and earlier, and WZR-HP-G450H firmware Ver. 1.90 and earlier.

CVE-2022-43464: Hidden functionality vulnerability in UDR-JA1604/UDR-JA1608/UDR-JA1616 firmware versions 71x10.1.107112.43A and earlier allows a remote authenticated attacker to execute an arbitrary OS command on the device or alter the device settings.

CVE-2022-43486: Hidden functionality vulnerability in Buffalo network devices allows a network-adjacent attacker with an administrative privilege to enable the debug functionalities and execute an arbitrary command on the affected devices.

CVE-2022-1741: The tested version of Dominion Voting Systems ImageCast X has a Terminal Emulator application which could be leveraged by an attacker to gain elevated privileges on a device and/or install malicious code.

CVE-2022-31260: In Montala ResourceSpace through 9.8 before r19636, csv_export_results_metadata.php allows attackers to export collection metadata via a non-NULL k value.

CVE-2022-26581: PAX A930 device with PayDroid_7.1.1_Virgo_V04.3.26T1_20210419 can allow an unauthorized attacker to perform privileged actions through the execution of specific binaries listed in ADB daemon. The attacker must have physical USB access to the device in order to exploit this vulnerability.

CVE-2022-29855: Mitel 6800 and 6900 Series SIP phone devices through 2022-04-27 have "undocumented functionality." A vulnerability in Mitel 6800 Series and 6900 Series SIP phones excluding 6970, versions 5.1 SP8 (5.1.0.8016) and earlier, and 6.0 (6.0.0.368) through 6.1 HF4 (6.1.0.165), could allow a unauthenticated attacker with physical access to the phone to gain root access due to insufficient access control for test functionality during system startup. A successful exploit could allow access to sensitive information and code execution.

# CWE-913 Improper Control of Dynamically-Managed Code Resources

## Description

The product does not properly restrict reading from or writing to dynamically-managed code resources such as variables, objects, classes, attributes, functions, or executable instructions or statements.

Many languages offer powerful features that allow the programmer to dynamically create or modify existing code, or resources used by code such as variables and objects. While these features can offer significant flexibility and reduce development time, they can be extremely dangerous if attackers can directly influence these code resources in unexpected ways.

## Observed Examples

CVE-2022-2054: Python compiler uses eval() to execute malicious strings as Python code.

CVE-2018-1000613: Cryptography API uses unsafe reflection when deserializing a private key

CVE-2015-8103: Deserialization issue in commonly-used Java library allows remote execution.

CVE-2006-7079: Chain: extract used for register_globals compatibility layer, enables path traversal (CWE-22)

CVE-2012-2055: Source version control product allows modification of trusted key using mass assignment.

## Top 25 Examples

CVE-2022-40634: Improper Control of Dynamically-Managed Code Resources vulnerability in Crafter Studio of Crafter CMS allows authenticated developers to execute OS commands via FreeMarker SSTI.

CVE-2022-25355: EC-CUBE 3.0.0 to 3.0.18-p3 and EC-CUBE 4.0.0 to 4.1.1 improperly handle HTTP Host header values, which may lead a remote unauthenticated attacker to direct the vulnerable version of EC-CUBE to send an Email with some forged reissue-password URL to EC-CUBE users.

# CWE-914 Improper Control of Dynamically-Identified Variables

## Description

The product does not properly restrict reading from or writing to dynamically-identified variables.

Many languages offer powerful features that allow the programmer to access arbitrary variables that are specified by an input string. While these features can offer significant flexibility and reduce development time, they can be extremely dangerous if attackers can modify unintended variables that have security implications.

## Observed Examples

CVE-2006-7135: extract issue enables file inclusion

CVE-2006-7079: Chain: extract used for register_globals compatibility layer, enables path traversal (CWE-22)

CVE-2007-0649: extract() buried in include files makes post-disclosure analysis confusing; original report had seemed incorrect.

CVE-2006-6661: extract() enables static code injection

CVE-2006-2828: import_request_variables() buried in include files makes post-disclosure analysis confusing

CVE-2009-0422: Chain: Dynamic variable evaluation allows resultant remote file inclusion and path traversal.

CVE-2007-2431: Chain: dynamic variable evaluation in PHP program used to modify critical, unexpected $_SERVER variable for resultant XSS.

CVE-2006-4904: Chain: dynamic variable evaluation in PHP program used to conduct remote file inclusion.

CVE-2006-4019: Dynamic variable evaluation in mail program allows reading and modifying attachments and preferences of other users.

# CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes

## Description

The product receives input from an upstream component that specifies multiple attributes, properties, or fields that are to be initialized or updated in an object, but it does not properly control which attributes can be modified.

If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability.


This weakness is sometimes known by the language-specific mechanisms that make it possible, such as mass assignment, autobinding, or object injection.

## Observed Examples

CVE-2024-3283: Application for using LLMs allows modification of a sensitive variable using mass assignment.

CVE-2012-2054: Mass assignment allows modification of arbitrary attributes using modified URL.

CVE-2012-2055: Source version control product allows modification of trusted key using mass assignment.

CVE-2008-7310: Attackers can bypass payment step in e-commerce product.

CVE-2013-1465: Use of PHP unserialize function on untrusted input allows attacker to modify application configuration.

CVE-2012-3527: Use of PHP unserialize function on untrusted input in content management system might allow code execution.

CVE-2012-0911: Use of PHP unserialize function on untrusted input in content management system allows code execution using a crafted cookie value.

CVE-2012-0911: Content management system written in PHP allows unserialize of arbitrary objects, possibly allowing code execution.

CVE-2011-4962: Content management system written in PHP allows code execution through page comments.

CVE-2009-4137: Use of PHP unserialize function on cookie value allows remote code execution or upload of arbitrary files.

CVE-2007-5741: Content management system written in Python interprets untrusted data as pickles, allowing code execution.

CVE-2011-2520: Python script allows local users to execute code via pickled data.

CVE-2005-2875: Python script allows remote attackers to execute arbitrary code using pickled objects.

CVE-2013-0277: Ruby on Rails allows deserialization of untrusted YAML to execute arbitrary code.

CVE-2011-2894: Spring framework allows deserialization of objects from untrusted sources to execute arbitrary code.

CVE-2012-1833: Grails allows binding of arbitrary parameters to modify arbitrary object properties.

CVE-2010-3258: Incorrect deserialization in web browser allows escaping the sandbox.

CVE-2008-1013: Media library allows deserialization of objects by untrusted Java applets, leading to arbitrary code execution.

## Top 25 Examples

CVE-2022-3225: Improper Control of Dynamically-Managed Code Resources in GitHub repository budibase/budibase prior to 1.3.20. 

# CWE-916 Use of Password Hash With Insufficient Computational Effort

## Description

The product generates a hash for a password, but it uses a scheme that does not provide a sufficient level of computational effort that would make password cracking attacks infeasible or expensive.

Many password storage mechanisms compute a hash and store the hash, instead of storing the original password in plaintext. In this design, authentication involves accepting an incoming password, computing its hash, and comparing it to the stored hash.


Many hash algorithms are designed to execute quickly with minimal overhead, even cryptographic hashes. However, this efficiency is a problem for password storage, because it can reduce an attacker's workload for brute-force password cracking. If an attacker can obtain the hashes through some other method (such as SQL injection on a database that stores hashes), then the attacker can store the hashes offline and use various techniques to crack the passwords by computing hashes efficiently. Without a built-in workload, modern attacks can compute large numbers of hashes, or even exhaust the entire space of all possible passwords, within a very short amount of time, using massively-parallel computing (such as cloud computing) and GPU, ASIC, or FPGA hardware. In such a scenario, an efficient hash algorithm helps the attacker.


There are several properties of a hash scheme that are relevant to its strength against an offline, massively-parallel attack:


  - The amount of CPU time required to compute the hash ("stretching")

  - The amount of memory required to compute the hash ("memory-hard" operations)

  - Including a random value, along with the password, as input to the hash computation ("salting")

  - Given a hash, there is no known way of determining an input (e.g., a password) that produces this hash value, other than by guessing possible inputs ("one-way" hashing)

  - Relative to the number of all possible hashes that can be generated by the scheme, there is a low likelihood of producing the same hash for multiple different inputs ("collision resistance")

Note that the security requirements for the product may vary depending on the environment and the value of the passwords. Different schemes might not provide all of these properties, yet may still provide sufficient security for the environment. Conversely, a solution might be very strong in preserving one property, which still being very weak for an attack against another property, or it might not be able to significantly reduce the efficiency of a massively-parallel attack.

## Observed Examples

CVE-2008-1526: Router does not use a salt with a hash, making it easier to crack passwords.

CVE-2006-1058: Router does not use a salt with a hash, making it easier to crack passwords.

CVE-2008-4905: Blogging software uses a hard-coded salt when calculating a password hash.

CVE-2002-1657: Database server uses the username for a salt when encrypting passwords, simplifying brute force attacks.

CVE-2001-0967: Server uses a constant salt when encrypting passwords, simplifying brute force attacks.

CVE-2005-0408: chain: product generates predictable MD5 hashes using a constant value combined with username, allowing authentication bypass.

## Top 25 Examples

CVE-2021-32997: The affected Baker Hughes Bentley Nevada products (3500 System 1 6.x, Part No. 3060/00 versions 6.98 and prior, 3500 System 1, Part No. 3071/xx & 3072/xx versions 21.1 HF1 and prior, 3500 Rack Configuration, Part No. 129133-01 versions 6.4 and prior, and 3500/22M Firmware, Part No. 288055-01 versions 5.05 and prior) utilize a weak encryption algorithm for storage and transmission of sensitive data, which may allow an attacker to more easily obtain credentials used for access.

CVE-2022-0022: Usage of a weak cryptographic algorithm in Palo Alto Networks PAN-OS software where the password hashes of administrator and local user accounts are not created with a sufficient level of computational effort, which allows for password cracking attacks on accounts in normal (non-FIPS-CC) operational mode. An attacker must have access to the account password hashes to take advantage of this weakness and can acquire those hashes if they are able to gain access to the PAN-OS software configuration. Fixed versions of PAN-OS software use a secure cryptographic algorithm for account password hashes. This issue does not impact Prisma Access firewalls. This issue impacts: PAN-OS 8.1 versions earlier than PAN-OS 8.1.21; All versions of PAN-OS 9.0; PAN-OS 9.1 versions earlier than PAN-OS 9.1.11; PAN-OS 10.0 versions earlier than PAN-OS 10.0.7.

CVE-2022-23348: BigAnt Software BigAnt Server v5.6.06 was discovered to utilize weak password hashes.

CVE-2022-26115: A use of password hash with insufficient computational effort vulnerability [CWE-916] in FortiSandbox before 4.2.0 may allow an attacker with access to the password database to efficiently mount bulk guessing attacks to recover the passwords.

CVE-2022-40258: AMI Megarac Weak password hashes for Redfish & API 

CVE-2022-24041: A vulnerability has been identified in Desigo DXR2 (All versions < V01.21.142.5-22), Desigo PXC3 (All versions < V01.21.142.4-18), Desigo PXC4 (All versions < V02.20.142.10-10884), Desigo PXC5 (All versions < V02.20.142.10-10884). The web application stores the PBKDF2 derived key of users passwords with a low iteration count. An attacker with user profile access privilege can retrieve the stored password hashes of other accounts and then successfully perform an offline cracking attack and recover the plaintext passwords of other users.

# CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')

## Description

The product constructs all or part of an expression language (EL) statement in a framework such as a Java Server Page (JSP) using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended EL statement before it is executed.

Frameworks such as Java Server Page (JSP) allow a developer to insert executable expressions within otherwise-static content. When the developer is not aware of the executable nature of these expressions and/or does not disable them, then if an attacker can inject expressions, this could lead to code execution or other unexpected behaviors.

## Observed Examples

CVE-2021-44228: Product does not neutralize ${xyz} style expressions, allowing remote code execution. (log4shell vulnerability in log4j)

## Top 25 Examples

CVE-2022-24818: GeoTools is an open source Java library that provides tools for geospatial data. The GeoTools library has a number of data sources that can perform unchecked JNDI lookups, which in turn can be used to perform class deserialization and result in arbitrary code execution. Similar to the Log4J case, the vulnerability can be triggered if the JNDI names are user-provided, but requires admin-level login to be triggered. The lookups are now restricted in GeoTools 26.4, GeoTools 25.6, and GeoTools 24.6. Users unable to upgrade should ensure that any downstream application should not allow usage of remotely provided JNDI strings.

CVE-2022-24847: GeoServer is an open source software server written in Java that allows users to share and edit geospatial data. The GeoServer security mechanism can perform an unchecked JNDI lookup, which in turn can be used to perform class deserialization and result in arbitrary code execution. The same can happen while configuring data stores with data sources located in JNDI, or while setting up the disk quota mechanism. In order to perform any of the above changes, the attack needs to have obtained admin rights and use either the GeoServer GUI, or its REST API. The lookups are going to be restricted in GeoServer 2.21.0, 2.20.4, 1.19.6. Users unable to upgrade should restrict access to the `geoserver/web` and `geoserver/rest` via a firewall and ensure that the GeoWebCache is not remotely accessible.

CVE-2022-26134: In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

CVE-2022-22947: In spring cloud gateway versions prior to 3.1.1+ and 3.0.7+ , applications are vulnerable to a code injection attack when the Gateway Actuator endpoint is enabled, exposed and unsecured. A remote attacker could make a maliciously crafted request that could allow arbitrary remote execution on the remote host.

CVE-2022-22963: In Spring Cloud Function versions 3.1.6, 3.2.2 and older unsupported versions, when using routing functionality it is possible for a user to provide a specially crafted SpEL as a routing-expression that may result in remote code execution and access to local resources.

CVE-2021-45046: It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

CVE-2021-26084: In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

CVE-2021-44228: Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.

CVE-2022-34466: A vulnerability has been identified in Mendix Applications using Mendix 9 (All versions >= V9.11 < V9.15), Mendix Applications using Mendix 9 (V9.12) (All versions < V9.12.3). An expression injection vulnerability was discovered in the Workflow subsystem of Mendix Runtime, that can affect the running applications. The vulnerability could allow a malicious user to leak sensitive information in a certain configuration.

CVE-2022-26111: The BeanShell components of IRISNext through 9.8.28 allow execution of arbitrary commands on the target server by creating a custom search (or editing an existing/predefined search) of the documents. The search components permit adding BeanShell expressions that result in Remote Code Execution in the context of the IRISNext application user, running on the web server.

# CWE-918 Server-Side Request Forgery (SSRF)

## Description

The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.

By providing URLs to unexpected hosts or ports, attackers can make it appear that the server is sending the request, possibly bypassing access controls such as firewalls that prevent the attackers from accessing the URLs directly. The server can be used as a proxy to conduct port scanning of hosts in internal networks, use other URLs such as that can access documents on the system (using file://), or use other protocols such as gopher:// or tftp://, which may provide greater control over the contents of requests.

## Observed Examples

CVE-2021-26855: Server Side Request Forgery (SSRF) in mail server, as exploited in the wild per CISA KEV.

CVE-2021-21973: Server Side Request Forgery in cloud platform, as exploited in the wild per CISA KEV.

CVE-2016-4029: Chain: incorrect validation of intended decimal-based IP address format (CWE-1286) enables parsing of octal or hexadecimal formats (CWE-1389), allowing bypass of an SSRF protection mechanism (CWE-918).

CVE-2002-1484: Web server allows attackers to request a URL from another server, including other ports, which allows proxied scanning.

CVE-2004-2061: CGI script accepts and retrieves incoming URLs.

CVE-2010-1637: Web-based mail program allows internal network scanning using a modified POP3 port number.

CVE-2009-0037: URL-downloading library automatically follows redirects to file:// and scp:// URLs

## Top 25 Examples

CVE-2021-40604: A Server-Side Request Forgery (SSRF) vulnerability in IPS Community Suite before 4.6.2 allows remote authenticated users to request arbitrary URLs or trigger deserialization via phar protocol when generating class names dynamically. In some cases an exploitation is possible by an unauthenticated user.

CVE-2022-1592: Server-Side Request Forgery in scout in GitHub repository clinical-genomics/scout prior to v4.42. An attacker could make the application perform arbitrary requests to fishing steal cookie, request to private area, or lead to xss...

CVE-2022-23544: MeterSphere is a one-stop open source continuous testing platform, covering test management, interface testing, UI testing and performance testing. Versions prior to 2.5.0 are subject to a Server-Side Request Forgery that leads to Cross-Site Scripting. A Server-Side request forgery in `IssueProxyResourceService::getMdImageByUrl` allows an attacker to access internal resources, as well as executing JavaScript code in the context of Metersphere's origin by a victim of a reflected XSS. This vulnerability has been fixed in v2.5.0. There are no known workarounds.

CVE-2022-41040: Microsoft Exchange Server Elevation of Privilege Vulnerability

CVE-2021-21975: Server Side Request Forgery in vRealize Operations Manager API (CVE-2021-21975) prior to 8.4 may allow a malicious actor with network access to the vRealize Operations Manager API can perform a Server Side Request Forgery attack to steal administrative credentials.

CVE-2021-22986: On BIG-IP versions 16.0.x before 16.0.1.1, 15.1.x before 15.1.2.1, 14.1.x before 14.1.4, 13.1.x before 13.1.3.6, and 12.1.x before 12.1.5.3 amd BIG-IQ 7.1.0.x before 7.1.0.3 and 7.0.0.x before 7.0.0.2, the iControl REST interface has an unauthenticated remote command execution vulnerability. Note: Software versions which have reached End of Software Development (EoSD) are not evaluated.

CVE-2021-26855: Microsoft Exchange Server Remote Code Execution Vulnerability

CVE-2021-27103: Accellion FTA 9_12_411 and earlier is affected by SSRF via a crafted POST request to wmProgressstat.html. The fixed version is FTA_9_12_416 and later.

CVE-2021-34473: Microsoft Exchange Server Remote Code Execution Vulnerability

CVE-2021-40438: A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the remote user. This issue affects Apache HTTP Server 2.4.48 and earlier.

CVE-2022-29180: A vulnerability in which attackers could forge HTTP requests to manipulate the `charm` data directory to access or delete anything on the server. This has been patched and is available in release [v0.12.1](https://github.com/charmbracelet/charm/releases/tag/v0.12.1). We recommend that all users running self-hosted `charm` instances update immediately. This vulnerability was found in-house and we haven't been notified of any potential exploiters. ### Additional notes * Encrypted user data uploaded to the Charm server is safe as Charm servers cannot decrypt user data. This includes filenames, paths, and all key-value data. * Users running the official Charm [Docker images](https://github.com/charmbracelet/charm/blob/main/docker.md) are at minimal risk because the exploit is limited to the containerized filesystem.

CVE-2022-29847: In Progress Ipswitch WhatsUp Gold 21.0.0 through 21.1.1, and 22.0.0, it is possible for an unauthenticated attacker to invoke an API transaction that would allow them to relay encrypted WhatsUp Gold user credentials to an arbitrary host.

CVE-2022-39055: RAVA certificate validation system has inadequate filtering for URL parameter. An unauthenticated remote attacker can perform SSRF attack to discover internal network topology base on query response.

CVE-2022-36997: An issue was discovered in Veritas NetBackup 8.1.x through 8.1.2, 8.2, 8.3.x through 8.3.0.2, 9.x through 9.0.0.1, and 9.1.x through 9.1.0.1 (and related NetBackup products). An attacker with authenticated access to a NetBackup Client could remotely trigger impacts that include arbitrary file read, Server-Side Request Forgery (SSRF), and denial of service.

CVE-2022-0528: Server-Side Request Forgery (SSRF) in GitHub repository transloadit/uppy prior to 3.3.1. 

CVE-2022-1815: Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository jgraph/drawio prior to 18.1.2.

CVE-2021-20325: Missing fixes for CVE-2021-40438 and CVE-2021-26691 in the versions of httpd, as shipped in Red Hat Enterprise Linux 8.5.0, causes a security regression compared to the versions shipped in Red Hat Enterprise Linux 8.4. A user who installs or updates to Red Hat Enterprise Linux 8.5.0 would be vulnerable to the mentioned CVEs, even if they were properly fixed in Red Hat Enterprise Linux 8.4. CVE-2021-20325 was assigned to that Red Hat specific security regression and it does not affect the upstream versions of httpd.

# CWE-920 Improper Restriction of Power Consumption

## Description

The product operates in an environment in which power is a limited resource that cannot be automatically replenished, but the product does not properly restrict the amount of power that its operation consumes.

In environments such as embedded or mobile devices, power can be a limited resource such as a battery, which cannot be automatically replenished by the product itself, and the device might not always be directly attached to a reliable power source. If the product uses too much power too quickly, then this could cause the device (and subsequently, the product) to stop functioning until power is restored, or increase the financial burden on the device owner because of increased power costs.


Normal operation of an application will consume power. However, in some cases, an attacker could cause the application to consume more power than intended, using components such as:


  - Display

  - CPU

  - Disk I/O

  - GPS

  - Sound

  - Microphone

  - USB interface

# CWE-921 Storage of Sensitive Data in a Mechanism without Access Control

## Description

The product stores sensitive information in a file system or device that does not have built-in access control.

While many modern file systems or devices utilize some form of access control in order to restrict access to data, not all storage mechanisms have this capability. For example, memory cards, floppy disks, CDs, and USB devices are typically made accessible to any user within the system. This can become a problem when sensitive data is stored in these mechanisms in a multi-user environment, because anybody on the system can read or write this data.


On Android devices, external storage is typically globally readable and writable by other applications on the device. External storage may also be easily accessible through the mobile device's USB connection or physically accessible through the device's memory card port.

# CWE-922 Insecure Storage of Sensitive Information

## Description

The product stores sensitive information without properly limiting read or write access by unauthorized actors.

If read access is not properly restricted, then attackers can steal the sensitive information. If write access is not properly restricted, then attackers can modify and possibly delete the data, causing incorrect results and possibly a denial of service.

## Observed Examples

CVE-2009-2272: password and username stored in cleartext in a cookie

## Top 25 Examples

CVE-2022-1257: Insecure storage of sensitive information vulnerability in MA for Linux, macOS, and Windows prior to 5.7.6 allows a local user to gain access to sensitive information through storage in ma.db. The sensitive information has been moved to encrypted database files.

CVE-2022-34354:  IBM Sterling Partner Engagement Manager 2.0 allows encrypted storage of client data to be stored locally which can be read by another user on the system. IBM X-Force ID: 230424. 

CVE-2022-41876: ezplatform-graphql is a GraphQL server implementation for Ibexa DXP and Ibexa Open Source. Versions prior to 2.3.12 and 1.0.13 are subject to Insecure Storage of Sensitive Information. Unauthenticated GraphQL queries for user accounts can expose password hashes of users that have created or modified content, typically administrators and editors. This issue has been patched in versions 2.3.12, and 1.0.13 on the 1.X branch. Users unable to upgrade can remove the "passwordHash" entry from "src/bundle/Resources/config/graphql/User.types.yaml" in the GraphQL package, and other properties like hash type, email, login if you prefer.

# CWE-923 Improper Restriction of Communication Channel to Intended Endpoints

## Description

The product establishes a communication channel to (or from) an endpoint for privileged or protected operations, but it does not properly ensure that it is communicating with the correct endpoint.

Attackers might be able to spoof the intended endpoint from a different system or process, thus gaining the same level of access as the intended endpoint.


While this issue frequently involves authentication between network-based clients and servers, other types of communication channels and endpoints can have this weakness.

## Observed Examples

CVE-2022-30319: S-bus functionality in a home automation product performs access control using an IP allowlist, which can be bypassed by a forged IP address.

CVE-2022-22547: A troubleshooting tool exposes a web server on a random port between 9000-65535 that could be used for information gathering

CVE-2022-4390: A WAN interface on a router has firewall restrictions enabled for IPv4, but it does not for IPv6, which is enabled by default

CVE-2012-2292: Product has a Silverlight cross-domain policy that does not restrict access to another application, which allows remote attackers to bypass the Same Origin Policy.

CVE-2012-5810: Mobile banking application does not verify hostname, leading to financial loss.

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversry-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

CVE-2000-1218: DNS server can accept DNS updates from hosts that it did not query, leading to cache poisoning

## Top 25 Examples

CVE-2022-22547: Simple Diagnostics Agent - versions 1.0 (up to version 1.57.), allows an attacker to access information which would otherwise be restricted via a random port 9000-65535. This allows information gathering which could be used exploit future open-source security exploits.

CVE-2022-44784: An issue was discovered in Appalti & Contratti 9.12.2. The target web applications LFS and DL229 expose a set of services provided by the Axis 1.4 instance, embedded directly into the applications, as hinted by the WEB-INF/web.xml file leaked through Local File Inclusion. Among the exposed services, there is the Axis AdminService, which, through the default configuration, should normally be accessible only by the localhost. Nevertheless, by trying to access the mentioned service, both in LFS and DL229, the service can actually be reached even by remote users, allowing creation of arbitrary services on the server side. When an attacker can reach the AdminService, they can use it to instantiate arbitrary services on the server. The exploit procedure is well known and described in Generic AXIS-SSRF exploitation. Basically, the attack consists of writing a JSP page inside the root directory of the web application, through the org.apache.axis.handlers.LogHandler class.

CVE-2022-26834: Improper access control vulnerability in Rakuten Casa version AP_F_V1_4_1 or AP_F_V2_0_0 allows a remote attacker to obtain the information stored in the product because the product is set to accept HTTP connections from the WAN side by default.

CVE-2022-4390: A network misconfiguration is present in versions prior to 1.0.9.90 of the NETGEAR RAX30 AX2400 series of routers. IPv6 is enabled for the WAN interface by default on these devices. While there are firewall restrictions in place that define access restrictions for IPv4 traffic, these restrictions do not appear to be applied to the WAN interface for IPv6. This allows arbitrary access to any services running on the device that may be inadvertently listening via IPv6, such as the SSH and Telnet servers spawned on ports 22 and 23 by default. This misconfiguration could allow an attacker to interact with services only intended to be accessible by clients on the local network.

CVE-2022-45414: If a Thunderbird user quoted from an HTML email, for example by replying to the email, and the email contained either a VIDEO tag with the POSTER attribute or an OBJECT tag with a DATA attribute, a network request to the referenced remote URL was performed, regardless of a configuration to block remote content. An image loaded from the POSTER attribute was shown in the composer window. These issues could have given an attacker additional capabilities when targetting releases that did not yet have a fix for CVE-2022-3033 which was reported around three months ago. This vulnerability affects Thunderbird < 102.5.1.

CVE-2022-47717: Last Yard 22.09.8-1 is vulnerable to Cross-origin resource sharing (CORS).

CVE-2022-3057: Inappropriate implementation in iframe Sandbox in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

CVE-2022-31055: kCTF is a Kubernetes-based infrastructure for capture the flag (CTF) competitions. Prior to version 1.6.0, the kctf cluster set-src-ip-ranges was broken and allowed traffic from any IP. The problem has been patched in v1.6.0. As a workaround, those who want to test challenges privately can mark them as `public: false` and use `kctf chal debug port-forward` to connect.

# CWE-924 Improper Enforcement of Message Integrity During Transmission in a Communication Channel

## Description

The product establishes a communication channel with an endpoint and receives a message from that endpoint, but it does not sufficiently ensure that the message was not modified during transmission.

Attackers might be able to modify the message and spoof the endpoint by interfering with the data as it crosses the network or by redirecting the connection to a system under their control.

# CWE-925 Improper Verification of Intent by Broadcast Receiver

## Description

The Android application uses a Broadcast Receiver that receives an Intent but does not properly verify that the Intent came from an authorized source.

Certain types of Intents, identified by action string, can only be broadcast by the operating system itself, not by third-party applications. However, when an application registers to receive these implicit system intents, it is also registered to receive any explicit intents. While a malicious application cannot send an implicit system intent, it can send an explicit intent to the target application, which may assume that any received intent is a valid implicit system intent and not an explicit intent from another application. This may lead to unintended behavior.

# CWE-926 Improper Export of Android Application Components

## Description

The Android application exports a component for use by other applications, but does not properly restrict which applications can launch the component or access the data it contains.

The attacks and consequences of improperly exporting a component may depend on the exported component:


  - If access to an exported Activity is not restricted, any application will be able to launch the activity. This may allow a malicious application to gain access to sensitive information, modify the internal state of the application, or trick a user into interacting with the victim application while believing they are still interacting with the malicious application.

  - If access to an exported Service is not restricted, any application may start and bind to the Service. Depending on the exposed functionality, this may allow a malicious application to perform unauthorized actions, gain access to sensitive information, or corrupt the internal state of the application.

  - If access to a Content Provider is not restricted to only the expected applications, then malicious applications might be able to access the sensitive data. Note that in Android before 4.2, the Content Provider is automatically exported unless it has been explicitly declared as NOT exported.



There are three types of components that can be exported in an Android application.


  - An Activity is an application component that provides a UI for users to interact with. A typical application will have multiple Activity screens that perform different functions, such as a main Activity screen and a separate settings Activity screen.

  - A Service is an application component that is started by another component to execute an operation in the background, even after the invoking component is terminated. Services do not have a UI component visible to the user.

  - The Content Provider mechanism can be used to share data with other applications or internally within the same application.



## Top 25 Examples

CVE-2021-25527: Improper export of Android application components vulnerability in Samsung Pay (India only) prior to version 4.1.77 allows attacker to access Bill Pay and Recharge menu without authentication.

CVE-2022-25817: Improper authentication in One UI Home prior to SMR Mar-2022 Release 1 allows attacker to generate pinned-shortcut without user consent.

# CWE-927 Use of Implicit Intent for Sensitive Communication

## Description

The Android application uses an implicit intent for transmitting sensitive data to other applications.

Since an implicit intent does not specify a particular application to receive the data, any application can process the intent by using an Intent Filter for that intent. This can allow untrusted applications to obtain sensitive data. There are two variations on the standard broadcast intent, ordered and sticky.


Ordered broadcast intents are delivered to a series of registered receivers in order of priority as declared by the Receivers. A malicious receiver can give itself a high priority and cause a denial of service by stopping the broadcast from propagating further down the chain. There is also the possibility of malicious data modification, as a receiver may also alter the data within the Intent before passing it on to the next receiver. The downstream components have no way of asserting that the data has not been altered earlier in the chain.


Sticky broadcast intents remain accessible after the initial broadcast. An old sticky intent will be broadcast again to any new receivers that register for it in the future, greatly increasing the chances of information exposure over time. Also, sticky broadcasts cannot be protected by permissions that may apply to other kinds of intents.


In addition, any broadcast intent may include a URI that references data that the receiving component does not normally have the privileges to access. The sender of the intent can include special privileges that grant the receiver read or write access to the specific URI included in the intent. A malicious receiver that intercepts this intent will also gain those privileges and be able to read or write the resource at the specified URI.

## Observed Examples

CVE-2022-4903: An Android application does not use FLAG_IMMUTABLE when creating a PendingIntent.

## Top 25 Examples

CVE-2022-39869: Improper access control vulnerability in cloudNotificationManager.java SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via REMOVE_PERSISTENT_BANNER broadcast.

CVE-2022-39870: Improper access control vulnerability in cloudNotificationManager.java SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via PUSH_MESSAGE_RECEIVED broadcast.

CVE-2022-39871: Improper access control vulnerability cloudNotificationManager.java in SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via implicit broadcasts.

CVE-2022-39878: Improper access control vulnerability in Samsung Checkout prior to version 5.0.55.3 allows attackers to access sensitive information via implicit intent broadcast.

CVE-2022-39894: Improper access control vulnerability in ContactListStartActivityHelper in Phone prior to SMR Dec-2022 Release 1 allows to access sensitive information via implicit intent.

CVE-2022-39895: Improper access control vulnerability in ContactListUtils in Phone prior to SMR Dec-2022 Release 1 allows to access contact group information via implicit intent.

CVE-2022-39896: Improper access control vulnerabilities in Contacts prior to SMR Dec-2022 Release 1 allows to access sensitive information via implicit intent.

CVE-2022-39915: Improper access control vulnerability in Calendar prior to versions 11.6.08.0 in Android Q(10), 12.2.11.3000 in Android R(11), 12.3.07.2000 in Android S(12), and 12.4.02.0 in Android T(13) allows attackers to access sensitive information via implicit intent.

CVE-2022-4903: A vulnerability was found in CodenameOne 7.0.70. It has been classified as problematic. Affected is an unknown function. The manipulation leads to use of implicit intent for sensitive communication. It is possible to launch the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. Upgrading to version 7.0.71 is able to address this issue. The patch is identified as dad49c9ef26a598619fc48d2697151a02987d478. It is recommended to upgrade the affected component. VDB-220470 is the identifier assigned to this vulnerability.

CVE-2022-36829: PendingIntent hijacking vulnerability in releaseAlarm in Charm by Samsung prior to version 1.2.3 allows local attackers to access files without permission via implicit intent.

CVE-2022-36830: PendingIntent hijacking vulnerability in cancelAlarmManager in Charm by Samsung prior to version 1.2.3 allows local attackers to access files without permission via implicit intent.

CVE-2022-33733: Sensitive information exposure in onCharacteristicRead in Charm by Samsung prior to version 1.2.3 allows attacker to get bluetooth connection information without permission.

CVE-2022-33734: Sensitive information exposure in onCharacteristicChanged in Charm by Samsung prior to version 1.2.3 allows attacker to get bluetooth connection information without permission.

# CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')

## Description

The product uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.

## Observed Examples

CVE-2002-1771: CRLF injection enables spam proxy (add mail headers) using email address or name.

CVE-2002-1783: CRLF injection in API function arguments modify headers for outgoing requests.

CVE-2004-1513: Spoofed entries in web server log file via carriage returns

CVE-2006-4624: Chain: inject fake log entries with fake timestamps using CRLF injection

CVE-2005-1951: Chain: Application accepts CRLF in an object ID, allowing HTTP response splitting.

CVE-2004-1687: Chain: HTTP response splitting via CRLF in parameter related to URL.

## Top 25 Examples

CVE-2021-31249: A CRLF injection vulnerability was found on BF-430, BF-431, and BF-450M TCP/IP Converter devices from CHIYU Technology Inc due to a lack of validation on the parameter redirect= available on multiple CGI components.

CVE-2022-31014: Nextcloud server is an open source personal cloud server. Affected versions were found to be vulnerable to SMTP command injection. The impact varies based on which commands are supported by the backend SMTP server. However, the main risk here is that the attacker can then hijack an already-authenticated SMTP session and run arbitrary SMTP commands as the email user, such as sending emails to other users, changing the FROM user, and so on. As before, this depends on the configuration of the server itself, but newlines should be sanitized to mitigate such arbitrary SMTP command injection. It is recommended that the Nextcloud Server is upgraded to 22.2.8 , 23.0.5 or 24.0.1. There are no known workarounds for this issue.

CVE-2022-31179: Shescape is a simple shell escape package for JavaScript. Versions prior to 1.5.8 were found to be subject to code injection on windows. This impacts users that use Shescape (any API function) to escape arguments for cmd.exe on Windows An attacker can omit all arguments following their input by including a line feed character (`'\\n'`) in the payload. This bug has been patched in [v1.5.8] which you can upgrade to now. No further changes are required. Alternatively, line feed characters (`'\\n'`) can be stripped out manually or the user input can be made the last argument (this only limits the impact).

CVE-2022-27924: Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 allows an unauthenticated attacker to inject arbitrary memcache commands into a targeted instance. These memcache commands becomes unescaped, causing an overwrite of arbitrary cached entries.

CVE-2022-29631: Jodd HTTP v6.0.9 was discovered to contain multiple CLRF injection vulnerabilities via the components jodd.http.HttpRequest#set and `jodd.http.HttpRequest#send. These vulnerabilities allow attackers to execute Server-Side Request Forgery (SSRF) via a crafted TCP payload.

CVE-2022-0391: A flaw was found in Python, specifically within the urllib.parse module. This module helps break Uniform Resource Locator (URL) strings into components. The issue involves how the urlparse method does not sanitize input and allows characters like '\\r' and '\\n' in the URL path. This flaw allows an attacker to input a crafted URL, leading to injection attacks. This flaw affects Python versions prior to 3.10.0b1, 3.9.5, 3.8.11, 3.7.11 and 3.6.14.

CVE-2022-25420: NTT Resonant Incorporated goo blog App Web Application 1.0 is vulnerable to CLRF injection. This vulnerability allows attackers to execute arbitrary code via a crafted HTTP request.

CVE-2022-29166: matrix-appservice-irc is a Node.js IRC bridge for Matrix. The vulnerability in node-irc allows an attacker to manipulate a Matrix user into executing IRC commands by having them reply to a maliciously crafted message. The vulnerability has been patched in matrix-appservice-irc 0.33.2. Refrain from replying to messages from untrusted participants in IRC-bridged Matrix rooms. There are no known workarounds for this issue.

CVE-2022-4768: A vulnerability was found in Dropbox merou. It has been classified as critical. Affected is the function add_public_key of the file grouper/public_key.py of the component SSH Public Key Handler. The manipulation of the argument public_key_str leads to injection. It is possible to launch the attack remotely. The name of the patch is d93087973afa26bc0a2d0a5eb5c0fde748bdd107. It is recommended to apply a patch to fix this issue. VDB-216906 is the identifier assigned to this vulnerability.

CVE-2022-24838: Nextcloud Calendar is a calendar application for the nextcloud framework. SMTP Command Injection in Appointment Emails via Newlines: as newlines and special characters are not sanitized in the email value in the JSON request, a malicious attacker can inject newlines to break out of the `RCPT TO:<BOOKING USER'S EMAIL> ` SMTP command and begin injecting arbitrary SMTP commands. It is recommended that Calendar is upgraded to 3.2.2. There are no workaround available.

CVE-2022-2992: A vulnerability in GitLab CE/EE affecting all versions from 11.10 prior to 15.1.6, 15.2 to 15.2.4, 15.3 to 15.3.2 allows an authenticated user to achieve remote code execution via the Import from GitHub API endpoint.

# CWE-939 Improper Authorization in Handler for Custom URL Scheme

## Description

The product uses a handler for a custom URL scheme, but it does not properly restrict which actors can invoke the handler using the scheme.

Mobile platforms and other architectures allow the use of custom URL schemes to facilitate communication between applications. In the case of iOS, this is the only method to do inter-application communication. The implementation is at the developer's discretion which may open security flaws in the application. An example could be potentially dangerous functionality such as modifying files through a custom URL scheme.

## Observed Examples

CVE-2013-5725: URL scheme has action replace which requires no user prompt and allows remote attackers to perform undesired actions.

CVE-2013-5726: URL scheme has action follow and favorite which allows remote attackers to force user to perform undesired actions.

## Top 25 Examples

CVE-2022-20736: A vulnerability in the web-based management interface of Cisco AppDynamics Controller Software could allow an unauthenticated, remote attacker to access a configuration file and the login page for an administrative console that they would not normally have authorization to access. This vulnerability is due to improper authorization checking for HTTP requests that are submitted to the affected web-based management interface. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected instance of AppDynamics Controller. A successful exploit could allow the attacker to access the login page for an administrative console. AppDynamics has released software updates that address this vulnerability.

CVE-2022-41797: Improper authorization in handler for custom URL scheme vulnerability in Lemon8 App for Android versions prior to 3.3.5 and Lemon8 App for iOS versions prior to 3.3.5 allows a remote attacker to lead a user to access an arbitrary website via the vulnerable App. As a result, the user may become a victim of a phishing attack.

# CWE-94 Improper Control of Generation of Code ('Code Injection')

## Description

The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.

When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product. Such an alteration could lead to arbitrary code execution.


Injection problems encompass a wide variety of issues -- all mitigated in very different ways. For this reason, the most effective way to discuss these weaknesses is to note the distinct features which classify them as injection weaknesses. The most important issue to note is that all injection problems share one thing in common -- i.e., they allow for the injection of control plane data into the user-controlled data plane. This means that the execution of the process may be altered by sending code in through legitimate data channels, using no other mechanism. While buffer overflows, and many other flaws, involve the use of some further issue to gain execution, injection problems need only for the data to be parsed. The most classic instantiations of this category of weakness are SQL injection and format string vulnerabilities.

## Observed Examples

CVE-2023-29374: Math component in an LLM framework translates user input into a Python expression that is input into the Python exec() method, allowing code execution - one variant of a "prompt injection" attack.

CVE-2024-5565: Python-based library uses an LLM prompt containing user input to dynamically generate code that is then fed as input into the Python exec() method, allowing code execution - one variant of a "prompt injection" attack.

CVE-2024-4181: Framework for LLM applications allows eval injection via a crafted response from a hosting provider.

CVE-2022-2054: Python compiler uses eval() to execute malicious strings as Python code.

CVE-2021-22204: Chain: regex in EXIF processor code does not correctly determine where a string ends (CWE-625), enabling eval injection (CWE-95), as exploited in the wild per CISA KEV.

CVE-2020-8218: "Code injection" in VPN product, as exploited in the wild per CISA KEV.

CVE-2008-5071: Eval injection in PHP program.

CVE-2002-1750: Eval injection in Perl program.

CVE-2008-5305: Eval injection in Perl program using an ID that should only contain hyphens and numbers.

CVE-2002-1752: Direct code injection into Perl eval function.

CVE-2002-1753: Eval injection in Perl program.

CVE-2005-1527: Direct code injection into Perl eval function.

CVE-2005-2837: Direct code injection into Perl eval function.

CVE-2005-1921: MFV. code injection into PHP eval statement using nested constructs that should not be nested.

CVE-2005-2498: MFV. code injection into PHP eval statement using nested constructs that should not be nested.

CVE-2005-3302: Code injection into Python eval statement from a field in a formatted file.

CVE-2007-1253: Eval injection in Python program.

CVE-2001-1471: chain: Resultant eval injection. An invalid value prevents initialization of variables, which can be modified by attacker and later injected into PHP eval statement.

CVE-2002-0495: Perl code directly injected into CGI library file from parameters to another CGI program.

CVE-2005-1876: Direct PHP code injection into supporting template file.

CVE-2005-1894: Direct code injection into PHP script that can be accessed by attacker.

CVE-2003-0395: PHP code from User-Agent HTTP header directly inserted into log file implemented as PHP script.

## Top 25 Examples

CVE-2022-23614: Twig is an open source template language for PHP. When in a sandbox mode, the `arrow` parameter of the `sort` filter must be a closure to avoid attackers being able to run arbitrary PHP functions. In affected versions this constraint was not properly enforced and could lead to code injection of arbitrary PHP code. Patched versions now disallow calling non Closure in the `sort` filter as is the case for some other filters. Users are advised to upgrade.

CVE-2022-25760: All versions of package accesslog are vulnerable to Arbitrary Code Injection due to the usage of the Function constructor without input sanitization. If (attacker-controlled) user input is given to the format option of the package's exported constructor function, it is possible for an attacker to execute arbitrary JavaScript code on the host that this package is being run on.

CVE-2022-29307: IonizeCMS v1.0.8.1 was discovered to contain a command injection vulnerability via the function copy_lang_content in application/models/lang_model.php.

CVE-2022-3236: A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

CVE-2022-3401: The Bricks theme for WordPress is vulnerable to remote code execution due to the theme allowing site editors to include executable code blocks in website content in versions 1.2 to 1.5.3. This, combined with the missing authorization vulnerability (CVE-2022-3400), makes it possible for authenticated attackers with minimal permissions, such as a subscriber, can edit any page, post, or template on the vulnerable WordPress website and inject a code execution block that can be used to achieve remote code execution.

CVE-2022-41882: The Nextcloud Desktop Client is a tool to synchronize files from Nextcloud Server with your computer. In version 3.6.0, if a user received a malicious file share and has it synced locally or the virtual filesystem enabled and clicked a nc://open/ link it will open the default editor for the file type of the shared file, which on Windows can also sometimes mean that a file depending on the type, e.g. "vbs", is being executed. It is recommended that the Nextcloud Desktop client is upgraded to version 3.6.1. As a workaround, users can block the Nextcloud Desktop client 3.6.0 by setting the `minimum.supported.desktop.version` system config to `3.6.1` on the server, so new files designed to use this attack vector are not downloaded anymore. Already existing files can still be used. Another workaround would be to enforce shares to be accepted by setting the `sharing.force_share_accept` system config to `true` on the server, so new files designed to use this attack vector are not downloaded anymore. Already existing shares can still be abused.

CVE-2022-38078: Movable Type XMLRPC API provided by Six Apart Ltd. contains a command injection vulnerability. Sending a specially crafted message by POST method to Movable Type XMLRPC API may allow arbitrary Perl script execution, and an arbitrary OS command may be executed through it. Affected products and versions are as follows: Movable Type 7 r.5202 and earlier, Movable Type Advanced 7 r.5202 and earlier, Movable Type 6.8.6 and earlier, Movable Type Advanced 6.8.6 and earlier, Movable Type Premium 1.52 and earlier, and Movable Type Premium Advanced 1.52 and earlier. Note that all versions of Movable Type 4.0 or later including unsupported (End-of-Life, EOL) versions are also affected by this vulnerability.

CVE-2022-41223: The Director database component of MiVoice Connect through 19.3 (22.22.6100.0) could allow an authenticated attacker to conduct a code-injection attack via crafted data due to insufficient restrictions on the database data type.

CVE-2021-22900: A vulnerability allowed multiple unrestricted uploads in Pulse Connect Secure before 9.1R11.4 that could lead to an authenticated administrator to perform a file write via a maliciously crafted archive upload in the administrator web interface.

CVE-2022-22965: A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

CVE-2022-29171: Sourcegraph is a fast and featureful code search and navigation engine. Versions before 3.38.0 are vulnerable to Remote Code Execution in the gitserver service. The Gitolite code host integration with Phabricator allows Sourcegraph site admins to specify a `callsignCommand`, which is used to obtain the Phabricator metadata for a Gitolite repository. An administrator who is able to edit or add a Gitolite code host and has administrative access to Sourcegraph’s bundled Grafana instance can change this command arbitrarily and run it remotely. This grants direct access to the infrastructure underlying the Sourcegraph installation. The attack requires: site-admin privileges on the instance of Sourcegraph, Administrative privileges on the bundled Grafana monitoring instance, Knowledge of the gitserver IP address or DNS name (if running in Kubernetes). This can be found through Grafana. The issue is patched in version 3.38.0. You may disable Gitolite code hosts. We still highly encourage upgrading regardless of workarounds.

CVE-2021-27446: The Weintek cMT product line is vulnerable to code injection, which may allow an unauthenticated remote attacker to execute commands with root privileges on the operation system.

CVE-2021-39908: In all versions of GitLab CE/EE starting from 0.8.0 before 14.2.6, all versions starting from 14.3 before 14.3.4, and all versions starting from 14.4 before 14.4.1 certain Unicode characters can be abused to commit malicious code into projects without being noticed in merge request or source code viewer UI.

CVE-2022-1159: Rockwell Automation Studio 5000 Logix Designer (all versions) are vulnerable when an attacker who achieves administrator access on a workstation running Studio 5000 Logix Designer could inject controller code undetectable to a user.

CVE-2022-21831: A code injection vulnerability exists in the Active Storage >= v5.2.0 that could allow an attacker to execute code via image_processing arguments.

CVE-2022-22285: A vulnerability using PendingIntent in Reminder prior to version 12.2.05.0 in Android R(11.0) and 12.3.02.1000 in Android S(12.0) allows attackers to execute privileged action by hijacking and modifying the intent.

CVE-2022-22286: A vulnerability using PendingIntent in Bixby Routines prior to version 3.1.21.8 in Android R(11.0) and 2.6.30.5 in Android Q(10.0) allows attackers to execute privileged action by hijacking and modifying the intent.

CVE-2022-23120: A code injection vulnerability in Trend Micro Deep Security and Cloud One - Workload Security Agent for Linux version 20 and below could allow an attacker to escalate privileges and run arbitrary code in the context of root. Please note: an attacker must first obtain access to the target agent in an un-activated and unconfigured state in order to exploit this vulnerability.

CVE-2022-23503: TYPO3 is an open source PHP based web content management system. Versions prior to 8.7.49, 9.5.38, 10.4.33, 11.5.20, and 12.1.1 are vulnerable to Code Injection. Due to the lack of separating user-submitted data from the internal configuration in the Form Designer backend module, it is possible to inject code instructions to be processed and executed via TypoScript as PHP code. The existence of individual TypoScript instructions for a particular form item and a valid backend user account with access to the form module are needed to exploit this vulnerability. This issue is patched in versions 8.7.49 ELTS, 9.5.38 ELTS, 10.4.33, 11.5.20, 12.1.1.

CVE-2022-24663: PHP Everywhere <= 2.0.3 included functionality that allowed execution of PHP Code Snippets via WordPress shortcodes, which can be used by any authenticated user.

CVE-2022-24735: Redis is an in-memory database that persists on disk. By exploiting weaknesses in the Lua script execution environment, an attacker with access to Redis prior to version 7.0.0 or 6.2.7 can inject Lua code that will execute with the (potentially higher) privileges of another Redis user. The Lua script execution environment in Redis provides some measures that prevent a script from creating side effects that persist and can affect the execution of the same, or different script, at a later time. Several weaknesses of these measures have been publicly known for a long time, but they had no security impact as the Redis security model did not endorse the concept of users or privileges. With the introduction of ACLs in Redis 6.0, these weaknesses can be exploited by a less privileged users to inject Lua code that will execute at a later time, when a privileged user executes a Lua script. The problem is fixed in Redis versions 7.0.0 and 6.2.7. An additional workaround to mitigate this problem without patching the redis-server executable, if Lua scripting is not being used, is to block access to `SCRIPT LOAD` and `EVAL` commands using ACL rules.

CVE-2022-24817: Flux2 is an open and extensible continuous delivery solution for Kubernetes. Flux2 versions between 0.1.0 and 0.29.0, helm-controller 0.1.0 to v0.19.0, and kustomize-controller 0.1.0 to v0.23.0 are vulnerable to Code Injection via malicious Kubeconfig. In multi-tenancy deployments this can also lead to privilege escalation if the controller's service account has elevated permissions. Workarounds include disabling functionality via Validating Admission webhooks by restricting users from setting the `spec.kubeConfig` field in Flux `Kustomization` and `HelmRelease` objects. Additional mitigations include applying restrictive AppArmor and SELinux profiles on the controller’s pod to limit what binaries can be executed. This vulnerability is fixed in kustomize-controller v0.23.0 and helm-controller v0.19.0, both included in flux2 v0.29.0

CVE-2022-29813: In JetBrains IntelliJ IDEA before 2022.1 local code execution via custom Pandoc path was possible

CVE-2022-29814: In JetBrains IntelliJ IDEA before 2022.1 local code execution via HTML descriptions in custom JSON schemas was possible

CVE-2022-29815: In JetBrains IntelliJ IDEA before 2022.1 local code execution via workspace settings was possible

CVE-2022-29819: In JetBrains IntelliJ IDEA before 2022.1 local code execution via links in Quick Documentation was possible

CVE-2022-29821: In JetBrains Rider before 2022.1 local code execution via links in ReSharper Quick Documentation was possible

CVE-2022-30083: EllieGrid Android Application version 3.4.1 is vulnerable to Code Injection. The application appears to evaluate user input as code (remote).

CVE-2022-34456:  Dell EMC Metro node, Version(s) prior to 7.1, contain a Code Injection Vulnerability. An authenticated nonprivileged attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the application. 

CVE-2022-34663: A vulnerability has been identified in RUGGEDCOM i800, RUGGEDCOM i800NC, RUGGEDCOM i801, RUGGEDCOM i801NC, RUGGEDCOM i802, RUGGEDCOM i802NC, RUGGEDCOM i803, RUGGEDCOM i803NC, RUGGEDCOM M2100, RUGGEDCOM M2100F, RUGGEDCOM M2100NC, RUGGEDCOM M2200, RUGGEDCOM M2200F, RUGGEDCOM M2200NC, RUGGEDCOM M969, RUGGEDCOM M969F, RUGGEDCOM M969NC, RUGGEDCOM RMC30, RUGGEDCOM RMC30NC, RUGGEDCOM RMC8388 V4.X, RUGGEDCOM RMC8388 V5.X, RUGGEDCOM RMC8388NC V4.X, RUGGEDCOM RMC8388NC V5.X, RUGGEDCOM RP110, RUGGEDCOM RP110NC, RUGGEDCOM RS1600, RUGGEDCOM RS1600F, RUGGEDCOM RS1600FNC, RUGGEDCOM RS1600NC, RUGGEDCOM RS1600T, RUGGEDCOM RS1600TNC, RUGGEDCOM RS400, RUGGEDCOM RS400F, RUGGEDCOM RS400NC, RUGGEDCOM RS401, RUGGEDCOM RS401NC, RUGGEDCOM RS416, RUGGEDCOM RS416F, RUGGEDCOM RS416NC, RUGGEDCOM RS416NCv2 V4.X, RUGGEDCOM RS416NCv2 V5.X, RUGGEDCOM RS416P, RUGGEDCOM RS416PF, RUGGEDCOM RS416PNC, RUGGEDCOM RS416PNCv2 V4.X, RUGGEDCOM RS416PNCv2 V5.X, RUGGEDCOM RS416Pv2 V4.X, RUGGEDCOM RS416Pv2 V5.X, RUGGEDCOM RS416v2 V4.X, RUGGEDCOM RS416v2 V5.X, RUGGEDCOM RS8000, RUGGEDCOM RS8000A, RUGGEDCOM RS8000ANC, RUGGEDCOM RS8000H, RUGGEDCOM RS8000HNC, RUGGEDCOM RS8000NC, RUGGEDCOM RS8000T, RUGGEDCOM RS8000TNC, RUGGEDCOM RS900, RUGGEDCOM RS900 (32M) V4.X, RUGGEDCOM RS900 (32M) V5.X, RUGGEDCOM RS900F, RUGGEDCOM RS900G, RUGGEDCOM RS900G (32M) V4.X, RUGGEDCOM RS900G (32M) V5.X, RUGGEDCOM RS900GF, RUGGEDCOM RS900GNC, RUGGEDCOM RS900GNC(32M) V4.X, RUGGEDCOM RS900GNC(32M) V5.X, RUGGEDCOM RS900GP, RUGGEDCOM RS900GPF, RUGGEDCOM RS900GPNC, RUGGEDCOM RS900L, RUGGEDCOM RS900LNC, RUGGEDCOM RS900M-GETS-C01, RUGGEDCOM RS900M-GETS-XX, RUGGEDCOM RS900M-STND-C01, RUGGEDCOM RS900M-STND-XX, RUGGEDCOM RS900MNC-GETS-C01, RUGGEDCOM RS900MNC-GETS-XX, RUGGEDCOM RS900MNC-STND-XX, RUGGEDCOM RS900MNC-STND-XX-C01, RUGGEDCOM RS900NC, RUGGEDCOM RS900NC(32M) V4.X, RUGGEDCOM RS900NC(32M) V5.X, RUGGEDCOM RS900W, RUGGEDCOM RS910, RUGGEDCOM RS910L, RUGGEDCOM RS910LNC, RUGGEDCOM RS910NC, RUGGEDCOM RS910W, RUGGEDCOM RS920L, RUGGEDCOM RS920LNC, RUGGEDCOM RS920W, RUGGEDCOM RS930L, RUGGEDCOM RS930LNC, RUGGEDCOM RS930W, RUGGEDCOM RS940G, RUGGEDCOM RS940GF, RUGGEDCOM RS940GNC, RUGGEDCOM RS969, RUGGEDCOM RS969NC, RUGGEDCOM RSG2100, RUGGEDCOM RSG2100 (32M) V4.X, RUGGEDCOM RSG2100 (32M) V5.X, RUGGEDCOM RSG2100F, RUGGEDCOM RSG2100NC, RUGGEDCOM RSG2100NC(32M) V4.X, RUGGEDCOM RSG2100NC(32M) V5.X, RUGGEDCOM RSG2100P, RUGGEDCOM RSG2100PF, RUGGEDCOM RSG2100PNC, RUGGEDCOM RSG2200, RUGGEDCOM RSG2200F, RUGGEDCOM RSG2200NC, RUGGEDCOM RSG2288 V4.X, RUGGEDCOM RSG2288 V5.X, RUGGEDCOM RSG2288NC V4.X, RUGGEDCOM RSG2288NC V5.X, RUGGEDCOM RSG2300 V4.X, RUGGEDCOM RSG2300 V5.X, RUGGEDCOM RSG2300F, RUGGEDCOM RSG2300NC V4.X, RUGGEDCOM RSG2300NC V5.X, RUGGEDCOM RSG2300P V4.X, RUGGEDCOM RSG2300P V5.X, RUGGEDCOM RSG2300PF, RUGGEDCOM RSG2300PNC V4.X, RUGGEDCOM RSG2300PNC V5.X, RUGGEDCOM RSG2488 V4.X, RUGGEDCOM RSG2488 V5.X, RUGGEDCOM RSG2488F, RUGGEDCOM RSG2488NC V4.X, RUGGEDCOM RSG2488NC V5.X, RUGGEDCOM RSG907R, RUGGEDCOM RSG908C, RUGGEDCOM RSG909R, RUGGEDCOM RSG910C, RUGGEDCOM RSG920P V4.X, RUGGEDCOM RSG920P V5.X, RUGGEDCOM RSG920PNC V4.X, RUGGEDCOM RSG920PNC V5.X, RUGGEDCOM RSL910, RUGGEDCOM RSL910NC, RUGGEDCOM RST2228, RUGGEDCOM RST2228P, RUGGEDCOM RST916C, RUGGEDCOM RST916P. Affected devices are vulnerable to a web-based code injection attack via the console. An attacker could exploit this vulnerability to inject code into the web server and cause malicious behavior in legitimate users accessing certain web resources on the affected device.

CVE-2022-34821: A vulnerability has been identified in RUGGEDCOM RM1224 LTE(4G) EU (All versions < V7.2), RUGGEDCOM RM1224 LTE(4G) NAM (All versions < V7.2), SCALANCE M804PB (All versions < V7.2), SCALANCE M812-1 ADSL-Router (Annex A) (All versions < V7.2), SCALANCE M812-1 ADSL-Router (Annex B) (All versions < V7.2), SCALANCE M816-1 ADSL-Router (Annex A) (All versions < V7.2), SCALANCE M816-1 ADSL-Router (Annex B) (All versions < V7.2), SCALANCE M826-2 SHDSL-Router (All versions < V7.2), SCALANCE M874-2 (All versions < V7.2), SCALANCE M874-3 (All versions < V7.2), SCALANCE M876-3 (EVDO) (All versions < V7.2), SCALANCE M876-3 (ROK) (All versions < V7.2), SCALANCE M876-4 (All versions < V7.2), SCALANCE M876-4 (EU) (All versions < V7.2), SCALANCE M876-4 (NAM) (All versions < V7.2), SCALANCE MUM853-1 (EU) (All versions < V7.2), SCALANCE MUM856-1 (EU) (All versions < V7.2), SCALANCE MUM856-1 (RoW) (All versions < V7.2), SCALANCE S615 (All versions < V7.2), SCALANCE S615 EEC (All versions < V7.2), SCALANCE SC622-2C (All versions < V2.3), SCALANCE SC622-2C (All versions >= V2.3 < V3.0), SCALANCE SC626-2C (All versions < V2.3), SCALANCE SC626-2C (All versions >= V2.3 < V3.0), SCALANCE SC632-2C (All versions < V2.3), SCALANCE SC632-2C (All versions >= V2.3 < V3.0), SCALANCE SC636-2C (All versions < V2.3), SCALANCE SC636-2C (All versions >= V2.3 < V3.0), SCALANCE SC642-2C (All versions < V2.3), SCALANCE SC642-2C (All versions >= V2.3 < V3.0), SCALANCE SC646-2C (All versions < V2.3), SCALANCE SC646-2C (All versions >= V2.3 < V3.0), SCALANCE WAM763-1 (All versions), SCALANCE WAM766-1 (EU) (All versions), SCALANCE WAM766-1 (US) (All versions), SCALANCE WAM766-1 EEC (EU) (All versions), SCALANCE WAM766-1 EEC (US) (All versions), SCALANCE WUM763-1 (All versions), SCALANCE WUM763-1 (All versions), SCALANCE WUM766-1 (EU) (All versions), SCALANCE WUM766-1 (US) (All versions), SIMATIC CP 1242-7 V2 (All versions < V3.3.46), SIMATIC CP 1243-1 (All versions < V3.3.46), SIMATIC CP 1243-7 LTE EU (All versions < V3.3.46), SIMATIC CP 1243-7 LTE US (All versions < V3.3.46), SIMATIC CP 1243-8 IRC (All versions < V3.3.46), SIMATIC CP 1542SP-1 IRC (All versions >= V2.0 < V2.2.28), SIMATIC CP 1543-1 (All versions < V3.0.22), SIMATIC CP 1543SP-1 (All versions >= V2.0 < V2.2.28), SIPLUS ET 200SP CP 1542SP-1 IRC TX RAIL (All versions >= V2.0 < V2.2.28), SIPLUS ET 200SP CP 1543SP-1 ISEC (All versions >= V2.0 < V2.2.28), SIPLUS ET 200SP CP 1543SP-1 ISEC TX RAIL (All versions >= V2.0 < V2.2.28), SIPLUS NET CP 1242-7 V2 (All versions < V3.3.46), SIPLUS NET CP 1543-1 (All versions < V3.0.22), SIPLUS S7-1200 CP 1243-1 (All versions < V3.3.46), SIPLUS S7-1200 CP 1243-1 RAIL (All versions < V3.3.46). By injecting code to specific configuration options for OpenVPN, an attacker could execute arbitrary code with elevated privileges.

CVE-2022-3696: A post-auth code injection vulnerability allows admins to execute code in Webadmin of Sophos Firewall releases older than version 19.5 GA.

CVE-2022-37009: In JetBrains IntelliJ IDEA before 2022.2 local code execution via a Vagrant executable was possible

CVE-2022-3713: A code injection vulnerability allows adjacent attackers to execute code in the Wifi controller of Sophos Firewall releases older than version 19.5 GA.

CVE-2022-40127: A vulnerability in Example Dags of Apache Airflow allows an attacker with UI access who can trigger DAGs, to execute arbitrary commands via manually provided run_id parameter. This issue affects Apache Airflow Apache Airflow versions prior to 2.4.0.

CVE-2022-4060: The User Post Gallery WordPress plugin through 2.19 does not limit what callback functions can be called by users, making it possible to any visitors to run code on sites running it.

CVE-2022-40628: This vulnerability exists in Tacitine Firewall, all versions of EN6200-PRIME QUAD-35 and EN6200-PRIME QUAD-100 between 19.1.1 to 22.20.1 (inclusive), due to improper control of code generation in the Tacitine Firewall web-based management interface. An unauthenticated remote attacker could exploit this vulnerability by sending a specially crafted http request on the targeted device. Successful exploitation of this vulnerability could allow an unauthenticated remote attacker to execute arbitrary commands on the targeted device.

CVE-2022-41205: SAP GUI allows an authenticated attacker to execute scripts in the local network. On successful exploitation, the attacker can gain access to registries which can cause a limited impact on confidentiality and high impact on availability of the application. 

CVE-2022-41264: Due to the unrestricted scope of the RFC function module, SAP BASIS - versions 731, 740, 750, 751, 752, 753, 754, 755, 756, 757, 789, 790, 791, allows an authenticated non-administrator attacker to access a system class and execute any of its public methods with parameters provided by the attacker. On successful exploitation the attacker can have full control of the system to which the class belongs, causing a high impact on the integrity of the application. 

CVE-2022-42268:  Omniverse Kit contains a vulnerability in the reference applications Create, Audio2Face, Isaac Sim, View, Code, and Machinima. These applications allow executable Python code to be embedded in Universal Scene Description (USD) files to customize all aspects of a scene. If a user opens a USD file that contains embedded Python code in one of these applications, the embedded Python code automatically runs with the privileges of the user who opened the file. As a result, an unprivileged remote attacker could craft a USD file containing malicious Python code and persuade a local user to open the file, which may lead to information disclosure, data tampering, and denial of service. 

CVE-2022-42699: Auth. Remote Code Execution vulnerability in Easy WP SMTP plugin <= 1.5.1 on WordPress. 

CVE-2022-43571: In Splunk Enterprise versions below 8.2.9, 8.1.12, and 9.0.2, an authenticated user can execute arbitrary code through the dashboard PDF generation component. 

CVE-2022-46157: Akeneo PIM is an open source Product Information Management (PIM). Akeneo PIM Community Edition versions before v5.0.119 and v6.0.53 allows remote authenticated users to execute arbitrary PHP code on the server by uploading a crafted image. Akeneo PIM Community Edition after the versions aforementioned provides patched Apache HTTP server configuration file, for docker setup and in documentation sample, to fix this vulnerability. Community Edition users must change their Apache HTTP server configuration accordingly to be protected. The patch for Cloud Based Akeneo PIM Services customers has been applied since 30th October 2022. Users are advised to upgrade. Users unable to upgrade may Replace any reference to `<FilesMatch \\.php$>` in their apache httpd configurations with: `<Location "/index.php">`.

CVE-2022-46166: Spring boot admins is an open source administrative user interface for management of spring boot applications. All users who run Spring Boot Admin Server, having enabled Notifiers (e.g. Teams-Notifier) and write access to environment variables via UI are affected. Users are advised to upgrade to the most recent releases of Spring Boot Admin 2.6.10 and 2.7.8 to resolve this issue. Users unable to upgrade may disable any notifier or disable write access (POST request) on `/env` actuator endpoint. 

CVE-2022-23332: Command injection vulnerability in Manual Ping Form (Web UI) in Shenzhen Ejoin Information Technology Co., Ltd. ACOM508/ACOM516/ACOM532 609-915-041-100-020 allows a remote attacker to inject arbitrary code via the field.

CVE-2022-24295: Okta Advanced Server Access Client for Windows prior to version 1.57.0 was found to be vulnerable to command injection via a specially crafted URL.

CVE-2022-21122: The package metacalc before 0.0.2 are vulnerable to Arbitrary Code Execution when it exposes JavaScript's Math class to the v8 context. As the Math class is exposed to user-land, it can be used to get access to JavaScript's Function constructor.

# CWE-940 Improper Verification of Source of a Communication Channel

## Description

The product establishes a communication channel to handle an incoming request that has been initiated by an actor, but it does not properly verify that the request is coming from the expected origin.

When an attacker can successfully establish a communication channel from an untrusted origin, the attacker may be able to gain privileges and access unexpected functionality.

## Observed Examples

CVE-2000-1218: DNS server can accept DNS updates from hosts that it did not query, leading to cache poisoning

CVE-2005-0877: DNS server can accept DNS updates from hosts that it did not query, leading to cache poisoning

CVE-2001-1452: DNS server caches glue records received from non-delegated name servers

## Top 25 Examples

CVE-2022-27491: A improper verification of source of a communication channel in Fortinet FortiOS with IPS engine version 7.201 through 7.214, 7.001 through 7.113, 6.001 through 6.121, 5.001 through 5.258 and before 4.086 allows a remote and unauthenticated attacker to trigger the sending of "blocked page" HTML data to an arbitrary victim via crafted TCP requests, potentially flooding the victim.

CVE-2022-29235: BigBlueButton is an open source web conferencing system. Starting in version 2.2 and prior to versions 2.3.18 and 2.4-rc-6, an attacker who is able to obtain the meeting identifier for a meeting on a server can find information related to an external video being shared, like the current timestamp and play/pause. The problem has been patched in versions 2.3.18 and 2.4-rc-6 by modifying the stream to send the data only for users in the meeting. There are currently no known workarounds.

# CWE-941 Incorrectly Specified Destination in a Communication Channel

## Description

The product creates a communication channel to initiate an outgoing request to an actor, but it does not correctly specify the intended destination for that actor.

Attackers at the destination may be able to spoof trusted servers to steal data or cause a denial of service.


There are at least two distinct weaknesses that can cause the product to communicate with an unintended destination:


  - If the product allows an attacker to control which destination is specified, then the attacker can cause it to connect to an untrusted or malicious destination. For example, because UDP is a connectionless protocol, UDP packets can be spoofed by specifying a false source address in the packet; when the server receives the packet and sends a reply, it will specify a destination by using the source of the incoming packet - i.e., the false source. The server can then be tricked into sending traffic to the wrong host, which is effective for hiding the real source of an attack and for conducting a distributed denial of service (DDoS). As another example, server-side request forgery (SSRF) and XML External Entity (XXE) can be used to trick a server into making outgoing requests to hosts that cannot be directly accessed by the attacker due to firewall restrictions.

  - If the product incorrectly specifies the destination, then an attacker who can control this destination might be able to spoof trusted servers. While the most common occurrence is likely due to misconfiguration by an administrator, this can be resultant from other weaknesses. For example, the product might incorrectly parse an e-mail or IP address and send sensitive data to an unintended destination. As another example, an Android application may use a "sticky broadcast" to communicate with a receiver for a particular application, but since sticky broadcasts can be processed by *any* receiver, this can allow a malicious application to access restricted data that was only intended for a different application.

## Observed Examples

CVE-2013-5211: composite: NTP feature generates large responses (high amplification factor) with spoofed UDP source addresses.

CVE-1999-0513: Classic "Smurf" attack, using spoofed ICMP packets to broadcast addresses.

CVE-1999-1379: DNS query with spoofed source address causes more traffic to be returned to spoofed address than was sent by the attacker.

## Top 25 Examples

CVE-2022-21671: @replit/crosis is a JavaScript client that speaks Replit's container protocol. A vulnerability that involves exposure of sensitive information exists in versions prior to 7.3.1. When using this library as a way to programmatically communicate with Replit in a standalone fashion, if there are multiple failed attempts to contact Replit through a WebSocket, the library will attempt to communicate using a fallback poll-based proxy. The URL of the proxy has changed, so any communication done to the previous URL could potentially reach a server that is outside of Replit's control and the token used to connect to the Repl could be obtained by an attacker, leading to full compromise of that Repl (not of the account). This was patched in version 7.3.1 by updating the address of the fallback WebSocket polling proxy to the new one. As a workaround, a user may specify the new address for the polling host (`gp-v2.replit.com`) in the `ConnectArgs`. More information about this workaround is available in the GitHub Security Advisory.

CVE-2022-21673: Grafana is an open-source platform for monitoring and observability. In affected versions when a data source has the Forward OAuth Identity feature enabled, sending a query to that datasource with an API token (and no other user credentials) will forward the OAuth Identity of the most recently logged-in user. This can allow API token holders to retrieve data for which they may not have intended access. This attack relies on the Grafana instance having data sources that support the Forward OAuth Identity feature, the Grafana instance having a data source with the Forward OAuth Identity feature toggled on, the Grafana instance having OAuth enabled, and the Grafana instance having usable API keys. This issue has been patched in versions 7.5.13 and 8.3.4.

# CWE-942 Permissive Cross-domain Policy with Untrusted Domains

## Description

The product uses a cross-domain policy file that includes domains that should not be trusted.

A cross-domain policy file ("crossdomain.xml" in Flash and "clientaccesspolicy.xml" in Silverlight) defines a list of domains from which a server is allowed to make cross-domain requests. When making a cross-domain request, the Flash or Silverlight client will first look for the policy file on the target server. If it is found, and the domain hosting the application is explicitly allowed to make requests, the request is made.


Therefore, if a cross-domain policy file includes domains that should not be trusted, such as when using wildcards, then the application could be attacked by these untrusted domains.


An overly permissive policy file allows many of the same attacks seen in Cross-Site Scripting (CWE-79). Once the user has executed a malicious Flash or Silverlight application, they are vulnerable to a variety of attacks. The attacker could transfer private information, such as cookies that may include session information, from the victim's machine to the attacker. The attacker could send malicious requests to a web site on behalf of the victim, which could be especially dangerous to the site if the victim has administrator privileges to manage that site.


In many cases, the attack can be launched without the victim even being aware of it.

## Observed Examples

CVE-2012-2292: Product has a Silverlight cross-domain policy that does not restrict access to another application, which allows remote attackers to bypass the Same Origin Policy.

CVE-2014-2049: The default Flash Cross Domain policies in a product allows remote attackers to access user files.

CVE-2007-6243: Chain: Adobe Flash Player does not sufficiently restrict the interpretation and usage of cross-domain policy files, which makes it easier for remote attackers to conduct cross-domain and cross-site scripting (XSS) attacks.

CVE-2008-4822: Chain: Adobe Flash Player and earlier does not properly interpret policy files, which allows remote attackers to bypass a non-root domain policy.

CVE-2010-3636: Chain: Adobe Flash Player does not properly handle unspecified encodings during the parsing of a cross-domain policy file, which allows remote web servers to bypass intended access restrictions via unknown vectors.

# CWE-943 Improper Neutralization of Special Elements in Data Query Logic

## Description

The product generates a query intended to access or manipulate data in a data store such as a database, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.

Depending on the capabilities of the query language, an attacker could inject additional logic into the query to:


  - Modify the intended selection criteria, thus changing which data entities (e.g., records) are returned, modified, or otherwise manipulated

  - Append additional commands to the query

  - Return more entities than intended

  - Return fewer entities than intended

  - Cause entities to be sorted in an unexpected way

The ability to execute additional commands or change which entities are returned has obvious risks. But when the product logic depends on the order or number of entities, this can also lead to vulnerabilities. For example, if the query expects to return only one entity that specifies an administrative user, but an attacker can change which entities are returned, this could cause the logic to return information for a regular user and incorrectly assume that the user has administrative privileges.

While this weakness is most commonly associated with SQL injection, there are many other query languages that are also subject to injection attacks, including HTSQL, LDAP, DQL, XQuery, Xpath, and "NoSQL" languages.

## Observed Examples

CVE-2014-2503: Injection using Documentum Query Language (DQL)

CVE-2014-2508: Injection using Documentum Query Language (DQL)

## Top 25 Examples

CVE-2022-35246: A NoSQL-Injection information disclosure vulnerability vulnerability exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 in the getS3FileUrl Meteor server method that can disclose arbitrary file upload URLs to users that should not be able to access.

CVE-2022-36084: cruddl is software for creating a GraphQL API for a database, using the GraphQL SDL to model a schema. If cruddl starting with version 1.1.0 and prior to versions 2.7.0 and 3.0.2 is used to generate a schema that uses `@flexSearchFulltext`, users of that schema may be able to inject arbitrary AQL queries that will be forwarded to and executed by ArangoDB. Schemas that do not use `@flexSearchFulltext` are not affected. The attacker needs to have `READ` permission to at least one root entity type that has `@flexSearchFulltext` enabled. The issue has been fixed in version 3.0.2 and in version 2.7.0 of cruddl. As a workaround, users can temporarily remove `@flexSearchFulltext` from their schemas.

CVE-2022-47909: Livestatus Query Language (LQL) injection in the AuthUser HTTP query header of Tribe29's Checkmk <= 2.1.0p11, Checkmk <= 2.0.0p28, and all versions of Checkmk 1.6.0 (EOL) allows an attacker to perform direct queries to the application's core from localhost.

# CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

## Description

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before using the input in a dynamic evaluation call (e.g. "eval").

This may allow an attacker to execute arbitrary code, or at least modify what code can be executed.

## Observed Examples

CVE-2024-4181: Framework for LLM applications allows eval injection via a crafted response from a hosting provider.

CVE-2022-2054: Python compiler uses eval() to execute malicious strings as Python code.

CVE-2021-22204: Chain: regex in EXIF processor code does not correctly determine where a string ends (CWE-625), enabling eval injection (CWE-95), as exploited in the wild per CISA KEV.

CVE-2021-22205: Chain: backslash followed by a newline can bypass a validation step (CWE-20), leading to eval injection (CWE-95), as exploited in the wild per CISA KEV.

CVE-2008-5071: Eval injection in PHP program.

CVE-2002-1750: Eval injection in Perl program.

CVE-2008-5305: Eval injection in Perl program using an ID that should only contain hyphens and numbers.

CVE-2002-1752: Direct code injection into Perl eval function.

CVE-2002-1753: Eval injection in Perl program.

CVE-2005-1527: Direct code injection into Perl eval function.

CVE-2005-2837: Direct code injection into Perl eval function.

CVE-2005-1921: MFV. code injection into PHP eval statement using nested constructs that should not be nested.

CVE-2005-2498: MFV. code injection into PHP eval statement using nested constructs that should not be nested.

CVE-2005-3302: Code injection into Python eval statement from a field in a formatted file.

CVE-2007-1253: Eval injection in Python program.

CVE-2001-1471: chain: Resultant eval injection. An invalid value prevents initialization of variables, which can be modified by attacker and later injected into PHP eval statement.

CVE-2007-2713: Chain: Execution after redirect triggers eval injection.

## Top 25 Examples

CVE-2021-23277: Eaton Intelligent Power Manager (IPM) prior to 1.69 is vulnerable to unauthenticated eval injection vulnerability. The software does not neutralize code syntax from users before using in the dynamic evaluation call in loadUserFile function under scripts/libs/utils.js. Successful exploitation can allow attackers to control the input to the function and execute attacker controlled commands.

CVE-2022-40871: Dolibarr ERP & CRM <=15.0.3 is vulnerable to Eval injection. By default, any administrator can be added to the installation page of dolibarr, and if successfully added, malicious code can be inserted into the database and then execute it by eval.

CVE-2021-22204: Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

CVE-2022-0845: Code Injection in GitHub repository pytorchlightning/pytorch-lightning prior to 1.6.0.

CVE-2022-29216: TensorFlow is an open source platform for machine learning. Prior to versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4, TensorFlow's `saved_model_cli` tool is vulnerable to a code injection. This can be used to open a reverse shell. This code path was maintained for compatibility reasons as the maintainers had several test cases where numpy expressions were used as arguments. However, given that the tool is always run manually, the impact of this is still not severe. The maintainers have now removed the `safe=False` argument, so all parsing is done without calling `eval`. The patch is available in versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4.

CVE-2022-32417: PbootCMS v3.1.2 was discovered to contain a remote code execution (RCE) vulnerability via the function parserIfLabel at function.php.

CVE-2022-3394: The WP All Export Pro WordPress plugin before 1.7.9 does not limit some functionality during exports only to users with the Administrator role, allowing any logged in user which has been given privileges to perform exports to execute arbitrary code on the site. By default only administrators can run exports, but the privilege can be delegated to lower privileged users.

CVE-2022-38193: There is a code injection vulnerability in Esri Portal for ArcGIS versions 10.8.1 and below that may allow a remote, unauthenticated attacker to pass strings which could potentially cause arbitrary code execution.

CVE-2022-46648: ruby-git versions prior to v1.13.0 allows a remote authenticated attacker to execute an arbitrary ruby code by having a user to load a repository containing a specially crafted filename to the product. This vulnerability is different from CVE-2022-47318.

CVE-2021-40553: piwigo 11.5.0 is affected by a remote code execution (RCE) vulnerability in the LocalFiles Editor.

CVE-2022-2054: Code Injection in GitHub repository nuitka/nuitka prior to 0.9. 

CVE-2022-45907: In PyTorch before trunk/89695, torch.jit.annotations.parse_type_line can cause arbitrary code execution because eval is used unsafely.

CVE-2022-46333: The admin user interface in Proofpoint Enterprise Protection (PPS/PoD) contains a command injection vulnerability that enables an admin to execute commands beyond their allowed scope. This affects all versions 8.19.0 and below. 

CVE-2022-48175: Rukovoditel v3.2.1 was discovered to contain a remote code execution (RCE) vulnerability in the component /rukovoditel/index.php?module=dashboard/ajax_request.

# CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')

## Description

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes code syntax before inserting the input into an executable resource, such as a library, configuration file, or template.

## Observed Examples

CVE-2002-0495: Perl code directly injected into CGI library file from parameters to another CGI program.

CVE-2005-1876: Direct PHP code injection into supporting template file.

CVE-2005-1894: Direct code injection into PHP script that can be accessed by attacker.

CVE-2003-0395: PHP code from User-Agent HTTP header directly inserted into log file implemented as PHP script.

CVE-2007-6652: chain: execution after redirect allows non-administrator to perform static code injection.

## Top 25 Examples

CVE-2022-26982: SimpleMachinesForum 2.1.1 and earlier allows remote authenticated administrators to execute arbitrary code by inserting a vulnerable php code because the themes can be modified by an administrator. NOTE: the vendor's position is that administrators are intended to have the ability to modify themes, and can thus choose any PHP code that they wish to have executed on the server.

CVE-2021-36424: An issue discovered in phpwcms 1.9.25 allows remote attackers to run arbitrary code via DB user field during installation.

CVE-2021-39426: An issue was discovered in /Upload/admin/admin_notify.php in Seacms 11.4 allows attackers to execute arbitrary php code via the notify1 parameter when the action parameter equals set.

CVE-2022-24664: PHP Everywhere <= 2.0.3 included functionality that allowed execution of PHP Code Snippets via WordPress metaboxes, which could be used by any user able to edit posts.

CVE-2022-24665: PHP Everywhere <= 2.0.3 included functionality that allowed execution of PHP Code Snippets via a WordPress gutenberg block by any user able to edit posts.

CVE-2022-25018: Pluxml v5.8.7 was discovered to allow attackers to execute arbitrary code via crafted PHP code inserted into static pages.

CVE-2022-25578: taocms v3.0.2 allows attackers to execute code injection via arbitrarily editing the .htaccess file.

CVE-2022-25812: The Transposh WordPress Translation WordPress plugin before 1.0.8 does not validate its debug settings, which could allow allowing high privilege users such as admin to perform RCE

CVE-2022-35516: DedeCMS v5.7.93 - v5.7.96 was discovered to contain a remote code execution vulnerability in login.php.

CVE-2022-36216: DedeCMS v5.7.94 - v5.7.97 was discovered to contain a remote code execution vulnerability in member_toadmin.php.

CVE-2022-48093: Seacms v12.7 was discovered to contain a remote code execution (RCE) vulnerability via the ip parameter at admin_ ip.php.

CVE-2022-36756: DIR845L A1 v1.00-v1.03 is vulnerable to command injection via /htdocs/upnpinc/gena.php.

CVE-2022-37053: TRENDnet TEW733GR v1.03B01 is vulnerable to Command injection via /htdocs/upnpinc/gena.php.

CVE-2022-36262: An issue was discovered in taocms 3.0.2. in the website settings that allows arbitrary php code to be injected by modifying config.php.

CVE-2021-41402: flatCore-CMS v2.0.8 has a code execution vulnerability, which could let a remote malicious user execute arbitrary PHP code.

CVE-2022-25498: CuppaCMS v1.0 was discovered to contain a remote code execution (RCE) vulnerability via the saveConfigData function in /classes/ajax/Functions.php.

# CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page

## Description

The product generates a web page, but does not neutralize or incorrectly neutralizes user-controllable input that could be interpreted as a server-side include (SSI) directive.

## Top 25 Examples

CVE-2022-43660: Improper neutralization of Server-Side Includes (SSW) within a web page in Movable Type series allows a remote authenticated attacker with Privilege of 'Manage of Content Types' may execute an arbitrary Perl script and/or an arbitrary OS command. Affected products/versions are as follows: Movable Type 7 r.5301 and earlier (Movable Type 7 Series), Movable Type Advanced 7 r.5301 and earlier (Movable Type Advanced 7 Series), Movable Type Premium 1.53 and earlier, and Movable Type Premium Advanced 1.53 and earlier.

# CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')

## Description

The PHP application receives input from an upstream component, but it does not restrict or incorrectly restricts the input before its usage in "require," "include," or similar functions.

In certain versions and configurations of PHP, this can allow an attacker to specify a URL to a remote location from which the product will obtain the code to execute. In other cases in association with path traversal, the attacker can specify a local file that may contain executable statements that can be parsed by PHP.

## Observed Examples

CVE-2004-0285: Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request.

CVE-2004-0030: Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request.

CVE-2004-0068: Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request.

CVE-2005-2157: Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request.

CVE-2005-2162: Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request.

CVE-2005-2198: Modification of assumed-immutable configuration variable in include file allows file inclusion via direct request.

CVE-2004-0128: Modification of assumed-immutable variable in configuration script leads to file inclusion.

CVE-2005-1864: PHP file inclusion.

CVE-2005-1869: PHP file inclusion.

CVE-2005-1870: PHP file inclusion.

CVE-2005-2154: PHP local file inclusion.

CVE-2002-1704: PHP remote file include.

CVE-2002-1707: PHP remote file include.

CVE-2005-1964: PHP remote file include.

CVE-2005-1681: PHP remote file include.

CVE-2005-2086: PHP remote file include.

CVE-2004-0127: Directory traversal vulnerability in PHP include statement.

CVE-2005-1971: Directory traversal vulnerability in PHP include statement.

CVE-2005-3335: PHP file inclusion issue, both remote and local; local include uses ".." and "%00" characters as a manipulation, but many remote file inclusion issues probably have this vector.

CVE-2009-1936: chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal.

## Top 25 Examples

CVE-2022-22308: IBM Planning Analytics 2.0 is vulnerable to a Remote File Include (RFI) attack. User input could be passed into file include commands and the web application could be tricked into including remote files with malicious code. IBM X-Force ID: 216891.

# CWE-99 Improper Control of Resource Identifiers ('Resource Injection')

## Description

The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.

A resource injection issue occurs when the following two conditions are met:


  1. An attacker can specify the identifier used to access a system resource. For example, an attacker might be able to specify part of the name of a file to be opened or a port number to be used.

  1. By specifying the resource, the attacker gains a capability that would not otherwise be permitted. For example, the program may give the attacker the ability to overwrite the specified file, run with a configuration controlled by the attacker, or transmit sensitive information to a third-party server.

This may enable an attacker to access or modify otherwise protected system resources.

## Observed Examples

CVE-2013-4787: chain: mobile OS verifies cryptographic signature of file in an archive, but then installs a different file with the same name that is also listed in the archive.

## Top 25 Examples

CVE-2022-1287: A vulnerability classified as critical was found in School Club Application System 1.0. This vulnerability affects a request to the file /scas/classes/Users.php?f=save_user. The manipulation with a POST request leads to privilege escalation. The attack can be initiated remotely and does not require authentication. The exploit has been disclosed to the public and may be used.

