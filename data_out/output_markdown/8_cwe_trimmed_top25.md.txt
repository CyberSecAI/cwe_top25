# CWE-8 J2EE Misconfiguration: Entity Bean Declared Remote

## Description

When an application exposes a remote interface for an entity bean, it might also expose methods that get or set the bean's data. These methods could be leveraged to read sensitive information, or to change data in ways that violate the application's expectations, potentially leading to other vulnerabilities.

# CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

## Description

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as "<", ">", and "&" that could be interpreted as web-scripting elements when they are sent to a downstream component that processes web pages.

This may allow such characters to be treated as control characters, which are executed client-side in the context of the user's session. Although this can be classified as an injection problem, the more pertinent issue is the improper conversion of such special characters to respective context-appropriate entities before displaying them to the user.

## Observed Examples

CVE-2002-0938: XSS in parameter in a link.

CVE-2002-1495: XSS in web-based email product via attachment filenames.

CVE-2003-1136: HTML injection in posted message.

CVE-2004-2171: XSS not quoted in error page.

## Top 25 Examples

CVE-2022-21145: A stored cross-site scripting vulnerability exists in the WebUserActions.aspx functionality of Lansweeper lansweeper 9.1.20.2. A specially-crafted HTTP request can lead to arbitrary Javascript code injection. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-28703: A stored cross-site scripting vulnerability exists in the HdConfigActions.aspx altertextlanguages functionality of Lansweeper lansweeper 10.1.1.0. A specially-crafted HTTP request can lead to arbitrary Javascript code injection. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-38210: There is a reflected HTML injection vulnerability in Esri Portal for ArcGIS versions 10.9.1 and below that may allow a remote, unauthenticated attacker to create a crafted link which when clicked could render arbitrary HTML in the victim’s browser.

CVE-2022-3844: A vulnerability, which was classified as problematic, was found in Webmin 2.001. Affected is an unknown function of the file xterm/index.cgi. The manipulation leads to basic cross site scripting. It is possible to launch the attack remotely. Upgrading to version 2.003 is able to address this issue. The patch is identified as d3d33af3c0c3fd3a889c84e287a038b7a457d811. It is recommended to upgrade the affected component. VDB-212862 is the identifier assigned to this vulnerability.

CVE-2021-44196: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in UBIT Information Technologies Student Information Management System.This issue affects Student Information Management System: before 20211126. 

CVE-2021-44197: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in UBIT Information Technologies Student Information Management System.This issue affects Student Information Management System: before 20211126. 

CVE-2022-25620: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in Group Functionality of Profelis IT Consultancy SambaBox allows AUTHENTICATED user to cause execute arbitrary codes on the vulnerable server. This issue affects: Profelis IT Consultancy SambaBox 4.0 version 4.0 and prior versions on x86.

# CWE-804 Guessable CAPTCHA

## Description

The product uses a CAPTCHA challenge, but the challenge can be guessed or automatically recognized by a non-human actor.

An automated attacker could bypass the intended protection of the CAPTCHA challenge and perform actions at a higher frequency than humanly possible, such as launching spam attacks.


There can be several different causes of a guessable CAPTCHA:


  - An audio or visual image that does not have sufficient distortion from the unobfuscated source image.

  - A question is generated with a format that can be automatically recognized, such as a math question.

  - A question for which the number of possible answers is limited, such as birth years or favorite sports teams.

  - A general-knowledge or trivia question for which the answer can be accessed using a data base, such as country capitals or popular entertainers.

  - Other data associated with the CAPTCHA may provide hints about its contents, such as an image whose filename contains the word that is used in the CAPTCHA.

## Observed Examples

CVE-2022-4036: Chain: appointment booking app uses a weak hash (CWE-328) for generating a CAPTCHA, making it guessable (CWE-804)

# CWE-805 Buffer Access with Incorrect Length Value

## Description

The product uses a sequential operation to read or write a buffer, but it uses an incorrect length value that causes it to access memory that is outside of the bounds of the buffer.

When the length value exceeds the size of the destination, a buffer overflow could occur.

## Observed Examples

CVE-2011-1959: Chain: large length value causes buffer over-read (CWE-126)

CVE-2011-1848: Use of packet length field to make a calculation, then copy into a fixed-size buffer

CVE-2011-0105: Chain: retrieval of length value from an uninitialized memory location

CVE-2011-0606: Crafted length value in document reader leads to buffer overflow

CVE-2011-0651: SSL server overflow when the sum of multiple length fields exceeds a given value

CVE-2010-4156: Language interpreter API function doesn't validate length argument, leading to information exposure

## Top 25 Examples

CVE-2022-0519: Buffer Access with Incorrect Length Value in GitHub repository radareorg/radare2 prior to 5.6.2.

CVE-2022-40757: A Buffer Access with Incorrect Length Value vulnerablity in the TEE_MACComputeFinal function in Samsung mTower through 0.3.0 allows a trusted application to trigger a Denial of Service (DoS) by invoking the function TEE_MACComputeFinal with an excessive size value of messageLen.

CVE-2022-40758: A Buffer Access with Incorrect Length Value vulnerablity in the TEE_CipherUpdate function in Samsung mTower through 0.3.0 allows a trusted application to trigger a Denial of Service (DoS) by invoking the function TEE_CipherUpdate with an excessive size value of srcLen.

CVE-2022-40760: A Buffer Access with Incorrect Length Value vulnerablity in the TEE_MACUpdate function in Samsung mTower through 0.3.0 allows a trusted application to trigger a Denial of Service (DoS) by invoking the function TEE_MACUpdate with an excessive size value of chunkSize.

CVE-2022-34399:  Dell Alienware m17 R5 BIOS version prior to 1.2.2 contain a buffer access vulnerability. A malicious user with admin privileges could potentially exploit this vulnerability by sending input larger than expected in order to leak certain sections of SMRAM. 

# CWE-806 Buffer Access Using Size of Source Buffer

## Description

The product uses the size of a source buffer when reading from or writing to a destination buffer, which may cause it to access memory that is outside of the bounds of the buffer.

When the size of the destination is smaller than the size of the source, a buffer overflow could occur.

# CWE-807 Reliance on Untrusted Inputs in a Security Decision

## Description

The product uses a protection mechanism that relies on the existence or values of an input, but the input can be modified by an untrusted actor in a way that bypasses the protection mechanism.

Developers may assume that inputs such as cookies, environment variables, and hidden form fields cannot be modified. However, an attacker could change these inputs using customized clients or other attacks. This change might not be detected. When security decisions such as authentication and authorization are made based on the values of these inputs, attackers can bypass the security of the software.


Without sufficient encryption, integrity checking, or other mechanism, any input that originates from an outsider cannot be trusted.

## Observed Examples

CVE-2009-1549: Attacker can bypass authentication by setting a cookie to a specific value.

CVE-2009-1619: Attacker can bypass authentication and gain admin privileges by setting an "admin" cookie to 1.

CVE-2009-0864: Content management system allows admin privileges by setting a "login" cookie to "OK."

CVE-2008-5784: e-dating application allows admin privileges by setting the admin cookie to 1.

CVE-2008-6291: Web-based email list manager allows attackers to gain admin privileges by setting a login cookie to "admin."

## Top 25 Examples

CVE-2021-36777: A Reliance on Untrusted Inputs in a Security Decision vulnerability in the login proxy of the openSUSE Build service allowed attackers to present users with a expected login form that then sends the clear text credentials to an attacker specified server. This issue affects: openSUSE Build service login-proxy-scripts versions prior to dc000cdfe9b9b715fb92195b1a57559362f689ef.

CVE-2021-4314: It is possible to manipulate the JWT token without the knowledge of the JWT secret and authenticate without valid JWT token as any user. This is happening only in the situation when zOSMF doesn’t have the APAR PH12143 applied. This issue affects: 1.16 versions to 1.19. What happens is that the services using the ZAAS client or the API ML API to query will be deceived into believing the information in the JWT token is valid when it isn’t. It’s possible to use this to persuade the southbound service that different user is authenticated.

CVE-2022-23654: Wiki.js is a wiki app built on Node.js. In affected versions an authenticated user with write access on a restricted set of paths can update a page outside the allowed paths by specifying a different target page ID while keeping the path intact. The access control incorrectly check the path access against the user-provided values instead of the actual path associated to the page ID. Commit https://github.com/Requarks/wiki/commit/411802ec2f654bb5ed1126c307575b81e2361c6b fixes this vulnerability by checking access control on the path associated with the page ID instead of the user-provided value. When the path is different than the current value, a second access control check is then performed on the user-provided path before the move operation.

CVE-2022-29518: Screen Creator Advance2, HMI GC-A2 series, and Real time remote monitoring and control tool Screen Creator Advance2 versions prior to Ver.0.1.1.3 Build01, HMI GC-A2 series(GC-A22W-CW, GC-A24W-C(W), GC-A26W-C(W), GC-A24, GC-A24-M, GC-A25, GC-A26, and GC-A26-J2), and Real time remote monitoring and control tool(Remote GC) allows a local attacker to bypass authentication due to the improper check for the Remote control setting's account names. This may allow attacker who can access the HMI from Real time remote monitoring and control tool may perform arbitrary operations on the HMI. As a result, the information stored in the HMI may be disclosed, deleted or altered, and/or the equipment may be illegally operated via the HMI.

CVE-2021-37791: MyAdmin v1.0 is affected by an incorrect access control vulnerability in viewing personal center in /api/user/userData?userCode=admin.

CVE-2022-20744: A vulnerability in the input protection mechanisms of Cisco Firepower Management Center (FMC) Software could allow an authenticated, remote attacker to view data without proper authorization. This vulnerability exists because of a protection mechanism that relies on the existence or values of a specific input. An attacker could exploit this vulnerability by modifying this input to bypass the protection mechanism and sending a crafted request to an affected device. A successful exploit could allow the attacker to view data beyond the scope of their authorization.

# CWE-81 Improper Neutralization of Script in an Error Message Web Page

## Description

The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters that could be interpreted as web-scripting elements when they are sent to an error page.

Error pages may include customized 403 Forbidden or 404 Not Found pages.


When an attacker can trigger an error that contains script syntax within the attacker's input, then cross-site scripting attacks may be possible.

## Observed Examples

CVE-2002-0840: XSS in default error page from Host: header.

CVE-2002-1053: XSS in error message.

CVE-2002-1700: XSS in error page from targeted parameter.

# CWE-82 Improper Neutralization of Script in Attributes of IMG Tags in a Web Page

## Description

The web application does not neutralize or incorrectly neutralizes scripting elements within attributes of HTML IMG tags, such as the src attribute.

Attackers can embed XSS exploits into the values for IMG attributes (e.g. SRC) that is streamed and then executed in a victim's browser. Note that when the page is loaded into a user's browsers, the exploit will automatically execute.

## Observed Examples

CVE-2006-3211: Stored XSS in a guestbook application using a javascript: URI in a bbcode img tag.

CVE-2002-1649: javascript URI scheme in IMG tag.

CVE-2002-1803: javascript URI scheme in IMG tag.

CVE-2002-1804: javascript URI scheme in IMG tag.

CVE-2002-1805: javascript URI scheme in IMG tag.

CVE-2002-1806: javascript URI scheme in IMG tag.

CVE-2002-1807: javascript URI scheme in IMG tag.

CVE-2002-1808: javascript URI scheme in IMG tag.

# CWE-820 Missing Synchronization

## Description

The product utilizes a shared resource in a concurrent manner but does not attempt to synchronize access to the resource.

If access to a shared resource is not synchronized, then the resource may not be in a state that is expected by the product. This might lead to unexpected or insecure behaviors, especially if an attacker can influence the shared resource.

## Top 25 Examples

CVE-2022-3565: A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211088.

# CWE-821 Incorrect Synchronization

## Description

The product utilizes a shared resource in a concurrent manner, but it does not correctly synchronize access to the resource.

If access to a shared resource is not correctly synchronized, then the resource may not be in a state that is expected by the product. This might lead to unexpected or insecure behaviors, especially if an attacker can influence the shared resource.

## Top 25 Examples

CVE-2022-1931: Incorrect Synchronization in GitHub repository polonel/trudesk prior to 1.2.3.

# CWE-822 Untrusted Pointer Dereference

## Description

The product obtains a value from an untrusted source, converts this value to a pointer, and dereferences the resulting pointer.

An attacker can supply a pointer for memory locations that the product is not expecting. If the pointer is dereferenced for a write operation, the attack might allow modification of critical state variables, cause a crash, or execute code. If the dereferencing operation is for a read, then the attack might allow reading of sensitive data, cause a crash, or set a variable to an unexpected value (since the value will be read from an unexpected memory location).


There are several variants of this weakness, including but not necessarily limited to:


  - The untrusted value is directly invoked as a function call.

  - In OS kernels or drivers where there is a boundary between "userland" and privileged memory spaces, an untrusted pointer might enter through an API or system call (see CWE-781 for one such example).

  - Inadvertently accepting the value from an untrusted control sphere when it did not have to be accepted as input at all. This might occur when the code was originally developed to be run by a single user in a non-networked environment, and the code is then ported to or otherwise exposed to a networked environment.

## Observed Examples

CVE-2007-5655: message-passing framework interprets values in packets as pointers, causing a crash.

CVE-2010-2299: labeled as a "type confusion" issue, also referred to as a "stale pointer." However, the bug ID says "contents are simply interpreted as a pointer... renderer ordinarily doesn't supply this pointer directly". The "handle" in the untrusted area is replaced in one function, but not another - thus also, effectively, exposure to wrong sphere (CWE-668).

CVE-2009-1719: Untrusted dereference using undocumented constructor.

CVE-2009-1250: An error code is incorrectly checked and interpreted as a pointer, leading to a crash.

CVE-2009-0311: An untrusted value is obtained from a packet and directly called as a function pointer, leading to code execution.

CVE-2010-1818: Undocumented attribute in multimedia software allows "unmarshaling" of an untrusted pointer.

CVE-2010-3189: ActiveX control for security software accepts a parameter that is assumed to be an initialized pointer.

CVE-2010-1253: Spreadsheet software treats certain record values that lead to "user-controlled pointer" (might be untrusted offset, not untrusted pointer).

## Top 25 Examples

CVE-2021-46020: An untrusted pointer dereference in mrb_vm_exec() of mruby v3.0.0 can lead to a segmentation fault or application crash.

CVE-2021-46023: An Untrusted Pointer Dereference was discovered in function mrb_vm_exec in mruby before 3.1.0-rc. The vulnerability causes a segmentation fault and application crash.

CVE-2022-22098: Memory corruption in multimedia driver due to untrusted pointer dereference while reading data from socket in Snapdragon Auto

CVE-2022-25661: Memory corruption due to untrusted pointer dereference in kernel in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2022-25658: Memory corruption due to incorrect pointer arithmetic when attempting to change the endianness in video parser function in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-41837: An issue was discovered in AhciBusDxe in the kernel 5.0 through 5.5 in Insyde InsydeH2O. Because of an Untrusted Pointer Dereference that causes SMM memory corruption, an attacker may be able to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2021-41839: An issue was discovered in NvmExpressDxe in the kernel 5.0 through 5.5 in Insyde InsydeH2O. Because of an Untrusted Pointer Dereference that causes SMM memory corruption, an attacker may be able to write fixed or predictable data to SMRAM. Exploiting this issue could lead to escalating privileges to SMM.

CVE-2022-25662: Information disclosure due to untrusted pointer dereference in kernel in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-22716: Microsoft Excel Information Disclosure Vulnerability

CVE-2022-29275: In UsbCoreDxe, untrusted input may allow SMRAM or OS memory tampering Use of untrusted pointers could allow OS or SMRAM memory tampering leading to escalation of privileges. This issue was discovered by Insyde during security review. It was fixed in: Kernel 5.0: version 05.09.21 Kernel 5.1: version 05.17.21 Kernel 5.2: version 05.27.21 Kernel 5.3: version 05.36.21 Kernel 5.4: version 05.44.21 Kernel 5.5: version 05.52.21 https://www.insyde.com/security-pledge/SA-2022058

CVE-2022-29279: Use of a untrusted pointer allows tampering with SMRAM and OS memory in SdHostDriver and SdMmcDevice Use of a untrusted pointer allows tampering with SMRAM and OS memory in SdHostDriver and SdMmcDevice. This issue was discovered by Insyde during security review. It was fixed in: Kernel 5.0: version 05.09.17 Kernel 5.1: version 05.17.17 Kernel 5.2: version 05.27.17 Kernel 5.3: version 05.36.17 Kernel 5.4: version 05.44.17 Kernel 5.5: version 05.52.17 https://www.insyde.com/security-pledge/SA-2022062

# CWE-823 Use of Out-of-range Pointer Offset

## Description

The product performs pointer arithmetic on a valid pointer, but it uses an offset that can point outside of the intended range of valid memory locations for the resulting pointer.

While a pointer can contain a reference to any arbitrary memory location, a program typically only intends to use the pointer to access limited portions of memory, such as contiguous memory used to access an individual array.


Programs may use offsets in order to access fields or sub-elements stored within structured data. The offset might be out-of-range if it comes from an untrusted source, is the result of an incorrect calculation, or occurs because of another error.


If an attacker can control or influence the offset so that it points outside of the intended boundaries of the structure, then the attacker may be able to read or write to memory locations that are used elsewhere in the product. As a result, the attack might change the state of the product as accessed through program variables, cause a crash or instable behavior, and possibly lead to code execution.

## Observed Examples

CVE-2010-2160: Invalid offset in undocumented opcode leads to memory corruption.

CVE-2010-1281: Multimedia player uses untrusted value from a file when using file-pointer calculations.

CVE-2009-3129: Spreadsheet program processes a record with an invalid size field, which is later used as an offset.

CVE-2009-2694: Instant messaging library does not validate an offset value specified in a packet.

CVE-2009-2687: Language interpreter does not properly handle invalid offsets in JPEG image, leading to out-of-bounds memory access and crash.

CVE-2009-0690: negative offset leads to out-of-bounds read

CVE-2008-4114: untrusted offset in kernel

CVE-2010-2873: "blind trust" of an offset value while writing heap memory allows corruption of function pointer,leading to code execution

CVE-2010-2866: negative value (signed) causes pointer miscalculation

CVE-2010-2872: signed values cause incorrect pointer calculation

CVE-2007-5657: values used as pointer offsets

CVE-2010-2867: a return value from a function is sign-extended if the value is signed, then used as an offset for pointer arithmetic

CVE-2009-1097: portions of a GIF image used as offsets, causing corruption of an object pointer.

CVE-2008-1807: invalid numeric field leads to a free of arbitrary memory locations, then code execution.

CVE-2007-2500: large number of elements leads to a free of an arbitrary address

CVE-2008-1686: array index issue (CWE-129) with negative offset, used to dereference a function pointer

CVE-2010-2878: "buffer seek" value - basically an offset?

## Top 25 Examples

CVE-2022-22104: Memory corruption in multimedia due to improper check on the messages received. in Snapdragon Auto

CVE-2022-25682: Memory corruption in MODEM UIM due to usage of out of range pointer offset while decoding command from card in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2022-25694: Memory corruption in Modem due to usage of Out-of-range pointer offset in UIM

CVE-2022-25709: Memory corruption in modem due to use of out of range pointer offset while processing qmi msg

CVE-2022-33210: Memory corruption in automotive multimedia due to use of out-of-range pointer offset while parsing command request packet with a very large type value. in Snapdragon Auto

CVE-2021-33742: Windows MSHTML Platform Remote Code Execution Vulnerability

CVE-2022-0614: Use of Out-of-range Pointer Offset in Homebrew mruby prior to 3.2.

CVE-2022-33246: Memory corruption in Audio due to use of out-of-range pointer offset while Initiating a voice call session from user space with invalid session id.

CVE-2022-42264: NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an unprivileged regular user can cause the use of an out-of-range pointer offset, which may lead to data tampering, data loss, information disclosure, or denial of service.

# CWE-824 Access of Uninitialized Pointer

## Description

The product accesses or uses a pointer that has not been initialized.

If the pointer contains an uninitialized value, then the value might not point to a valid memory location. This could cause the product to read from or write to unexpected memory locations, leading to a denial of service. If the uninitialized pointer is used as a function call, then arbitrary functions could be invoked. If an attacker can influence the portion of uninitialized memory that is contained in the pointer, this weakness could be leveraged to execute code or perform other attacks.


Depending on memory layout, associated memory management behaviors, and product operation, the attacker might be able to influence the contents of the uninitialized pointer, thus gaining more fine-grained control of the memory location to be accessed.

## Observed Examples

CVE-2024-32878: LLM product has a free of an uninitialized pointer

CVE-2010-0211: chain: unchecked return value (CWE-252) leads to free of invalid, uninitialized pointer (CWE-824).

CVE-2009-2768: Pointer in structure is not initialized, leading to NULL pointer dereference (CWE-476) and system crash.

CVE-2009-1721: Free of an uninitialized pointer.

CVE-2009-1415: Improper handling of invalid signatures leads to free of invalid pointer.

CVE-2009-0846: Invalid encoding triggers free of uninitialized pointer.

CVE-2009-0040: Crafted PNG image leads to free of uninitialized pointer.

CVE-2008-2934: Crafted GIF image leads to free of uninitialized pointer.

CVE-2007-4682: Access of uninitialized pointer might lead to code execution.

CVE-2007-4639: Step-based manipulation: invocation of debugging function before the primary initialization function leads to access of an uninitialized pointer and code execution.

CVE-2007-4000: Unchecked return values can lead to a write to an uninitialized pointer.

CVE-2007-2442: zero-length input leads to free of uninitialized pointer.

CVE-2007-1213: Crafted font leads to uninitialized function pointer.

CVE-2006-6143: Uninitialized function pointer in freed memory is invoked

CVE-2006-4175: LDAP server mishandles malformed BER queries, leading to free of uninitialized memory

CVE-2006-0054: Firewall can crash with certain ICMP packets that trigger access of an uninitialized pointer.

CVE-2003-1201: LDAP server does not initialize members of structs, which leads to free of uninitialized pointer if an LDAP request fails.

## Top 25 Examples

CVE-2022-28690: The affected product is vulnerable to an out-of-bounds write via uninitialized pointer, which may allow an attacker to execute arbitrary code.

CVE-2022-29488: The affected product is vulnerable to an out-of-bounds read via uninitialized pointer, which may allow an attacker to execute arbitrary code.

CVE-2022-29925: Access of uninitialized pointer vulnerability exists in the simulator module contained in the graphic editor 'V-SFT' versions prior to v6.1.6.0, which may allow an attacker to obtain information and/or execute arbitrary code by having a user to open a specially crafted image file.

CVE-2022-30540: The affected product is vulnerable to a heap-based buffer overflow via uninitialized pointer, which may allow an attacker to execute arbitrary code

CVE-2022-33280: Memory corruption due to access of uninitialized pointer in Bluetooth HOST while processing the AVRCP packet.

CVE-2022-43606: A use-of-uninitialized-pointer vulnerability exists in the Forward Open connection_management_entry functionality of EIP Stack Group OpENer development commit 58ee13c. A specially-crafted EtherNet/IP request can lead to use of a null pointer, causing the server to crash. An attacker can send a series of EtherNet/IP requests to trigger this vulnerability.

CVE-2022-21971: Windows Runtime Remote Code Execution Vulnerability

# CWE-825 Expired Pointer Dereference

## Description

The product dereferences a pointer that contains a location for memory that was previously valid, but is no longer valid.

When a product releases memory, but it maintains a pointer to that memory, then the memory might be re-allocated at a later time. If the original pointer is accessed to read or write data, then this could cause the product to read or modify data that is in use by a different function or process. Depending on how the newly-allocated memory is used, this could lead to a denial of service, information exposure, or code execution.

## Observed Examples

CVE-2008-5013: access of expired memory address leads to arbitrary code execution

CVE-2010-3257: stale pointer issue leads to denial of service and possibly other consequences

CVE-2008-0062: Chain: a message having an unknown message type may cause a reference to uninitialized memory resulting in a null pointer dereference (CWE-476) or dangling pointer (CWE-825), possibly crashing the system or causing heap corruption.

CVE-2007-1211: read of value at an offset into a structure after the offset is no longer valid

## Top 25 Examples

CVE-2021-39693: In onUidStateChanged of AppOpsService.java, there is a possible way to access location without a visible indicator due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-208662370

# CWE-826 Premature Release of Resource During Expected Lifetime

## Description

The product releases a resource that is still intended to be used by itself or another actor.

This weakness focuses on errors in which the product should not release a resource, but performs the release anyway. This is different than a weakness in which the product releases a resource at the appropriate time, but it maintains a reference to the resource, which it later accesses. For this weakness, the resource should still be valid upon the subsequent access.


When a product releases a resource that is still being used, it is possible that operations will still be taken on this resource, which may have been repurposed in the meantime, leading to issues similar to CWE-825. Consequences may include denial of service, information exposure, or code execution.

## Observed Examples

CVE-2009-3547: Chain: race condition (CWE-362) might allow resource to be released before operating on it, leading to NULL dereference (CWE-476)

## Top 25 Examples

CVE-2022-27499: Premature release of resource during expected lifetime in the Intel(R) SGX SDK software may allow a privileged user to potentially enable information disclosure via local access.

# CWE-827 Improper Control of Document Type Definition

## Description

The product does not restrict a reference to a Document Type Definition (DTD) to the intended control sphere. This might allow attackers to reference arbitrary DTDs, possibly causing the product to expose files, consume excessive system resources, or execute arbitrary http requests on behalf of the attacker.

As DTDs are processed, they might try to read or include files on the machine performing the parsing. If an attacker is able to control the DTD, then the attacker might be able to specify sensitive resources or requests or provide malicious content.


For example, the SOAP specification prohibits SOAP messages from containing DTDs.

## Observed Examples

CVE-2010-2076: Product does not properly reject DTDs in SOAP messages, which allows remote attackers to read arbitrary files, send HTTP requests to intranet servers, or cause a denial of service.

# CWE-828 Signal Handler with Functionality that is not Asynchronous-Safe

## Description

The product defines a signal handler that contains code sequences that are not asynchronous-safe, i.e., the functionality is not reentrant, or it can be interrupted.

This can lead to an unexpected system state with a variety of potential consequences depending on context, including denial of service and code execution.


Signal handlers are typically intended to interrupt normal functionality of a program, or even other signals, in order to notify the process of an event. When a signal handler uses global or static variables, or invokes functions that ultimately depend on such state or its associated metadata, then it could corrupt system state that is being used by normal functionality. This could subject the program to race conditions or other weaknesses that allow an attacker to cause the program state to be corrupted. While denial of service is frequently the consequence, in some cases this weakness could be leveraged for code execution.


There are several different scenarios that introduce this issue:


  - Invocation of non-reentrant functions from within the handler. One example is malloc(), which modifies internal global variables as it manages memory. Very few functions are actually reentrant.

  - Code sequences (not necessarily function calls) contain non-atomic use of global variables, or associated metadata or structures, that can be accessed by other functionality of the program, including other signal handlers. Frequently, the same function is registered to handle multiple signals.

  - The signal handler function is intended to run at most one time, but instead it can be invoked multiple times. This could happen by repeated delivery of the same signal, or by delivery of different signals that have the same handler function (CWE-831).

Note that in some environments or contexts, it might be possible for the signal handler to be interrupted itself.

If both a signal handler and the normal behavior of the product have to operate on the same set of state variables, and a signal is received in the middle of the normal execution's modifications of those variables, the variables may be in an incorrect or corrupt state during signal handler execution, and possibly still incorrect or corrupt upon return.

## Observed Examples

CVE-2008-4109: Signal handler uses functions that ultimately call the unsafe syslog/malloc/s*printf, leading to denial of service via multiple login attempts

CVE-2006-5051: Chain: Signal handler contains too much functionality (CWE-828), introducing a race condition (CWE-362) that leads to a double free (CWE-415).

CVE-2001-1349: unsafe calls to library functions from signal handler

CVE-2004-0794: SIGURG can be used to remotely interrupt signal handler; other variants exist.

CVE-2004-2259: SIGCHLD signal to FTP server can cause crash under heavy load while executing non-reentrant functions like malloc/free.

CVE-2002-1563: SIGCHLD not blocked in a daemon loop while counter is modified, causing counter to get out of sync.

# CWE-829 Inclusion of Functionality from Untrusted Control Sphere

## Description

The product imports, requires, or includes executable functionality (such as a library) from a source that is outside of the intended control sphere.

When including third-party functionality, such as a web widget, library, or other source of functionality, the product must effectively trust that functionality. Without sufficient protection mechanisms, the functionality could be malicious in nature (either by coming from an untrusted source, being spoofed, or being modified in transit from a trusted source). The functionality might also contain its own weaknesses, or grant access to additional functionality and state information that should be kept private to the base system, such as system state information, sensitive application data, or the DOM of a web application.


This might lead to many different consequences depending on the included functionality, but some examples include injection of malware, information exposure by granting excessive privileges or permissions to the untrusted functionality, DOM-based XSS vulnerabilities, stealing user's cookies, or open redirect to malware (CWE-601).

## Observed Examples

CVE-2010-2076: Product does not properly reject DTDs in SOAP messages, which allows remote attackers to read arbitrary files, send HTTP requests to intranet servers, or cause a denial of service.

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

# CWE-83 Improper Neutralization of Script in Attributes in a Web Page

## Description

The product does not neutralize or incorrectly neutralizes "javascript:" or other URIs from dangerous attributes within tags, such as onmouseover, onload, onerror, or style.

## Observed Examples

CVE-2001-0520: Bypass filtering of SCRIPT tags using onload in BODY, href in A, BUTTON, INPUT, and others.

CVE-2002-1493: guestbook XSS in STYLE or IMG SRC attributes.

CVE-2002-1965: Javascript in onerror attribute of IMG tag.

CVE-2002-1495: XSS in web-based email product via onmouseover event.

CVE-2002-1681: XSS via script in <P> tag.

CVE-2004-1935: Onload, onmouseover, and other events in an e-mail attachment.

CVE-2005-0945: Onmouseover and onload events in img, link, and mail tags.

CVE-2003-1136: Javascript in onmouseover attribute in e-mail address or URL.

## Top 25 Examples

CVE-2022-0565: Cross-site Scripting in Packagist pimcore/pimcore prior to 10.3.1. 

# CWE-830 Inclusion of Web Functionality from an Untrusted Source

## Description

The product includes web functionality (such as a web widget) from another domain, which causes it to operate within the domain of the product, potentially granting total access and control of the product to the untrusted source.

Including third party functionality in a web-based environment is risky, especially if the source of the functionality is untrusted.


Even if the third party is a trusted source, the product may still be exposed to attacks and malicious behavior if that trusted source is compromised, or if the code is modified in transmission from the third party to the product.


This weakness is common in "mashup" development on the web, which may include source functionality from other domains. For example, Javascript-based web widgets may be inserted by using '<SCRIPT SRC="http://other.domain.here">' tags, which causes the code to run in the domain of the product, not the remote site from which the widget was loaded. As a result, the included code has access to the local DOM, including cookies and other data that the developer might not want the remote site to be able to access.


Such dependencies may be desirable, or even required, but sometimes programmers are not aware that a dependency exists.

# CWE-831 Signal Handler Function Associated with Multiple Signals

## Description

The product defines a function that is used as a handler for more than one signal.

While sometimes intentional and safe, when the same function is used to handle multiple signals, a race condition could occur if the function uses any state outside of its local declaration, such as global variables or non-reentrant functions, or has any side effects.


An attacker could send one signal that invokes the handler function; in many OSes, this will typically prevent the same signal from invoking the handler again, at least until the handler function has completed execution. However, the attacker could then send a different signal that is associated with the same handler function. This could interrupt the original handler function while it is still executing. If there is shared state, then the state could be corrupted. This can lead to a variety of potential consequences depending on context, including denial of service and code execution.


Another rarely-explored possibility arises when the signal handler is only designed to be executed once (if at all). By sending multiple signals, an attacker could invoke the function more than once. This may generate extra, unintended side effects. A race condition might not even be necessary; the attacker could send one signal, wait until it is handled, then send the other signal.

# CWE-832 Unlock of a Resource that is not Locked

## Description

The product attempts to unlock a resource that is not locked.

Depending on the locking functionality, an unlock of a non-locked resource might cause memory corruption or other modification to the resource (or its associated metadata that is used for tracking locks).

## Observed Examples

CVE-2010-4210: function in OS kernel unlocks a mutex that was not previously locked, causing a panic or overwrite of arbitrary memory.

CVE-2008-4302: Chain: OS kernel does not properly handle a failure of a function call (CWE-755), leading to an unlock of a resource that was not locked (CWE-832), with resultant crash.

CVE-2009-1243: OS kernel performs an unlock in some incorrect circumstances, leading to panic.

# CWE-833 Deadlock

## Description

The product contains multiple threads or executable segments that are waiting for each other to release a necessary lock, resulting in deadlock.

## Observed Examples

CVE-1999-1476: A bug in some Intel Pentium processors allow DoS (hang) via an invalid "CMPXCHG8B" instruction, causing a deadlock

CVE-2009-2857: OS deadlock

CVE-2009-1961: OS deadlock involving 3 separate functions

CVE-2009-2699: deadlock in library

CVE-2009-4272: deadlock triggered by packets that force collisions in a routing table

CVE-2002-1850: read/write deadlock between web server and script

CVE-2004-0174: web server deadlock involving multiple listening connections

CVE-2009-1388: multiple simultaneous calls to the same function trigger deadlock.

CVE-2006-5158: chain: other weakness leads to NULL pointer dereference (CWE-476) or deadlock (CWE-833).

CVE-2006-4342: deadlock when an operation is performed on a resource while it is being removed.

CVE-2006-2374: Deadlock in device driver triggered by using file handle of a related device.

CVE-2006-2275: Deadlock when large number of small messages cannot be processed quickly enough.

CVE-2005-3847: OS kernel has deadlock triggered by a signal during a core dump.

CVE-2005-3106: Race condition leads to deadlock.

CVE-2005-2456: Chain: array index error (CWE-129) leads to deadlock (CWE-833)

## Top 25 Examples

CVE-2021-3735: A deadlock issue was found in the AHCI controller device of QEMU. It occurs on a software reset (ahci_reset_port) while handling a host-to-device Register FIS (Frame Information Structure) packet from the guest. A privileged user inside the guest could use this flaw to hang the QEMU process on the host, resulting in a denial of service condition. The highest threat from this vulnerability is to system availability.

CVE-2021-43395: An issue was discovered in illumos before f859e7171bb5db34321e45585839c6c3200ebb90, OmniOS Community Edition r151038, OpenIndiana Hipster 2021.04, and SmartOS 20210923. A local unprivileged user can cause a deadlock and kernel panic via crafted rename and rmdir calls on tmpfs filesystems. Oracle Solaris 10 and 11 is also affected.

CVE-2022-31621: MariaDB Server before 10.7 is vulnerable to Denial of Service. In extra/mariabackup/ds_xbstream.cc, when an error occurs (stream_ctxt->dest_file == NULL) while executing the method xbstream_open, the held lock is not released correctly, which allows local users to trigger a denial of service due to the deadlock. Note: The vendor argues this is just an improper locking bug and not a vulnerability with adverse effects.

CVE-2022-31622: MariaDB Server before 10.7 is vulnerable to Denial of Service. In extra/mariabackup/ds_compress.cc, when an error occurs (pthread_create returns a nonzero value) while executing the method create_worker_threads, the held lock is not released correctly, which allows local users to trigger a denial of service due to the deadlock. Note: The vendor argues this is just an improper locking bug and not a vulnerability with adverse effects.

CVE-2022-31623: MariaDB Server before 10.7 is vulnerable to Denial of Service. In extra/mariabackup/ds_compress.cc, when an error occurs (i.e., going to the err label) while executing the method create_worker_threads, the held lock thd->ctrl_mutex is not released correctly, which allows local users to trigger a denial of service due to the deadlock. Note: The vendor argues this is just an improper locking bug and not a vulnerability with adverse effects.

CVE-2022-31624: MariaDB Server before 10.7 is vulnerable to Denial of Service. While executing the plugin/server_audit/server_audit.c method log_statement_ex, the held lock lock_bigbuffer is not released correctly, which allows local users to trigger a denial of service due to the deadlock.

CVE-2022-38791: In MariaDB before 10.9.2, compress_write in extra/mariabackup/ds_compress.cc does not release data_mutex upon a stream write failure, which allows local users to trigger a deadlock.

CVE-2022-42328: Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock could occur in case of netpoll being active for the interface the xen-netback driver is connected to (CVE-2022-42329).

CVE-2022-42329: Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock could occur in case of netpoll being active for the interface the xen-netback driver is connected to (CVE-2022-42329).

# CWE-834 Excessive Iteration

## Description

The product performs an iteration or loop without sufficiently limiting the number of times that the loop is executed.

If the iteration can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory. In many cases, a loop does not need to be infinite in order to cause enough resource consumption to adversely affect the product or its host system; it depends on the amount of resources consumed per iteration.

## Observed Examples

CVE-2011-1027: Chain: off-by-one error (CWE-193) leads to infinite loop (CWE-835) using invalid hex-encoded characters.

CVE-2006-6499: Chain: web browser crashes due to infinite loop - "bad looping logic [that relies on] floating point math [CWE-1339] to exit the loop [CWE-835]"

## Top 25 Examples

CVE-2022-36083: JOSE is "JSON Web Almost Everything" - JWA, JWS, JWE, JWT, JWK, JWKS with no dependencies using runtime's native crypto in Node.js, Browser, Cloudflare Workers, Electron, and Deno. The PBKDF2-based JWE key management algorithms expect a JOSE Header Parameter named `p2c` PBES2 Count, which determines how many PBKDF2 iterations must be executed in order to derive a CEK wrapping key. The purpose of this parameter is to intentionally slow down the key derivation function in order to make password brute-force and dictionary attacks more expensive. This makes the PBES2 algorithms unsuitable for situations where the JWE is coming from an untrusted source: an adversary can intentionally pick an extremely high PBES2 Count value, that will initiate a CPU-bound computation that may take an unreasonable amount of time to finish. Under certain conditions, it is possible to have the user's environment consume unreasonable amount of CPU time. The impact is limited only to users utilizing the JWE decryption APIs with symmetric secrets to decrypt JWEs from untrusted parties who do not limit the accepted JWE Key Management Algorithms (`alg` Header Parameter) using the `keyManagementAlgorithms` (or `algorithms` in v1.x) decryption option or through other means. The `v1.28.2`, `v2.0.6`, `v3.20.4`, and `v4.9.2` releases limit the maximum PBKDF2 iteration count to `10000` by default. It is possible to adjust this limit with a newly introduced `maxPBES2Count` decryption option. If users are unable to upgrade their required library version, they have two options depending on whether they expect to receive JWEs using any of the three PBKDF2-based JWE key management algorithms. They can use the `keyManagementAlgorithms` decryption option to disable accepting PBKDF2 altogether, or they can inspect the JOSE Header prior to using the decryption API and limit the PBKDF2 iteration count (`p2c` Header Parameter).

# CWE-835 Loop with Unreachable Exit Condition ('Infinite Loop')

## Description

The product contains an iteration or loop with an exit condition that cannot be reached, i.e., an infinite loop.

If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Observed Examples

CVE-2022-22224: Chain: an operating system does not properly process malformed Open Shortest Path First (OSPF) Type/Length/Value Identifiers (TLV) (CWE-703), which can cause the process to enter an infinite loop (CWE-835)

CVE-2022-25304: A Python machine communication platform did not account for receiving a malformed packet with a null size, causing the receiving function to never update the message buffer and be caught in an infinite loop.

CVE-2011-1027: Chain: off-by-one error (CWE-193) leads to infinite loop (CWE-835) using invalid hex-encoded characters.

CVE-2011-1142: Chain: self-referential values in recursive definitions lead to infinite loop.

CVE-2011-1002: NULL UDP packet is never cleared from a queue, leading to infinite loop.

CVE-2006-6499: Chain: web browser crashes due to infinite loop - "bad looping logic [that relies on] floating point math [CWE-1339] to exit the loop [CWE-835]"

CVE-2010-4476: Floating point conversion routine cycles back and forth between two different values.

CVE-2010-4645: Floating point conversion routine cycles back and forth between two different values.

CVE-2010-2534: Chain: improperly clearing a pointer in a linked list leads to infinite loop.

CVE-2013-1591: Chain: an integer overflow (CWE-190) in the image size calculation causes an infinite loop (CWE-835) which sequentially allocates buffers without limits (CWE-1325) until the stack is full.

CVE-2008-3688: Chain: A denial of service may be caused by an uninitialized variable (CWE-457) allowing an infinite loop (CWE-835) resulting from a connection to an unresponsive server.

## Top 25 Examples

CVE-2022-24191: In HTMLDOC 1.9.14, an infinite loop in the gif_read_lzw function can lead to a pointer arbitrarily pointing to heap memory and resulting in a buffer overflow.

CVE-2022-23437: There's a vulnerability within the Apache Xerces Java (XercesJ) XML parser when handling specially crafted XML document payloads. This causes, the XercesJ XML parser to wait in an infinite loop, which may sometimes consume system resources for prolonged duration. This vulnerability is present within XercesJ version 2.12.1 and the previous versions.

CVE-2022-23641: Discourse is an open source discussion platform. In versions prior to 2.8.1 in the `stable` branch, 2.9.0.beta2 in the `beta` branch, and 2.9.0.beta2 in the `tests-passed` branch, users can trigger a Denial of Service attack by posting a streaming URL. Parsing Oneboxes in the background job trigger an infinite loop, which cause memory leaks. This issue is patched in version 2.8.1 of the `stable` branch, 2.9.0.beta2 of the `beta` branch, and 2.9.0.beta2 of the `tests-passed` branch. As a workaround, disable onebox in admin panel completely or specify allow list of domains that will be oneboxed.

CVE-2022-31628: In PHP versions before 7.4.31, 8.0.24 and 8.1.11, the phar uncompressor code would recursively uncompress "quines" gzip files, resulting in an infinite loop.

CVE-2022-46770: qubes-mirage-firewall (aka Mirage firewall for QubesOS) 0.8.x through 0.8.3 allows guest OS users to cause a denial of service (CPU consumption and loss of forwarding) via a crafted multicast UDP packet (IP address range of 224.0.0.0 through 239.255.255.255).

# CWE-836 Use of Password Hash Instead of Password for Authentication

## Description

The product records password hashes in a data store, receives a hash of a password from a client, and compares the supplied hash to the hash obtained from the data store.

Some authentication mechanisms rely on the client to generate the hash for a password, possibly to reduce load on the server or avoid sending the password across the network. However, when the client is used to generate the hash, an attacker can bypass the authentication by obtaining a copy of the hash, e.g. by using SQL injection to compromise a database of authentication credentials, or by exploiting an information exposure. The attacker could then use a modified client to replay the stolen hash without having knowledge of the original password.


As a result, the server-side comparison against a client-side hash does not provide any more security than the use of passwords without hashing.

## Observed Examples

CVE-2009-1283: Product performs authentication with user-supplied password hashes that can be obtained from a separate SQL injection vulnerability (CVE-2009-1282).

CVE-2005-3435: Product allows attackers to bypass authentication by obtaining the password hash for another user and specifying the hash in the pwd argument.

## Top 25 Examples

CVE-2021-36460: VeryFitPro (com.veryfit2hr.second) 3.2.8 hashes the account's password locally on the device and uses the hash to authenticate in all communication with the backend API, including login, registration and changing of passwords. This allows an attacker in possession of a hash to takeover a user's account, rendering the benefits of storing hashed passwords in the database useless.

CVE-2021-45036:  Velneo vClient on its 28.1.3 version, could allow an attacker with knowledge of the victims's username and hashed password to spoof the victim's id against the server. 

CVE-2022-25155: Use of Password Hash Instead of Password for Authentication vulnerability in Mitsubishi Electric MELSEC iQ-F series FX5U(C) CPU all versions, Mitsubishi Electric MELSEC iQ-F series FX5UJ CPU all versions, Mitsubishi Electric MELSEC iQ-R series R00/01/02CPU all versions, Mitsubishi Electric MELSEC iQ-R series R04/08/16/32/120(EN)CPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120SFCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PSFCPU all versions, Mitsubishi Electric MELSEC iQ-R series RJ71GN11-T2 all versions, Mitsubishi Electric MELSEC iQ-R series RJ71GN11-EIP all versions, Mitsubishi Electric MELSEC iQ-R series RJ71C24(-R2/R4) all versions, Mitsubishi Electric MELSEC iQ-R series RJ71EN71 all versions, Mitsubishi Electric MELSEC iQ-R series RJ72GF15-T2 all versions, Mitsubishi Electric MELSEC Q series Q03UDECPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/10/13/20/26/50/100UDEHCPU all versions, Mitsubishi Electric MELSEC Q series Q03/04/06/13/26UDVCPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/13/26UDPVCPU all versions, Mitsubishi Electric MELSEC Q series QJ71C24N(-R2/R4) all versions, Mitsubishi Electric MELSEC Q series QJ71E71-100 all versions, Mitsubishi Electric MELSEC Q series QJ72BR15 all versions, Mitsubishi Electric MELSEC Q series QJ72LP25(-25/G/GE) all versions, Mitsubishi Electric MELSEC L series L02/06/26CPU(-P) all versions, Mitsubishi Electric MELSEC L series L26CPU-(P)BT all versions, Mitsubishi Electric MELSEC L series LJ71C24(-R2) all versions, Mitsubishi Electric MELSEC L series LJ71E71-100 all versions and Mitsubishi Electric MELSEC L series LJ72GF15-T2 all versions allows a remote unauthenticated attacker to login to the product by replaying an eavesdropped password hash.

CVE-2022-25157: Use of Password Hash Instead of Password for Authentication vulnerability in Mitsubishi Electric MELSEC iQ-F series FX5U(C) CPU all versions, Mitsubishi Electric MELSEC iQ-F series FX5UJ CPU all versions, Mitsubishi Electric MELSEC iQ-R series R00/01/02CPU all versions, Mitsubishi Electric MELSEC iQ-R series R04/08/16/32/120(EN)CPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120SFCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PSFCPU all versions, Mitsubishi Electric MELSEC iQ-R series R16/32/64MTCPU all versions, Mitsubishi Electric MELSEC iQ-R series RJ71C24(-R2/R4) all versions, Mitsubishi Electric MELSEC iQ-R series RJ71EN71 all versions, Mitsubishi Electric MELSEC iQ-R series RJ71GF11-T2 all versions, Mitsubishi Electric MELSEC iQ-R series RJ71GP21(S)-SX all versions, Mitsubishi Electric MELSEC iQ-R series RJ72GF15-T2 all versions, Mitsubishi Electric MELSEC Q series Q03UDECPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/10/13/20/26/50/100UDEHCPU all versions, Mitsubishi Electric MELSEC Q series Q03/04/06/13/26UDVCPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/13/26UDPVCPU all versions, Mitsubishi Electric MELSEC Q series QJ71C24N(-R2/R4) all versions, Mitsubishi Electric MELSEC Q series QJ71E71-100 all versions, Mitsubishi Electric MELSEC L series L02/06/26CPU(-P) all versions, Mitsubishi Electric MELSEC L series L26CPU-(P)BT all versions, Mitsubishi Electric MELSEC L series LJ71C24(-R2) all versions, Mitsubishi Electric MELSEC L series LJ71E71-100 all versions and Mitsubishi Electric MELSEC L series LJ72GF15-T2 all versions allows a remote unauthenticated attacker to disclose or tamper with the information in the product by using an eavesdropped password hash.

CVE-2022-32282: An improper password check exists in the login functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. An attacker that owns a users' password hash will be able to use it to directly login into the account, leading to increased privileges.

# CWE-837 Improper Enforcement of a Single, Unique Action

## Description

The product requires that an actor should only be able to perform an action once, or to have only one unique action, but the product does not enforce or improperly enforces this restriction.

In various applications, a user is only expected to perform a certain action once, such as voting, requesting a refund, or making a purchase. When this restriction is not enforced, sometimes this can have security implications. For example, in a voting application, an attacker could attempt to "stuff the ballot box" by voting multiple times. If these votes are counted separately, then the attacker could directly affect who wins the vote. This could have significant business impact depending on the purpose of the product.

## Observed Examples

CVE-2008-0294: Ticket-booking web application allows a user to lock a seat more than once.

CVE-2005-4051: CMS allows people to rate downloads by voting more than once.

CVE-2002-216: Polling software allows people to vote more than once by setting a cookie.

CVE-2003-1433: Chain: lack of validation of a challenge key in a game allows a player to register multiple times and lock other players out of the game.

CVE-2002-1018: Library feature allows attackers to check out the same e-book multiple times, preventing other users from accessing copies of the e-book.

CVE-2009-2346: Protocol implementation allows remote attackers to cause a denial of service (call-number exhaustion) by initiating many message exchanges.

# CWE-838 Inappropriate Encoding for Output Context

## Description

The product uses or specifies an encoding when generating output to a downstream component, but the specified encoding is not the same as the encoding that is expected by the downstream component.

This weakness can cause the downstream component to use a decoding method that produces different data than what the product intended to send. When the wrong encoding is used - even if closely related - the downstream component could decode the data incorrectly. This can have security consequences when the provided boundaries between control and data are inadvertently broken, because the resulting data could introduce control characters or special elements that were not sent by the product. The resulting data could then be used to bypass protection mechanisms such as input validation, and enable injection attacks.


While using output encoding is essential for ensuring that communications between components are accurate, the use of the wrong encoding - even if closely related - could cause the downstream component to misinterpret the output.


For example, HTML entity encoding is used for elements in the HTML body of a web page. However, a programmer might use entity encoding when generating output for that is used within an attribute of an HTML tag, which could contain functional Javascript that is not affected by the HTML encoding.


While web applications have received the most attention for this problem, this weakness could potentially apply to any type of product that uses a communications stream that could support multiple encodings.

## Observed Examples

CVE-2009-2814: Server does not properly handle requests that do not contain UTF-8 data; browser assumes UTF-8, allowing XSS.

## Top 25 Examples

CVE-2022-43408: Jenkins Pipeline: Stage View Plugin 2.26 and earlier does not correctly encode the ID of 'input' steps when using it to generate URLs to proceed or abort Pipeline builds, allowing attackers able to configure Pipelines to specify 'input' step IDs resulting in URLs that would bypass the CSRF protection of any target URL in Jenkins.

CVE-2022-43407: Jenkins Pipeline: Input Step Plugin 451.vf1a_a_4f405289 and earlier does not restrict or sanitize the optionally specified ID of the 'input' step, which is used for the URLs that process user interactions for the given 'input' step (proceed or abort) and is not correctly encoded, allowing attackers able to configure Pipelines to have Jenkins build URLs from 'input' step IDs that would bypass the CSRF protection of any target URL in Jenkins when the 'input' step is interacted with.

# CWE-839 Numeric Range Comparison Without Minimum Check

## Description

The product checks a value to ensure that it is less than or equal to a maximum, but it does not also verify that the value is greater than or equal to the minimum.

Some products use signed integers or floats even when their values are only expected to be positive or 0. An input validation check might assume that the value is positive, and only check for the maximum value. If the value is negative, but the code assumes that the value is positive, this can produce an error. The error may have security consequences if the negative value is used for memory allocation, array access, buffer access, etc. Ultimately, the error could lead to a buffer overflow or other type of memory corruption.


The use of a negative number in a positive-only context could have security implications for other types of resources. For example, a shopping cart might check that the user is not requesting more than 10 items, but a request for -3 items could cause the application to calculate a negative price and credit the attacker's account.

## Observed Examples

CVE-2010-1866: Chain: integer overflow (CWE-190) causes a negative signed value, which later bypasses a maximum-only check (CWE-839), leading to heap-based buffer overflow (CWE-122).

CVE-2009-1099: Chain: 16-bit counter can be interpreted as a negative value, compared to a 32-bit maximum value, leading to buffer under-write.

CVE-2011-0521: Chain: kernel's lack of a check for a negative value leads to memory corruption.

CVE-2010-3704: Chain: parser uses atoi() but does not check for a negative value, which can happen on some platforms, leading to buffer under-write.

CVE-2010-2530: Chain: Negative value stored in an int bypasses a size check and causes allocation of large amounts of memory.

CVE-2009-3080: Chain: negative offset value to IOCTL bypasses check for maximum index, then used as an array index for buffer under-read.

CVE-2008-6393: chain: file transfer client performs signed comparison, leading to integer overflow and heap-based buffer overflow.

CVE-2008-4558: chain: negative ID in media player bypasses check for maximum index, then used as an array index for buffer under-read.

# CWE-84 Improper Neutralization of Encoded URI Schemes in a Web Page

## Description

The web application improperly neutralizes user-controlled input for executable script disguised with URI encodings.

## Observed Examples

CVE-2005-0563: Cross-site scripting (XSS) vulnerability in Microsoft Outlook Web Access (OWA) component in Exchange Server 5.5 allows remote attackers to inject arbitrary web script or HTML via an email message with an encoded javascript: URL ("jav&#X41sc&#0010;ript:") in an IMG tag.

CVE-2005-2276: Cross-site scripting (XSS) vulnerability in Novell Groupwise WebAccess 6.5 before July 11, 2005 allows remote attackers to inject arbitrary web script or HTML via an e-mail message with an encoded javascript URI (e.g. "j&#X41vascript" in an IMG tag).

CVE-2005-0692: Encoded script within BBcode IMG tag.

CVE-2002-0117: Encoded "javascript" in IMG tag.

CVE-2002-0118: Encoded "javascript" in IMG tag.

## Top 25 Examples

CVE-2022-40181: A vulnerability has been identified in Desigo PXM30-1 (All versions < V02.20.126.11-41), Desigo PXM30.E (All versions < V02.20.126.11-41), Desigo PXM40-1 (All versions < V02.20.126.11-41), Desigo PXM40.E (All versions < V02.20.126.11-41), Desigo PXM50-1 (All versions < V02.20.126.11-41), Desigo PXM50.E (All versions < V02.20.126.11-41), PXG3.W100-1 (All versions < V02.20.126.11-37), PXG3.W100-2 (All versions < V02.20.126.11-41), PXG3.W200-1 (All versions < V02.20.126.11-37), PXG3.W200-2 (All versions < V02.20.126.11-41). The device embedded browser does not prevent interaction with alternative URI schemes when redirected to corresponding resources by web application code. By setting the homepage URI, the favorite URIs, or redirecting embedded browser users via JavaScript code to alternative scheme resources, a remote low privileged attacker can perform a range of attacks against the device, such as read arbitrary files on the filesystem, execute arbitrary JavaScript code in order to steal or manipulate the information on the screen, or trigger denial of service conditions.

# CWE-841 Improper Enforcement of Behavioral Workflow

## Description

The product supports a session in which more than one behavior must be performed by an actor, but it does not properly ensure that the actor performs the behaviors in the required sequence.

By performing actions in an unexpected order, or by omitting steps, an attacker could manipulate the business logic of the product or cause it to enter an invalid state. In some cases, this can also expose resultant weaknesses.


For example, a file-sharing protocol might require that an actor perform separate steps to provide a username, then a password, before being able to transfer files. If the file-sharing server accepts a password command followed by a transfer command, without any username being provided, the product might still perform the transfer.


Note that this is different than CWE-696, which focuses on when the product performs actions in the wrong sequence; this entry is closely related, but it is focused on ensuring that the actor performs actions in the correct sequence.


Workflow-related behaviors include:


  - Steps are performed in the expected order.

  - Required steps are not omitted.

  - Steps are not interrupted.

  - Steps are performed in a timely fashion.

## Observed Examples

CVE-2011-0348: Bypass of access/billing restrictions by sending traffic to an unrestricted destination before sending to a restricted destination.

CVE-2007-3012: Attacker can access portions of a restricted page by canceling out of a dialog.

CVE-2009-5056: Ticket-tracking system does not enforce a permission setting.

CVE-2004-2164: Shopping cart does not close a database connection when user restores a previous order, leading to connection exhaustion.

CVE-2003-0777: Chain: product does not properly handle dropped connections, leading to missing NULL terminator (CWE-170) and segmentation fault.

CVE-2005-3327: Chain: Authentication bypass by skipping the first startup step as required by the protocol.

CVE-2004-0829: Chain: File server crashes when sent a "find next" request without an initial "find first."

CVE-2010-2620: FTP server allows remote attackers to bypass authentication by sending (1) LIST, (2) RETR, (3) STOR, or other commands without performing the required login steps first.

CVE-2005-3296: FTP server allows remote attackers to list arbitrary directories as root by running the LIST command before logging in.

# CWE-842 Placement of User into Incorrect Group

## Description

The product or the administrator places a user into an incorrect group.

If the incorrect group has more access or privileges than the intended group, the user might be able to bypass intended security policy to access unexpected resources or perform unexpected actions. The access-control system might not be able to detect malicious usage of this group membership.

## Observed Examples

CVE-1999-1193: Operating system assigns user to privileged wheel group, allowing the user to gain root privileges.

CVE-2010-3716: Chain: drafted web request allows the creation of users with arbitrary group membership.

CVE-2008-5397: Chain: improper processing of configuration options causes users to contain unintended group memberships.

CVE-2007-6644: CMS does not prevent remote administrators from promoting other users to the administrator group, in violation of the intended security model.

CVE-2007-3260: Product assigns members to the root group, allowing escalation of privileges.

CVE-2002-0080: Chain: daemon does not properly clear groups before dropping privileges.

## Top 25 Examples

CVE-2022-45097:  Dell PowerScale OneFS 9.0.0.x-9.4.0.x contains an Incorrect User Management vulnerability. A low privileged network attacker could potentially exploit this vulnerability, leading to escalation of privileges, and information disclosure. 

# CWE-843 Access of Resource Using Incompatible Type ('Type Confusion')

## Description

The product allocates or initializes a resource such as a pointer, object, or variable using one type, but it later accesses that resource using a type that is incompatible with the original type.

When the product accesses the resource using an incompatible type, this could trigger logical errors because the resource does not have expected properties. In languages without memory safety, such as C and C++, type confusion can lead to out-of-bounds memory access.


While this weakness is frequently associated with unions when parsing data with many different embedded object types in C, it can be present in any application that can interpret the same variable or memory location in multiple ways.


This weakness is not unique to C and C++. For example, errors in PHP applications can be triggered by providing array parameters when scalars are expected, or vice versa. Languages such as Perl, which perform automatic conversion of a variable of one type when it is accessed as if it were another type, can also contain these issues.

## Observed Examples

CVE-2010-4577: Type confusion in CSS sequence leads to out-of-bounds read.

CVE-2011-0611: Size inconsistency allows code execution, first discovered when it was actively exploited in-the-wild.

CVE-2010-0258: Improperly-parsed file containing records of different types leads to code execution when a memory location is interpreted as a different object than intended.

## Top 25 Examples

CVE-2021-26635: In the code that verifies the file size in the ark library, it is possible to manipulate the offset read from the target file due to the wrong use of the data type. An attacker could use this vulnerability to cause a stack buffer overflow and as a result, perform an attack such as remote code execution.

CVE-2021-38007: Type confusion in V8 in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-38012: Type confusion in V8 in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4056: Type confusion in loader in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4061: Type confusion in V8 in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4078: Type confusion in V8 in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0102: Type confusion in V8 in Google Chrome prior to 97.0.4692.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0457: Type confusion in V8 in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0795: Type confusion in Blink Layout in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1096: Type confusion in V8 in Google Chrome prior to 99.0.4844.84 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1134: Type confusion in V8 in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1232: Type confusion in V8 in Google Chrome prior to 100.0.4896.75 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1314: Type confusion in V8 in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1364: Type confusion in V8 Turbofan in Google Chrome prior to 100.0.4896.127 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1869: Type Confusion in V8 in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-20461: In pinReplyNative of com_android_bluetooth_btservice_AdapterService.cpp, there is a possible out of bounds read due to type confusion. This could lead to local escalation of privilege of BLE with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-228602963

CVE-2022-26433: In mailbox, there is a possible out of bounds write due to type confusion. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07138400; Issue ID: ALPS07138400.

CVE-2022-3315: Type confusion in Blink in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)

CVE-2022-3889: Type confusion in V8 in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4174: Type confusion in V8 in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-25721: Memory corruption in video driver due to type confusion error during video playback

CVE-2022-2295: Type confusion in V8 in Google Chrome prior to 103.0.5060.114 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-34918: An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.

CVE-2022-3652: Type confusion in V8 in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-23583: Tensorflow is an Open Source Machine Learning Framework. A malicious user can cause a denial of service by altering a `SavedModel` such that any binary op would trigger `CHECK` failures. This occurs when the protobuf part corresponding to the tensor arguments is modified such that the `dtype` no longer matches the `dtype` expected by the op. In that case, calling the templated binary operator for the binary op would receive corrupted data, due to the type confusion involved. If `Tin` and `Tout` don't match the type of data in `out` and `input_*` tensors then `flat<*>` would interpret it wrongly. In most cases, this would be a silent failure, but we have noticed scenarios where this results in a `CHECK` crash, hence a denial of service. The fix will be included in TensorFlow 2.8.0. We will also cherrypick this commit on TensorFlow 2.7.1, TensorFlow 2.6.3, and TensorFlow 2.5.3, as these are also affected and still in supported range.

CVE-2022-3723: Type confusion in V8 in Google Chrome prior to 107.0.5304.87 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4262: Type confusion in V8 in Google Chrome prior to 108.0.5359.94 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2021-1789: A type confusion issue was addressed with improved state handling. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, tvOS 14.4, watchOS 7.3, iOS 14.4 and iPadOS 14.4, Safari 14.0.3. Processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-21224: Type confusion in V8 in Google Chrome prior to 90.0.4430.85 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page.

CVE-2021-30551: Type confusion in V8 in Google Chrome prior to 91.0.4472.101 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-30563: Type Confusion in V8 in Google Chrome prior to 91.0.4472.164 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-30869: A type confusion issue was addressed with improved state handling. This issue is fixed in iOS 12.5.5, iOS 14.4 and iPadOS 14.4, macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, Security Update 2021-006 Catalina. A malicious application may be able to execute arbitrary code with kernel privileges. Apple is aware of reports that an exploit for this issue exists in the wild.

CVE-2022-41033: Windows COM+ Event System Service Elevation of Privilege Vulnerability

CVE-2022-42856: A type confusion issue was addressed with improved state handling. This issue is fixed in Safari 16.2, tvOS 16.2, macOS Ventura 13.1, iOS 15.7.2 and iPadOS 15.7.2, iOS 16.1.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited against versions of iOS released before iOS 15.1..

CVE-2022-21656: Envoy is an open source edge and service proxy, designed for cloud-native applications. The default_validator.cc implementation used to implement the default certificate validation routines has a "type confusion" bug when processing subjectAltNames. This processing allows, for example, an rfc822Name or uniformResourceIndicator to be authenticated as a domain name. This confusion allows for the bypassing of nameConstraints, as processed by the underlying OpenSSL/BoringSSL implementation, exposing the possibility of impersonation of arbitrary servers. As a result Envoy will trust upstream certificates that should not be trusted.

CVE-2021-33624: In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a side-channel attack, aka CID-9183671af6db.

# CWE-85 Doubled Character XSS Manipulations

## Description

The web application does not filter user-controlled input for executable script disguised using doubling of the involved characters.

## Observed Examples

CVE-2002-2086: XSS using "<script".

CVE-2000-0116: Encoded "javascript" in IMG tag.

CVE-2001-1157: Extra "<" in front of SCRIPT tag.

# CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages

## Description

The product does not neutralize or incorrectly neutralizes invalid characters or byte sequences in the middle of tag names, URI schemes, and other identifiers.

Some web browsers may remove these sequences, resulting in output that may have unintended control implications. For example, the product may attempt to remove a "javascript:" URI scheme, but a "java%00script:" URI may bypass this check and still be rendered as active javascript by some browsers, allowing XSS or other attacks.

## Observed Examples

CVE-2004-0595: XSS filter doesn't filter null characters before looking for dangerous tags, which are ignored by web browsers. Multiple Interpretation Error (MIE) and validate-before-cleanse.

# CWE-862 Missing Authorization

## Description

The product does not perform an authorization check when an actor attempts to access a resource or perform an action.

Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-control specifications that apply to the resource.


When access control checks are not applied, users are able to access data or perform actions that they should not be allowed to perform. This can lead to a wide range of problems, including information exposures, denial of service, and arbitrary code execution.

An access control list (ACL) represents who/what has permissions to a given object. Different operating systems implement (ACLs) in different ways. In UNIX, there are three types of permissions: read, write, and execute. Users are divided into three classes for file access: owner, group owner, and all other users where each class has a separate set of rights. In Windows NT, there are four basic types of permissions for files: "No access", "Read access", "Change access", and "Full control". Windows NT extends the concept of three types of users in UNIX to include a list of users and groups along with their associated permissions. A user can create an object (file) and assign specified permissions to that object.

## Observed Examples

CVE-2022-24730: Go-based continuous deployment product does not check that a user has certain privileges to update or create an app, allowing adversaries to read sensitive repository information

CVE-2009-3168: Web application does not restrict access to admin scripts, allowing authenticated users to reset administrative passwords.

CVE-2009-3597: Web application stores database file under the web root with insufficient access control (CWE-219), allowing direct request.

CVE-2009-2282: Terminal server does not check authorization for guest access.

CVE-2008-5027: System monitoring software allows users to bypass authorization by creating custom forms.

CVE-2009-3781: Content management system does not check access permissions for private files, allowing others to view those files.

CVE-2008-6548: Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.

CVE-2009-2960: Web application does not restrict access to admin scripts, allowing authenticated users to modify passwords of other users.

CVE-2009-3230: Database server does not use appropriate privileges for certain sensitive operations.

CVE-2009-2213: Gateway uses default "Allow" configuration for its authorization settings.

CVE-2009-0034: Chain: product does not properly interpret a configuration option for a system group, allowing users to gain privileges.

CVE-2008-6123: Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect.

CVE-2008-7109: Chain: reliance on client-side security (CWE-602) allows attackers to bypass authorization using a custom client.

CVE-2008-3424: Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.

CVE-2005-1036: Chain: Bypass of access restrictions due to improper authorization (CWE-862) of a user results from an improperly initialized (CWE-909) I/O permission bitmap

CVE-2008-4577: ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.

CVE-2007-2925: Default ACL list for a DNS server does not set certain ACLs, allowing unauthorized DNS queries.

CVE-2006-6679: Product relies on the X-Forwarded-For HTTP header for authorization, allowing unintended access by spoofing the header.

CVE-2005-3623: OS kernel does not check for a certain privilege before setting ACLs for files.

CVE-2005-2801: Chain: file-system code performs an incorrect comparison (CWE-697), preventing default ACLs from being properly applied.

CVE-2001-1155: Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence (CWE-783), allowing bypass of DNS-based access restrictions.

CVE-2020-17533: Chain: unchecked return value (CWE-252) of some functions for policy enforcement leads to authorization bypass (CWE-862)

## Top 25 Examples

CVE-2022-43581: IBM Content Navigator 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.0.7, 3.0.8, 3.0.9, 3.0.10, 3.0.11, and 3.0.12 is vulnerable to missing authorization and could allow an authenticated user to load external plugins and execute code. IBM X-Force ID: 238805.

CVE-2022-0421: The Five Star Restaurant Reservations WordPress plugin before 2.4.12 does not have authorisation when changing whether a payment was successful or failed, allowing unauthenticated users to change the payment status of arbitrary bookings. Furthermore, due to the lack of sanitisation and escaping, attackers could perform Cross-Site Scripting attacks against a logged in admin viewing the failed payments

CVE-2022-0423: The 3D FlipBook WordPress plugin before 1.12.1 does not have authorisation and CSRF checks when updating its settings, and does not have any sanitisation/escaping, allowing any authenticated users, such as subscriber to put Cross-Site Scripting payloads in all pages with a 3d flipbook.

CVE-2022-0450: The Menu Image, Icons made easy WordPress plugin before 3.0.6 does not have authorisation and CSRF checks when saving menu settings, and does not validate, sanitise and escape them. As a result, any authenticate users, such as subscriber can update the settings or arbitrary menu and put Cross-Site Scripting payloads in them which will be triggered in the related menu in the frontend

CVE-2022-0818: The WooCommerce Affiliate Plugin WordPress plugin before 4.16.4.5 does not have authorization and CSRF checks on a specific action handler, as well as does not sanitize its settings, which enables an unauthenticated attacker to inject malicious XSS payloads into the settings page of the plugin.

CVE-2022-1557: The ULeak Security & Monitoring WordPress plugin through 1.2.3 does not have authorisation and CSRF checks when updating its settings, and is also lacking sanitisation as well as escaping in some of them, which could allow any authenticated users such as subscriber to perform Stored Cross-Site Scripting attacks against admins viewing the settings

CVE-2022-20054: In ims service, there is a possible AT command injection due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06219083; Issue ID: ALPS06219083.

CVE-2022-22735: The Simple Quotation WordPress plugin through 1.3.2 does not have authorisation (and CSRF) checks in various of its AJAX actions and is lacking escaping of user data when using it in SQL statements, allowing any authenticated users, such as subscriber to perform SQL injection attacks

CVE-2022-2846: The Calendar Event Multi View WordPress plugin before 1.4.07 does not have any authorisation and CSRF checks in place when creating an event, and is also lacking sanitisation as well as escaping in some of the event fields. This could allow unauthenticated attackers to create arbitrary events and put Cross-Site Scripting payloads in it.

CVE-2022-3024: The Simple Bitcoin Faucets WordPress plugin through 1.7.0 does not have any authorisation and CSRF in an AJAX action, allowing any authenticated users, such as subscribers to call it and add/delete/edit Bonds. Furthermore, due to the lack of sanitisation and escaping, it could also lead to Stored Cross-Site Scripting issues

CVE-2022-4125: The Popup Manager WordPress plugin through 1.6.6 does not have authorisation and CSRF check when creating/updating popups, and is missing sanitisation as well as escaping, which could allow unauthenticated attackers to create arbitrary popups and add Stored XSS payloads as well

CVE-2022-47339: In cmd services, there is a OS command injection issue due to missing permission check. This could lead to local escalation of privilege with system execution privileges needed.

CVE-2022-0634: The ThirstyAffiliates WordPress plugin before 3.10.5 lacks authorization checks in the ta_insert_external_image action, allowing a low-privilege user (with a role as low as Subscriber) to add an image from an external URL to an affiliate link. Further the plugin lacks csrf checks, allowing an attacker to trick a logged in user to perform the action by crafting a special request.

CVE-2022-0833: The Church Admin WordPress plugin before 3.4.135 does not have authorisation and CSRF in some of its action as well as requested files, allowing unauthenticated attackers to repeatedly request the "refresh-backup" action, and simultaneously keep requesting a publicly accessible temporary file generated by the plugin in order to disclose the final backup filename, which can then be fetched by the attacker to download the backup of the plugin's DB data

CVE-2022-0952: The Sitemap by click5 WordPress plugin before 1.0.36 does not have authorisation and CSRF checks when updating options via a REST endpoint, and does not ensure that the option to be updated belongs to the plugin. As a result, unauthenticated attackers could change arbitrary blog options, such as the users_can_register and default_role, allowing them to create a new admin account and take over the blog.

CVE-2022-1092: The myCred WordPress plugin before 2.4.3.1 does not have authorisation and CSRF checks in its mycred-tools-import-export AJAX action, allowing any authenticated user to call and and retrieve the list of email address present in the blog

CVE-2022-1203: The Content Mask WordPress plugin before 1.8.4.1 does not have authorisation and CSRF checks in various AJAX actions, as well as does not validate the option to be updated to ensure it belongs to the plugin. As a result, any authenticated user, such as subscriber could modify arbitrary blog options

CVE-2022-1570: The Files Download Delay WordPress plugin before 1.0.7 does not have authorisation and CSRF checks when reseting its settings, which could allow any authenticated users, such as subscriber to perform such action.

CVE-2022-1572: The HTML2WP WordPress plugin through 1.0.0 does not have authorisation and CSRF checks in an AJAX action, available to any authenticated users such as subscriber, which could allow them to delete arbitrary file

CVE-2022-1574: The HTML2WP WordPress plugin through 1.0.0 does not have authorisation and CSRF checks when importing files, and does not validate them, as a result, unauthenticated attackers can upload arbitrary files (such as PHP) on the remote server

CVE-2022-3911: The iubenda WordPress plugin before 3.3.3 does does not have authorisation and CSRF in an AJAX action, and does not ensure that the options to be updated belong to the plugin as long as they are arrays. As a result, any authenticated users, such as subscriber can grant themselves any privileges, such as edit_plugins etc

CVE-2022-4102: The Royal Elementor Addons WordPress plugin before 1.3.56 does not have authorization and CSRF checks when deleting a template and does not ensure that the post to be deleted is a template. This could allow any authenticated users, such as subscribers, to delete arbitrary posts assuming they know the related slug.

CVE-2021-39190: The SCCM plugin for GLPI is a plugin to synchronize computers from SCCM (version 1802) to GLPI. In versions prior to 2.3.0, the Configuration page is publicly accessible in read-only mode. This issue is patched in version 2.3.0. No known workarounds exist.

CVE-2021-37976: Inappropriate implementation in Memory in Google Chrome prior to 94.0.4606.71 allowed a remote attacker to obtain potentially sensitive information from process memory via a crafted HTML page.

CVE-2022-0543: It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

CVE-2021-0735: In PackageManager, there is a possible way to get information about installed packages ignoring limitations introduced in Android 11 due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-188913056

CVE-2021-31577: In Boa, there is a possible escalation of privilege due to a missing permission check. This could lead to remote escalation of privilege from a proximal attacker with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: A20210008; Issue ID: OSBNB00123241.

CVE-2022-0163: The Smart Forms WordPress plugin before 2.6.71 does not have authorisation in its rednao_smart_forms_entries_list AJAX action, allowing any authenticated users, such as subscriber, to download arbitrary form's data, which could include sensitive information such as PII depending on the form.

CVE-2022-0179: snipe-it is vulnerable to Missing Authorization

CVE-2022-0755: Missing Authorization in GitHub repository salesagility/suitecrm prior to 7.12.5.

CVE-2022-1054: The RSVP and Event Management Plugin WordPress plugin before 2.7.8 does not have any authorisation checks when exporting its entries, and has the export function hooked to the init action. As a result, unauthenticated attackers could call it and retrieve PII such as first name, last name and email address of user registered for events

CVE-2022-20002: In incfs, there is a possible way of mounting on arbitrary paths due to a missing permission check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-198657657

CVE-2022-20049: In vpu, there is a possible escalation of privilege due to a missing permission check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05954679; Issue ID: ALPS05954679.

CVE-2022-20053: In ims service, there is a possible escalation of privilege due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06219097; Issue ID: ALPS06219097.

CVE-2022-20126: In setScanMode of AdapterService.java, there is a possible way to enable Bluetooth discovery mode without user interaction due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-203431023

CVE-2022-20133: In setDiscoverableTimeout of AdapterService.java, there is a possible bypass of user interaction due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-206807679

CVE-2022-20137: In onCreateContextMenu of NetworkProviderSettings.java, there is a possible way for non-owner users to change WiFi settings due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-206986392

CVE-2022-20138: In ACTION_MANAGED_PROFILE_PROVISIONED of DevicePolicyManagerService.java, there is a possible way for unprivileged app to send MANAGED_PROFILE_PROVISIONED intent due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-210469972

CVE-2022-20172: In onbind of ShannonRcsService.java, there is a possible access to protect data due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-206987222References: N/A

CVE-2022-20182: In handle_ramdump of pixel_loader.c, there is a possible way to create a ramdump of non-secure memory due to a missing permission check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-222348453References: N/A

CVE-2022-20200: In updateApState of SoftApManager.java, there is a possible leak of hotspot state due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-212695058

CVE-2022-20204: In registerRemoteBugreportReceivers of DevicePolicyManagerService.java, there is a possible reporting of falsified bug reports due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-171495100

CVE-2022-20206: In setPackageOrComponentEnabled of NotificationManagerService.java, there is a missing permission check. This could lead to local information disclosure about enabled notification listeners with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-220737634

CVE-2022-20240: In sOpAllowSystemRestrictionBypass of AppOpsManager.java, there is a possible leak of location information due to a missing permission check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-231496105

CVE-2022-20255: In SettingsProvider, there is a possible way to read or change the default ringtone due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-222687217

CVE-2022-20259: In Telephony, there is a possible leak of ICCID and EID due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-221431393

CVE-2022-20261: In LocationManager, there is a possible way to get location information due to a missing permission check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-219835125

CVE-2022-20262: In ActivityManager, there is a possible way to check another process's capabilities due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-218338453

CVE-2022-20263: In ActivityManager, there is a way to read process state for other users due to a missing permission check. This could lead to local information disclosure of app usage with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-217935264

CVE-2022-20267: In bluetooth, there is a possible way to enable or disable bluetooth connection without user consent due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-211646835

CVE-2022-20274: In Keyguard, there is a missing permission check. This could lead to local escalation of privilege and prevention of screen timeout with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-206470146

CVE-2022-20281: In Core, there is a possible way to start an activity from the background due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204083967

CVE-2022-20282: In AppWidget, there is a possible way to start an activity from the background due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204083104

CVE-2022-20284: In Telephony, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure of phone accounts with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-231986341

CVE-2022-20294: In Content, there is a possible way to learn about an account present on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-202160705

CVE-2022-20295: In ContentService, there is a possible way to check if an account exists on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-202160584

CVE-2022-20296: In ContentService, there is a possible way to check if an account exists on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-201794303

CVE-2022-20298: In ContentService, there is a possible way to check if an account exists on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-201416182

CVE-2022-20299: In ContentService, there is a possible way to check if the given account exists on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-201415895

CVE-2022-20300: In Content, there is a possible way to check if the given account exists on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-200956588

CVE-2022-20301: In Content, there is a possible way to check if an account exists on the device due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-200956614

CVE-2022-20303: In ContentService, there is a possible way to determine if an account is on the device without GET_ACCOUNTS permission due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-200573021

CVE-2022-20305: In ContentService, there is a possible disclosure of available account types due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-199751623

CVE-2022-20310: In Telecomm, there is a possible disclosure of registered self managed phone accounts due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-192663798

CVE-2022-20311: In Telecomm, there is a possible disclosure of registered self managed phone accounts due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-192663553

CVE-2022-20312: In WifiP2pManager, there is a possible toobtain WiFi P2P MAC address without user consent due to missing permission check. This could lead to local information disclosure without additional execution privileges needed. User interaction is not needed forexploitationProduct: AndroidVersions: Android-13Android ID: A-192244925

CVE-2022-20315: In ActivityManager, there is a possible disclosure of installed packages due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-191058227

CVE-2022-20321: In Settings, there is a possible way for an application without permissions to read content of WiFi QR codes due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187176859

CVE-2022-20322: In PackageManager, there is a possible installed package disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187176993

CVE-2022-20323: In PackageManager, there is a possible package installation disclosure due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-187176203

CVE-2022-20326: In Telephony, there is a possible disclosure of SIM identifiers due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-185235527

CVE-2022-20327: In Wi-Fi, there is a possible way to retrieve the WiFi SSID without location permissions due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-185126813

CVE-2022-20328: In PackageManager, there is a possible way to determine whether an app is installed due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-184948501

CVE-2022-20329: In Wifi, there is a possible way to enable Wifi without permissions due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-183410556

CVE-2022-20330: In Bluetooth, there is a possible way to connect or disconnect bluetooth devices without user awareness due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-181962588

CVE-2022-20341: In ConnectivityService, there is a possible bypass of network permissions due to a missing permission check. This could lead to local information disclosure of tethering interfaces with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-162952629

CVE-2022-20348: In updateState of LocationServicesWifiScanningPreferenceController.java, there is a possible admin restriction bypass due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-228315529

CVE-2022-20349: In WifiScanningPreferenceController and BluetoothScanningPreferenceController, there is a possible admin restriction bypass due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-228315522

CVE-2022-20352: In addProviderRequestListener of LocationManagerService.java, there is a possible way to learn which packages request location information due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-222473855

CVE-2022-20358: In startSync of AbstractThreadedSyncAdapter.java, there is a possible way to access protected content of content providers due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-203229608

CVE-2022-20360: In setChecked of SecureNfcPreferenceController.java, there is a missing permission check. This could lead to local escalation of privilege from the guest user with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-228314987

CVE-2022-20394: In getInputMethodWindowVisibleHeight of InputMethodManagerService.java, there is a possible way to determine when another app is showing an IME due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-204906124

CVE-2022-20511: In getNearbyAppStreamingPolicy of DevicePolicyManagerService.java, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-235821829

CVE-2022-20547: In multiple functions of AdapterService.java, there is a possible way to manipulate Bluetooth state due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-240301753

CVE-2022-20572: In verity_target of dm-verity-target.c, there is a possible way to modify read-only files due to a missing permission check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-234475629References: Upstream kernel

CVE-2022-21748: In telephony, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is needed for exploitation. Patch ID: ALPS06511030; Issue ID: ALPS06511030.

CVE-2022-21749: In telephony, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06511058; Issue ID: ALPS06511058.

CVE-2022-2379: The Easy Student Results WordPress plugin through 2.2.8 lacks authorisation in its REST API, allowing unauthenticated users to retrieve information related to the courses, exams, departments as well as student's grades and PII such as email address, physical address, phone number etc

CVE-2022-26429: In cta, there is a possible way to write permission usage records of an app due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07025415; Issue ID: ALPS07025415.

CVE-2022-27211: A missing permission check in Jenkins Kubernetes Continuous Deploy Plugin 2.3.1 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified SSH server using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-32768: Multiple authentication bypass vulnerabilities exist in the objects id handling functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request by an authenticated user can lead to unauthorized access and takeover of resources. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the Live Schedules plugin, allowing an attacker to bypass authentication by guessing a sequential ID, allowing them to take over the another user's streams.

CVE-2022-32769: Multiple authentication bypass vulnerabilities exist in the objects id handling functionality of WWBN AVideo 11.6 and dev master commit 3f7c0364. A specially-crafted HTTP request by an authenticated user can lead to unauthorized access and takeover of resources. An attacker can send an HTTP request to trigger this vulnerability.This vulnerability exists in the Playlists plugin, allowing an attacker to bypass authentication by guessing a sequential ID, allowing them to take over the another user's playlists.

CVE-2022-3482: An improper access control issue in GitLab CE/EE affecting all versions from 11.3 prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allowed an unauthorized user to see release names even when releases we set to be restricted to project members only

CVE-2022-36856: Improper access control vulnerability in Telecom application prior to SMR Sep-2022 Release 1 allows attacker to start emergency calls via undefined permission.

CVE-2022-39081: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39082: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39083: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39084: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39085: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39086: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39087: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39088: In network service, there is a missing permission check. This could lead to local escalation of privilege with System execution privileges needed.

CVE-2022-39811: Italtel NetMatch-S CI 5.2.0-20211008 has incorrect Access Control under NMSCI-WebGui/advancedsettings.jsp and NMSCIWebGui/SaveFileUploader. By not verifying permissions for access to resources, it allows an attacker to view pages that are not allowed, and modify the system configuration, bypassing all controls (without checking for user identity).

CVE-2022-42766: In wlan driver, there is a possible missing permission check, This could lead to local information disclosure.

CVE-2022-42782: In wlan driver, there is a possible missing permission check, This could lead to local information disclosure.

CVE-2022-44421: In wlan driver, there is a possible missing permission check. This could lead to local In wlan driver, information disclosure.

CVE-2022-47324: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47325: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47326: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47327: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47328: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47329: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47330: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47332: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47333: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-47357: In log service, there is a missing permission check. This could lead to local denial of service in log service.

CVE-2022-47367: In bluetooth driver, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47450: In wlan driver, there is a possible missing permission check. This could lead to local information disclosure.

CVE-2022-1066: Aethon TUG Home Base Server versions prior to version 24 are affected by un unauthenticated attacker who can freely access hashed user credentials.

CVE-2022-1070: Aethon TUG Home Base Server versions prior to version 24 are affected by un unauthenticated attacker who can freely access hashed user credentials.

CVE-2022-20941: A vulnerability in the web-based management interface of Cisco Firepower Management Center (FMC) Software could allow an unauthenticated, remote attacker to access sensitive information. This vulnerability is due to missing authorization for certain resources in the web-based management interface together with insufficient entropy in these resource names. An attacker could exploit this vulnerability by sending a series of HTTPS requests to an affected device to enumerate resources on the device. A successful exploit could allow the attacker to retrieve sensitive information from the device.

CVE-2022-26423: Aethon TUG Home Base Server versions prior to version 24 are affected by un unauthenticated attacker who can freely access hashed user credentials.

CVE-2022-36091: XWiki Platform Web Templates are templates for XWiki Platform, a generic wiki platform. Through the suggestion feature, string and list properties of objects the user shouldn't have access to can be accessed in versions prior to 13.10.4 and 14.2. This includes private personal information like email addresses and salted password hashes of registered users but also other information stored in properties of objects. Sensitive configuration fields like passwords for LDAP or SMTP servers could be accessed. By exploiting an additional vulnerability, this issue can even be exploited on private wikis at least for string properties. The issue is patched in version 13.10.4 and 14.2. Password properties are no longer displayed and rights are checked for other properties. A workaround is available. The template file `suggest.vm` can be replaced by a patched version without upgrading or restarting XWiki unless it has been overridden, in which case the overridden template should be patched, too. This might need adjustments for older versions, though.

CVE-2021-25519: An improper access control vulnerability in CPLC prior to SMR Dec-2021 Release 1 allows local attackers to access CPLC information without permission.

CVE-2022-0203: Improper Access Control in GitHub repository crater-invoice/crater prior to 6.0.2.

CVE-2022-0726: Missing Authorization in GitHub repository chocobozzz/peertube prior to 4.1.0.

CVE-2022-0756: Missing Authorization in GitHub repository salesagility/suitecrm prior to 7.12.5.

CVE-2022-0871: Missing Authorization in GitHub repository gogs/gogs prior to 0.12.5.

CVE-2022-0905: Missing Authorization in GitHub repository go-gitea/gitea prior to 1.16.4.

CVE-2022-0932: Missing Authorization in GitHub repository saleor/saleor prior to 3.1.2.

CVE-2022-1442: The Metform WordPress plugin is vulnerable to sensitive information disclosure due to improper access control in the ~/core/forms/action.php file which can be exploited by an unauthenticated attacker to view all API keys and secrets of integrated third-party APIs like that of PayPal, Stripe, Mailchimp, Hubspot, HelpScout, reCAPTCHA and many more, in versions up to and including 2.1.3.

CVE-2022-1511: Missing Authorization in GitHub repository snipe/snipe-it prior to 5.4.4.

CVE-2022-20004: In checkSlicePermission of SliceManagerService.java, it is possible to access any slice URI due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-179699767

CVE-2022-24768: Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. All unpatched versions of Argo CD starting with 1.0.0 are vulnerable to an improper access control bug, allowing a malicious user to potentially escalate their privileges to admin-level. Versions starting with 0.8.0 and 0.5.0 contain limited versions of this issue. To perform exploits, an authorized Argo CD user must have push access to an Application's source git or Helm repository or `sync` and `override` access to an Application. Once a user has that access, different exploitation levels are possible depending on their other RBAC privileges. A patch for this vulnerability has been released in Argo CD versions 2.3.2, 2.2.8, and 2.1.14. Some mitigation measures are available but do not serve as a substitute for upgrading. To avoid privilege escalation, limit who has push access to Application source repositories or `sync` + `override` access to Applications; and limit which repositories are available in projects where users have `update` access to Applications. To avoid unauthorized resource inspection/tampering, limit who has `delete`, `get`, or `action` access to Applications.

CVE-2022-28866: Multiple Improper Access Control was discovered in Nokia AirFrame BMC Web GUI < R18 Firmware v4.13.00. It does not properly validate requests for access to (or editing of) data and functionality in all endpoints under /#settings/* and /api/settings/*. By not verifying the permissions for access to resources, it allows a potential attacker to view pages, with sensitive data, that are not allowed, and modify system configurations also causing DoS, which should be accessed only by user with administration profile, bypassing all controls (without checking for user identity).

CVE-2022-4366: Missing Authorization in GitHub repository lirantal/daloradius prior to master branch.

CVE-2022-44009: Improper access control in Key-Value RBAC in StackStorm version 3.7.0 didn't check the permissions in Jinja filters, allowing attackers to access K/V pairs of other users, potentially leading to the exposure of sensitive Information.

CVE-2022-0390: Improper access control in Gitlab CE/EE versions 12.7 to 14.5.4, 14.6 to 14.6.4, and 14.7 to 14.7.1 allowed for project non-members to retrieve issue details when it was linked to an item from the vulnerability dashboard.

CVE-2022-1423: Improper access control in the CI/CD cache mechanism in GitLab CE/EE affecting all versions starting from 1.0.2 before 14.8.6, all versions from 14.9.0 before 14.9.4, and all versions from 14.10.0 before 14.10.1 allows a malicious actor with Developer privileges to perform cache poisoning leading to arbitrary code execution in protected branches

CVE-2022-0125: An issue has been discovered in GitLab affecting all versions starting from 12.0 before 14.4.5, all versions starting from 14.5.0 before 14.5.3, all versions starting from 14.6.0 before 14.6.2. GitLab was not verifying that a maintainer of a project had the right access to import members from a target project.

CVE-2022-0579: Missing Authorization in Packagist snipe/snipe-it prior to 5.3.9. 

CVE-2022-0611: Missing Authorization in Packagist snipe/snipe-it prior to 5.3.11. 

CVE-2022-38512: The Translation module in Liferay Portal v7.4.3.12 through v7.4.3.36, and Liferay DXP 7.4 update 8 through 36 does not check permissions before allowing a user to export a web content for translation, allowing attackers to download a web content page's XLIFF translation file via crafted URL.

CVE-2022-0178: Missing Authorization vulnerability in snipe snipe/snipe-it.This issue affects snipe/snipe-i before 5.3.8. 

CVE-2022-3082: The miniOrange Discord Integration WordPress plugin before 2.1.6 does not have authorisation and CSRF in some of its AJAX actions, allowing any logged in users, such as subscriber to call them, and disable the app for example

CVE-2022-3923: The ActiveCampaign for WooCommerce WordPress plugin before 1.9.8 does not have authorisation check when cleaning up its error logs via an AJAX action, which could allow any authenticated users, such as subscriber to call it and remove error logs.

CVE-2022-21718: Electron is a framework for writing cross-platform desktop applications using JavaScript, HTML and CSS. A vulnerability in versions prior to `17.0.0-alpha.6`, `16.0.6`, `15.3.5`, `14.2.4`, and `13.6.6` allows renderers to obtain access to a bluetooth device via the web bluetooth API if the app has not configured a custom `select-bluetooth-device` event handler. This has been patched and Electron versions `17.0.0-alpha.6`, `16.0.6`, `15.3.5`, `14.2.4`, and `13.6.6` contain the fix. Code from the GitHub Security Advisory can be added to the app to work around the issue.

CVE-2022-40316: The H5P activity attempts report did not filter by groups, which in separate groups mode could reveal information to non-editing teachers about attempts/users in groups they should not have access to.

CVE-2022-2732: Missing Authorization in GitHub repository openemr/openemr prior to 7.0.0.1. 

CVE-2022-1323: The Discy WordPress theme before 5.0 lacks authorization checks then processing ajax requests to the discy_update_options action, allowing any logged in users (with privileges as low as Subscriber,) to change Theme options by sending a crafted POST request.

CVE-2021-0978: In getSerialForPackage of DeviceIdentifiersPolicyService.java, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-192587406

CVE-2021-0986: In hasGrantedPolicy of DevicePolicyManagerService.java, there is a possible information disclosure about the device owner, profile owner, or device admin due to a logic error in the code. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-192247339

CVE-2021-1037: The broadcast that DevicePickerFragment sends when a new device is paired doesn't have any permission checks, so any app can register to listen for it. This lets apps keep track of what devices are paired without requesting BLUETOOTH permissions.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-162951906

CVE-2022-20529: In multiple locations of WifiDialogActivity.java, there is a possible limited lockscreen bypass due to a logic error in the code. This could lead to local escalation of privilege in wifi settings with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-231583603

CVE-2022-36226: SiteServerCMS 5.X has a Remote-download-Getshell-vulnerability via /SiteServer/Ajax/ajaxOtherService.aspx.

CVE-2022-2370: The YaySMTP WordPress plugin before 2.2.1 does not have capability check before displaying the Mailer Credentials in JS code for the settings, allowing any authenticated users, such as subscriber to retrieve them

CVE-2022-30746: Missing caller check in Smart Things prior to version 1.7.85.12 allows attacker to access senstive information remotely using javascript interface API.

CVE-2022-0492: A vulnerability was found in the Linux kernel’s cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

CVE-2022-32560: An issue was discovered in Couchbase Server before 7.0.4. XDCR lacks role checking when changing internal settings.

CVE-2022-28993: Multi Store Inventory Management System v1.0 allows attackers to perform an account takeover via a crafted POST request.

CVE-2022-38183: In Gitea before 1.16.9, it was possible for users to add existing issues to projects. Due to improper access controls, an attacker could assign any issue to any project in Gitea (there was no permission check for fetching the issue). As a result, the attacker would get access to private issue titles.

CVE-2021-28052: A tenant administrator Hitachi Content Platform (HCP) may modify the configuration in another tenant without authorization, potentially allowing unauthorized access to data in the other tenant. Also, a tenant user (non-administrator) may view configuration in another tenant without authorization. This issue affects: Hitachi Vantara Hitachi Content Platform versions prior to 8.3.7; 9.0.0 versions prior to 9.2.3.

CVE-2021-31576: In Boa, there is a possible information disclosure due to a missing permission check. This could lead to remote information disclosure to a proximal attacker with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: A20210008; Issue ID: OSBNB00123241.

CVE-2021-32504: Unauthenticated users can access sensitive web URLs through GET request, which should be restricted to maintenance users only. A malicious attacker could use this sensitive information’s to launch further attacks on the system.

CVE-2021-42848: An information disclosure vulnerability was reported in some Lenovo Personal Cloud Storage devices that could allow an unauthenticated user to retrieve device and networking details.

CVE-2021-4331: The Plus Addons for Elementor plugin for WordPress is vulnerable to privilege escalation in versions up to, and including 4.1.9 (pro) and 2.0.6 (free). The plugin adds a registration form to the Elementor page builders functionality. As part of the registration form, users can choose which role to set as the default for users upon registration. This field is not hidden for lower-level users so any user with access to the Elementor page builder, such as contributors, can set the default role to administrator. Since contributors can not publish posts, only author+ users can elevate privileges without interaction via a site administrator (to approve a post).

CVE-2022-0152: An issue has been discovered in GitLab affecting all versions starting from 13.10 before 14.4.5, all versions starting from 14.5.0 before 14.5.3, all versions starting from 14.6.0 before 14.6.2. GitLab was vulnerable to unauthorized access to some particular fields through the GraphQL API.

CVE-2022-0236: The WP Import Export WordPress plugin (both free and premium versions) is vulnerable to unauthenticated sensitive data disclosure due to a missing capability check on the download function wpie_process_file_download found in the ~/includes/classes/class-wpie-general.php file. This made it possible for unauthenticated attackers to download any imported or exported information from a vulnerable site which can contain sensitive information like user data. This affects versions up to, and including, 3.9.15.

CVE-2022-20011: In getArray of NotificationManagerService.java , there is a possible leak of one user notifications to another due to missing check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-214999128

CVE-2022-20024: In system service, there is a possible permission bypass due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06219064; Issue ID: ALPS06219064.

CVE-2022-20041: In Bluetooth, there is a possible escalation of privilege due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06108596; Issue ID: ALPS06108596.

CVE-2022-20043: In Bluetooth, there is a possible escalation of privilege due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06148177; Issue ID: ALPS06148177.

CVE-2022-20084: In telephony, there is a possible way to disable receiving emergency broadcasts due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06498874; Issue ID: ALPS06498874.

CVE-2022-20093: In telephony, there is a possible way to disable receiving SMS messages due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06498868; Issue ID: ALPS06498868.

CVE-2022-20098: In aee daemon, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06419017; Issue ID: ALPS06419017.

CVE-2022-20100: In aee daemon, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06383944; Issue ID: ALPS06270804.

CVE-2022-20102: In aee daemon, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06296442; Issue ID: ALPS06296405.

CVE-2022-20115: In broadcastServiceStateChanged of TelephonyRegistry.java, there is a possible way to learn base station information without location permission due to a missing permission check. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-210118427

CVE-2022-20121: In getNodeValue of USCCDMPlugin.java, there is a possible disclosure of ICCID due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-212573046References: N/A

CVE-2022-20225: In getSubscriptionProperty of SubscriptionController.java, there is a possible read of a sensitive identifier due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-213457638

CVE-2022-20335: In Wifi Slice, there is a possible way to adjust Wi-Fi settings even when the permission has been disabled due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-178014725

CVE-2022-20336: In Settings, there is a possible installed application disclosure due to a missing permission check. This could lead to local information disclosure of applications allow-listed to use the network during VPN lockdown mode with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-177239688

CVE-2022-20340: In SELinux policy, there is a possible way of inferring which websites are being opened in the browser due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-166269532

CVE-2022-20430: There is an missing authorization issue in the system service. Since the component does not have permission check , resulting in Local Elevation of privilege.Product: AndroidVersions: Android SoCAndroid ID: A-242221233

CVE-2022-20431: There is an missing authorization issue in the system service. Since the component does not have permission check , resulting in Local Elevation of privilege.Product: AndroidVersions: Android SoCAndroid ID: A-242221238

CVE-2022-20432: There is an missing authorization issue in the system service. Since the component does not have permission check and permission protection,, resulting in Local Elevation of privilege.Product: AndroidVersions: Android SoCAndroid ID: A-242221899

CVE-2022-20433: There is an missing authorization issue in the system service. Since the component does not have permission check , resulting in Local Elevation of privilege.Product: AndroidVersions: Android SoCAndroid ID: A-242221901

CVE-2022-20434: There is an missing authorization issue in the system service. Since the component does not have permission check , resulting in Local Elevation of privilege.Product: AndroidVersions: Android SoCAndroid ID: A-242244028

CVE-2022-20446: In AlwaysOnHotwordDetector of AlwaysOnHotwordDetector.java, there is a possible way to access the microphone from the background due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11Android ID: A-229793943

CVE-2022-20450: In restorePermissionState of PermissionManagerServiceImpl.java, there is a possible way to bypass user consent due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-210065877

CVE-2022-20451: In onCallRedirectionComplete of CallsManager.java, there is a possible permissions bypass due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-235098883

CVE-2022-20503: In onCreate of WifiDppConfiguratorActivity.java, there is a possible way for a guest user to add a WiFi configuration due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-224772890

CVE-2022-20504: In multiple locations of DreamManagerService.java, there is a missing permission check. This could lead to local escalation of privilege and dismissal of system dialogs with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-225878553

CVE-2022-20506: In onCreate of WifiDialogActivity.java, there is a missing permission check. This could lead to local escalation of privilege from a guest user with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-226133034

CVE-2022-20519: In onCreate of AddAppNetworksActivity.java, there is a possible way for a guest user to configure WiFi networks due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-224772678

CVE-2022-20522: In getSlice of ProviderModelSlice.java, there is a missing permission check. This could lead to local escalation of privilege from the guest user with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-227470877

CVE-2022-20533: In getSlice of WifiSlice.java, there is a possible way to connect a new WiFi network from the guest mode due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-232798363

CVE-2022-20536: In registerBroadcastReceiver of RcsService.java, there is a possible way to change preferred TTY mode due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-235100180

CVE-2022-20537: In createDialog of WifiScanModeActivity.java, there is a possible way for a Guest user to enable location-sensitive settings due to a missing permission check. This could lead to local escalation of privilege from the Guest user with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-235601169

CVE-2022-20544: In onOptionsItemSelected of ManageApplications.java, there is a possible bypass of profile owner restrictions due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-238745070

CVE-2022-20556: In launchConfigNewNetworkFragment of NetworkProviderSettings.java, there is a possible way for the guest user to add a new WiFi network due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-246301667

CVE-2022-20614: A missing permission check in Jenkins Mailer Plugin 391.ve4a_38c1b_cf4b_ and earlier allows attackers with Overall/Read access to use the DNS used by the Jenkins instance to resolve an attacker-specified hostname.

CVE-2022-20616: Jenkins Credentials Binding Plugin 1.27 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Overall/Read access to validate if a credential ID refers to a secret file credential and whether it's a zip file.

CVE-2022-20618: A missing permission check in Jenkins Bitbucket Branch Source Plugin 737.vdf9dc06105be and earlier allows attackers with Overall/Read access to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-20620: Missing permission checks in Jenkins SSH Agent Plugin 1.23 and earlier allows attackers with Overall/Read access to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-21660: Gin-vue-admin is a backstage management system based on vue and gin. In versions prior to 2.4.7 low privilege users are able to modify higher privilege users. Authentication is missing on the `setUserInfo` function. Users are advised to update as soon as possible. There are no known workarounds.

CVE-2022-21763: In telecom service, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07044717; Issue ID: ALPS07044708.

CVE-2022-21764: In telecom service, there is a possible information disclosure due to a missing permission check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07044717; Issue ID: ALPS07044717.

CVE-2022-21777: In Autoboot, there is a possible permission bypass due to a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06713894; Issue ID: ALPS06713894.

CVE-2022-21953: A Missing Authorization vulnerability in of SUSE Rancher allows authenticated user to create an unauthorized shell pod and kubectl access in the local cluster This issue affects: SUSE Rancher Rancher versions prior to 2.5.17; Rancher versions prior to 2.6.10; Rancher versions prior to 2.7.1.

CVE-2022-22107: In Daybyday CRM, versions 2.0.0 through 2.2.0 are vulnerable to Missing Authorization. An attacker that has the lowest privileges account (employee type user), can view the appointments of all users in the system including administrators. However, this type of user is not authorized to view the calendar at all.

CVE-2022-22108: In Daybyday CRM, versions 2.0.0 through 2.2.0 are vulnerable to Missing Authorization. An attacker that has the lowest privileges account (employee type user), can view the absences of all users in the system including administrators. This type of user is not authorized to view this kind of information.

CVE-2022-22111: In DayByDay CRM, version 2.2.0 is vulnerable to missing authorization. Any application user in the application who has update user permission enabled is able to change the password of other users, including the administrator’s. This allows the attacker to gain access to the highest privileged user in the application.

CVE-2022-22535: SAP ERP HCM Portugal - versions 600, 604, 608, does not perform necessary authorization checks for a report that reads the payroll data of employees in a certain area. Since the affected report only reads the payroll information, the attacker can neither modify any information nor cause availability impacts.

CVE-2022-2276: The WP Edit Menu WordPress plugin before 1.5.0 does not have authorisation and CSRF in an AJAX action, which could allow unauthenticated attackers to delete arbitrary posts/pages from the blog

CVE-2022-23055: In ERPNext, versions v11.0.0-beta through v13.0.2 are vulnerable to Missing Authorization, in the chat rooms functionality. A low privileged attacker can send a direct message or a group message to any member or group, impersonating themselves as the administrator. The attacker can also read chat messages of groups that they do not belong to, and of other users.

CVE-2022-23112: A missing permission check in Jenkins Publish Over SSH Plugin 1.22 and earlier allows attackers with Overall/Read access to connect to an attacker-specified SSH server using attacker-specified credentials.

CVE-2022-23183: Missing authorization vulnerability in Advanced Custom Fields versions prior to 5.12.1 and Advanced Custom Fields Pro versions prior to 5.12.1 allows a remote authenticated attacker to view the information on the database without the access permission.

CVE-2022-2350: The Disable User Login WordPress plugin through 1.0.1 does not have authorisation and CSRF checks when updating its settings, allowing unauthenticated attackers to block (or unblock) users at will.

CVE-2022-23617: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In affected versions any user with edit right can copy the content of a page it does not have access to by using it as template of a new page. This issue has been patched in XWiki 13.2CR1 and 12.10.6. Users are advised to update. There are no known workarounds for this issue.

CVE-2022-2369: The YaySMTP WordPress plugin before 2.2.1 does not have capability check in an AJAX action, allowing any logged in users, such as subscriber to view the Logs of the plugin

CVE-2022-23709: A flaw was discovered in Kibana in which users with Read access to the Uptime feature could modify alerting rules. A user with this privilege would be able to create new alerting rules or overwrite existing ones. However, any new or modified rules would not be enabled, and a user with this privilege could not modify alerting connectors. This effectively means that Read users could disable existing alerting rules.

CVE-2022-2373: The Simply Schedule Appointments WordPress plugin before 1.5.7.7 is missing authorisation in a REST endpoint, allowing unauthenticated users to retrieve WordPress users details such as name and email address

CVE-2022-2376: The Directorist WordPress plugin before 7.3.1 discloses the email address of all users in an AJAX action available to both unauthenticated and any authenticated users

CVE-2022-2377: The Directorist WordPress plugin before 7.3.0 does not have authorisation and CSRF checks in an AJAX action, allowing any authenticated users to send arbitrary emails on behalf of the blog

CVE-2022-2382: The Product Slider for WooCommerce WordPress plugin before 2.5.7 has flawed CSRF checks and lack authorisation in some of its AJAX actions, allowing any authenticated users, such as subscriber to call them. One in particular could allow them to delete arbitrary blog options.

CVE-2022-2389: The Abandoned Cart Recovery for WooCommerce, Follow Up Emails, Newsletter Builder & Marketing Automation By Autonami WordPress plugin before 2.1.2 does not have authorisation and CSRF checks in one of its AJAX action, allowing any authenticated users, such as subscriber to create automations

CVE-2022-2405: The WP Popup Builder WordPress plugin before 1.2.9 does not have authorisation and CSRF check in an AJAX action, allowing any authenticated users, such as subscribers to delete arbitrary Popup

CVE-2022-24190: The /device/acceptBind end-point for Ourphoto App version 1.4.1 does not require authentication or authorization. The user_token header is not implemented or present on this end-point. An attacker can send a request to bind their account to any users picture frame, then send a POST request to accept their own bind request, without the end-users approval or interaction.

CVE-2022-24317: A CWE-862: Missing Authorization vulnerability exists that could cause information exposure when an attacker sends a specific message. Affected Product: Interactive Graphical SCADA System Data Server (V15.0.0.22020 and prior)

CVE-2022-2450: The reSmush.it : the only free Image Optimizer & compress plugin WordPress plugin before 0.4.4 lacks authorization in various AJAX actions, allowing any logged-in users, such as subscribers to call them.

CVE-2022-24669: It may be possible to gain some details of the deployment through a well-crafted attack. This may allow that data to be used to probe internal network services.

CVE-2022-24896: Tuleap is a Free & Open Source Suite to manage software developments and collaboration. In versions prior to 13.7.99.239 Tuleap does not properly verify authorizations when displaying the content of tracker report renderer and chart widgets. Malicious users could use this vulnerability to retrieve the name of a tracker they cannot access as well as the name of the fields used in reports.

CVE-2022-25190: A missing permission check in Jenkins Conjur Secrets Plugin 1.0.11 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-25193: Missing permission checks in Jenkins Snow Commander Plugin 1.10 and earlier allow attackers with Overall/Read permission to connect to an attacker-specified webserver using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-25195: A missing permission check in Jenkins autonomiq Plugin 1.15 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials.

CVE-2022-25199: A missing permission check in Jenkins SCP publisher Plugin 1.8 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified SSH server using attacker-specified credentials.

CVE-2022-25201: Missing permission checks in Jenkins Checkmarx Plugin 2022.1.2 and earlier allow attackers with Overall/Read permission to connect to an attacker-specified webserver using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-25206: A missing check in Jenkins dbCharts Plugin 0.5.2 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified database via JDBC using attacker-specified credentials.

CVE-2022-25208: A missing permission check in Jenkins Chef Sinatra Plugin 1.20 and earlier allows attackers with Overall/Read permission to have Jenkins send an HTTP request to an attacker-controlled URL and have it parse an XML response.

CVE-2022-25211: A missing permission check in Jenkins SWAMP Plugin 1.2.6 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified web server using attacker-specified credentials.

CVE-2022-2543: The Visual Portfolio, Photo Gallery & Post Grid WordPress plugin before 2.18.0 does not have proper authorisation checks in some of its REST endpoints, allowing unauthenticated users to call them and inject arbitrary CSS in arbitrary saved layouts

CVE-2022-25810: The Transposh WordPress Translation WordPress plugin through 1.0.8 exposes a couple of sensitive actions such has “tp_reset” under the Utilities tab (/wp-admin/admin.php?page=tp_utils), which can be used/executed as the lowest-privileged user. Basically all Utilities functionalities are vulnerable this way, which involves resetting configurations and backup/restore operations.

CVE-2022-26102: Due to missing authorization check, SAP NetWeaver Application Server for ABAP - versions 700, 701, 702, 731, allows an authenticated attacker, to access content on the start screen of any transaction that is available with in the same SAP system even if he/she isn't authorized for that transaction. A successful exploitation could expose information and in worst case manipulate data before the start screen is executed, resulting in limited impact on confidentiality and integrity of the application.

CVE-2022-26104: SAP Financial Consolidation - version 10.1, does not perform necessary authorization checks for updating homepage messages, resulting for an unauthorized user to alter the maintenance system message.

CVE-2022-26546: Hospital Management System v1.0 was discovered to lack an authorization component, allowing attackers to access sensitive information and obtain the admin password.

CVE-2022-2696: The Restaurant Menu – Food Ordering System – Table Reservation plugin for WordPress is vulnerable to authorization bypass via several AJAX actions in versions up to, and including 2.3.0 due to missing capability checks and missing nonce validation. This makes it possible for authenticated attackers with minimal permissions to perform a wide variety of actions such as modifying the plugin's settings and modifying the ordering system preferences.

CVE-2022-27199: A missing permission check in Jenkins CloudBees AWS Credentials Plugin 189.v3551d5642995 and earlier allows attackers with Overall/Read permission to connect to an AWS service using an attacker-specified token.

CVE-2022-27205: A missing permission check in Jenkins Extended Choice Parameter Plugin 346.vd87693c5a_86c and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL.

CVE-2022-27209: A missing permission check in Jenkins Kubernetes Continuous Deploy Plugin 2.3.1 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-27215: A missing permission check in Jenkins Release Helper Plugin 1.3.3 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials.

CVE-2022-27658: Under certain conditions, SAP Innovation management - version 2.0, allows an attacker to access information which could lead to information gathering for further exploits and attacks.

CVE-2022-27669: An unauthenticated user can use functions of XML Data Archiving Service of SAP NetWeaver Application Server for Java - version 7.50, to which access should be restricted. This may result in an escalation of privileges.

CVE-2022-28134: Jenkins Bitbucket Server Integration Plugin 3.1.0 and earlier does not perform permission checks in several HTTP endpoints, allowing attackers with Overall/Read permission to create, view, and delete BitBucket Server consumers.

CVE-2022-28137: A missing permission check in Jenkins JiraTestResultReporter Plugin 165.v817928553942 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials.

CVE-2022-28139: A missing permission check in Jenkins RocketChat Notifier Plugin 1.4.10 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials.

CVE-2022-28144: Jenkins Proxmox Plugin 0.7.0 and earlier does not perform a permission check in several HTTP endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified host using attacker-specified username and password (perform a connection test), disable SSL/TLS validation for the entire Jenkins controller JVM as part of the connection test (see CVE-2022-28142), and test a rollback with attacker-specified parameters.

CVE-2022-28147: A missing permission check in Jenkins Continuous Integration with Toad Edge Plugin 2.3 and earlier allows attackers with Overall/Read permission to check for the existence of an attacker-specified file path on the Jenkins controller file system.

CVE-2022-28151: A missing permission check in Jenkins Job and Node ownership Plugin 0.13.0 and earlier allows attackers with Item/Read permission to change the owners and item-specific permissions of a job.

CVE-2022-28158: A missing permission check in Jenkins Pipeline: Phoenix AutoTest Plugin 1.3 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-29051: Missing permission checks in Jenkins Publish Over FTP Plugin 1.16 and earlier allow attackers with Overall/Read permission to connect to an FTP server using attacker-specified credentials.

CVE-2022-29611: SAP NetWeaver Application Server for ABAP and ABAP Platform do not perform necessary authorization checks for an authenticated user, resulting in escalation of privileges.

CVE-2022-2985: In music service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.

CVE-2022-2987: The Ldap WP Login / Active Directory Integration WordPress plugin before 3.0.2 does not have any authorisation and CSRF checks when updating it's settings (which are hooked to the init action), allowing unauthenticated attackers to update them. Attackers could set their own LDAP server to be used to authenticated users, therefore bypassing the current authentication

CVE-2022-30951: Jenkins WMI Windows Agents Plugin 1.8 and earlier includes the Windows Remote Command library does not implement access control, potentially allowing users to start processes even if they're not allowed to log in.

CVE-2022-30954: Jenkins Blue Ocean Plugin 1.25.3 and earlier does not perform a permission check in several HTTP endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified HTTP server.

CVE-2022-30955: Jenkins GitLab Plugin 1.5.31 and earlier does not perform a permission check in an HTTP endpoint, allowing attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-30957: A missing permission check in Jenkins SSH Plugin 2.6.1 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-31128: Tuleap is a Free & Open Source Suite to improve management of software developments and collaboration. In affected versions Tuleap does not properly verify permissions when creating branches with the REST API in Git repositories using the fine grained permissions. Users can create branches via the REST endpoint `POST git/:id/branches` regardless of the permissions set on the repository. This issue has been fixed in version 13.10.99.82 Tuleap Community Edition as well as in version 13.10-3 of Tuleap Enterprise Edition. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-31167: XWiki Platform Security Parent POM contains the security APIs for XWiki Platform, a generic wiki platform. Starting with version 5.0 and prior to 12.10.11, 13.10.1, and 13.4.6, a bug in the security cache stores rules associated to document Page1.Page2 and space Page1.Page2 in the same cache entry. That means that it's possible to overwrite the rights of a space or a document by creating the page of the space with the same name and checking the right of the new one first so that they end up in the security cache and are used for the other too. The problem has been patched in XWiki 12.10.11, 13.10.1, and 13.4.6. There are no known workarounds.

CVE-2022-31592: The application SAP Enterprise Extension Defense Forces & Public Security - versions 605, 606, 616,617,618, 802, 803, 804, 805, 806, does not perform necessary authorization checks for an authenticated user over the network, resulting in escalation of privileges leading to a limited impact on confidentiality.

CVE-2022-31597: Within SAP S/4HANA - versions S4CORE 101, 102, 103, 104, 105, 106, SAPSCORE 127, the application business partner extension for Spain/Slovakia does not perform necessary authorization checks for a low privileged authenticated user over the network, resulting in escalation of privileges leading to low impact on confidentiality and integrity of the data.

CVE-2022-3400: The Bricks theme for WordPress is vulnerable to authorization bypass due to a missing capability check on the bricks_save_post AJAX action in versions 1.0 to 1.5.3. This makes it possible for authenticated attackers with minimal permissions, such as a subscriber, to edit any page, post, or template on the vulnerable WordPress website.

CVE-2022-34796: A missing permission check in Jenkins Deployment Dashboard Plugin 1.0.10 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-34798: Jenkins Deployment Dashboard Plugin 1.0.10 and earlier does not perform a permission check in several HTTP endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified HTTP URL using attacker-specified credentials.

CVE-2022-34810: A missing check in Jenkins RQM Plugin 2.8 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-34811: A missing permission check in Jenkins XPath Configuration Viewer Plugin 1.1.1 and earlier allows attackers with Overall/Read permission to access the XPath Configuration Viewer page.

CVE-2022-34813: A missing permission check in Jenkins XPath Configuration Viewer Plugin 1.1.1 and earlier allows attackers with Overall/Read permission to create and delete XPath expressions.

CVE-2022-34818: Jenkins Failed Job Deactivator Plugin 1.2.1 and earlier does not perform permission checks in several views and HTTP endpoints, allowing attackers with Overall/Read permission to disable jobs.

CVE-2022-3501: Article template contents with sensitive data could be accessed from agents without permissions.

CVE-2022-35247: A information disclosure vulnerability exists in Rocket.chat <v5, <v4.8.2 and <v4.7.5 where the lack of ACL checks in the getRoomRoles Meteor method leak channel members with special roles to unauthorized clients.

CVE-2022-35293: Due to insecure session management, SAP Enable Now allows an unauthenticated attacker to gain access to user's account. On successful exploitation, an attacker can view or modify user data causing limited impact on confidentiality and integrity of the application.

CVE-2022-36068: Discourse is an open source discussion platform. In versions prior to 2.8.9 on the `stable` branch and prior to 2.9.0.beta10 on the `beta` and `tests-passed` branches, a moderator can create new and edit existing themes by using the API when they should not be able to do so. The problem is patched in version 2.8.9 on the `stable` branch and version 2.9.0.beta10 on the `beta` and `tests-passed` branches. There are no known workarounds.

CVE-2022-36340: Unauthenticated Optin Campaign Cache Deletion vulnerability in MailOptin plugin <= 1.2.49.0 at WordPress.

CVE-2022-36883: A missing permission check in Jenkins Git Plugin 4.11.3 and earlier allows unauthenticated attackers to trigger builds of jobs configured to use an attacker-specified Git repository and to cause them to check out an attacker-specified commit.

CVE-2022-36888: A missing permission check in Jenkins HashiCorp Vault Plugin 354.vdb_858fd6b_f48 and earlier allows attackers with Overall/Read permission to obtain credentials stored in Vault with attacker-specified path and keys.

CVE-2022-36891: A missing permission check in Jenkins Deployer Framework Plugin 85.v1d1888e8c021 and earlier allows attackers with Item/Read permission but without Deploy Now/Deploy permission to read deployment logs.

CVE-2022-36892: Jenkins rhnpush-plugin Plugin 0.5.1 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Item/Read permission but without Item/Workspace or Item/Configure permission to check whether attacker-specified file patterns match workspace contents.

CVE-2022-36893: Jenkins rpmsign-plugin Plugin 0.5.0 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Item/Read permission but without Item/Workspace or Item/Configure permission to check whether attacker-specified file patterns match workspace contents.

CVE-2022-36895: A missing permission check in Jenkins Compuware Topaz Utilities Plugin 1.0.8 and earlier allows attackers with Overall/Read permission to enumerate hosts and ports of Compuware configurations and credentials IDs of credentials stored in Jenkins.

CVE-2022-36896: A missing permission check in Jenkins Compuware Source Code Download for Endevor, PDS, and ISPW Plugin 2.0.12 and earlier allows attackers with Overall/Read permission to enumerate hosts and ports of Compuware configurations and credentials IDs of credentials stored in Jenkins.

CVE-2022-36897: A missing permission check in Jenkins Compuware Xpediter Code Coverage Plugin 1.0.7 and earlier allows attackers with Overall/Read permission to enumerate hosts and ports of Compuware configurations and credentials IDs of credentials stored in Jenkins.

CVE-2022-36898: A missing permission check in Jenkins Compuware ISPW Operations Plugin 1.0.8 and earlier allows attackers with Overall/Read permission to enumerate hosts and ports of Compuware configurations and credentials IDs of credentials stored in Jenkins.

CVE-2022-36903: A missing permission check in Jenkins Repository Connector Plugin 2.2.0 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-36904: Jenkins Repository Connector Plugin 2.2.0 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Overall/Read permission to check for the existence of an attacker-specified file path on the Jenkins controller file system.

CVE-2022-36907: A missing permission check in Jenkins OpenShift Deployer Plugin 1.2.0 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified username and password.

CVE-2022-36909: A missing permission check in Jenkins OpenShift Deployer Plugin 1.2.0 and earlier allows attackers with Overall/Read permission to check for the existence of an attacker-specified file path on the Jenkins controller file system and to upload a SSH key file from the Jenkins controller file system to an attacker-specified URL.

CVE-2022-36910: Jenkins Lucene-Search Plugin 370.v62a5f618cd3a and earlier does not perform a permission check in several HTTP endpoints, allowing attackers with Overall/Read permission to reindex the database and to obtain information about jobs otherwise inaccessible to them.

CVE-2022-36912: A missing permission check in Jenkins Openstack Heat Plugin 1.5 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL.

CVE-2022-36913: Jenkins Openstack Heat Plugin 1.5 and earlier does not perform permission checks in methods implementing form validation, allowing attackers with Overall/Read permission to check for the existence of an attacker-specified file path on the Jenkins controller file system.

CVE-2022-36914: Jenkins Files Found Trigger Plugin 1.5 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Overall/Read permission to check for the existence of an attacker-specified file path on the Jenkins controller file system.

CVE-2022-36915: Jenkins Android Signing Plugin 2.2.5 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Item/Read permission but without Item/Workspace or Item/Configure permission to check whether attacker-specified file patterns match workspace contents.

CVE-2022-36917: A missing permission check in Jenkins Google Cloud Backup Plugin 0.6 and earlier allows attackers with Overall/Read permission to request a manual backup.

CVE-2022-36918: Jenkins Buckminster Plugin 1.1.1 and earlier does not perform a permission check in a method implementing form validation, allowing attackers with Overall/Read permission to check for the existence of an attacker-specified file path on the Jenkins controller file system.

CVE-2022-36919: A missing permission check in Jenkins Coverity Plugin 1.11.4 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-36921: A missing permission check in Jenkins Coverity Plugin 1.11.4 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-38367: The Netic User Export add-on before 2.0.6 for Atlassian Jira does not perform authorization checks. This might allow an unauthenticated user to export all users from Jira by making an HTTP request to the affected endpoint.

CVE-2022-38370: Apache IoTDB grafana-connector version 0.13.0 contains an interface without authorization, which may expose the internal structure of database. Users should upgrade to version 0.13.1 which addresses this issue.

CVE-2022-39960: The Netic Group Export add-on before 1.0.3 for Atlassian Jira does not perform authorization checks. This might allow an unauthenticated user to export all groups from the Jira instance by making a groupexport_download=true request to a plugins/servlet/groupexportforjira/admin/ URI.

CVE-2022-40673: KDiskMark before 3.1.0 lacks authorization checking for D-Bus methods such as Helper::flushPageCache.

CVE-2022-41250: A missing permission check in Jenkins SCM HttpClient Plugin 1.5 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified HTTP server using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-41251: A missing permission check in Jenkins Apprenda Plugin 2.2.0 and earlier allows users with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-41252: Missing permission checks in Jenkins CONS3RT Plugin 1.0.0 and earlier allows users with Overall/Read permission to enumerate credentials ID of credentials stored in Jenkins.

CVE-2022-41254: Missing permission checks in Jenkins CONS3RT Plugin 1.0.0 and earlier allow attackers with Overall/Read permission to connect to an attacker-specified HTTP server using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-4169: The Theme and plugin translation for Polylang is vulnerable to authorization bypass in versions up to, and including, 3.2.16 due to missing capability checks in the process_polylang_theme_translation_wp_loaded() function. This makes it possible for unauthenticated attackers to update plugin and theme translation settings and to import translation strings.

CVE-2022-41929: org.xwiki.platform:xwiki-platform-oldcore is missing authorization in User#setDisabledStatus, which may allow an incorrectly authorized user with only Script rights to enable or disable a user. This operation is meant to only be available for users with admin rights. This problem has been patched in XWiki 13.10.7, 14.4.2 and 14.5RC1.

CVE-2022-41930: org.xwiki.platform:xwiki-platform-user-profile-ui is missing authorization to enable or disable users. Any user (logged in or not) with access to the page XWiki.XWikiUserProfileSheet can enable or disable any user profile. This might allow to a disabled user to re-enable themselves, or to an attacker to disable any user of the wiki. The problem has been patched in XWiki 13.10.7, 14.5RC1 and 14.4.2. Workarounds: The problem can be patched immediately by editing the page `XWiki.XWikiUserProfileSheet` in the wiki and by performing the changes contained in https://github.com/xwiki/xwiki-platform/commit/5be1cc0adf917bf10899c47723fa451e950271fa.

CVE-2022-41937: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. The application allows anyone with view access to modify any page of the wiki by importing a crafted XAR package. The problem has been patched in XWiki 14.6RC1, 14.6 and 13.10.8. As a workaround, setting the right of the page Filter.WebHome and making sure only the main wiki administrators can view the application installed on main wiki or edit the page and apply the changed described in commit fb49b4f.

CVE-2022-43413: Jenkins Job Import Plugin 3.5 and earlier does not perform a permission check in an HTTP endpoint, allowing attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-43417: Jenkins Katalon Plugin 1.0.32 and earlier does not perform permission checks in several HTTP endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-43427: Jenkins Compuware Topaz for Total Test Plugin 2.4.8 and earlier does not perform permission checks in several HTTP endpoints, allowing attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-43431: Jenkins Compuware Strobe Measurement Plugin 1.0.1 and earlier does not perform a permission check in an HTTP endpoint, allowing attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-4501: The Mega Addons plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the vc_saving_data function in versions up to, and including, 4.2.7. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to update the plugin's settings.

CVE-2022-4555: The WP Shamsi plugin for WordPress is vulnerable to authorization bypass due to a missing capability check on the deactivate() function hooked via init() in versions up to, and including, 4.1.0. This makes it possible for unauthenticated attackers to deactivate arbitrary plugins on the site. This can be used to deactivate security plugins that aids in exploiting other vulnerabilities.

CVE-2022-4931: The BackupWordPress plugin for WordPress is vulnerable to information disclosure in versions up to, and including 3.12. This is due to missing authorization on the heartbeat_received() function that triggers on WordPress heartbeat. This makes it possible for authenticated attackers, with subscriber-level permissions and above to retrieve back-up paths that can subsequently be used to download the back-up.

CVE-2022-4932: The Total Upkeep plugin for WordPress is vulnerable to information disclosure in versions up to, and including 1.14.13. This is due to missing authorization on the heartbeat_received() function that triggers on WordPress heartbeat. This makes it possible for authenticated attackers, with subscriber-level permissions and above to retrieve back-up paths that can subsequently be used to download the back-up.

CVE-2021-36225: Western Digital My Cloud devices before OS5 allow REST API access by low-privileged accounts, as demonstrated by API commands for firmware uploads and installation.

CVE-2022-2108: The plugin Wbcom Designs – BuddyPress Group Reviews for WordPress is vulnerable to unauthorized settings changes and review modification due to missing capability checks and improper nonce checks in several functions related to said actions in versions up to, and including, 2.8.3. This makes it possible for unauthenticated attackers to modify reviews and plugin settings on the affected site.

CVE-2022-21707: wasmCloud Host Runtime is a server process that securely hosts and provides dispatch for web assembly (WASM) actors and capability providers. In versions prior to 0.52.2 actors can bypass capability authorization. Actors are normally required to declare their capabilities for inbound invocations, but with this vulnerability actor capability claims are not verified upon receiving invocations. This compromises the security model for actors as they can receive unauthorized invocations from linked capability providers. The problem has been patched in versions `0.52.2` and greater. There is no workaround and users are advised to upgrade to an unaffected version as soon as possible.

CVE-2022-24450: NATS nats-server before 2.7.2 has Incorrect Access Control. Any authenticated user can obtain the privileges of the System account by misusing the "dynamically provisioned sandbox accounts" feature.

CVE-2022-2459: An issue has been discovered in GitLab EE affecting all versions before 15.0.5, all versions starting from 15.1 before 15.1.4, all versions starting from 15.2 before 15.2.1. It may be possible for email invited members to join a project even after the Group Owner has enabled the setting to prevent members from being added to projects in a group, if the invite was sent before the setting was enabled.

CVE-2022-29906: The admin API module in the QuizGame extension for MediaWiki through 1.37.2 (before 665e33a68f6fa1167df99c0aa18ed0157cdf9f66) omits a check for the quizadmin user.

CVE-2022-30594: The Linux kernel before 5.17.2 mishandles seccomp permissions. The PTRACE_SEIZE code path allows attackers to bypass intended restrictions on setting the PT_SUSPEND_SECCOMP flag.

CVE-2022-31595: SAP Financial Consolidation - version 1010,?does not perform necessary authorization checks for an authenticated user, resulting in escalation of privileges. 

CVE-2022-39233: Tuleap is a Free & Open Source Suite to improve management of software developments and collaboration. In versions 12.9.99.228 and above, prior to 14.0.99.24, authorizations are not properly verified when updating the branch prefix used by the GitLab repository integration. Authenticated users can change the branch prefix of any of the GitLab repository integration they can see vie the REST endpoint `PATCH /gitlab_repositories/{id}`. This action should be restricted to Git administrators. This issue is patched in Tuleap Community Edition 14.0.99.24 and Tuleap Enterprise Edition 14.0-3. There are no known workarounds.

CVE-2022-39329: Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Nextcloud Server and Nextcloud Enterprise Server prior to versions 23.0.9 and 24.0.5 are vulnerable to exposure of information that cannot be controlled by administrators without direct database access. Versions 23.0.9 and 24.0.5 contains patches for this issue. No known workarounds are available.

CVE-2022-39340: OpenFGA is an authorization/permission engine. Prior to version 0.2.4, the `streamed-list-objects` endpoint was not validating the authorization header, resulting in disclosure of objects in the store. Users `openfga/openfga` versions 0.2.3 and prior who are exposing the OpenFGA service to the internet are vulnerable. Version 0.2.4 contains a patch for this issue.

CVE-2022-41230: Jenkins Build-Publisher Plugin 1.22 and earlier does not perform a permission check in an HTTP endpoint, allowing attackers with Overall/Read permission to obtain names and URLs of Jenkins servers that the plugin is configured to publish builds to, as well as builds pending for publication to those Jenkins servers.

CVE-2022-42903: Zoho ManageEngine SupportCenter Plus through 11024 allows low-privileged users to view the organization users list.

CVE-2022-45636: An issue discovered in MEGAFEIS, BOFEI DBD+ Application for IOS & Android v1.4.4 allows attacker to unlock model(s) without authorization via arbitrary API requests.

CVE-2022-48367: An issue was discovered in eZ Publish Ibexa Kernel before 7.5.28. Access control based on object state is mishandled.

CVE-2022-36836: Unprotected provider vulnerability in Charm by Samsung prior to version 1.2.3 allows attackers to read connection state without permission.

CVE-2022-38669: In soundrecorder service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.

CVE-2022-38670: In soundrecorder service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.

CVE-2022-38677: In cell service, there is a missing permission check. This could lead to local denial of service in cell service with no additional execution privileges needed.

CVE-2022-38678: In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-38679: In music service, there is a missing permission check. This could lead to local denial of service in music service with no additional execution privileges needed.

CVE-2022-38682: In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-38683: In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-38684: In contacts service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-38687: In messaging service, there is a missing permission check. This could lead to local denial of service in messaging service with no additional execution privileges needed.

CVE-2022-38688: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-38689: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-38697: In messaging service, there is a missing permission check. This could lead to access unexpected provider in contacts service with no additional execution privileges needed.

CVE-2022-38698: In messaging service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.

CVE-2022-39080: In messaging service, there is a missing permission check. This could lead to elevation of privilege in contacts service with no additional execution privileges needed.

CVE-2022-39090: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39091: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39092: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39093: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39094: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39095: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39096: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39097: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39098: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39099: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39100: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39101: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39102: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-39103: In Gallery service, there is a missing permission check. This could lead to local denial of service in Gallery service with no additional execution privileges needed.

CVE-2022-39104: In contacts service, there is a missing permission check. This could lead to local denial of service in Contacts service with no additional execution privileges needed.

CVE-2022-39107: In Soundrecorder service, there is a missing permission check. This could lead to elevation of privilege in Soundrecorder service with no additional execution privileges needed.

CVE-2022-39108: In Music service, there is a missing permission check. This could lead to elevation of privilege in Music service with no additional execution privileges needed.

CVE-2022-39109: In Music service, there is a missing permission check. This could lead to elevation of privilege in Music service with no additional execution privileges needed.

CVE-2022-39110: In Music service, there is a missing permission check. This could lead to elevation of privilege in Music service with no additional execution privileges needed.

CVE-2022-39111: In Music service, there is a missing permission check. This could lead to elevation of privilege in Music service with no additional execution privileges needed.

CVE-2022-39112: In Music service, there is a missing permission check. This could lead to local denial of service in Music service with no additional execution privileges needed.

CVE-2022-39113: In Music service, there is a missing permission check. This could lead to local denial of service in Music service with no additional execution privileges needed.

CVE-2022-39114: In Music service, there is a missing permission check. This could lead to local denial of service in Music service with no additional execution privileges needed.

CVE-2022-39115: In Music service, there is a missing permission check. This could lead to local denial of service in Music service with no additional execution privileges needed.

CVE-2022-39117: In messaging service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-39119: In network service, there is a missing permission check. This could lead to local escalation of privilege with no additional execution privileges needed

CVE-2022-3920: HashiCorp Consul and Consul Enterprise 1.13.0 up to 1.13.3 do not filter cluster filtering's imported nodes and services for HTTP or RPC endpoints used by the UI. Fixed in 1.14.0.

CVE-2022-3946: The Welcart e-Commerce WordPress plugin before 2.8.4 does not have authorisation and CSRF in an AJAX action, allowing any logged-in user to create, update and delete shipping methods.

CVE-2022-3961: The Directorist WordPress plugin before 7.4.4 does not prevent users with low privileges (like subscribers) from accessing sensitive system information.

CVE-2022-39861: Unprotected Receiver in AtBroadcastReceiver in FactoryCamera prior to version 3.5.51 allows attackers to record video without camera privilege.

CVE-2022-39975: The Layout module in Liferay Portal v7.3.3 through v7.4.3.34, and Liferay DXP 7.3 before update 10, and 7.4 before update 35 does not check user permission before showing the preview of a "Content Page" type page, allowing attackers to view unpublished "Content Page" pages via URL manipulation.

CVE-2022-3999: The DPD Baltic Shipping WordPress plugin before 1.2.57 does not have authorisation and CSRF in an AJAX action, which could allow any authenticated users, such as subscriber to delete arbitrary options from the blog, which could make the blog unavailable.

CVE-2022-4024: The Registration Forms WordPress plugin before 3.8.1.3 does not have authorisation and CSRF when deleting users via an init action handler, allowing unauthenticated attackers to delete arbitrary users (along with their posts)

CVE-2022-4103: The Royal Elementor Addons WordPress plugin before 1.3.56 does not have authorisation and CSRF checks when creating a template, and does not ensure that the post created is a template. This could allow any authenticated users, such as subscriber to create a post (as well as any post type) with an arbitrary title

CVE-2022-41228: A missing permission check in Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.129 and earlier allows attackers with Overall/Read permissions to connect to an attacker-specified webserver using attacker-specified credentials.

CVE-2022-41233: Jenkins Rundeck Plugin 3.6.11 and earlier does not perform Run/Artifacts permission checks in multiple HTTP endpoints, allowing attackers with Item/Read permission to obtain information about build artifacts of a given job, if the optional Run/Artifacts permission is enabled.

CVE-2022-41234: Jenkins Rundeck Plugin 3.6.11 and earlier does not protect access to the /plugin/rundeck/webhook/ endpoint, allowing users with Overall/Read permission to trigger jobs that are configured to be triggerable via Rundeck.

CVE-2022-41238: A missing permission check in Jenkins DotCi Plugin 2.40.00 and earlier allows unauthenticated attackers to trigger builds of jobs corresponding to the attacker-specified repository for attacker-specified commits.

CVE-2022-4124: The Popup Manager WordPress plugin through 1.6.6 does not have authorisation and CSRF checks when deleting popups, which could allow unauthenticated users to delete them

CVE-2022-41242: A missing permission check in Jenkins extreme-feedback Plugin 1.7 and earlier allows attackers with Overall/Read permission to discover information about job names attached to lamps, discover MAC and IP addresses of existing lamps, and rename lamps.

CVE-2022-41246: A missing permission check in Jenkins Worksoft Execution Manager Plugin 10.0.3.503 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-41692: Missing Authorization vulnerability in Appointment Hour Booking plugin <= 1.3.71 on WordPress.

CVE-2022-42488: OpenHarmony-v3.1.2 and prior versions have a Missing permission validation vulnerability in param service of startup subsystem. An malicious application installed on the device could elevate its privileges to the root user, disable security features, or cause DoS by disabling particular services.

CVE-2022-42776: In UscAIEngine service, there is a missing permission check. This could lead to set up UscAIEngine service with no additional execution privileges needed.

CVE-2022-42777: In power management service, there is a missing permission check. This could lead to set up power management service with no additional execution privileges needed.

CVE-2022-42778: In windows manager service, there is a missing permission check. This could lead to set up windows manager service with no additional execution privileges needed.

CVE-2022-43482: Missing Authorization vulnerability in Appointment Booking Calendar plugin <= 1.3.69 on WordPress.

CVE-2022-4384: The Stream WordPress plugin before 3.9.2 does not prevent users with little privileges on the site (like subscribers) from using its alert creation functionality, which may enable them to leak sensitive information.

CVE-2022-4385: The Intuitive Custom Post Order WordPress plugin before 3.1.4 does not check for authorization in the update-menu-order ajax action, allowing any logged in user (with roles as low as Subscriber) to update the menu order

CVE-2022-44422: In music service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44423: In music service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44424: In music service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44434: In messaging service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44435: In messaging service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44436: In messaging service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44437: In messaging service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44438: In messaging service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-44439: In messaging service, there is a missing permission check. This could lead to local denial of service in contacts service with no additional execution privileges needed.

CVE-2022-45385: A missing permission check in Jenkins CloudBees Docker Hub/Registry Notification Plugin 2.6.2 and earlier allows unauthenticated attackers to trigger builds of jobs corresponding to the attacker-specified repository.

CVE-2022-45389: A missing permission check in Jenkins XP-Dev Plugin 1.0 and earlier allows unauthenticated attackers to trigger builds of jobs corresponding to an attacker-specified repository.

CVE-2022-45390: A missing permission check in Jenkins loader.io Plugin 1.0.1 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-45394: A missing permission check in Jenkins Delete log Plugin 1.0 and earlier allows attackers with Item/Read permission to delete build logs.

CVE-2022-45399: A missing permission check in Jenkins Cluster Statistics Plugin 0.4.6 and earlier allows attackers to delete recorded Jenkins Cluster Statistics.

CVE-2022-47341: In engineermode services, there is a missing permission check. This could lead to local escalation of privilege with system execution privileges needed.

CVE-2022-47358: In log service, there is a missing permission check. This could lead to local denial of service in log service.

CVE-2022-47361: In firewall service, there is a missing permission check. This could lead to local escalation of privilege with system execution privileges needed.

CVE-2022-47461: In telephone service, there is a missing permission check. This could lead to local escalation of privilege with system execution privileges needed.

CVE-2022-47462: In telephone service, there is a missing permission check. This could lead to local escalation of privilege with system execution privileges needed.

CVE-2022-47471: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47472: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47473: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47474: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47475: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47476: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47477: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47478: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47479: In telephony service, there is a missing permission check. This could lead to local information disclosure with no additional execution privileges needed.

CVE-2022-47480: In telephony service, there is a missing permission check. This could lead to local denial of service in telephone service with no additional execution privileges needed.

CVE-2022-47481: In telephony service, there is a missing permission check. This could lead to local denial of service in telephone service with no additional execution privileges needed.

CVE-2022-47482: In telephony service, there is a missing permission check. This could lead to local denial of service in telephone service with no additional execution privileges needed.

CVE-2022-47483: In telephony service, there is a missing permission check. This could lead to local denial of service in telephone service with no additional execution privileges needed.

CVE-2022-47484: In telephony service, there is a missing permission check. This could lead to local denial of service in telephone service with no additional execution privileges needed.

CVE-2022-48318: No authorisation controls in the RestAPI documentation for Tribe29's Checkmk <= 2.1.0p13 and Checkmk <= 2.0.0p29 which may lead to unintended information disclosure through automatically generated user specific tags within Rest API documentation.

CVE-2022-4872: The Chained Products WordPress plugin before 2.12.0 does not have authorisation and CSRF checks, as well as does not ensure that the option to be updated belong to the plugin, allowing unauthenticated attackers to set arbitrary options to 'no'

CVE-2022-0404: The Material Design for Contact Form 7 WordPress plugin through 2.6.4 does not check authorization or that the option mentioned in the notice param belongs to the plugin when processing requests to the cf7md_dismiss_notice action, allowing any logged in user (with roles as low as Subscriber) to set arbitrary options to true, potentially leading to Denial of Service by breaking the site.

CVE-2022-0837: The Amelia WordPress plugin before 1.0.48 does not have proper authorisation when handling Amelia SMS service, allowing any customer to send paid test SMS notification as well as retrieve sensitive information about the admin, such as the email, account balance and payment history. A malicious actor can abuse this vulnerability to drain out the account balance by keep sending SMS notification.

CVE-2022-25342: An issue was discovered on Olivetti d-COLOR MF3555 2XD_S000.002.271 devices. The Web Application is affected by Broken Access Control. It does not properly validate requests for access to data and functionality under the /mngset/authset path. By not verifying permissions for access to resources, it allows a potential attacker to view pages that are not allowed.

CVE-2022-33913: In Mahara 21.04 before 21.04.6, 21.10 before 21.10.4, and 22.04.2, files can sometimes be downloaded through thumb.php with no permission check.

CVE-2022-30959: A missing permission check in Jenkins SSH Plugin 2.6.1 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified SSH server using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-3096: The WP Total Hacks WordPress plugin through 4.7.2 does not prevent low privilege users from modifying the plugin's settings. This could allow users such as subscribers to perform Stored Cross-Site Scripting attacks against other users, like administrators, due to the lack of sanitisation and escaping as well.

CVE-2022-31752: Missing authorization vulnerability in the system components. Successful exploitation of this vulnerability will affect confidentiality.

CVE-2022-31765: Affected devices do not properly authorize the change password function of the web interface. This could allow low privileged users to escalate their privileges.

CVE-2022-3244: The Import all XML, CSV & TXT WordPress plugin before 6.5.8 does not have authorisation in some places, which could allow any authenticated users to access some of the plugin features if they manage to get the related nonce

CVE-2022-32966: RTL8168FP-CG Dash remote management function has missing authorization. An unauthenticated attacker within the adjacent network can connect to DASH service port to disrupt service.

CVE-2022-3320: It was possible to bypass policies configured for Zero Trust Secure Web Gateway by using warp-cli 'set-custom-endpoint' subcommand. Using this command with an unreachable endpoint caused the WARP Client to disconnect and allowed bypassing administrative restrictions on a Zero Trust enrolled endpoint. 

CVE-2022-3321: It was possible to bypass Lock WARP switch feature https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/warp-settings/#lock-warp-switch on the WARP iOS mobile client by enabling both "Disable for cellular networks" and "Disable for Wi-Fi networks" switches at once in the application settings. Such configuration caused the WARP client to disconnect and allowed the user to bypass restrictions and policies enforced by the Zero Trust platform.

CVE-2022-3337: It was possible for a user to delete a VPN profile from WARP mobile client on iOS platform despite the Lock WARP switch https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/warp-settings/#lock-warp-switch feature being enabled on Zero Trust Platform. This led to bypassing policies and restrictions enforced for enrolled devices by the Zero Trust platform. 

CVE-2022-34201: A missing permission check in Jenkins Convertigo Mobile Platform Plugin 1.1 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL.

CVE-2022-34204: A missing permission check in Jenkins EasyQA Plugin 1.0 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified HTTP server.

CVE-2022-34206: A missing permission check in Jenkins Jianliao Notification Plugin 1.1 and earlier allows attackers with Overall/Read permission to send HTTP POST requests to an attacker-specified URL.

CVE-2022-34208: A missing permission check in Jenkins Beaker builder Plugin 1.10 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL.

CVE-2022-34210: A missing permission check in Jenkins ThreadFix Plugin 1.5.4 and earlier allows attackers with Overall/Read permission to connect to an attacker-specified URL.

CVE-2022-34212: A missing permission check in Jenkins vRealize Orchestrator Plugin 3.0 and earlier allows attackers with Overall/Read permission to send an HTTP POST request to an attacker-specified URL.

CVE-2022-34779: A missing permission check in Jenkins XebiaLabs XL Release Plugin 22.0.0 and earlier allows attackers with Overall/Read permission to enumerate credentials IDs of credentials stored in Jenkins.

CVE-2022-34781: Missing permission checks in Jenkins XebiaLabs XL Release Plugin 22.0.0 and earlier allow attackers with Overall/Read permission to connect to an attacker-specified HTTP server using attacker-specified credentials IDs obtained through another method, capturing credentials stored in Jenkins.

CVE-2022-34785: Jenkins build-metrics Plugin 1.3 and earlier does not perform permission checks in multiple HTTP endpoints, allowing attackers with Overall/Read permission to obtain information about jobs otherwise inaccessible to them.

CVE-2022-34794: Missing permission checks in Jenkins Recipe Plugin 1.2 and earlier allow attackers with Overall/Read permission to send an HTTP request to an attacker-specified URL and parse the response as XML.

CVE-2022-0885: The Member Hero WordPress plugin through 1.0.9 lacks authorization checks, and does not validate the a request parameter in an AJAX action, allowing unauthenticated users to call arbitrary PHP functions with no arguments.

CVE-2022-23642: Sourcegraph is a code search and navigation engine. Sourcegraph prior to version 3.37 is vulnerable to remote code execution in the `gitserver` service. The service acts as a git exec proxy, and fails to properly restrict calling `git config`. This allows an attacker to set the git `core.sshCommand` option, which sets git to use the specified command instead of ssh when they need to connect to a remote system. Exploitation of this vulnerability depends on how Sourcegraph is deployed. An attacker able to make HTTP requests to internal services like gitserver is able to exploit it. This issue is patched in Sourcegraph version 3.37. As a workaround, ensure that requests to gitserver are properly protected.

CVE-2022-4223: The pgAdmin server includes an HTTP API that is intended to be used to validate the path a user selects to external PostgreSQL utilities such as pg_dump and pg_restore. The utility is executed by the server to determine what PostgreSQL version it is from. Versions of pgAdmin prior to 6.17 failed to properly secure this API, which could allow an unauthenticated user to call it with a path of their choosing, such as a UNC path to a server they control on a Windows machine. This would cause an appropriately named executable in the target path to be executed by the pgAdmin server.

CVE-2022-41417: BlogEngine.NET v3.3.8.0 allows an attacker to create any folder with "files" prefix under ~/App_Data/.

CVE-2022-0287: The myCred WordPress plugin before 2.4.4.1 does not have any authorisation in place in its mycred-tools-select-user AJAX action, allowing any authenticated user, such as subscriber to call and retrieve all email addresses from the blog

CVE-2022-0588: Missing Authorization in Packagist librenms/librenms prior to 22.2.0. 

CVE-2022-31095: discourse-chat is a chat plugin for the Discourse application. Versions prior to 0.4 are vulnerable to an exposure of sensitive information, where an attacker who knows the message ID for a channel they do not have access to can view that message using the chat message lookup endpoint, primarily affecting direct message channels. There are no known workarounds for this issue, and users are advised to update the plugin.

CVE-2022-32220: An information disclosure vulnerability exists in Rocket.Chat <v5 due to the getUserMentionsByChannel meteor server method discloses messages from private channels and direct messages regardless of the users access permission to the room.

CVE-2022-35249: A information disclosure vulnerability exists in Rocket.Chat <v5 where the getUserMentionsByChannel meteor server method discloses messages from private channels and direct messages regardless of the users access permission to the room.

CVE-2022-39222: Dex is an identity service that uses OpenID Connect to drive authentication for other apps. Dex instances with public clients (and by extension, clients accepting tokens issued by those Dex instances) are affected by this vulnerability if they are running a version prior to 2.35.0. An attacker can exploit this vulnerability by making a victim navigate to a malicious website and guiding them through the OIDC flow, stealing the OAuth authorization code in the process. The authorization code then can be exchanged by the attacker for a token, gaining access to applications accepting that token. Version 2.35.0 has introduced a fix for this issue. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-39289: ZoneMinder is a free, open source Closed-circuit television software application. In affected versions the ZoneMinder API Exposes Database Log contents to user without privileges, allows insertion, modification, deletion of logs without System Privileges. Users are advised yo upgrade as soon as possible. Users unable to upgrade should disable database logging.

CVE-2022-46158: PrestaShop is an open-source e-commerce solution. Versions prior to 1.7.8.8 did not properly restrict host filesystem access for users. Users may have been able to view the contents of the upload directory without appropriate permissions. This issue has been addressed and users are advised to upgrade to version 1.7.8.8. There are no known workarounds for this issue.

# CWE-863 Incorrect Authorization

## Description

The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check. This allows attackers to bypass intended access restrictions.

Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-control specifications that apply to the resource.


When access control checks are incorrectly applied, users are able to access data or perform actions that they should not be allowed to perform. This can lead to a wide range of problems, including information exposures, denial of service, and arbitrary code execution.

An access control list (ACL) represents who/what has permissions to a given object. Different operating systems implement (ACLs) in different ways. In UNIX, there are three types of permissions: read, write, and execute. Users are divided into three classes for file access: owner, group owner, and all other users where each class has a separate set of rights. In Windows NT, there are four basic types of permissions for files: "No access", "Read access", "Change access", and "Full control". Windows NT extends the concept of three types of users in UNIX to include a list of users and groups along with their associated permissions. A user can create an object (file) and assign specified permissions to that object.

## Observed Examples

CVE-2021-39155: Chain: A microservice integration and management platform compares the hostname in the HTTP Host header in a case-sensitive way (CWE-178, CWE-1289), allowing bypass of the authorization policy (CWE-863) using a hostname with mixed case or other variations.

CVE-2019-15900: Chain: sscanf() call is used to check if a username and group exists, but the return value of sscanf() call is not checked (CWE-252), causing an uninitialized variable to be checked (CWE-457), returning success to allow authorization bypass for executing a privileged (CWE-863).

CVE-2009-2213: Gateway uses default "Allow" configuration for its authorization settings.

CVE-2009-0034: Chain: product does not properly interpret a configuration option for a system group, allowing users to gain privileges.

CVE-2008-6123: Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect.

CVE-2008-7109: Chain: reliance on client-side security (CWE-602) allows attackers to bypass authorization using a custom client.

CVE-2008-3424: Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.

CVE-2008-4577: ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.

CVE-2006-6679: Product relies on the X-Forwarded-For HTTP header for authorization, allowing unintended access by spoofing the header.

CVE-2005-2801: Chain: file-system code performs an incorrect comparison (CWE-697), preventing default ACLs from being properly applied.

CVE-2001-1155: Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence (CWE-783), allowing bypass of DNS-based access restrictions.

## Top 25 Examples

CVE-2022-30308: In Festo Controller CECC-X-M1 product family in multiple versions, the http-endpoint "cecc-x-web-viewer-request-on" POST request doesn’t check for port syntax. This can result in unauthorized execution of system commands with root privileges due to improper access control command injection. 

CVE-2022-30309: In Festo Controller CECC-X-M1 product family in multiple versions, the http-endpoint "cecc-x-web-viewer-request-off" POST request doesn’t check for port syntax. This can result in unauthorized execution of system commands with root privileges due to improper access control command injection. 

CVE-2022-30310: In Festo Controller CECC-X-M1 product family in multiple versions, the http-endpoint "cecc-x-acknerr-request" POST request doesn’t check for port syntax. This can result in unauthorized execution of system commands with root privileges due to improper access control command injection. 

CVE-2022-30311: In Festo Controller CECC-X-M1 product family in multiple versions, the http-endpoint "cecc-x-refresh-request" POST request doesn’t check for port syntax. This can result in unauthorized execution of system commands with root privileges due to improper access control command injection. 

CVE-2022-1589: The Change wp-admin login WordPress plugin before 1.1.0 does not properly check for authorisation and is also missing CSRF check when updating its settings, which could allow unauthenticated users to change the settings. The attacked could also be performed via a CSRF vector

CVE-2022-3879: The Car Dealer (Dealership) and Vehicle sales WordPress Plugin WordPress plugin before 3.05 does not have proper authorisation and CSRF in an AJAX action, allowing any authenticated users, such as subscriber to call it and install and activate arbitrary plugins from wordpress.org

CVE-2022-3882: The Memory Usage, Memory Limit, PHP and Server Memory Health Check and Fix Plugin WordPress plugin before 2.46 does not have proper authorisation and CSRF in an AJAX action, allowing any authenticated users, such as subscriber to call it and install and activate arbitrary plugins from wordpress.org

CVE-2021-30533: Insufficient policy enforcement in PopupBlocker in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass navigation restrictions via a crafted iframe.

CVE-2021-3493: The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

CVE-2021-3956: A read-only authentication bypass vulnerability was reported in the Third Quarter 2021 release of Lenovo XClarity Controller (XCC) firmware affecting XCC devices configured in LDAP Authentication Only Mode and using an LDAP server that supports “unauthenticated bind”, such as Microsoft Active Directory. An unauthenticated user can gain read-only access to XCC in such a configuration, thereby allowing the XCC device configuration to be viewed but not changed. XCC devices configured to use local authentication, LDAP Authentication + Authorization Mode, or LDAP servers that support only “authenticated bind” and/or “anonymous bind” are not affected.

CVE-2022-1983: Incorrect authorization in GitLab EE affecting all versions from 10.7 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1, allowed an attacker already in possession of a valid Deploy Key or a Deploy Token to misuse it from any location to access Container Registries even when IP address restrictions were configured.

CVE-2022-29271: In Nagios XI through 5.8.5, a read-only Nagios user (due to an incorrect permission check) is able to schedule downtime for any host/services. This allows an attacker to permanently disable all monitoring checks.

CVE-2022-34782: An incorrect permission check in Jenkins requests-plugin Plugin 2.2.16 and earlier allows attackers with Overall/Read permission to view the list of pending requests.

CVE-2022-3819: An improper authorization issue in GitLab CE/EE affecting all versions from 15.0 prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allows a malicious users to set emojis on internal notes they don't have access to.

CVE-2022-40816: Zammad 5.2.1 is vulnerable to Incorrect Access Control. Zammad's asset handling mechanism has logic to ensure that customer users are not able to see personal information of other users. This logic was not effective when used through a web socket connection, so that a logged-in attacker would be able to fetch personal data of other users by querying the Zammad API. This issue is fixed in , 5.2.2.

CVE-2022-45383: An incorrect permission check in Jenkins Support Core Plugin 1206.v14049fa_b_d860 and earlier allows attackers with Support/DownloadBundle permission to download a previously created support bundle containing information limited to users with Overall/Administer permission.

CVE-2022-46076: D-Link DIR-869 DIR869Ax_FW102B15 is vulnerable to Authentication Bypass via phpcgi.

CVE-2021-24917: The WPS Hide Login WordPress plugin before 1.9.1 has a bug which allows to get the secret login page by setting a random referer string and making a request to /wp-admin/options.php as an unauthenticated user.

CVE-2022-1746: The authentication mechanism used by poll workers to administer voting using the tested version of Dominion Voting Systems ImageCast X can expose cryptographic secrets used to protect election information. An attacker could leverage this vulnerability to gain access to sensitive information and perform privileged actions, potentially affecting other election equipment.

CVE-2022-22967: An issue was discovered in SaltStack Salt in versions before 3002.9, 3003.5, 3004.2. PAM auth fails to reject locked accounts, which allows a previously authorized user whose account is locked still run Salt commands when their account is locked. This affects both local shell accounts with an active session and salt-api users that authenticate via PAM eauth.

CVE-2022-23822: In this physical attack, an attacker may potentially exploit the Zynq-7000 SoC First Stage Boot Loader (FSBL) by bypassing authentication and loading a malicious image onto the device. This in turn may further allow the attacker to perform additional attacks such as such as using the device as a decryption oracle. An anticipated mitigation via a 2022.1 patch will resolve the issue.

CVE-2022-24778: The imgcrypt library provides API exensions for containerd to support encrypted container images and implements the ctd-decoder command line tool for use by containerd to decrypt encrypted container images. The imgcrypt function `CheckAuthorization` is supposed to check whether the current used is authorized to access an encrypted image and prevent the user from running an image that another user previously decrypted on the same system. In versions prior to 1.1.4, a failure occurs when an image with a ManifestList is used and the architecture of the local host is not the first one in the ManifestList. Only the first architecture in the list was tested, which may not have its layers available locally since it could not be run on the host architecture. Therefore, the verdict on unavailable layers was that the image could be run anticipating that image run failure would occur later due to the layers not being available. However, this verdict to allow the image to run enabled other architectures in the ManifestList to run an image without providing keys if that image had previously been decrypted. A patch has been applied to imgcrypt 1.1.4. Workarounds may include usage of different namespaces for each remote user.

CVE-2022-33174: Power Distribution Units running on Powertek firmware (multiple brands) before 3.30.30 allows remote authorization bypass in the web interface. To exploit the vulnerability, an attacker must send an HTTP packet to the data retrieval interface (/cgi/get_param.cgi) with the tmpToken cookie set to an empty string followed by a semicolon. This bypasses an active session authorization check. This can be then used to fetch the values of protected sys.passwd and sys.su.name fields that contain the username and password in cleartext.

CVE-2021-22240: Improper access control in GitLab EE versions 13.11.6, 13.12.6, and 14.0.2 allows users to be created via single sign on despite user cap being enabled

CVE-2021-35112: A user with user level permission can access graphics protected region due to improper access control in register configuration in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-37409: Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-0574: Improper Access Control in GitHub repository publify/publify prior to 9.2.8.

CVE-2022-1944: When the feature is configured, improper authorization in the Interactive Web Terminal in GitLab CE/EE affecting all versions from 11.3 prior to 14.9.5, 14.10 prior to 14.10.4, and 15.0 prior to 15.0.1 allows users with the Developer role to open terminals on other Developers' running jobs

CVE-2022-2095: An improper access control check in GitLab CE/EE affecting all versions starting from 13.7 before 15.0.5, all versions starting from 15.1 before 15.1.4, all versions starting from 15.2 before 15.2.1 allows a malicious authenticated user to view a public project's Deploy Key's public fingerprint and name when that key has write permission. Note that GitLab never asks for nor stores the private key.

CVE-2022-23488: BigBlueButton is an open source web conferencing system. Versions prior to 2.4-rc-6 are vulnerable to Insertion of Sensitive Information Into Sent Data. The moderators-only webcams lock setting is not enforced on the backend, which allows an attacker to subscribe to viewers' webcams, even when the lock setting is applied. (The required streamId was being sent to all users even with lock setting applied). This issue is fixed in version 2.4-rc-6. There are no workarounds.

CVE-2022-0406: Improper Authorization in GitHub repository janeczku/calibre-web prior to 0.6.16.

CVE-2022-35921: fof/byobu is a private discussions extension for Flarum forum. Affected versions were found to not respect private discussion disablement by users. Users of Byobu should update the extension to version 1.1.7, where this has been patched. Users of Byobu with Flarum 1.0 or 1.1 should upgrade to Flarum 1.2 or later, or evaluate the impact this issue has on your forum's users and choose to disable the extension if needed. There are no workarounds for this issue.

CVE-2022-41923: Grails Spring Security Core plugin is vulnerable to privilege escalation. The vulnerability allows an attacker access to one endpoint (i.e. the targeted endpoint) using the authorization requirements of a different endpoint (i.e. the donor endpoint). In some Grails framework applications, access to the targeted endpoint will be granted based on meeting the authorization requirements of the donor endpoint, which can result in a privilege escalation attack. This vulnerability has been patched in grails-spring-security-core versions 3.3.2, 4.0.5 and 5.1.1. Impacted Applications: Grails Spring Security Core plugin versions: 1.x 2.x >=3.0.0 <3.3.2 >=4.0.0 <4.0.5 >=5.0.0 <5.1.1 We strongly suggest that all Grails framework applications using the Grails Spring Security Core plugin be updated to a patched release of the plugin. Workarounds: Users should create a subclass extending one of the following classes from the `grails.plugin.springsecurity.web.access.intercept` package, depending on their security configuration: * `AnnotationFilterInvocationDefinition` * `InterceptUrlMapFilterInvocationDefinition` * `RequestmapFilterInvocationDefinition` In each case, the subclass should override the `calculateUri` method like so: ``` @Override protected String calculateUri(HttpServletRequest request) { UrlPathHelper.defaultInstance.getRequestUri(request) } ``` This should be considered a temporary measure, as the patched versions of grails-spring-security-core deprecates the `calculateUri` method. Once upgraded to a patched version of the plugin, this workaround is no longer needed. The workaround is especially important for version 2.x, as no patch is available version 2.x of the GSSC plugin.

CVE-2022-0580: Incorrect Authorization in Packagist librenms/librenms prior to 22.2.0. 

CVE-2022-1223: Incorrect Authorization in GitHub repository phpipam/phpipam prior to 1.4.6. 

CVE-2022-0117: Policy bypass in Blink in Google Chrome prior to 97.0.4692.71 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

CVE-2022-0334: A flaw was found in Moodle in versions 3.11 to 3.11.4, 3.10 to 3.10.8, 3.9 to 3.9.11 and earlier unsupported versions. Insufficient capability checks could lead to users accessing their grade report for courses where they did not have the required gradereport/user:view capability.

CVE-2022-0762: Incorrect Authorization in GitHub repository microweber/microweber prior to 1.3. 

CVE-2022-36074: Nextcloud server is an open source personal cloud product. Affected versions of this package are vulnerable to Information Exposure which fails to strip the Authorization header on HTTP downgrade. This can lead to account access exposure and compromise. It is recommended that the Nextcloud Server is upgraded to 23.0.7 or 24.0.3. It is recommended that the Nextcloud Enterprise Server is upgraded to 22.2.11, 23.0.7 or 24.0.3. There are no known workarounds for this issue.

CVE-2022-24783: Deno is a runtime for JavaScript and TypeScript. The versions of Deno between release 1.18.0 and 1.20.2 (inclusive) are vulnerable to an attack where a malicious actor controlling the code executed in a Deno runtime could bypass all permission checks and execute arbitrary shell code. This vulnerability does not affect users of Deno Deploy. The vulnerability has been patched in Deno 1.20.3. There is no workaround. All users are recommended to upgrade to 1.20.3 immediately.

CVE-2022-25318: An issue was discovered in Cerebrate through 1.4. An incorrect sharing group ACL allowed an unprivileged user to edit and modify sharing groups.

CVE-2022-27575: Information exposure vulnerability in One UI Home prior to SMR April-2022 Release 1 allows to access currently launched foreground app information without permission.

CVE-2022-35716: IBM UrbanCode Deploy (UCD) 6.2.0.0 through 6.2.7.16, 7.0.0.0 through 7.0.5.11, 7.1.0.0 through 7.1.2.7, and 7.2.0.0 through 7.2.3.0 could allow an authenticated user to obtain sensitive information in some instances due to improper security checking. IBM X-Force ID: 231360.

CVE-2022-2408: The Guest account feature in Mattermost version 6.7.0 and earlier fails to properly restrict the permissions, which allows a guest user to fetch a list of all public channels in the team, in spite of not being part of those channels.

CVE-2022-0985: Insufficient capability checks could allow users with the moodle/site:uploadusers capability to delete users, without having the necessary moodle/user:delete capability.

CVE-2022-1460: An issue has been discovered in GitLab affecting all versions starting from 9.2 before 14.8.6, all versions starting from 14.9 before 14.9.4, all versions starting from 14.10 before 14.10.1. GitLab was not performing correct authorizations on scheduled pipelines allowing a malicious user to run a pipeline in the context of another user.

CVE-2022-24748: Shopware is an open commerce platform based on the Symfony php Framework and the Vue javascript framework. In versions prior to 6.4.8.2 it is possible to modify customers and to create orders without App Permission. This issue is a result of improper api route checking. Users are advised to upgrade to version 6.4.8.2. There are no known workarounds.

CVE-2022-25335: RigoBlock Dragos through 2022-02-17 lacks the onlyOwner modifier for setMultipleAllowances. This enables token manipulation, as exploited in the wild in February 2022. NOTE: although 2022-02-17 is the vendor's vulnerability announcement date, the vulnerability will not be remediated until a major protocol upgrade occurs.

CVE-2022-36103: Talos Linux is a Linux distribution built for Kubernetes deployments. Talos worker nodes use a join token to get accepted into the Talos cluster. Due to improper validation of the request while signing a worker node CSR (certificate signing request) Talos control plane node might issue Talos API certificate which allows full access to Talos API on a control plane node. Accessing Talos API with full level access on a control plane node might reveal sensitive information which allows full level access to the cluster (Kubernetes and Talos PKI, etc.). Talos API join token is stored in the machine configuration on the worker node. When configured correctly, Kubernetes workloads don't have access to the machine configuration, but due to a misconfiguration workload might access the machine configuration and reveal the join token. This problem has been fixed in Talos 1.2.2. Enabling the Pod Security Standards mitigates the vulnerability by denying hostPath mounts and host networking by default in the baseline policy. Clusters that don't run untrusted workloads are not affected. Clusters with correct Pod Security configurations which don't allow hostPath mounts, and secure access to cloud metadata server (or machine configuration is not supplied via cloud metadata server) are not affected.

CVE-2022-46792: Hasura GraphQL Engine before 2.15.2 mishandles row-level authorization in the Update Many API for Postgres backends. The fixed versions are 2.10.2, 2.11.3, 2.12.1, 2.13.2, 2.14.1, and 2.15.2. (Versions before 2.10.0 are unaffected.)

CVE-2022-3048: Inappropriate implementation in Chrome OS lockscreen in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a local attacker to bypass lockscreen navigation restrictions via physical access to the device.

CVE-2021-30538: Insufficient policy enforcement in content security policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page.

CVE-2021-30539: Insufficient policy enforcement in content security policy in Google Chrome prior to 91.0.4472.77 allowed a remote attacker to bypass content security policy via a crafted HTML page.

CVE-2021-31876: Bitcoin Core 0.12.0 through 0.21.1 does not properly implement the replacement policy specified in BIP125, which makes it easier for attackers to trigger a loss of funds, or a denial of service attack against downstream projects such as Lightning network nodes. An unconfirmed child transaction with nSequence = 0xff_ff_ff_ff, spending an unconfirmed parent with nSequence <= 0xff_ff_ff_fd, should be replaceable because there is inherited signaling by the child transaction. However, the actual PreChecks implementation does not enforce this. Instead, mempool rejects the replacement attempt of the unconfirmed child transaction.

CVE-2021-3763: A flaw was found in the Red Hat AMQ Broker management console in version 7.8 where an existing user is able to access some limited information even when the role the user is assigned to should not be allow access to the management console. The main impact is to confidentiality as this flaw means some role bindings are incorrectly checked, some privileged meta information such as queue names and configuration details are disclosed but the impact is limited as not all information is accessible and there is no affect to integrity.

CVE-2021-39206: Pomerium is an open source identity-aware access proxy. Envoy, which Pomerium is based on, contains two authorization related vulnerabilities CVE-2021-32777 and CVE-2021-32779. This may lead to incorrect routing or authorization policy decisions. With specially crafted requests, incorrect authorization or routing decisions may be made by Pomerium. Pomerium v0.14.8 and v0.15.1 contain an upgraded envoy binary with these vulnerabilities patched. This issue can only be triggered when using path prefix based policy. Removing any such policies should provide mitigation.

CVE-2022-0333: A flaw was found in Moodle in versions 3.11 to 3.11.4, 3.10 to 3.10.8, 3.9 to 3.9.11 and earlier unsupported versions. The calendar:manageentries capability allowed managers to access or modify any calendar event, but should have been restricted from accessing user level events.

CVE-2022-0633: The UpdraftPlus WordPress plugin Free before 1.22.3 and Premium before 2.22.3 do not properly validate a user has the required privileges to access a backup's nonce identifier, which may allow any users with an account on the site (such as subscriber) to download the most recent site & database backup.

CVE-2022-0740: Incorrect authorization in the Asana integration's branch restriction feature in all versions of GitLab CE/EE starting from version 7.8.0 before 14.7.7, all versions starting from 14.8 before 14.8.5, all versions starting from 14.9 before 14.9.2 makes it possible to close Asana tasks from unrestricted branches.

CVE-2022-0825: The Amelia WordPress plugin before 1.0.49 does not have proper authorisation when managing appointments, allowing any customer to update other's booking status, as well as retrieve sensitive information about the bookings, such as the full name and phone number of the person who booked it.

CVE-2022-1935: Incorrect authorization in GitLab EE affecting all versions from 12.0 before 14.9.5, all versions starting from 14.10 before 14.10.4, all versions starting from 15.0 before 15.0.1 allowed an attacker already in possession of a valid Project Trigger Token to misuse it from any location even when IP address restrictions were configured

CVE-2022-1936: Incorrect authorization in GitLab EE affecting all versions from 12.0 before 14.9.5, all versions starting from 14.10 before 14.10.4, all versions starting from 15.0 before 15.0.1 allowed an attacker already in possession of a valid Project Deploy Token to misuse it from any location even when IP address restrictions were configured

CVE-2022-1981: An issue has been discovered in GitLab EE affecting all versions starting from 12.2 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1. In GitLab, if a group enables the setting to restrict access to users belonging to specific domains, that allow-list may be bypassed if a Maintainer uses the 'Invite a group' feature to invite a group that has members that don't comply with domain allow-list.

CVE-2022-21701: Istio is an open platform to connect, manage, and secure microservices. In versions 1.12.0 and 1.12.1 Istio is vulnerable to a privilege escalation attack. Users who have `CREATE` permission for `gateways.gateway.networking.k8s.io` objects can escalate this privilege to create other resources that they may not have access to, such as `Pod`. This vulnerability impacts only an Alpha level feature, the Kubernetes Gateway API. This is not the same as the Istio Gateway type (gateways.networking.istio.io), which is not vulnerable. Users are advised to upgrade to resolve this issue. Users unable to upgrade should implement any of the following which will prevent this vulnerability: Remove the gateways.gateway.networking.k8s.io CustomResourceDefinition, set PILOT_ENABLE_GATEWAY_API_DEPLOYMENT_CONTROLLER=true environment variable in Istiod, or remove CREATE permissions for gateways.gateway.networking.k8s.io objects from untrusted users.

CVE-2022-22326: IBM Datapower Gateway 10.0.2.0 through 10.0.4.0, 10.0.1.0 through 10.0.1.5, and 2018.4.1.0 through 2018.4.1.18 could allow unauthorized viewing of logs and files due to insufficient authorization checks. IBM X-Force ID: 218856.

CVE-2022-23490: BigBlueButton is an open source web conferencing system. Versions prior to 2.4.0 expose sensitive information to Unauthorized Actors. This issue affects meetings with polls, where the attacker is a meeting participant. Subscribing to the current-poll collection does not update the client UI, but does give the attacker access to the contents of the collection, which include the individual poll responses. This issue is patched in version 2.4.0. There are no workarounds. 

CVE-2022-23615: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In affected versions any user with SCRIPT right can save a document with the right of the current user which allow accessing API requiring programming right if the current user has programming right. This has been patched in XWiki 13.0. Users are advised to update to resolve this issue. The only known workaround is to limit SCRIPT access.

CVE-2022-23627: ArchiSteamFarm (ASF) is a C# application with primary purpose of idling Steam cards from multiple accounts simultaneously. Due to a bug in ASF code, introduced in version V5.2.2.2, the program didn't adequately verify effective access of the user sending proxy (i.e. `[Bots]`) commands. In particular, a proxy-like command sent to bot `A` targeting bot `B` has incorrectly verified user's access against bot `A` - instead of bot `B`, to which the command was originally designated. This in result allowed access to resources beyond those configured, being a security threat affecting confidentiality of other bot instances. A successful attack exploiting this bug requires a significant access granted explicitly by original owner of the ASF process prior to that, as attacker has to control at least a single bot in the process to make use of this inadequate access verification loophole. The issue is patched in ASF V5.2.2.5, V5.2.3.2 and future versions. Users are advised to update as soon as possible.

CVE-2022-23739: An incorrect authorization vulnerability was identified in GitHub Enterprise Server, allowing for escalation of privileges in GraphQL API requests from GitHub Apps. This vulnerability allowed an app installed on an organization to gain access to and modify most organization-level resources that are not tied to a repository regardless of granted permissions, such as users and organization-wide projects. Resources associated with repositories were not impacted, such as repository file content, repository-specific projects, issues, or pull requests. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.7.1 and was fixed in versions 3.3.16, 3.4.11, 3.5.8, 3.6.4, 3.7.1. This vulnerability was reported via the GitHub Bug Bounty program.

CVE-2022-23741: An incorrect authorization vulnerability was identified in GitHub Enterprise Server that allowed a scoped user-to-server token to escalate to full admin/owner privileges. An attacker would require an account with admin access to install a malicious GitHub App. This vulnerability was fixed in versions 3.3.17, 3.4.12, 3.5.9, and 3.6.5. This vulnerability was reported via the GitHub Bug Bounty program.

CVE-2022-24307: Mastodon before 3.3.2 and 3.4.x before 3.4.6 has incorrect access control because it does not compact incoming signed JSON-LD activities. (JSON-LD signing has been supported since version 1.6.0.)

CVE-2022-24714: Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Installations of Icinga 2 with the IDO writer enabled are affected. If you use service custom variables in role restrictions, and you regularly decommission service objects, users with said roles may still have access to a collection of content. Note that this only applies if a role has implicitly permitted access to hosts, due to permitted access to at least one of their services. If access to a host is permitted by other means, no sensible information has been disclosed to unauthorized users. This issue has been resolved in versions 2.8.6, 2.9.6 and 2.10 of Icinga Web 2.

CVE-2022-24721: CometD is a scalable comet implementation for web messaging. In any version prior to 5.0.11, 6.0.6, and 7.0.6, internal usage of Oort and Seti channels is improperly authorized, so any remote user could subscribe and publish to those channels. By subscribing to those channels, a remote user may be able to watch cluster-internal traffic that contains other users' (possibly sensitive) data. By publishing to those channels, a remote user may be able to create/modify/delete other user's data and modify the cluster structure. A fix is available in versions 5.0.11, 6.0.6, and 7.0.6. As a workaround, install a custom `SecurityPolicy` that forbids subscription and publishing to remote, non-Oort, sessions on Oort and Seti channels.

CVE-2022-2597: The Visual Portfolio, Photo Gallery & Post Grid WordPress plugin before 2.19.0 does not have proper authorisation checks in some of its REST endpoints, allowing users with a role as low as contributor to call them and inject arbitrary CSS in arbitrary saved layouts

CVE-2022-26767: The issue was addressed with additional permissions checks. This issue is fixed in macOS Monterey 12.4, macOS Big Sur 11.6.6. A malicious application may be able to bypass Privacy preferences.

CVE-2022-27551: HCL Launch could allow an authenticated user to obtain sensitive information in some instances due to improper security checking.

CVE-2022-27608: Forcepoint One Endpoint prior to version 22.01 installed on Microsoft Windows is vulnerable to registry key tampering by users with Administrator privileges. This could result in a user disabling anti-tampering mechanisms which would then allow the user to disable Forcepoint One Endpoint and the protection offered by it.

CVE-2022-27609: Forcepoint One Endpoint prior to version 22.01 installed on Microsoft Windows does not provide sufficient anti-tampering protection of services by users with Administrator privileges. This could result in a user disabling Forcepoint One Endpoint and the protection offered by it.

CVE-2022-27668: Depending on the configuration of the route permission table in file 'saprouttab', it is possible for an unauthenticated attacker to execute SAProuter administration commands in SAP NetWeaver and ABAP Platform - versions KERNEL 7.49, 7.77, 7.81, 7.85, 7.86, 7.87, 7.88, KRNL64NUC 7.49, KRNL64UC 7.49, SAP_ROUTER 7.53, 7.22, from a remote client, for example stopping the SAProuter, that could highly impact systems availability.

CVE-2022-31039: Greenlight is a simple front-end interface for your BigBlueButton server. In affected versions an attacker can view any room's settings even though they are not authorized to do so. Only the room owner and administrator should be able to view a room's settings. This issue has been patched in release version 2.12.6.

CVE-2022-31107: Grafana is an open-source platform for monitoring and observability. In versions 5.3 until 9.0.3, 8.5.9, 8.4.10, and 8.3.10, it is possible for a malicious user who has authorization to log into a Grafana instance via a configured OAuth IdP which provides a login name to take over the account of another user in that Grafana instance. This can occur when the malicious user is authorized to log in to Grafana via OAuth, the malicious user's external user id is not already associated with an account in Grafana, the malicious user's email address is not already associated with an account in Grafana, and the malicious user knows the Grafana username of the target user. If these conditions are met, the malicious user can set their username in the OAuth provider to that of the target user, then go through the OAuth flow to log in to Grafana. Due to the way that external and internal user accounts are linked together during login, if the conditions above are all met then the malicious user will be able to log in to the target user's Grafana account. Versions 9.0.3, 8.5.9, 8.4.10, and 8.3.10 contain a patch for this issue. As a workaround, concerned users can disable OAuth login to their Grafana instance, or ensure that all users authorized to log in via OAuth have a corresponding user account in Grafana linked to their email address.

CVE-2022-31155: Sourcegraph is an opensource code search and navigation engine. In Sourcegraph versions before 3.41.0, it is possible for an attacker to delete other users’ saved searches due to a bug in the authorization check. The vulnerability does not allow the reading of other users’ saved searches, only overwriting them with attacker-controlled searches. The issue is patched in Sourcegraph version 3.41.0. There is no workaround for this issue and updating to a secure version is highly recommended.

CVE-2022-31168: Zulip is an open source team chat tool. Due to an incorrect authorization check in Zulip Server 5.4 and earlier, a member of an organization could craft an API call that grants organization administrator privileges to one of their bots. The vulnerability is fixed in Zulip Server 5.5. Members who don’t own any bots, and lack permission to create them, can’t exploit the vulnerability. As a workaround for the vulnerability, an organization administrator can restrict the `Who can create bots` permission to administrators only, and change the ownership of existing bots.

CVE-2022-39214: Combodo iTop is an open source, web-based IT service management platform. Prior to versions 2.7.8 and 3.0.2-1, a user who can log in on iTop is able to take over any account just by knowing the account's username. This issue is fixed in versions 2.7.8 and 3.0.2-1.

CVE-2022-39302: Ree6 is a moderation bot. This vulnerability would allow other server owners to create configurations such as "Better-Audit-Logging" which contain a channel from another server as a target. This would mean you could send log messages to another Guild channel and bypass raid and webhook protections. A specifically crafted log message could allow spamming and mass advertisements. This issue has been patched in version 1.9.9. There are currently no known workarounds.

CVE-2022-39322: @keystone-6/core is a core package for Keystone 6, a content management system for Node.js. Starting with version 2.2.0 and prior to version 2.3.1, users who expected their `multiselect` fields to use the field-level access control - if configured - are vulnerable to their field-level access control not being used. List-level access control is not affected. Field-level access control for fields other than `multiselect` are not affected. Version 2.3.1 contains a fix for this issue. As a workaround, stop using the `multiselect` field.

CVE-2022-41274: SAP Disclosure Management - version 10.1, allows an authenticated attacker to exploit certain misconfigured application endpoints to read sensitive data. These endpoints are normally exposed over the network and successful exploitation can lead to the exposure of data like financial reports.

CVE-2022-4167: Incorrect Authorization check affecting all versions of GitLab EE from 13.11 prior to 15.5.7, 15.6 prior to 15.6.4, and 15.7 prior to 15.7.2 allows group access tokens to continue working even after the group owner loses the ability to revoke them.

CVE-2022-41962: BigBlueButton is an open source web conferencing system. Versions prior to 2.4-rc-6, and 2.5-alpha-1 contain Incorrect Authorization for setting emoji status. A user with moderator rights can use the clear status feature to set any emoji status for other users. Moderators should only be able to set none as the status of other users. This issue is patched in 2.4-rc-6 and 2.5-alpha-1There are no workarounds.

CVE-2022-42351: Adobe Experience Manager version 6.5.14 (and earlier) is affected by an Incorrect Authorization vulnerability that could result in a security feature bypass. A low-privileged attacker could leverage this vulnerability to disclose low level confidentiality information. Exploitation of this issue does not require user interaction.

CVE-2022-42978: In the Netic User Export add-on before 1.3.5 for Atlassian Confluence, authorization is mishandled. An unauthenticated attacker could access files on the remote system.

CVE-2022-43438: The Administrator function of EasyTest has an Incorrect Authorization vulnerability. A remote attacker authenticated as a general user can exploit this vulnerability to bypass the intended access restrictions, to make API functions calls, manipulate system and terminate service.

CVE-2022-43872:  IBM Financial Transaction Manager 3.2.4 authorization checks are done incorrectly for some HTTP requests which allows getting unauthorized technical information (e.g. event log entries) about the FTM SWIFT system. IBM X-Force ID: 239708. 

CVE-2022-45172: An issue was discovered in LIVEBOX Collaboration vDesk before v018. Broken Access Control can occur under the /api/v1/registration/validateEmail endpoint, the /api/v1/vdeskintegration/user/adduser endpoint, and the /api/v1/registration/changePasswordUser endpoint. The web application is affected by flaws in authorization logic, through which a malicious user (with no privileges) is able to perform privilege escalation to the administrator role, and steal the accounts of any users on the system.

CVE-2022-45353: Broken Access Control in Betheme theme <= 26.6.1 on WordPress. 

CVE-2022-45435: IdentityIQ 8.3 and all 8.3 patch levels prior to 8.3p2, IdentityIQ 8.2 and all 8.2 patch levels prior to 8.2p5, IdentityIQ 8.1 and all 8.1 patch levels prior to 8.1p7, IdentityIQ 8.0 and all 8.0 patch levels prior to 8.0p6, and all prior versions allow authenticated users assigned the Identity Administrator capability or any custom capability that contains the SetIdentityForwarding right to modify the work item forwarding configuration for identities other than the ones that should be allowed by Lifecycle Manager Quicklink Population configuration.

CVE-2022-45891: Planet eStream before 6.72.10.07 allows attackers to call restricted functions, and perform unauthenticated uploads (Upload2.ashx) or access content uploaded by other users (View.aspx after Ajax.asmx/SaveGrantAccessList).

CVE-2022-45956: Boa Web Server versions 0.94.13 through 0.94.14 fail to validate the correct security constraint on the HEAD HTTP method allowing everyone to bypass the Basic Authorization mechanism.

CVE-2022-46160: Tuleap is an Open Source Suite to improve management of software developments and collaboration. In versions prior to 14.2.99.104, project level authorizations are not properly verified when accessing the project "homepage"/dashboards. Users not authorized to access a project may still be able to get some information provided by the widgets (e.g. number of members, content of the Notes widget...). This issue has been patched in Tuleap Community Edition 14.2.99.104, Tuleap Enterprise Edition 14.2-4, and Tuleap Enterprise Edition 14.1-5.

CVE-2022-46258: An incorrect authorization vulnerability was identified in GitHub Enterprise Server that allowed a repository-scoped token with read/write access to modify Action Workflow files without a Workflow scope. The Create or Update file contents API should enforce workflow scope. This vulnerability affected all versions of GitHub Enterprise Server prior to version 3.7 and was fixed in versions 3.3.16, 3.4.11, 3.5.8, and 3.6.4. This vulnerability was reported via the GitHub Bug Bounty program.

CVE-2021-40692: Insufficient capability checks made it possible for teachers to download users outside of their courses.

CVE-2022-0594: The Professional Social Sharing Buttons, Icons & Related Posts WordPress plugin before 9.7.6 does not have proper authorisation check in one of the AJAX action, available to unauthenticated (in v < 9.7.5) and author+ (in v9.7.5) users, allowing them to call it and retrieve various information such as the list of active plugins, various version like PHP, cURL, WP etc.

CVE-2022-0720: The Amelia WordPress plugin before 1.0.47 does not have proper authorisation when managing appointments, allowing any customer to update other's booking, as well as retrieve sensitive information about the bookings, such as the full name and phone number of the person who booked it.

CVE-2022-0920: The Salon booking system Free and Pro WordPress plugins before 7.6.3 do not have proper authorisation in some of its endpoints, which could allow customers to access all bookings and other customer's data

CVE-2022-0984: Users with the capability to configure badge criteria (teachers and managers by default) were able to configure course badges with profile field criteria, which should only be available for site badges.

CVE-2022-20928: A vulnerability in the authentication and authorization flows for VPN connections in Cisco Adaptive Security Appliance (ASA) Software and Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to establish a connection as a different user. This vulnerability is due to a flaw in the authorization verifications during the VPN authentication flow. An attacker could exploit this vulnerability by sending a crafted packet during a VPN authentication. The attacker must have valid credentials to establish a VPN connection. A successful exploit could allow the attacker to establish a VPN connection with access privileges from a different user.

CVE-2022-20942: A vulnerability in the web-based management interface of Cisco Email Security Appliance (ESA), Cisco Secure Email and Web Manager, and Cisco Secure Web Appliance, formerly known as Cisco Web Security Appliance (WSA), could allow an authenticated, remote attacker to retrieve sensitive information from an affected device, including user credentials. This vulnerability is due to weak enforcement of back-end authorization checks. An attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A successful exploit could allow the attacker to obtain confidential data that is stored on the affected device.

CVE-2022-21141: MMP: All versions prior to v1.0.3, PTP C-series: Device versions prior to v2.8.6.1, and PTMP C-series and A5x: Device versions prior to v2.5.4.1 does not perform proper authorization checks on multiple API functions. An attacker may gain access to these functions and achieve remote code execution, create a denial-of-service condition, and obtain sensitive information.

CVE-2022-22157: A traffic classification vulnerability in Juniper Networks Junos OS on the SRX Series Services Gateways may allow an attacker to bypass Juniper Deep Packet Inspection (JDPI) rules and access unauthorized networks or resources, when 'no-syn-check' is enabled on the device. JDPI incorrectly classifies out-of-state asymmetric TCP flows as the dynamic-application INCONCLUSIVE instead of UNKNOWN, which is more permissive, causing the firewall to allow traffic to be forwarded that should have been denied. This issue only occurs when 'set security flow tcp-session no-syn-check' is configured on the device. This issue affects Juniper Networks Junos OS on SRX Series: 18.4 versions prior to 18.4R2-S9, 18.4R3-S9; 19.1 versions prior to 19.1R2-S3, 19.1R3-S6; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior to 19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R2-S5, 19.4R3-S3; 20.1 versions prior to 20.1R2-S2, 20.1R3; 20.2 versions prior to 20.2R3-S1; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S1, 20.4R3; 21.1 versions prior to 21.1R1-S1, 21.1R2. This issue does not affect Juniper Networks Junos OS versions prior to 18.4R1.

CVE-2022-22167: A traffic classification vulnerability in Juniper Networks Junos OS on the SRX Series Services Gateways may allow an attacker to bypass Juniper Deep Packet Inspection (JDPI) rules and access unauthorized networks or resources, when 'no-syn-check' is enabled on the device. While JDPI correctly classifies out-of-state asymmetric TCP flows as the dynamic-application UNKNOWN, this classification is not provided to the policy module properly and hence traffic continues to use the pre-id-default-policy, which is more permissive, causing the firewall to allow traffic to be forwarded that should have been denied. This issue only occurs when 'set security flow tcp-session no-syn-check' is configured on the device. This issue affects Juniper Networks Junos OS on SRX Series: 18.4 versions prior to 18.4R2-S10, 18.4R3-S10; 19.1 versions prior to 19.1R3-S8; 19.2 versions prior to 19.2R1-S8, 19.2R3-S4; 19.3 versions prior to 19.3R3-S3; 19.4 versions prior to 19.4R3-S5; 20.1 versions prior to 20.1R3-S1; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R2-S2, 20.4R3; 21.1 versions prior to 21.1R2-S2, 21.1R3; 21.2 versions prior to 21.2R2. This issue does not affect Juniper Networks Junos OS versions prior to 18.4R1.

CVE-2022-22978: In spring security versions prior to 5.4.11+, 5.5.7+ , 5.6.4+ and older unsupported versions, RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers. Applications using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.

CVE-2022-23009: On BIG-IQ Centralized Management 8.x before 8.1.0, an authenticated administrative role user on a BIG-IQ managed BIG-IP device can access other BIG-IP devices managed by the same BIG-IQ system. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-24189: The user_token authorization header on the Ourphoto App version 1.4.1 /apiv1/* end-points is not implemented properly. Removing the value causes all requests to succeed, bypassing authorization and session management. The impact of this vulnerability allows an attacker POST api calls with other users unique identifiers and enumerate information of all other end-users.

CVE-2022-24306: Zoho ManageEngine SharePoint Manager Plus before 4329 allows account takeover because authorization is mishandled.

CVE-2022-31178: eLabFTW is an electronic lab notebook manager for research teams. A vulnerability was discovered which allows a logged in user to read a template without being authorized to do so. This vulnerability has been patched in 4.3.4. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-31252: A Incorrect Authorization vulnerability in chkstat of SUSE Linux Enterprise Server 12-SP5; openSUSE Leap 15.3, openSUSE Leap 15.4, openSUSE Leap Micro 5.2 did not consider group writable path components, allowing local attackers with access to a group what can write to a location included in the path to a privileged binary to influence path resolution. This issue affects: SUSE Linux Enterprise Server 12-SP5 permissions versions prior to 20170707. openSUSE Leap 15.3 permissions versions prior to 20200127. openSUSE Leap 15.4 permissions versions prior to 20201225. openSUSE Leap Micro 5.2 permissions versions prior to 20181225.

CVE-2022-32532: Apache Shiro before 1.9.1, A RegexRequestMatcher can be misconfigured to be bypassed on some servlet containers. Applications using RegExPatternMatcher with `.` in the regular expression are possibly vulnerable to an authorization bypass.

CVE-2022-34814: Jenkins Request Rename Or Delete Plugin 1.1.0 and earlier does not correctly perform a permission check in an HTTP endpoint, allowing attackers with Overall/Read permission to view an administrative configuration page listing pending requests.

CVE-2022-35487: Zammad 5.2.0 suffers from Incorrect Access Control. Zammad did not correctly perform authorization on certain attachment endpoints. This could be abused by an unauthenticated attacker to gain access to attachments, such as emails or attached files.

CVE-2022-36634: An access control issue in ZKTeco ZKBioSecurity V5000 3.0.5_r allows attackers to arbitrarily create admin users via a crafted HTTP request.

CVE-2022-3880: The Disable Json API, Login Lockdown, XMLRPC, Pingback, Stop User Enumeration Anti Hacker Scan WordPress plugin before 4.20 does not have proper authorisation and CSRF in an AJAX action, allowing any authenticated users, such as subscriber to call it and install and activate arbitrary plugins from wordpress.org

CVE-2022-3881: The WP Tools Increase Maximum Limits, Repair, Server PHP Info, Javascript errors, File Permissions, Transients, Error Log WordPress plugin before 3.43 does not have proper authorisation and CSRF in an AJAX action, allowing any authenticated users, such as subscriber to call it and install and activate arbitrary plugins from wordpress.org

CVE-2022-3883: The Block Bad Bots and Stop Bad Bots Crawlers and Spiders and Anti Spam Protection WordPress plugin before 7.24 does not have proper authorisation and CSRF in an AJAX action, allowing any authenticated users, such as subscriber to call it and install and activate arbitrary plugins from wordpress.org

CVE-2022-39029: Smart eVision has inadequate authorization for the database query function. A remote attacker with general user privilege, who is not explicitly authorized to access the information, can access sensitive information.

CVE-2022-39030: smart eVision has inadequate authorization for system information query function. An unauthenticated remote attacker, who is not explicitly authorized to access the information, can access sensitive information.

CVE-2022-39031: Smart eVision has insufficient authorization for task acquisition function. An unauthorized remote attacker can exploit this vulnerability to acquire the Session IDs of other general users only.

CVE-2022-34180: Jenkins Embeddable Build Status Plugin 2.0.3 and earlier does not correctly perform the ViewStatus permission check in the HTTP endpoint it provides for "unprotected" status badge access, allowing attackers without any permissions to obtain the build status badge icon for any attacker-specified job and/or build.

CVE-2022-31087: LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings) stored in an LDAP directory. In versions prior to 8.0 the tmp directory, which is accessible by /lam/tmp/, allows interpretation of .php (and .php5/.php4/.phpt/etc) files. An attacker capable of writing files under www-data privileges can write a web-shell into this directory, and gain a Code Execution on the host. This issue has been fixed in version 8.0. Users unable to upgrade should disallow executing PHP scripts in (/var/lib/ldap-account-manager/)tmp directory.

CVE-2022-2354: The WP-DBManager WordPress plugin before 2.80.8 does not prevent administrators from running arbitrary commands on the server in multisite installations, where only super-administrators should.

CVE-2022-32310: An access control issue in Ingredient Stock Management System v1.0 allows attackers to take over user accounts via a crafted POST request to /isms/classes/Users.php.

CVE-2022-21678: Discourse is an open source discussion platform. Prior to version 2.8.0.beta11 in the `tests-passed` branch, version 2.8.0.beta11 in the `beta` branch, and version 2.7.13 in the `stable` branch, the bios of users who made their profiles private were still visible in the `<meta>` tags on their users' pages. The problem is patched in `tests-passed` version 2.8.0.beta11, `beta` version 2.8.0.beta11, and `stable` version 2.7.13 of Discourse.

CVE-2022-2462: The Transposh WordPress Translation plugin for WordPress is vulnerable to sensitive information disclosure to unauthenticated users in versions up to, and including, 1.0.8.1. This is due to insufficient permissions checking on the 'tp_history' AJAX action and insufficient restriction on the data returned in the response. This makes it possible for unauthenticated users to exfiltrate usernames of individuals who have translated text.

CVE-2022-31139: UnsafeAccessor (UA) is a bridge to access jdk.internal.misc.Unsafe & sun.misc.Unsafe. Normally, if UA is loaded as a named module, the internal data of UA is protected by JVM and others can only access UA via UA's standard API. The main application can set up `SecurityCheck.AccessLimiter` for UA to limit access to UA. Starting with version 1.4.0 and prior to version 1.7.0, when `SecurityCheck.AccessLimiter` is set up, untrusted code can access UA without limitation, even when UA is loaded as a named module. This issue does not affect those for whom `SecurityCheck.AccessLimiter` is not set up. Version 1.7.0 contains a patch.

CVE-2022-31190: DSpace open source software is a repository application which provides durable access to digital resources. dspace-xmlui is a UI component for DSpace. In affected versions metadata on a withdrawn Item is exposed via the XMLUI "mets.xml" object, as long as you know the handle/URL of the withdrawn Item. This vulnerability only impacts the XMLUI. Users are advised to upgrade to version 6.4 or newer.

CVE-2022-41944: Discourse is an open-source discussion platform. In stable versions prior to 2.8.12 and beta or tests-passed versions prior to 2.9.0.beta.13, under certain conditions, a user can see notifications for topics they no longer have access to. If there is sensitive information in the topic title, it will therefore have been exposed. This issue is patched in stable version 2.8.12, beta version 2.9.0.beta13, and tests-passed version 2.9.0.beta13. There are no workarounds available.

CVE-2022-42724: app/Controller/UsersController.php in MISP before 2.4.164 allows attackers to discover role names (this is information that only the site admin should have).

CVE-2021-41571: In Apache Pulsar it is possible to access data from BookKeeper that does not belong to the topics accessible by the authenticated user. The Admin API get-message-by-id requires the user to input a topic and a ledger id. The ledger id is a pointer to the data, and it is supposed to be a valid it for the topic. Authorisation controls are performed against the topic name and there is not proper validation the that ledger id is valid in the context of such ledger. So it may happen that the user is able to read from a ledger that contains data owned by another tenant. This issue affects Apache Pulsar Apache Pulsar version 2.8.0 and prior versions; Apache Pulsar version 2.7.3 and prior versions; Apache Pulsar version 2.6.4 and prior versions.

# CWE-87 Improper Neutralization of Alternate XSS Syntax

## Description

The product does not neutralize or incorrectly neutralizes user-controlled input for alternate script syntax.

## Observed Examples

CVE-2002-0738: XSS using "&={script}".

# CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')

## Description

The product constructs a string for a command to be executed by a separate component
in another control sphere, but it does not properly delimit the
intended arguments, options, or switches within that command string.

When creating commands using interpolation into a string, developers may assume that only the arguments/options that they specify will be processed. This assumption may be even stronger when the programmer has encoded the command in a way that prevents separate commands from being provided maliciously, e.g. in the case of shell metacharacters. When constructing the command, the developer may use whitespace or other delimiters that are required to separate arguments when the command. However, if an attacker can provide an untrusted input that contains argument-separating delimiters, then the resulting command will have more arguments than intended by the developer. The attacker may then be able to change the behavior of the command. Depending on the functionality supported by the extraneous arguments, this may have security-relevant consequences.

## Observed Examples

CVE-2022-36069: Python-based dependency management tool avoids OS command injection when generating Git commands but allows injection of optional arguments with input beginning with a dash (CWE-88), potentially allowing for code execution.

CVE-1999-0113: Canonical Example - "-froot" argument is passed on to another program, where the "-f" causes execution as user "root"

CVE-2001-0150: Web browser executes Telnet sessions using command line arguments that are specified by the web site, which could allow remote attackers to execute arbitrary commands.

CVE-2001-0667: Web browser allows remote attackers to execute commands by spawning Telnet with a log file option on the command line and writing arbitrary code into an executable file which is later executed.

CVE-2002-0985: Argument injection vulnerability in the mail function for PHP may allow attackers to bypass safe mode restrictions and modify command line arguments to the MTA (e.g. sendmail) possibly executing commands.

CVE-2003-0907: Help and Support center in windows does not properly validate HCP URLs, which allows remote attackers to execute arbitrary code via quotation marks in an "hcp://" URL.

CVE-2004-0121: Mail client does not sufficiently filter parameters of mailto: URLs when using them as arguments to mail executable, which allows remote attackers to execute arbitrary programs.

CVE-2004-0473: Web browser doesn't filter "-" when invoking various commands, allowing command-line switches to be specified.

CVE-2004-0480: Mail client allows remote attackers to execute arbitrary code via a URI that uses a UNC network share pathname to provide an alternate configuration file.

CVE-2004-0489: SSH URI handler for web browser allows remote attackers to execute arbitrary code or conduct port forwarding via the a command line option.

CVE-2004-0411: Web browser doesn't filter "-" when invoking various commands, allowing command-line switches to be specified.

CVE-2005-4699: Argument injection vulnerability in TellMe 1.2 and earlier allows remote attackers to modify command line arguments for the Whois program and obtain sensitive information via "--" style options in the q_Host parameter.

CVE-2006-1865: Beagle before 0.2.5 can produce certain insecure command lines to launch external helper applications while indexing, which allows attackers to execute arbitrary commands. NOTE: it is not immediately clear whether this issue involves argument injection, shell metacharacters, or other issues.

CVE-2006-2056: Argument injection vulnerability in Internet Explorer 6 for Windows XP SP2 allows user-assisted remote attackers to modify command line arguments to an invoked mail client via " (double quote) characters in a mailto: scheme handler, as demonstrated by launching Microsoft Outlook with an arbitrary filename as an attachment. NOTE: it is not clear whether this issue is implementation-specific or a problem in the Microsoft API.

CVE-2006-2057: Argument injection vulnerability in Mozilla Firefox 1.0.6 allows user-assisted remote attackers to modify command line arguments to an invoked mail client via " (double quote) characters in a mailto: scheme handler, as demonstrated by launching Microsoft Outlook with an arbitrary filename as an attachment. NOTE: it is not clear whether this issue is implementation-specific or a problem in the Microsoft API.

CVE-2006-2058: Argument injection vulnerability in Avant Browser 10.1 Build 17 allows user-assisted remote attackers to modify command line arguments to an invoked mail client via " (double quote) characters in a mailto: scheme handler, as demonstrated by launching Microsoft Outlook with an arbitrary filename as an attachment. NOTE: it is not clear whether this issue is implementation-specific or a problem in the Microsoft API.

CVE-2006-2312: Argument injection vulnerability in the URI handler in Skype 2.0.*.104 and 2.5.*.0 through 2.5.*.78 for Windows allows remote authorized attackers to download arbitrary files via a URL that contains certain command-line switches.

CVE-2006-3015: Argument injection vulnerability in WinSCP 3.8.1 build 328 allows remote attackers to upload or download arbitrary files via encoded spaces and double-quote characters in a scp or sftp URI.

CVE-2006-4692: Argument injection vulnerability in the Windows Object Packager (packager.exe) in Microsoft Windows XP SP1 and SP2 and Server 2003 SP1 and earlier allows remote user-assisted attackers to execute arbitrary commands via a crafted file with a "/" (slash) character in the filename of the Command Line property, followed by a valid file extension, which causes the command before the slash to be executed, aka "Object Packager Dialogue Spoofing Vulnerability."

CVE-2006-6597: Argument injection vulnerability in HyperAccess 8.4 allows user-assisted remote attackers to execute arbitrary vbscript and commands via the /r option in a telnet:// URI, which is configured to use hawin32.exe.

CVE-2007-0882: Argument injection vulnerability in the telnet daemon (in.telnetd) in Solaris 10 and 11 (SunOS 5.10 and 5.11) misinterprets certain client "-f" sequences as valid requests for the login program to skip authentication, which allows remote attackers to log into certain accounts, as demonstrated by the bin account.

CVE-2001-1246: Language interpreter's mail function accepts another argument that is concatenated to a string used in a dangerous popen() call. Since there is no neutralization of this argument, both OS Command Injection (CWE-78) and Argument Injection (CWE-88) are possible.

CVE-2019-13475: Argument injection allows execution of arbitrary commands by injecting a "-exec" option, which is executed by the command.

CVE-2016-10033: Argument injection in mail-processing function allows writing unxpected files and executing programs using tecnically-valid email addresses that insert "-o" and "-X" switches.

## Top 25 Examples

CVE-2022-21187: The package libvcs before 0.11.1 are vulnerable to Command Injection via argument injection. When calling the update_repo function (when using hg), the url parameter is passed to the hg clone command. By injecting some hg options it was possible to get arbitrary command execution.

CVE-2022-21223: The package cocoapods-downloader before 1.6.2 are vulnerable to Command Injection via hg argument injection. When calling the download function (when using hg), the url (and/or revision, tag, branch) is passed to the hg clone command in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-21235: The package github.com/masterminds/vcs before 1.13.3 are vulnerable to Command Injection via argument injection. When hg is executed, argument strings are passed to hg in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-24433: The package simple-git before 3.3.0 are vulnerable to Command Injection via argument injection. When calling the .fetch(remote, branch, handlerFn) function, both the remote and branch parameters are passed to the git fetch subcommand. By injecting some git options it was possible to get arbitrary command execution.

CVE-2022-24440: The package cocoapods-downloader before 1.6.0, from 1.6.2 and before 1.6.3 are vulnerable to Command Injection via git argument injection. When calling the Pod::Downloader.preprocess_options function and using git, both the git and branch parameters are passed to the git ls-remote subcommand in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-25648: The package git before 1.11.0 are vulnerable to Command Injection via git argument injection. When calling the fetch(remote = 'origin', opts = {}) function, the remote parameter is passed to the git fetch subcommand in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-25766: The package ungit before 1.5.20 are vulnerable to Remote Code Execution (RCE) via argument injection. The issue occurs when calling the /api/fetch endpoint. User controlled values (remote and ref) are passed to the git fetch command. By injecting some git options it was possible to get arbitrary command execution.

CVE-2022-25865: The package workspace-tools before 0.18.4 are vulnerable to Command Injection via git argument injection. When calling the fetchRemoteBranch(remote: string, remoteBranch: string, cwd: string) function, both the remote and remoteBranch parameters are passed to the git fetch subcommand in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-25866: The package czproject/git-php before 4.0.3 are vulnerable to Command Injection via git argument injection. When calling the isRemoteUrlReadable($url, array $refs = NULL) function, both the url and refs parameters are passed to the git ls-remote subcommand in a way that additional flags can be set. The additional flags can be used to perform a command injection.

CVE-2022-25900: All versions of package git-clone are vulnerable to Command Injection due to insecure usage of the --upload-pack feature of git.

CVE-2022-26532: A argument injection vulnerability in the 'packet-trace' CLI command of Zyxel USG/ZyWALL series firmware versions 4.09 through 4.71, USG FLEX series firmware versions 4.50 through 5.21, ATP series firmware versions 4.32 through 5.21, VPN series firmware versions 4.30 through 5.21, NSG series firmware versions 1.00 through 1.33 Patch 4, NXC2500 firmware version 6.10(AAIG.3) and earlier versions, NAP203 firmware version 6.25(ABFA.7) and earlier versions, NWA50AX firmware version 6.25(ABYW.5) and earlier versions, WAC500 firmware version 6.30(ABVS.2) and earlier versions, and WAX510D firmware version 6.30(ABTF.2) and earlier versions, that could allow a local authenticated attacker to execute arbitrary OS commands by including crafted arguments to the CLI command.

CVE-2022-36069: Poetry is a dependency manager for Python. When handling dependencies that come from a Git repository instead of a registry, Poetry uses various commands, such as `git clone`. These commands are constructed using user input (e.g. the repository URL). When building the commands, Poetry correctly avoids Command Injection vulnerabilities by passing an array of arguments instead of a command string. However, there is the possibility that a user input starts with a dash (`-`) and is therefore treated as an optional argument instead of a positional one. This can lead to Code Execution because some of the commands have options that can be leveraged to run arbitrary executables. If a developer is exploited, the attacker could steal credentials or persist their access. If the exploit happens on a server, the attackers could use their access to attack other internal systems. Since this vulnerability requires a fair amount of user interaction, it is not as dangerous as a remotely exploitable one. However, it still puts developers at risk when dealing with untrusted files in a way they think is safe, because the exploit still works when the victim tries to make sure nothing can happen, e.g. by vetting any Git or Poetry config files that might be present in the directory. Versions 1.1.9 and 1.2.0b1 contain patches for this issue.

CVE-2022-37027: Ahsay AhsayCBS 9.1.4.0 allows an authenticated system user to inject arbitrary Java JVM options. Administrators that can modify the Runtime Options in the web interface can inject Java Runtime Options. These take effect after a restart. For example, an attacker can enable JMX services and consequently achieve remote code execution as the system user.

CVE-2022-23221: H2 Console before 2.1.210 allows remote attackers to execute arbitrary code via a jdbc:h2:mem JDBC URL containing the IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;INIT=RUNSCRIPT substring, a different vulnerability than CVE-2021-42392.

CVE-2022-24066: The package simple-git before 3.5.0 are vulnerable to Command Injection due to an incomplete fix of [CVE-2022-24433](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-2421199) which only patches against the git fetch attack vector. A similar use of the --upload-pack feature of git is also supported for git clone, which the prior fix didn't cover.

CVE-2022-24376: All versions of package git-promise are vulnerable to Command Injection due to an inappropriate fix of a prior [vulnerability](https://security.snyk.io/vuln/SNYK-JS-GITPROMISE-567476) in this package. **Note:** Please note that the vulnerability will not be fixed. The README file was updated with a warning regarding this issue.

CVE-2022-24437: The package git-pull-or-clone before 2.0.2 are vulnerable to Command Injection due to the use of the --upload-pack feature of git which is also supported for git clone. The source includes the use of the secure child process API spawn(). However, the outpath parameter passed to it may be a command-line argument to the git clone command and result in arbitrary command injection.

CVE-2021-46850: myVesta Control Panel before 0.9.8-26-43 and Vesta Control Panel before 0.9.8-26 are vulnerable to command injection. An authenticated and remote administrative user can execute arbitrary commands via the v_sftp_license parameter when sending HTTP POST requests to the /edit/server endpoint.

CVE-2022-24953: The Crypt_GPG extension before 1.6.7 for PHP does not prevent additional options in GPG calls, which presents a risk for certain environments and GPG versions.

# CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

## Description

The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Observed Examples

CVE-2023-32530: SQL injection in security product dashboard using crafted certificate fields

CVE-2021-42258: SQL injection in time and billing software, as exploited in the wild per CISA KEV.

CVE-2021-27101: SQL injection in file-transfer system via a crafted Host header, as exploited in the wild per CISA KEV.

CVE-2020-12271: SQL injection in firewall product's admin interface or user portal, as exploited in the wild per CISA KEV.

CVE-2019-3792: An automation system written in Go contains an API that is vulnerable to SQL injection allowing the attacker to read privileged data.

CVE-2004-0366: chain: SQL injection in library intended for database authentication allows SQL injection and authentication bypass.

CVE-2008-2790: SQL injection through an ID that was supposed to be numeric.

CVE-2008-2223: SQL injection through an ID that was supposed to be numeric.

CVE-2007-6602: SQL injection via user name.

CVE-2008-5817: SQL injection via user name or password fields.

CVE-2003-0377: SQL injection in security product, using a crafted group name.

CVE-2008-2380: SQL injection in authentication library.

CVE-2017-11508: SQL injection in vulnerability management and reporting tool, using a crafted password.

## Top 25 Examples

CVE-2021-26634: SQL injection and file upload attacks are possible due to insufficient validation of input values in some parameters and variables of files compromising Maxboard, which may lead to arbitrary code execution or privilege escalation. Attackers can use these vulnerabilities to perform attacks such as stealing server management rights using a web shell.

CVE-2021-41433: SQL Injection vulnerability exists in version 1.0 of the Resumes Management and Job Application Website application login form by EGavilan Media that allows authentication bypass through login.php.

CVE-2022-0366: An authenticated and authorized agent user could potentially gain administrative access via an SQLi vulnerability to Capsule8 Console between versions 4.6.0 and 4.9.1.

CVE-2022-0439: The Email Subscribers & Newsletters WordPress plugin before 5.3.2 does not correctly escape the `order` and `orderby` parameters to the `ajax_fetch_report_list` action, making it vulnerable to blind SQL injection attacks by users with roles as low as Subscriber. Further, it does not have any CSRF protection in place for the action, allowing an attacker to trick any logged in user to perform the action by clicking a link.

CVE-2022-23857: model/criteria/criteria.go in Navidrome before 0.47.5 is vulnerable to SQL injection attacks when processing crafted Smart Playlists. An authenticated user could abuse this to extract arbitrary data from the database, including the user table (which contains sensitive information such as the users' encrypted passwords).

CVE-2022-24690: An issue was discovered in DSK DSKNet 2.16.136.0 and 2.17.136.5. A PresAbs.php SQL Injection vulnerability allows unauthenticated users to taint database data and extract sensitive information via crafted HTTP requests. The type of SQL Injection is blind boolean based. (An unauthenticated attacker can discover the endpoint by abusing a Broken Access Control issue with further SQL injection attacks to gather all user's badge numbers and PIN codes.)

CVE-2022-29603: A SQL Injection vulnerability exists in UniverSIS UniverSIS-API through 1.2.1 via the $select parameter to multiple API endpoints. A remote authenticated attacker could send crafted SQL statements to a vulnerable endpoint (such as /api/students/me/messages/) to, for example, retrieve personal information or change grades.

CVE-2022-29652: Online Sports Complex Booking System 1.0 is vulnerable to SQL Injection via /scbs/classes/Users.php?f=save_client.

CVE-2022-30335: Bonanza Wealth Management System (BWM) 7.3.2 allows SQL injection via the login form. Users who supply the application with a SQL injection payload in the User Name textbox could collect all passwords in encrypted format from the Microsoft SQL Server component.

CVE-2022-36669: Hospital Information System version 1.0 suffers from a remote SQL injection vulnerability that allows for authentication bypass.

CVE-2021-20016: A SQL-Injection vulnerability in the SonicWall SSLVPN SMA100 product allows a remote unauthenticated attacker to perform SQL query to access username password and other session related information. This vulnerability impacts SMA100 build version 10.x.

CVE-2021-20028: Improper neutralization of a SQL Command leading to SQL Injection vulnerability impacting end-of-life Secure Remote Access (SRA) products, specifically the SRA appliances running all 8.x firmware and 9.0.0.9-26sv or earlier

CVE-2021-42258: BQE BillQuick Web Suite 2018 through 2021 before 22.0.9.1 allows SQL injection for unauthenticated remote code execution, as exploited in the wild in October 2021 for ransomware installation. SQL injection can, for example, use the txtID (aka username) parameter. Successful exploitation can include the ability to execute arbitrary code as MSSQLSERVER$ via xp_cmdshell.

CVE-2021-35226: An entity in Network Configuration Manager product is misconfigured and exposing password field to Solarwinds Information Service (SWIS). Exposed credentials are encrypted and require authenticated access with an NCM role. 

CVE-2022-46163: Travel support program is a rails app to support the travel support program of openSUSE (TSP). Sensitive user data (bank account details, password Hash) can be extracted via Ransack query injection. Every deployment of travel-support-program below the patched version is affected. The travel-support-program uses the Ransack library to implement search functionality. In its default configuration, Ransack will allow for query conditions based on properties of associated database objects [1]. The `*_start`, `*_end` or `*_cont` search matchers [2] can then be abused to exfiltrate sensitive string values of associated database objects via character-by-character brute-force (A match is indicated by the returned JSON not being empty). A single bank account number can be extracted with <200 requests, a password hash can be extracted with ~1200 requests, all within a few minutes. The problem has been patched in commit d22916275c51500b4004933ff1b0a69bc807b2b7. In order to work around this issue, you can also cherry pick that patch, however it will not work without the Rails 5.0 migration that was done in #150, which in turn had quite a few pull requests it depended on.

CVE-2021-3958: Improper Handling of Parameters vulnerability in Ipack Automation Systems Ipack SCADA Software allows : Blind SQL Injection.This issue affects Ipack SCADA Software: from unspecified before 1.1.0. 

CVE-2021-42760: A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiWLM version 8.6.1 and below allows attacker to disclose sensitive information from DB tables via crafted requests.

CVE-2021-43077: A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiWLM version 8.6.2 and below, version 8.5.2 and below, version 8.4.2 and below, version 8.3.2 and below allows attacker to execute unauthorized code or commands via crafted HTTP requests to the AP monitor handlers.

CVE-2021-43925: Improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability in Log Management functionality in Synology DiskStation Manager (DSM) before 7.0.1-42218-2 allows remote attackers to inject SQL commands via unspecified vectors.

CVE-2021-43926: Improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability in Log Management functionality in Synology DiskStation Manager (DSM) before 7.0.1-42218-2 allows remote attackers to inject SQL commands via unspecified vectors.

CVE-2021-43927: Improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability in Security Management functionality in Synology DiskStation Manager (DSM) before 7.0.1-42218-2 allows remote attackers to inject SQL commands via unspecified vectors.

CVE-2022-0224: dolibarr is vulnerable to Improper Neutralization of Special Elements used in an SQL Command

CVE-2022-0258: pimcore is vulnerable to Improper Neutralization of Special Elements used in an SQL Command

CVE-2022-1358: The affected On-Premise is vulnerable to data exfiltration through improper neutralization of special elements used in an SQL command. This could allow an attacker to exfiltrate and dump all data held in the cnMaestro database.

CVE-2022-1361: The affected On-Premise cnMaestro is vulnerable to a pre-auth data exfiltration through improper neutralization of special elements used in an SQL command. This could allow an attacker to exfiltrate data about other user’s accounts and devices.

CVE-2022-22280: Improper Neutralization of Special Elements used in an SQL Command leading to Unauthenticated SQL Injection vulnerability, impacting SonicWall GMS 9.3.1-SP2-Hotfix1, Analytics On-Prem 2.5.0.3-2520 and earlier versions.

CVE-2022-3332: A vulnerability classified as critical has been found in SourceCodester Food Ordering Management System. This affects an unknown part of the file router.php of the component POST Parameter Handler. The manipulation of the argument username leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-209583.

CVE-2022-3414: A vulnerability was found in SourceCodester Web-Based Student Clearance System. It has been classified as critical. Affected is an unknown function of the file /Admin/login.php of the component POST Parameter Handler. The manipulation of the argument txtusername leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-210246 is the identifier assigned to this vulnerability.

CVE-2022-3467: A vulnerability classified as critical was found in Jiusi OA. Affected by this vulnerability is an unknown functionality of the file /jsoa/hntdCustomDesktopActionContent. The manipulation of the argument inforid leads to sql injection. The exploit has been disclosed to the public and may be used. The identifier VDB-210709 was assigned to this vulnerability.

CVE-2022-3470: A vulnerability was found in SourceCodester Human Resource Management System. It has been classified as critical. Affected is an unknown function of the file getstatecity.php. The manipulation of the argument sc leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-210714 is the identifier assigned to this vulnerability.

CVE-2022-3825: A vulnerability was found in Huaxia ERP 2.3 and classified as critical. Affected by this issue is some unknown functionality of the component User Management. The manipulation of the argument login leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-212792.

CVE-2022-3827: A vulnerability was found in centreon. It has been declared as critical. This vulnerability affects unknown code of the file formContactGroup.php of the component Contact Groups Form. The manipulation of the argument cg_id leads to sql injection. The attack can be initiated remotely. The name of the patch is 293b10628f7d9f83c6c82c78cf637cbe9b907369. It is recommended to apply a patch to fix this issue. VDB-212794 is the identifier assigned to this vulnerability.

CVE-2022-3868: A vulnerability classified as critical has been found in SourceCodester Sanitization Management System. Affected is an unknown function of the file /php-sms/classes/Master.php?f=save_quote. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-213012.

CVE-2022-3971: A vulnerability was found in matrix-appservice-irc up to 0.35.1. It has been declared as critical. This vulnerability affects unknown code of the file src/datastore/postgres/PgDataStore.ts. The manipulation of the argument roomIds leads to sql injection. Upgrading to version 0.36.0 is able to address this issue. The name of the patch is 179313a37f06b298150edba3e2b0e5a73c1415e7. It is recommended to upgrade the affected component. VDB-213550 is the identifier assigned to this vulnerability.

CVE-2022-3972: A vulnerability was found in Pingkon HMS-PHP. It has been rated as critical. This issue affects some unknown processing of the file admin/adminlogin.php. The manipulation of the argument uname/pass leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-213551.

CVE-2022-3973: A vulnerability classified as critical has been found in Pingkon HMS-PHP. Affected is an unknown function of the file /admin/admin.php of the component Data Pump Metadata. The manipulation of the argument uname/pass leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-213552.

CVE-2022-3997: A vulnerability, which was classified as critical, has been found in MonikaBrzica scm. Affected by this issue is some unknown functionality of the file upis_u_bazu.php. The manipulation of the argument email/lozinka/ime/id leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-213698 is the identifier assigned to this vulnerability.

CVE-2022-3998: A vulnerability, which was classified as critical, was found in MonikaBrzica scm. This affects an unknown part of the file uredi_korisnika.php. The manipulation of the argument id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-213699.

CVE-2022-4015: A vulnerability, which was classified as critical, was found in Sports Club Management System 119. This affects an unknown part of the file admin/make_payments.php. The manipulation of the argument m_id/plan leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-213789 was assigned to this vulnerability.

CVE-2022-4247: A vulnerability classified as critical was found in Movie Ticket Booking System. This vulnerability affects unknown code of the file booking.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-214624.

CVE-2022-4248: A vulnerability, which was classified as critical, has been found in Movie Ticket Booking System. This issue affects some unknown processing of the file editBooking.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-214625 was assigned to this vulnerability.

CVE-2022-3471: A vulnerability was found in SourceCodester Human Resource Management System. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file city.php. The manipulation of the argument searccity leads to sql injection. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-210715.

CVE-2022-3472: A vulnerability was found in SourceCodester Human Resource Management System. It has been rated as critical. Affected by this issue is some unknown functionality of the file city.php. The manipulation of the argument cityedit leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-210716.

CVE-2022-3473: A vulnerability classified as critical has been found in SourceCodester Human Resource Management System. This affects an unknown part of the file getstatecity.php. The manipulation of the argument ci leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-210717 was assigned to this vulnerability.

CVE-2022-3579: A vulnerability classified as critical was found in SourceCodester Cashier Queuing System 1.0. This vulnerability affects unknown code of the file /queuing/login.php of the component Login Page. The manipulation of the argument username/password leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-211186 is the identifier assigned to this vulnerability.

CVE-2022-3584: A vulnerability was found in SourceCodester Canteen Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file edituser.php. The manipulation of the argument id leads to sql injection. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-211193 was assigned to this vulnerability.

CVE-2022-3671: A vulnerability classified as critical was found in SourceCodester eLearning System 1.0. This vulnerability affects unknown code of the file /admin/students/manage.php. The manipulation of the argument id leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-212014 is the identifier assigned to this vulnerability.

CVE-2022-3714: A vulnerability classified as critical has been found in SourceCodester Online Medicine Ordering System 1.0. Affected is an unknown function of the file admin/?page=orders/view_order. The manipulation of the argument id leads to sql injection. It is possible to launch the attack remotely. VDB-212346 is the identifier assigned to this vulnerability.

CVE-2022-3729: A vulnerability, which was classified as critical, has been found in seccome Ehoney. This issue affects some unknown processing of the file /api/v1/attack. The manipulation of the argument AttackIP leads to sql injection. The attack may be initiated remotely. The associated identifier of this vulnerability is VDB-212411.

CVE-2022-3730: A vulnerability, which was classified as critical, was found in seccome Ehoney. Affected is an unknown function of the file /api/v1/attack/falco. The manipulation of the argument Payload leads to sql injection. It is possible to launch the attack remotely. The identifier of this vulnerability is VDB-212412.

CVE-2022-3731: A vulnerability has been found in seccome Ehoney and classified as critical. Affected by this vulnerability is an unknown functionality of the file /api/v1/attack/token. The manipulation of the argument Payload leads to sql injection. The attack can be launched remotely. The identifier VDB-212413 was assigned to this vulnerability.

CVE-2022-3733: A vulnerability was found in SourceCodester Web-Based Student Clearance System. It has been classified as critical. This affects an unknown part of the file Admin/edit-admin.php. The manipulation of the argument id leads to sql injection. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-212415.

