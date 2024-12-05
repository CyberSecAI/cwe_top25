# CWE-20 Improper Input Validation

## Description

The product receives input or data, but it does
        not validate or incorrectly validates that the input has the
        properties that are required to process the data safely and
        correctly.

Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with other components. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution.


Input validation is not the only technique for processing input, however. Other techniques attempt to transform potentially-dangerous input into something safe, such as filtering (CWE-790) - which attempts to remove dangerous inputs - or encoding/escaping (CWE-116), which attempts to ensure that the input is not misinterpreted when it is included in output to another component. Other techniques exist as well (see CWE-138 for more examples.)


Input validation can be applied to:


  - raw data - strings, numbers, parameters, file contents, etc.

  - metadata - information about the raw data, such as headers or size

Data can be simple or structured. Structured data can be composed of many nested layers, composed of combinations of metadata and raw data, with other simple or structured data.

Many properties of raw data or metadata may need to be validated upon entry into the code, such as:


  - specified quantities such as size, length, frequency, price, rate, number of operations, time, etc.

  - implied or derived quantities, such as the actual size of a file instead of a specified size

  - indexes, offsets, or positions into more complex data structures

  - symbolic keys or other elements into hash tables, associative arrays, etc.

  - well-formedness, i.e. syntactic correctness - compliance with expected syntax 

  - lexical token correctness - compliance with rules for what is treated as a token

  - specified or derived type - the actual type of the input (or what the input appears to be)

  - consistency - between individual data elements, between raw data and metadata, between references, etc.

  - conformance to domain-specific rules, e.g. business logic 

  - equivalence - ensuring that equivalent inputs are treated the same

  - authenticity, ownership, or other attestations about the input, e.g. a cryptographic signature to prove the source of the data

Implied or derived properties of data must often be calculated or inferred by the code itself. Errors in deriving properties may be considered a contributing factor to improper input validation. 

Note that "input validation" has very different meanings to different people, or within different classification schemes. Caution must be used when referencing this CWE entry or mapping to it. For example, some weaknesses might involve inadvertently giving control to an attacker over an input when they should not be able to provide an input at all, but sometimes this is referred to as input validation.


Finally, it is important to emphasize that the distinctions between input validation and output escaping are often blurred, and developers must be careful to understand the difference, including how input validation is not always sufficient to prevent vulnerabilities, especially when less stringent data types must be supported, such as free-form text. Consider a SQL injection scenario in which a person's last name is inserted into a query. The name "O'Reilly" would likely pass the validation step since it is a common last name in the English language. However, this valid name cannot be directly inserted into the database because it contains the "'" apostrophe character, which would need to be escaped or otherwise transformed. In this case, removing the apostrophe might reduce the risk of SQL injection, but it would produce incorrect behavior because the wrong name would be recorded.

## Observed Examples

CVE-2024-37032: Large language model (LLM) management tool does not validate the format of a digest value (CWE-1287) from a private, untrusted model registry, enabling relative path traversal (CWE-23), a.k.a. Probllama

CVE-2022-45918: Chain: a learning management tool debugger uses external input to locate previous session logs (CWE-73) and does not properly validate the given path (CWE-20), allowing for filesystem path traversal using "../" sequences (CWE-24)

CVE-2021-30860: Chain: improper input validation (CWE-20) leads to integer overflow (CWE-190) in mobile OS, as exploited in the wild per CISA KEV.

CVE-2021-30663: Chain: improper input validation (CWE-20) leads to integer overflow (CWE-190) in mobile OS, as exploited in the wild per CISA KEV.

CVE-2021-22205: Chain: backslash followed by a newline can bypass a validation step (CWE-20), leading to eval injection (CWE-95), as exploited in the wild per CISA KEV.

CVE-2021-21220: Chain: insufficient input validation (CWE-20) in browser allows heap corruption (CWE-787), as exploited in the wild per CISA KEV.

CVE-2020-9054: Chain: improper input validation (CWE-20) in username parameter, leading to OS command injection (CWE-78), as exploited in the wild per CISA KEV.

CVE-2020-3452: Chain: security product has improper input validation (CWE-20) leading to directory traversal (CWE-22), as exploited in the wild per CISA KEV.

CVE-2020-3161: Improper input validation of HTTP requests in IP phone, as exploited in the wild per CISA KEV.

CVE-2020-3580: Chain: improper input validation (CWE-20) in firewall product leads to XSS (CWE-79), as exploited in the wild per CISA KEV.

CVE-2021-37147: Chain: caching proxy server has improper input validation (CWE-20) of headers, allowing HTTP response smuggling (CWE-444) using an "LF line ending"

CVE-2008-5305: Eval injection in Perl program using an ID that should only contain hyphens and numbers.

CVE-2008-2223: SQL injection through an ID that was supposed to be numeric.

CVE-2008-3477: lack of input validation in spreadsheet program leads to buffer overflows, integer overflows, array index errors, and memory corruption.

CVE-2008-3843: insufficient validation enables XSS

CVE-2008-3174: driver in security product allows code execution due to insufficient validation

CVE-2007-3409: infinite loop from DNS packet with a label that points to itself

CVE-2006-6870: infinite loop from DNS packet with a label that points to itself

CVE-2008-1303: missing parameter leads to crash

CVE-2007-5893: HTTP request with missing protocol version number leads to crash

CVE-2006-6658: request with missing parameters leads to information exposure

CVE-2008-4114: system crash with offset value that is inconsistent with packet size

CVE-2006-3790: size field that is inconsistent with packet size leads to buffer over-read

CVE-2008-2309: product uses a denylist to identify potentially dangerous content, allowing attacker to bypass a warning

CVE-2008-3494: security bypass via an extra header

CVE-2008-3571: empty packet triggers reboot

CVE-2006-5525: incomplete denylist allows SQL injection

CVE-2008-1284: NUL byte in theme name causes directory traversal impact to be worse

CVE-2008-0600: kernel does not validate an incoming pointer before dereferencing it

CVE-2008-1738: anti-virus product has insufficient input validation of hooked SSDT functions, allowing code execution

CVE-2008-1737: anti-virus product allows DoS via zero-length field

CVE-2008-3464: driver does not validate input from userland to the kernel

CVE-2008-2252: kernel does not validate parameters sent in from userland, allowing code execution

CVE-2008-2374: lack of validation of string length fields allows memory consumption or buffer over-read

CVE-2008-1440: lack of validation of length field leads to infinite loop

CVE-2008-1625: lack of validation of input to an IOCTL allows code execution

CVE-2008-3177: zero-length attachment causes crash

CVE-2007-2442: zero-length input causes free of uninitialized pointer

CVE-2008-5563: crash via a malformed frame structure

CVE-2008-5285: infinite loop from a long SMTP request

CVE-2008-3812: router crashes with a malformed packet

CVE-2008-3680: packet with invalid version number leads to NULL pointer dereference

CVE-2008-3660: crash via multiple "." characters in file extension

## Top 25 Examples

CVE-2021-0674: In alac decoder, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06064258; Issue ID: ALPS06064237.

CVE-2021-0676: In geniezone driver, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05863009; Issue ID: ALPS05863009.

CVE-2021-0678: In apusys, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05722511.

CVE-2021-0895: In apusys, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05672003.

CVE-2021-0896: In apusys, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05671206.

CVE-2021-0900: In apusys, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05672055.

CVE-2021-0902: In apusys, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05656484.

CVE-2021-0903: In apusys, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05672107; Issue ID: ALPS05656488.

CVE-2021-21891: A stack-based buffer overflow vulnerability exists in the Web Manager FsBrowseClean functionality of Lantronix PremierWave 2050 8.9.0.0R4 (in QEMU). A specially crafted HTTP request can lead to remote code execution in the vulnerable portion of the branch (deletefile). An attacker can make an authenticated HTTP request to trigger this vulnerability.

CVE-2021-21892: A stack-based buffer overflow vulnerability exists in the Web Manager FsUnmount functionality of Lantronix PremierWave 2050 8.9.0.0R4 (in QEMU). A specially crafted HTTP request can lead to remote code execution. An attacker can make an authenticated HTTP request to trigger this vulnerability.

CVE-2021-21903: A stack-based buffer overflow vulnerability exists in the CMA check_udp_crc function of Garrett Metal Detectors’ iC Module CMA Version 5.0. A specially-crafted packet can lead to a stack-based buffer overflow during a call to strcpy. An attacker can send a malicious packet to trigger this vulnerability.

CVE-2021-21905: Stack-based buffer overflow vulnerability exists in how the CMA readfile function of Garrett Metal Detectors iC Module CMA Version 5.0 is used at various locations. The Garrett iC Module exposes an authenticated CLI over TCP port 6877. This interface is used by a secondary GUI client, called “CMA Connect”, to interact with the iC Module on behalf of the user. After a client successfully authenticates, they can send plaintext commands to manipulate the device.

CVE-2021-23138: WECON LeviStudioU Versions 2019-09-21 and prior are vulnerable to a stack-based buffer overflow, which may allow an attacker to remotely execute code.

CVE-2021-29568: TensorFlow is an end-to-end open source platform for machine learning. An attacker can trigger undefined behavior by binding to null pointer in `tf.raw_ops.ParameterizedTruncatedNormal`. This is because the implementation(https://github.com/tensorflow/tensorflow/blob/3f6fe4dfef6f57e768260b48166c27d148f3015f/tensorflow/core/kernels/parameterized_truncated_normal_op.cc#L630) does not validate input arguments before accessing the first element of `shape`. If `shape` argument is empty, then `shape_tensor.flat<T>()` is an empty array. The fix will be included in TensorFlow 2.5.0. We will also cherrypick this commit on TensorFlow 2.4.2, TensorFlow 2.3.3, TensorFlow 2.2.3 and TensorFlow 2.1.4, as these are also affected and still in supported range.

CVE-2021-30289: Possible buffer overflow due to lack of range check while processing a DIAG command for COEX management in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-32040: It may be possible to have an extremely long aggregation pipeline in conjunction with a specific stage/operator and cause a stack overflow due to the size of the stack frames used by that stage. If an attacker could cause such an aggregation to occur, they could maliciously crash MongoDB in a DoS attack. This vulnerability affects MongoDB Server v4.4 versions prior to and including 4.4.28, MongoDB Server v5.0 versions prior to 5.0.4 and MongoDB Server v4.2 versions prior to 4.2.16. Workaround: >= v4.2.16 users and all v4.4 users can add the --setParameter internalPipelineLengthLimit=50 instead of the default 1000 to mongod at startup to prevent a crash. 

CVE-2021-34874: This vulnerability allows remote attackers to execute arbitrary code on affected installations of Bentley View 10.15.0.75. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the processing of 3DS files. The issue results from the lack of proper validation of user-supplied data, which can result in a memory corruption condition. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-14736.

CVE-2021-34934: This vulnerability allows remote attackers to execute arbitrary code on affected installations of Bentley View 10.15.0.75. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of JT files. The issue results from the lack of proper validation of user-supplied data, which can result in a memory corruption condition. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-14912.

CVE-2021-35005: This vulnerability allows local attackers to disclose sensitive information on affected installations of TeamViewer. An attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability. The specific flaw exists within the TeamViewer service. The issue results from the lack of proper validation of user-supplied data, which can result in a read past the end of an allocated array. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-13818.

CVE-2021-35098: Improper validation of session id in PCM routing process can lead to memory corruption in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-35134: Due to insufficient validation of ELF headers, an Incorrect Calculation of Buffer Size can occur in Boot leading to memory corruption in Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2021-37404: There is a potential heap buffer overflow in Apache Hadoop libhdfs native code. Opening a file path provided by user without validation may result in a denial of service or arbitrary code execution. Users should upgrade to Apache Hadoop 2.10.2, 3.2.3, 3.3.2 or higher.

CVE-2021-39623: In doRead of SimpleDecodingSource.cpp, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-194105348

CVE-2021-39708: In gatt_process_notification of gatt_cl.cc, there is a possible out of bounds write due to an incorrect bounds check. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-206128341

CVE-2021-39805: In l2cble_process_sig_cmd of l2c_ble.cc, there is a possible out of bounds read due to a missing bounds check. This could lead to remote information disclosure through Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-212694559

CVE-2021-44016: A vulnerability has been identified in JT2Go (All versions < V13.2.0.7), Solid Edge SE2021 (All versions < SE2021MP9), Solid Edge SE2022 (All versions < SE2022MP1), Teamcenter Visualization V13.1 (All versions < V13.1.0.9), Teamcenter Visualization V13.2 (All versions < V13.2.0.7), Teamcenter Visualization V13.3 (All versions < V13.3.0.1). The plmxmlAdapterSE70.dll library is vulnerable to memory corruption condition while parsing specially crafted PAR files. An attacker could leverage this vulnerability to execute code in the context of the current process. (ZDI-CAN-15110)

CVE-2021-44422: An Improper Input Validation Vulnerability exists when reading a BMP file using Open Design Alliance Drawings SDK before 2022.12. Crafted data in a BMP file can trigger a write operation past the end of an allocated buffer, or lead to a heap-based buffer overflow. An attacker can leverage this vulnerability to execute code in the context of the current process.

CVE-2021-46153: A vulnerability has been identified in Simcenter Femap V2020.2 (All versions), Simcenter Femap V2021.1 (All versions). Affected application contains a memory corruption vulnerability while parsing NEU files. This could allow an attacker to execute code in the context of the current process. (ZDI-CAN-14645, ZDI-CAN-15305, ZDI-CAN-15589, ZDI-CAN-15599)

CVE-2021-46157: A vulnerability has been identified in Simcenter Femap V2020.2 (All versions), Simcenter Femap V2021.1 (All versions). Affected application contains a memory corruption vulnerability while parsing NEU files. This could allow an attacker to execute code in the context of the current process. (ZDI-CAN-14757)

CVE-2021-46598: This vulnerability allows remote attackers to execute arbitrary code on affected installations of Bentley MicroStation CONNECT 10.16.0.80. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of JT files. The issue results from the lack of proper validation of user-supplied data, which can result in a memory corruption condition. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-15392.

CVE-2021-46768: Insufficient input validation in SEV firmware may allow an attacker to perform out-of-bounds memory reads within the ASP boot loader, potentially leading to a denial of service. 

CVE-2022-20014: In vow driver, there is a possible memory corruption due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05857308; Issue ID: ALPS05857308.

CVE-2022-20038: In ccu driver, there is a possible memory corruption due to an incorrect bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06183335; Issue ID: ALPS06183335.

CVE-2022-20070: In ssmr, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is no needed for exploitation. Patch ID: ALPS06362920; Issue ID: ALPS06362920.

CVE-2022-20201: In getAppSize of InstalldNativeService.cpp, there is a possible out of bounds read due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-220733817

CVE-2022-20237: In BuildDevIDResponse of miscdatabuilder.cpp, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-229621649References: N/A

CVE-2022-20513: In decrypt_1_2 of CryptoPlugin.cpp, there is a possible out of bounds read due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-244569759

CVE-2022-20569: In thermal_cooling_device_stats_update of thermal_sysfs.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege in the kernel with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-229258234References: N/A

CVE-2022-20574: In sec_sysmmu_info of drm_fw.c, there is a possible out of bounds read due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-237582191References: N/A

CVE-2022-21765: In CCCI, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06641673; Issue ID: ALPS06641673.

CVE-2022-21766: In CCCI, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06641673; Issue ID: ALPS06641653.

CVE-2022-21784: In WLAN driver, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06704526; Issue ID: ALPS06704462.

CVE-2022-22070: Memory corruption in audio due to lack of check of invalid routing address into APR Routing table in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2022-22080: Improper validation of backend id in PCM routing process can lead to memory corruption in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music

CVE-2022-22627: An out-of-bounds read was addressed with improved bounds checking. This issue is fixed in macOS Big Sur 11.6.5, macOS Monterey 12.3, Security Update 2022-003 Catalina. Processing a maliciously crafted AppleScript binary may result in unexpected application termination or disclosure of process memory.

CVE-2022-23095: Open Design Alliance Drawings SDK before 2022.12.1 mishandles the loading of JPG files. Unchecked input data from a crafted JPG file leads to memory corruption. An attacker can leverage this vulnerability to execute code in the context of the current process.

CVE-2022-24313: A CWE-120: Buffer Copy without Checking Size of Input vulnerability exists that could cause a stack-based buffer overflow potentially leading to remote code execution when an attacker sends a specially crafted message. Affected Product: Interactive Graphical SCADA System Data Server (V15.0.0.22020 and prior)

CVE-2022-25654: Memory corruption in kernel due to improper input validation while processing ION commands in Snapdragon Auto, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Wearables

CVE-2022-25697: Memory corruption in i2c buses due to improper input validation while reading address configuration from i2c driver in Snapdragon Mobile, Snapdragon Wearables

CVE-2022-25698: Memory corruption in SPI buses due to improper input validation while reading address configuration from spi buses in Snapdragon Mobile, Snapdragon Wearables

CVE-2022-26447: In BT firmware, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06784478; Issue ID: ALPS06784478.

CVE-2022-26475: In wlan, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07310743; Issue ID: ALPS07310743.

CVE-2022-26723: A memory corruption issue was addressed with improved input validation. This issue is fixed in macOS Monterey 12.4, macOS Big Sur 11.6.6. Mounting a maliciously crafted Samba network share may lead to arbitrary code execution.

CVE-2022-26730: A memory corruption issue existed in the processing of ICC profiles. This issue was addressed with improved input validation. This issue is fixed in macOS Ventura 13. Processing a maliciously crafted image may lead to arbitrary code execution.

CVE-2022-28193: NVIDIA Jetson Linux Driver Package contains a vulnerability in the Cboot module tegrabl_cbo.c, where insufficient validation of untrusted data may allow a local attacker with elevated privileges to cause a memory buffer overflow, which may lead to code execution, loss of integrity, limited denial of service, and some impact to confidentiality.

CVE-2022-28196: NVIDIA Jetson Linux Driver Package contains a vulnerability in the Cboot blob_decompress function, where insufficient validation of untrusted data may allow a local attacker with elevated privileges to cause a memory buffer overflow, which may lead to code execution, limited loss of Integrity, and limited denial of service. The scope of impact can extend to other components.

CVE-2022-3045: Insufficient validation of untrusted input in V8 in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-32593: In vowe, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07138493; Issue ID: ALPS07138493.

CVE-2022-32595: In widevine, there is a possible out of bounds read due to an incorrect bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07446236; Issue ID: ALPS07446236.

CVE-2022-32603: In gpu drm, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07310704; Issue ID: ALPS07310704.

CVE-2022-32631: In Wi-Fi, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07453613; Issue ID: ALPS07453613.

CVE-2022-32632: In Wi-Fi, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07441630; Issue ID: ALPS07441630.

CVE-2022-32634: In ccci, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07138646; Issue ID: ALPS07138646.

CVE-2022-32635: In gps, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07573237; Issue ID: ALPS07573237.

CVE-2022-32636: In keyinstall, there is a possible out of bounds write due to an integer overflow. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07510064; Issue ID: ALPS07510064.

CVE-2022-32637: In hevc decoder, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07491374; Issue ID: ALPS07491374.

CVE-2022-32639: In watchdog, there is a possible out of bounds read due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494487; Issue ID: ALPS07494487.

CVE-2022-32640: In meta wifi, there is a possible out of bounds write due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07441652; Issue ID: ALPS07441652.

CVE-2022-32641: In meta wifi, there is a possible out of bounds read due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07453594; Issue ID: ALPS07453594.

CVE-2022-32646: In gpu drm, there is a possible stack overflow due to a missing bounds check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07363501; Issue ID: ALPS07363501.

CVE-2022-32647: In ccu, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07554646; Issue ID: ALPS07554646.

CVE-2022-32821: A memory corruption issue was addressed with improved validation. This issue is fixed in watchOS 8.7, tvOS 15.6, iOS 15.6 and iPadOS 15.6, macOS Monterey 12.5. An app may be able to execute arbitrary code with kernel privileges.

CVE-2022-33218: Memory corruption in Automotive due to improper input validation.

CVE-2022-33300: Memory corruption in Automotive Android OS due to improper input validation.

CVE-2022-33719: Improper input validation in baseband prior to SMR Aug-2022 Release 1 allows attackers to cause integer overflow to heap overflow.

CVE-2022-3377: Horner Automation's Cscape version 9.90 SP 6 and prior does not properly validate user-supplied data. If a user opens a maliciously formed FNT file, then an attacker could execute arbitrary code within the current process by accessing an uninitialized pointer, leading to an out-of-bounds memory read. 

CVE-2022-3378:  Horner Automation's Cscape version 9.90 SP 7 and prior does not properly validate user-supplied data. If a user opens a maliciously formed FNT file, then an attacker could execute arbitrary code within the current process by accessing an uninitialized pointer, leading to an out-of-bounds memory write. 

CVE-2022-35218: The NHI card’s web service component has a heap-based buffer overflow vulnerability due to insufficient validation for packet origin parameter length. A LAN attacker with general user privilege can exploit this vulnerability to disrupt service.

CVE-2022-35219: The NHI card’s web service component has a stack-based buffer overflow vulnerability due to insufficient validation for network packet key parameter. A LAN attacker with general user privilege can exploit this vulnerability to disrupt service.

CVE-2022-42377: This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of U3D files. The issue results from the lack of proper validation of user-supplied data, which can result in a memory corruption condition. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18630.

CVE-2022-42498: In Pixel cellular firmware, there is a possible out of bounds write due to a missing bounds check. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-240662453References: N/A

CVE-2022-48423: In the Linux kernel before 6.1.3, fs/ntfs3/record.c does not validate resident attribute names. An out-of-bounds write may occur.

CVE-2021-3442: A flaw was found in the Red Hat OpenShift API Management product. User input is not validated allowing an authenticated user to inject scripts into some text boxes leading to a XSS attack. The highest threat from this vulnerability is to data confidentiality.

CVE-2021-21906: Stack-based buffer overflow vulnerability exists in how the CMA readfile function of Garrett Metal Detectors iC Module CMA Version 5.0 is used at various locations. The Garrett iC Module exposes an authenticated CLI over TCP port 6877. This interface is used by a secondary GUI client, called “CMA Connect”, to interact with the iC Module on behalf of the user. Every time a user submits a password to the CLI password prompt, the buffer containing their input is passed as the password parameter to the checkPassword function.

CVE-2022-43762:  Lack of verification in B&R APROL Tbase server versions < R 4.2-07 may lead to memory leaks when receiving messages 

CVE-2021-1594: A vulnerability in the REST API of Cisco Identity Services Engine (ISE) could allow an unauthenticated, remote attacker to perform a command injection attack and elevate privileges to root. This vulnerability is due to insufficient input validation for specific API endpoints. An attacker in a man-in-the-middle position could exploit this vulnerability by intercepting and modifying specific internode communications from one ISE persona to another ISE persona. A successful exploit could allow the attacker to run arbitrary commands with root privileges on the underlying operating system. To exploit this vulnerability, the attacker would need to decrypt HTTPS traffic between two ISE personas that are located on separate nodes.

CVE-2021-29854: IBM Maximo Asset Management 7.6.1.1 and 7.6.1.2 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. By sending a specially crafted HTTP request, a remote attacker could exploit this vulnerability to inject HTTP HOST header, which will allow the attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 205680.

CVE-2021-38997: IBM API Connect V10.0.0.0 through V10.0.5.0, V10.0.1.0 through V10.0.1.7, and V2018.4.1.0 through 2018.4.1.19 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 213212.

CVE-2021-39028: IBM Engineering Lifecycle Optimization - Publishing 6.0.6, 6.0.6.1, 7.0, 7.0.1, and 7.0.2 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 213866.

CVE-2022-0073: Improper Input Validation vulnerability in LiteSpeed Technologies OpenLiteSpeed Web Server and LiteSpeed Web Server dashboards allows Command Injection. This affects 1.7.0 versions before 1.7.16.1. 

CVE-2022-20713: A vulnerability in the VPN web client services component of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct browser-based attacks against users of an affected device. This vulnerability is due to improper validation of input that is passed to the VPN web client services component before being returned to the browser that is in use. An attacker could exploit this vulnerability by persuading a user to visit a website that is designed to pass malicious requests to a device that is running Cisco ASA Software or Cisco FTD Software and has web services endpoints supporting VPN features enabled. A successful exploit could allow the attacker to reflect malicious input from the affected device to the browser that is in use and conduct browser-based attacks, including cross-site scripting attacks. The attacker could not directly impact the affected device.

CVE-2022-20725: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-20727: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-20852: Multiple vulnerabilities in the web interface of Cisco Webex Meetings could allow a remote attacker to conduct a cross-site scripting (XSS) attack or a frame hijacking attack against a user of the web interface. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-22344: IBM Spectrum Copy Data Management 2.2.0.0 through 2.2.14.3 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 220038

CVE-2022-24881: Ballcat Codegen provides the function of online editing code to generate templates. In versions prior to 1.0.0.beta.2, attackers can implement remote code execution through malicious code injection of the template engine. This happens because Velocity and freemarker templates are introduced but input verification is not done. The fault is rectified in version 1.0.0.beta.2.

CVE-2022-24926: Improper input validation vulnerability in SmartTagPlugin prior to version 1.2.15-6 allows privileged attackers to trigger a XSS on a victim's devices.

CVE-2022-26889: In Splunk Enterprise versions before 8.1.2, the uri path to load a relative resource within a web page is vulnerable to path traversal. It allows an attacker to potentially inject arbitrary content into the web page (e.g., HTML Injection, XSS) or bypass SPL safeguards for risky commands. The attack is browser-based. An attacker cannot exploit the attack at will and requires the attacker to initiate a request within the victim's browser (e.g., phishing).

CVE-2022-29539: resi-calltrace in RESI Gemini-Net 4.2 is affected by OS Command Injection. It does not properly check the parameters sent as input before they are processed on the server. Due to the lack of validation of user input, an unauthenticated attacker can bypass the syntax intended by the software (e.g., concatenate `&|;\\r\\ commands) and inject arbitrary system commands with the privileges of the application user.

CVE-2022-31898: gl-inet GL-MT300N-V2 Mango v3.212 and GL-AX1800 Flint v3.214 were discovered to contain multiple command injection vulnerabilities via the ping_addr and trace_addr function parameters.

CVE-2022-34165: IBM WebSphere Application Server 7.0, 8.0, 8.5, and 9.0 and IBM WebSphere Application Server Liberty 17.0.0.3 through 22.0.0.9 are vulnerable to HTTP header injection, caused by improper validation. This could allow an attacker to conduct various attacks against the vulnerable system, including cache poisoning and cross-site scripting. IBM X-Force ID: 229429.

CVE-2022-34306: IBM CICS TX Standard and Advanced 11.1 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 229435.

CVE-2022-34362:  IBM Sterling Secure Proxy 6.0.3 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 230523. 

CVE-2022-35739: PRTG Network Monitor through 22.2.77.2204 does not prevent custom input for a device’s icon, which can be modified to insert arbitrary content into the style tag for that device. When the device page loads, the arbitrary Cascading Style Sheets (CSS) data is inserted into the style tag, loading malicious content. Due to PRTG Network Monitor preventing “characters, and from modern browsers disabling JavaScript support in style tags, this vulnerability could not be escalated into a Cross-Site Scripting vulnerability.

CVE-2022-36775: IBM Security Verify Access 10.0.0.0, 10.0.1.0, 10.0.2.0, 10.0.3.0, and10.0.4.0 is vulnerable to HTTP header injection, caused by improper validation of input by the HOST headers. This could allow an attacker to conduct various attacks against the vulnerable system, including cross-site scripting, cache poisoning or session hijacking. IBM X-Force ID: 233576.

CVE-2022-36859: Improper input validation vulnerability in SmartTagPlugin prior to version 1.2.21-6 allows privileged attackers to trigger a XSS on a victim&#39;s devices.

CVE-2022-3721: Code Injection in GitHub repository froxlor/froxlor prior to 0.10.39.

CVE-2022-39056: RAVA certificate validation system has insufficient validation for user input. An unauthenticated remote attacker can inject arbitrary SQL command to access, modify and delete database.

CVE-2022-39072: There is a SQL injection vulnerability in Some ZTE Mobile Internet products. Due to insufficient validation of the input parameters of the SNTP interface, an authenticated attacker could use the vulnerability to execute stored XSS attacks.

CVE-2022-40743: Improper Input Validation vulnerability for the xdebug plugin in Apache Software Foundation Apache Traffic Server can lead to cross site scripting and cache poisoning attacks.This issue affects Apache Traffic Server: 9.0.0 to 9.1.3. Users should upgrade to 9.1.4 or later versions. 

CVE-2022-41942: Sourcegraph is a code intelligence platform. In versions prior to 4.1.0 a command Injection vulnerability existed in the gitserver service, present in all Sourcegraph deployments. This vulnerability was caused by a lack of input validation on the host parameter of the `/list-gitolite` endpoint. It was possible to send a crafted request to gitserver that would execute commands inside the container. Successful exploitation requires the ability to send local requests to gitserver. The issue is patched in version 4.1.0.

CVE-2022-43562: In Splunk Enterprise versions below 8.1.12, 8.2.9, and 9.0.2, Splunk Enterprise fails to properly validate and escape the Host header, which could let a remote authenticated user conduct various attacks against the system, including cross-site scripting and cache poisoning. 

CVE-2022-4427: Improper Input Validation vulnerability in OTRS AG OTRS, OTRS AG ((OTRS)) Community Edition allows SQL Injection via TicketSearch Webservice This issue affects OTRS: from 7.0.1 before 7.0.40 Patch 1, from 8.0.1 before 8.0.28 Patch 1; ((OTRS)) Community Edition: from 6.0.1 through 6.0.34. 

CVE-2022-4466: The WordPress Infinite Scroll WordPress plugin before 5.6.0.3 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

CVE-2022-45470: missing input validation in Apache Hama may cause information disclosure through path traversal and XSS. Since Apache Hama is EOL, we do not expect these issues to be fixed.

CVE-2022-4557: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') vulnerability in Group Arge Energy and Control Systems Smartpower Web allows SQL Injection.This issue affects Smartpower Web: before 23.01.01. 

CVE-2022-47208: The “puhttpsniff” service, which runs by default, is susceptible to command injection due to improperly sanitized user input. An unauthenticated attacker on the same network segment as the router can execute arbitrary commands on the device without authentication.

CVE-2022-48069: Totolink A830R V4.1.2cu.5182 was discovered to contain a command injection vulnerability via the QUERY_STRING parameter.

CVE-2022-3215: NIOHTTP1 and projects using it for generating HTTP responses can be subject to a HTTP Response Injection attack. This occurs when a HTTP/1.1 server accepts user generated input from an incoming request and reflects it into a HTTP/1.1 response header in some form. A malicious user can add newlines to their input (usually in encoded form) and "inject" those newlines into the returned HTTP response. This capability allows users to work around security headers and HTTP/1.1 framing headers by injecting entirely false responses or other new headers. The injected false responses may also be treated as the response to subsequent requests, which can lead to XSS, cache poisoning, and a number of other flaws. This issue was resolved by adding validation to the HTTPHeaders type, ensuring that there's no whitespace incorrectly present in the HTTP headers provided by users. As the existing API surface is non-failable, all invalid characters are replaced by linear whitespace.

CVE-2022-28215: SAP NetWeaver ABAP Server and ABAP Platform - versions 740, 750, 787, allows an unauthenticated attacker to redirect users to a malicious site due to insufficient URL validation. This could lead to the user being tricked to disclose personal information.

CVE-2022-29081: Zoho ManageEngine Access Manager Plus before 4302, Password Manager Pro before 12007, and PAM360 before 5401 are vulnerable to access-control bypass on a few Rest API URLs (for SSOutAction. SSLAction. LicenseMgr. GetProductDetails. GetDashboard. FetchEvents. and Synchronize) via the ../RestAPI substring.

CVE-2022-34179: Jenkins Embeddable Build Status Plugin 2.0.3 and earlier allows specifying a `style` query parameter that is used to choose a different SVG image style without restricting possible values, resulting in a relative path traversal vulnerability that allows attackers without Overall/Read permission to specify paths to other SVG images on the Jenkins controller file system.

CVE-2022-35650: The vulnerability was found in Moodle, occurs due to input validation error when importing lesson questions. This insufficient path checks results in arbitrary file read risk. This vulnerability allows a remote attacker to perform directory traversal attacks. The capability to access this feature is only available to teachers, managers and admins by default.

CVE-2022-35861: pyenv 1.2.24 through 2.3.2 allows local users to gain privileges via a .python-version file in the current working directory. An attacker can craft a Python version string in .python-version to execute shims under their control. (Shims are executables that pass a command along to a specific version of pyenv. The version string is used to construct the path to the command, and there is no validation of whether the version specified is a valid version. Thus, relative path traversal can occur.)

CVE-2022-41215: SAP NetWeaver ABAP Server and ABAP Platform allows an unauthenticated attacker to redirect users to a malicious site due to insufficient URL validation. This could lead to the user being tricked to disclose personal information. 

CVE-2022-27836: Improper access control and path traversal vulnerability in Storage Manager and Storage Manager Service prior to SMR Apr-2022 Release 1 allow local attackers to access arbitrary system files without a proper permission. The patch adds proper validation logic to prevent arbitrary files access.

CVE-2021-34854: This vulnerability allows local attackers to escalate privileges on affected installations of Parallels Desktop 16.1.3 (49160). An attacker must first obtain the ability to execute low-privileged code on the target guest system in order to exploit this vulnerability. The specific flaw exists within the Toolgate component. The issue results from the lack of proper validation of user-supplied data, which can result in an uncontrolled memory allocation. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of the hypervisor. Was ZDI-CAN-13544.

CVE-2022-20079: In vow, there is a possible read of uninitialized data due to a improper input validation. This could lead to local information disclosure with System execution privileges needed. User interaction is no needed for exploitation. Patch ID: ALPS05837742; Issue ID: ALPS05857289.

CVE-2022-20176: In auth_store of sjtag-driver.c, there is a possible read of uninitialized memory due to a missing bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-197787879References: N/A

CVE-2022-29204: TensorFlow is an open source platform for machine learning. Prior to versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4, the implementation of `tf.raw_ops.UnsortedSegmentJoin` does not fully validate the input arguments. This results in a `CHECK`-failure which can be used to trigger a denial of service attack. The code assumes `num_segments` is a positive scalar but there is no validation. Since this value is used to allocate the output tensor, a negative value would result in a `CHECK`-failure (assertion failure), as per TFSA-2021-198. Versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4 contain a patch for this issue.

CVE-2021-35247: Serv-U web login screen to LDAP authentication was allowing characters that were not sufficiently sanitized. SolarWinds has updated the input mechanism to perform additional validation and sanitization. Please Note: No downstream affect has been detected as the LDAP servers ignored improper characters. To insure proper input validation is completed in all environments. SolarWinds recommends scheduling an update to the latest version of Serv-U.

CVE-2022-24086: Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

CVE-2022-29499: The Service Appliance component in Mitel MiVoice Connect through 19.2 SP3 allows remote code execution because of incorrect data validation. The Service Appliances are SA 100, SA 400, and Virtual SA.

CVE-2022-3075: Insufficient data validation in Mojo in Google Chrome prior to 105.0.5195.102 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

CVE-2021-21220: Insufficient validation of untrusted input in V8 in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-21973: The vSphere Client (HTML5) contains an SSRF (Server Side Request Forgery) vulnerability due to improper validation of URLs in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue by sending a POST request to vCenter Server plugin leading to information disclosure. This affects: VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

CVE-2021-22205: An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.9. GitLab was not properly validating image files that were passed to a file parser which resulted in a remote command execution.

CVE-2021-22502: Remote Code execution vulnerability in Micro Focus Operation Bridge Reporter (OBR) product, affecting version 10.40. The vulnerability could be exploited to allow Remote Code Execution on the OBR server.

CVE-2021-27102: Accellion FTA 9_12_411 and earlier is affected by OS command execution via a local web service call. The fixed version is FTA_9_12_416 and later.

CVE-2021-27104: Accellion FTA 9_12_370 and earlier is affected by OS command execution via a crafted POST request to various admin endpoints. The fixed version is FTA_9_12_380 and later.

CVE-2021-30663: An integer overflow was addressed with improved input validation. This issue is fixed in iOS 14.5.1 and iPadOS 14.5.1, tvOS 14.6, iOS 12.5.3, Safari 14.1.1, macOS Big Sur 11.3.1. Processing maliciously crafted web content may lead to arbitrary code execution.

CVE-2021-30860: An integer overflow was addressed with improved input validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. Processing a maliciously crafted PDF may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

CVE-2021-30900: An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 14.8.1 and iPadOS 14.8.1, iOS 15.1 and iPadOS 15.1. A malicious application may be able to execute arbitrary code with kernel privileges.

CVE-2021-31010: A deserialization issue was addressed through improved validation. This issue is fixed in Security Update 2021-005 Catalina, iOS 12.5.5, iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6, watchOS 7.6.2. A sandboxed process may be able to circumvent sandbox restrictions. Apple was aware of a report that this issue may have been actively exploited at the time of release..

CVE-2021-31207: Microsoft Exchange Server Security Feature Bypass Vulnerability

CVE-2021-35395: Realtek Jungle SDK version v2.x up to v3.4.14B provides an HTTP web server exposing a management interface that can be used to configure the access point. Two versions of this management interface exists: one based on Go-Ahead named webs and another based on Boa named boa. Both of them are affected by these vulnerabilities. Specifically, these binaries are vulnerable to the following issues: - stack buffer overflow in formRebootCheck due to unsafe copy of submit-url parameter - stack buffer overflow in formWsc due to unsafe copy of submit-url parameter - stack buffer overflow in formWlanMultipleAP due to unsafe copy of submit-url parameter - stack buffer overflow in formWlSiteSurvey due to unsafe copy of ifname parameter - stack buffer overflow in formStaticDHCP due to unsafe copy of hostname parameter - stack buffer overflow in formWsc due to unsafe copy of 'peerPin' parameter - arbitrary command execution in formSysCmd via the sysCmd parameter - arbitrary command injection in formWsc via the 'peerPin' parameter Exploitability of identified issues will differ based on what the end vendor/manufacturer did with the Realtek SDK webserver. Some vendors use it as-is, others add their own authentication implementation, some kept all the features from the server, some remove some of them, some inserted their own set of features. However, given that Realtek SDK implementation is full of insecure calls and that developers tends to re-use those examples in their custom code, any binary based on Realtek SDK webserver will probably contains its own set of issues on top of the Realtek ones (if kept). Successful exploitation of these issues allows remote attackers to gain arbitrary code execution on the device.

CVE-2021-36741: An improper input validation vulnerability in Trend Micro Apex One, Apex One as a Service, OfficeScan XG, and Worry-Free Business Security 10.0 SP1 allows a remote attached to upload arbitrary files on affected installations. Please note: an attacker must first obtain the ability to logon to the product?s management console in order to exploit this vulnerability.

CVE-2021-36742: A improper input validation vulnerability in Trend Micro Apex One, Apex One as a Service, OfficeScan XG and Worry-Free Business Security 10.0 SP1 allows a local attacker to escalate privileges on affected installations. Please note: an attacker must first obtain the ability to execute low-privileged code on the target system in order to exploit this vulnerability.

CVE-2021-38406: Delta Electronic DOPSoft 2 (Version 2.00.07 and prior) lacks proper validation of user-supplied data when parsing specific project files. This could result in multiple out-of-bounds write instances. An attacker could leverage this vulnerability to execute code in the context of the current process.

CVE-2021-4034: A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

CVE-2022-20708: Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-22587: A memory corruption issue was addressed with improved input validation. This issue is fixed in iOS 15.3 and iPadOS 15.3, macOS Big Sur 11.6.3, macOS Monterey 12.2. A malicious application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited..

CVE-2022-22674: An out-of-bounds read issue existed that led to the disclosure of kernel memory. This was addressed with improved input validation. This issue is fixed in macOS Monterey 12.3.1, Security Update 2022-004 Catalina, macOS Big Sur 11.6.6. A local user may be able to read kernel memory.

CVE-2022-22675: An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in tvOS 15.5, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.3.1, iOS 15.4.1 and iPadOS 15.4.1. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited..

CVE-2022-32893: An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.6.1 and iPadOS 15.6.1, macOS Monterey 12.5.1, Safari 15.6.1. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

CVE-2022-32894: An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.6.1 and iPadOS 15.6.1, macOS Monterey 12.5.1. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited.

CVE-2022-32917: The issue was addressed with improved bounds checks. This issue is fixed in macOS Monterey 12.6, iOS 15.7 and iPadOS 15.7, iOS 16, macOS Big Sur 11.7. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited..

CVE-2022-37969: Windows Common Log File System Driver Elevation of Privilege Vulnerability

CVE-2022-39197: An XSS (Cross Site Scripting) vulnerability was found in HelpSystems Cobalt Strike through 4.7 that allowed a remote attacker to execute HTML on the Cobalt Strike teamserver. To exploit the vulnerability, one must first inspect a Cobalt Strike payload, and then modify the username field in the payload (or create a new payload with the extracted information and then modify that username field to be malformed).

CVE-2022-42827: An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 15.7.1 and iPadOS 15.7.1, iOS 16.1 and iPadOS 16. An application may be able to execute arbitrary code with kernel privileges. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-30713: A permissions issue was addressed with improved validation. This issue is fixed in macOS Big Sur 11.4. A malicious application may be able to bypass Privacy preferences. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-42278: Active Directory Domain Services Elevation of Privilege Vulnerability

CVE-2022-26019: Improper access control vulnerability in pfSense CE and pfSense Plus (pfSense CE software versions prior to 2.6.0 and pfSense Plus software versions prior to 22.01) allows a remote attacker with the privilege to change NTP GPS settings to rewrite existing files on the file system, which may result in arbitrary command execution.

CVE-2022-42344: Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Incorrect Authorization vulnerability. An authenticated attacker can exploit this vulnerability to achieve information exposure and privilege escalation.

CVE-2022-22423: IBM Common Cryptographic Architecture (CCA 5.x MTM for 4767 and CCA 7.x MTM for 4769) could allow a local user to cause a denial of service due to improper input validation. IBM X-Force ID: 223596.

CVE-2022-31036: Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. All versions of Argo CD starting with v1.3.0 are vulnerable to a symlink following bug allowing a malicious user with repository write access to leak sensitive YAML files from Argo CD's repo-server. A malicious Argo CD user with write access for a repository which is (or may be) used in a Helm-type Application may commit a symlink which points to an out-of-bounds file. If the target file is a valid YAML file, the attacker can read the contents of that file. Sensitive files which could be leaked include manifest files from other Applications' source repositories (potentially decrypted files, if you are using a decryption plugin) or any YAML-formatted secrets which have been mounted as files on the repo-server. Patches for this vulnerability has been released in the following Argo CD versions: v2.4.1, v2.3.5, v2.2.10 and v2.1.16. If you are using a version >=v2.3.0 and do not have any Helm-type Applications you may disable the Helm config management tool as a workaround.

CVE-2021-26622: An remote code execution vulnerability due to SSTI vulnerability and insufficient file name parameter validation was discovered in Genian NAC. Remote attackers are able to execute arbitrary malicious code with SYSTEM privileges on all connected nodes in NAC through this vulnerability.

CVE-2022-20958: A vulnerability in the web-based management interface of Cisco BroadWorks CommPilot application could allow an unauthenticated, remote attacker to perform a server-side request forgery (SSRF) attack on an affected device. This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted HTTP request to the web interface. A successful exploit could allow the attacker to obtain confidential information from the BroadWorks server and other device on the network. {{value}} ["%7b%7bvalue%7d%7d"])}]] 

CVE-2022-2165: Insufficient data validation in URL formatting in Google Chrome prior to 103.0.5060.53 allowed a remote attacker to perform domain spoofing via IDN homographs via a crafted domain name.

CVE-2021-0943: In MMU_MapPages of TBD, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android SoCAndroid ID: A-238916921

CVE-2021-1573: A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to trigger a denial of service (DoS) condition. This vulnerability is due to improper input validation when parsing HTTPS requests. An attacker could exploit this vulnerability by sending a malicious HTTPS request to an affected device. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition.

CVE-2021-21978: VMware View Planner 4.x prior to 4.6 Security Patch 1 contains a remote code execution vulnerability. Improper input validation and lack of authorization leading to arbitrary file upload in logupload web application. An unauthorized attacker with network access to View Planner Harness could upload and execute a specially crafted file leading to remote code execution within the logupload container.

CVE-2021-22127: An improper input validation vulnerability in FortiClient for Linux 6.4.x before 6.4.3, FortiClient for Linux 6.2.x before 6.2.9 may allow an unauthenticated attacker to execute arbitrary code on the host operating system as root via tricking the user into connecting to a network with a malicious name.

CVE-2021-30267: Possible integer overflow to buffer overflow due to improper input validation in FTM ARA commands in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2021-34704: A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to trigger a denial of service (DoS) condition. This vulnerability is due to improper input validation when parsing HTTPS requests. An attacker could exploit this vulnerability by sending a malicious HTTPS request to an affected device. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition.

CVE-2021-35105: Possible out of bounds access due to improper input validation during graphics profiling in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-39666: In extract of MediaMetricsItem.h, there is a possible out of bounds read due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12Android ID: A-204445255

CVE-2021-39733: In amcs_cdev_unlocked_ioctl of audiometrics.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-206128522References: N/A

CVE-2021-39970: HwPCAssistant has a Improper Input Validation vulnerability.Successful exploitation of this vulnerability may create any file with the system app permission.

CVE-2022-1778: Improper Input Validation vulnerability in Hitachi Energy MicroSCADA X SYS600 while reading a specific configuration file causes a buffer-overflow that causes a failure to start the SYS600. The configuration file can only be accessed by an administrator access. This issue affects: Hitachi Energy MicroSCADA X SYS600 version 10 to version 10.3.1. cpe:2.3:a:hitachienergy:microscada_x_sys600:10:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3.1:*:*:*:*:*:*:*

CVE-2022-20099: In aee daemon, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06296442; Issue ID: ALPS06296442.

CVE-2022-20132: In lg_probe and related functions of hid-lg.c and other USB HID files, there is a possible out of bounds read due to improper input validation. This could lead to local information disclosure if a malicious USB HID device were plugged in, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-188677105References: Upstream kernel

CVE-2022-20221: In avrc_ctrl_pars_vendor_cmd of avrc_pars_ct.cc, there is a possible out of bounds read due to improper input validation. This could lead to remote information disclosure over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-205571133

CVE-2022-20226: In finishDrawingWindow of WindowManagerService.java, there is a possible tapjacking due to improper input validation. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-12 Android-12LAndroid ID: A-213644870

CVE-2022-20231: In smc_intc_request_fiq of arm_gic.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-211485702References: N/A

CVE-2022-20369: In v4l2_m2m_querybuf of v4l2-mem2mem.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-223375145References: Upstream kernel

CVE-2022-20427: In (TBD) of (TBD), there is a possible way to corrupt memory due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-239555070References: N/A

CVE-2022-20460: In (TBD) mprot_unmap? of (TBD), there is a possible way to corrupt the memory mapping due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-239557547References: N/A

CVE-2022-20548: In setParameter of EqualizerEffect.cpp, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-240919398

CVE-2022-20582: In ppmp_unprotect_mfcfw_buf of drm_fw.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-233645166References: N/A

CVE-2022-20583: In ppmp_unprotect_mfcfw_buf of drm_fw.c, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege in S-EL1 with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-234859169References: N/A

CVE-2022-20824: A vulnerability in the Cisco Discovery Protocol feature of Cisco FXOS Software and Cisco NX-OS Software could allow an unauthenticated, adjacent attacker to execute arbitrary code with root privileges or cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper input validation of specific values that are within a Cisco Discovery Protocol message. An attacker could exploit this vulnerability by sending a malicious Cisco Discovery Protocol packet to an affected device. A successful exploit could allow the attacker to execute arbitrary code with root privileges or cause the Cisco Discovery Protocol process to crash and restart multiple times, which would cause the affected device to reload, resulting in a DoS condition. Note: Cisco Discovery Protocol is a Layer 2 protocol. To exploit this vulnerability, an attacker must be in the same broadcast domain as the affected device (Layer 2 adjacent).

CVE-2022-20934: A vulnerability in the CLI of Cisco Firepower Threat Defense (FTD) Software and Cisco FXOS Software could allow an authenticated, local attacker to execute arbitrary commands on the underlying operating system as root. This vulnerability is due to improper input validation for specific CLI commands. An attacker could exploit this vulnerability by injecting operating system commands into a legitimate command. A successful exploit could allow the attacker to escape the restricted command prompt and execute arbitrary commands on the underlying operating system. To successfully exploit this vulnerability, an attacker would need valid Administrator credentials.

CVE-2022-22241: An Improper Input Validation vulnerability in the J-Web component of Juniper Networks Junos OS may allow an unauthenticated attacker to access data without proper authorization. Utilizing a crafted POST request, deserialization may occur which could lead to unauthorized local file access or the ability to execute arbitrary commands. This issue affects Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7, 19.4R3-S9; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2.

CVE-2022-22243: An XPath Injection vulnerability due to Improper Input Validation in the J-Web component of Juniper Networks Junos OS allows an authenticated attacker to add an XPath command to the XPath stream, which may allow chaining to other unspecified vulnerabilities, leading to a partial loss of confidentiality. This issue affects Juniper Networks Junos OS: all versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S7; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 versions prior to 20.1R3-S5; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2.

CVE-2022-22951: VMware Carbon Black App Control (8.5.x prior to 8.5.14, 8.6.x prior to 8.6.6, 8.7.x prior to 8.7.4 and 8.8.x prior to 8.8.2) contains an OS command injection vulnerability. An authenticated, high privileged malicious actor with network access to the VMware App Control administration interface may be able to execute commands on the server due to improper input validation leading to remote code execution.

CVE-2022-23766: An improper input validation vulnerability leading to arbitrary file execution was discovered in BigFileAgent. In order to cause arbitrary files to be executed, the attacker makes the victim access a web page d by them or inserts a script using XSS into a general website.

CVE-2022-2422: Due to improper input validation in the Feathers js library, it is possible to perform a SQL injection attack on the back-end database, in case the feathers-sequelize package is used.

CVE-2022-24711: CodeIgniter4 is the 4.x branch of CodeIgniter, a PHP full-stack web framework. Prior to version 4.1.9, an improper input validation vulnerability allows attackers to execute CLI routes via HTTP request. Version 4.1.9 contains a patch. There are currently no known workarounds for this vulnerability.

CVE-2022-26446: In Modem 4G RRC, there is a possible system crash due to improper input validation. This could lead to remote denial of service, when concatenating improper SIB12 (CMAS message), with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: MOLY00867883; Issue ID: ALPS07274118.

CVE-2022-27573: Improper input validation vulnerability in parser_infe and sheifd_find_itemIndexin fuctions of libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by privileged attackers.

CVE-2022-27574: Improper input validation vulnerability in parser_iloc and sheifd_find_itemIndexin fuctions of libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by privileged attacker.

CVE-2022-27807: Improper input validation vulnerability in Link of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to disable to add Categories.

CVE-2022-27833: Improper input validation in DSP driver prior to SMR Apr-2022 Release 1 allows out-of-bounds write by integer overflow.

CVE-2022-28692: Improper input validation vulnerability in Scheduler of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to alter the data of Scheduler.

CVE-2022-28811: In Carlo Gavazzi UWP3.0 in multiple versions and CPY Car Park Server in Version 2.8.3 a remote, unauthenticated attacker could utilize an improper input validation on an API-submitted parameter to execute arbitrary OS commands.

CVE-2022-29494: Improper input validation in firmware for OpenBMC in some Intel(R) platforms before versions egs-0.91-179 and bhs-04-45 may allow an authenticated user to potentially enable denial of service via network access.

CVE-2022-29892: Improper input validation vulnerability in Space of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to repeatedly display errors in certain functions and cause a denial-of-service (DoS).

CVE-2022-32664: In Config Manager, there is a possible command injection due to improper input validation. This could lead to remote escalation of privilege with User execution privileges needed. User interaction is needed for exploitation. Patch ID: A20220004; Issue ID: OSBNB00140929.

CVE-2022-32665: In Boa, there is a possible command injection due to improper input validation. This could lead to remote escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: A20220026; Issue ID: OSBNB00144124.

CVE-2022-33216: Transient Denial-of-service in Automotive due to improper input validation while parsing ELF file.

CVE-2022-33690: Improper input validation in Contacts Storage prior to SMR Jul-2022 Release 1 allows attacker to access arbitrary file.

CVE-2022-33708: Improper input validation vulnerability in AppsPackageInstaller in Galaxy Store prior to version 4.5.41.8 allows local attackers to launch activities as Galaxy Store privilege.

CVE-2022-33709: Improper input validation vulnerability in ApexPackageInstaller in Galaxy Store prior to version 4.5.41.8 allows local attackers to launch activities as Galaxy Store privilege.

CVE-2022-33710: Improper input validation vulnerability in BillingPackageInsraller in Galaxy Store prior to version 4.5.41.8 allows local attackers to launch activities as Galaxy Store privilege.

CVE-2022-33876: Multiple instances of improper input validation vulnerability in Fortinet FortiADC version 7.1.0, version 7.0.0 through 7.0.2 and version 6.2.4 and below allows an authenticated attacker to retrieve files with specific extension from the underlying Linux system via crafted HTTP requests.

CVE-2022-34146: Transient DOS due to improper input validation in WLAN Host while parsing frame during defragmentation.

CVE-2022-34391: Dell Client BIOS Versions prior to the remediated version contain an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-35942: Improper input validation on the `contains` LoopBack filter may allow for arbitrary SQL injection. When the extended filter property `contains` is permitted to be interpreted by the Postgres connector, it is possible to inject arbitrary SQL which may affect the confidentiality and integrity of data stored on the connected database. A patch was released in version 5.5.1. This affects users who does any of the following: - Connect to the database via the DataSource with `allowExtendedProperties: true` setting OR - Uses the connector's CRUD methods directly OR - Uses the connector's other methods to interpret the LoopBack filter. Users who are unable to upgrade should do the following if applicable: - Remove `allowExtendedProperties: true` DataSource setting - Add `allowExtendedProperties: false` DataSource setting - When passing directly to the connector functions, manually sanitize the user input for the `contains` LoopBack filter beforehand.

CVE-2022-36960: SolarWinds Platform was susceptible to Improper Input Validation. This vulnerability allows a remote adversary with valid access to SolarWinds Web Console to escalate user privileges. 

CVE-2022-38099: Improper input validation in BIOS firmware for some Intel(R) NUC 11 Compute Elements before version EBTGL357.0065 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-39017:  Improper input validation and output encoding in all comments fields, in M-Files Hubshare before 3.3.10.9 allows authenticated attackers to introduce cross-site scripting attacks via specially crafted comments. 

CVE-2022-39836: An issue was discovered in Connected Vehicle Systems Alliance (COVESA) dlt-daemon through 2.18.8. Due to a faulty DLT file parser, a crafted DLT file that crashes the process can be created. This is due to missing validation checks. There is a heap-based buffer over-read of one byte.

CVE-2022-39881: Improper input validation vulnerability for processing SIB12 PDU in Exynos modems prior to SMR Sep-2022 Release allows remote attacker to read out of bounds memory.

CVE-2022-40502: Transient DOS due to improper input validation in WLAN Host.

CVE-2022-42500: In OEM_OnRequest of sced.cpp, there is a possible shell command execution due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-239701389References: N/A

CVE-2022-42510: In StringsRequestData::encode of requestdata.cpp, there is a possible out of bounds read due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-241762656References: N/A

CVE-2022-42521: In encode of wlandata.cpp, there is a possible out of bounds write due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-243130019References: N/A

CVE-2022-45089: Improper Input Validation vulnerability in Group Arge Energy and Control Systems Smartpower Web allows SQL Injection.This issue affects Smartpower Web: before 23.01.01. 

CVE-2022-45090: Improper Input Validation vulnerability in Group Arge Energy and Control Systems Smartpower Web allows SQL Injection.This issue affects Smartpower Web: before 23.01.01. 

CVE-2022-45725: Improper Input Validation in Comfast router CF-WR6110N V2.3.1 allows a remote attacker on the same network to execute arbitrary code on the target via an HTTP POST request

CVE-2021-0928: In createFromParcel of OutputConfiguration.java, there is a possible parcel serialization/deserialization mismatch due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-9Android ID: A-188675581

CVE-2021-3607: An integer overflow was found in the QEMU implementation of VMWare's paravirtual RDMA device in versions prior to 6.1.0. The issue occurs while handling a "PVRDMA_REG_DSRHIGH" write from the guest due to improper input validation. This flaw allows a privileged guest user to make QEMU allocate a large amount of memory, resulting in a denial of service. The highest threat from this vulnerability is to system availability.

CVE-2021-39676: In writeThrowable of AndroidFuture.java, there is a possible parcel serialization/deserialization mismatch due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11Android ID: A-197228210

CVE-2022-1107: During an internal product security audit a potential vulnerability due to use of Boot Services in the SmmOEMInt15 SMI handler was discovered in some ThinkPad models could be exploited by an attacker with elevated privileges that could allow for execution of code.

CVE-2022-1108: A potential vulnerability due to improper buffer validation in the SMI handler LenovoFlashDeviceInterface in Thinkpad X1 Fold Gen 1 could be exploited by an attacker with local access and elevated privileges to execute arbitrary code.

CVE-2022-20906: Multiple vulnerabilities in Cisco Nexus Dashboard could allow an authenticated, local attacker to elevate privileges on an affected device. These vulnerabilities are due to insufficient input validation during CLI command execution on an affected device. An attacker could exploit these vulnerabilities by authenticating as the rescue-user and executing vulnerable CLI commands using a malicious payload. A successful exploit could allow the attacker to elevate privileges to root on an affected device.

CVE-2022-20907: Multiple vulnerabilities in Cisco Nexus Dashboard could allow an authenticated, local attacker to elevate privileges on an affected device. These vulnerabilities are due to insufficient input validation during CLI command execution on an affected device. An attacker could exploit these vulnerabilities by authenticating as the rescue-user and executing vulnerable CLI commands using a malicious payload. A successful exploit could allow the attacker to elevate privileges to root on an affected device.

CVE-2021-39633: In gre_handle_offloads of ip_gre.c, there is a possible page fault due to an invalid memory access. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-150694665References: Upstream kernel

CVE-2021-45116: An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. Due to leveraging the Django Template Language's variable resolution logic, the dictsort template filter was potentially vulnerable to information disclosure, or an unintended method call, if passed a suitably crafted key.

CVE-2022-43566: In Splunk Enterprise versions below 8.2.9, 8.1.12, and 9.0.2, an authenticated user can run risky commands using a more privileged user’s permissions to bypass SPL safeguards for risky commands https://docs.splunk.com/Documentation/SplunkCloud/latest/Security/SPLsafeguards in the Analytics Workspace. The vulnerability requires the attacker to phish the victim by tricking them into initiating a request within their browser. The attacker cannot exploit the vulnerability at will. 

CVE-2022-2479: Insufficient validation of untrusted input in File in Google Chrome on Android prior to 103.0.5060.134 allowed an attacker who convinced a user to install a malicious app to obtain potentially sensitive information from internal file directories via a crafted HTML page.

CVE-2022-23992: XCOM Data Transport for Windows, Linux, and UNIX 11.6 releases contain a vulnerability due to insufficient input validation that could potentially allow remote attackers to execute arbitrary commands with elevated privileges.

CVE-2022-26707: An issue in the handling of environment variables was addressed with improved validation. This issue is fixed in macOS Monterey 12.4. A user may be able to view sensitive user information.

CVE-2022-27421: Chamilo LMS v1.11.13 lacks validation on the user modification form, allowing attackers to escalate privileges to Platform Admin.

CVE-2022-39266: isolated-vm is a library for nodejs which gives the user access to v8's Isolate interface. In versions 4.3.6 and prior, if the untrusted v8 cached data is passed to the API through CachedDataOptions, attackers can bypass the sandbox and run arbitrary code in the nodejs process. Version 4.3.7 changes the documentation to warn users that they should not accept `cachedData` payloads from a user.

CVE-2021-21126: Insufficient policy enforcement in extensions in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to bypass site isolation via a crafted Chrome Extension.

CVE-2022-0270: Prior to v0.6.1, bored-agent failed to sanitize incoming kubernetes impersonation headers allowing a user to override assigned user name and groups.

CVE-2022-29154: An issue was discovered in rsync before 3.2.5 that allows malicious remote servers to write arbitrary files inside the directories of connecting peers. The server chooses which files/directories are sent to the client. However, the rsync client performs insufficient validation of file names. A malicious rsync server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the rsync client target directory and subdirectories (for example, overwrite the .ssh/authorized_keys file).

CVE-2022-40773: Zoho ManageEngine ServiceDesk Plus MSP before 10609 and SupportCenter Plus before 11025 are vulnerable to privilege escalation. This allows users to obtain sensitive data during an exportMickeyList export of requests from the list view.

CVE-2022-1509: Sed Injection Vulnerability in GitHub repository hestiacp/hestiacp prior to 1.5.12. An authenticated remote attacker with low privileges can execute arbitrary code under root context.

CVE-2022-20693: A vulnerability in the web UI feature of Cisco IOS XE Software could allow an authenticated, remote attacker to perform an injection attack against an affected device. This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending crafted input to the web UI API. A successful exploit could allow the attacker to inject commands to the underlying operating system with root privileges.

CVE-2022-3967: A vulnerability, which was classified as critical, was found in Vesta Control Panel. Affected is an unknown function of the file func/main.sh of the component sed Handler. The manipulation leads to argument injection. An attack has to be approached locally. The name of the patch is 39561c32c12cabe563de48cc96eccb9e2c655e25. It is recommended to apply a patch to fix this issue. VDB-213546 is the identifier assigned to this vulnerability.

CVE-2022-42797: An injection issue was addressed with improved input validation. This issue is fixed in Xcode 14.1. An app may be able to gain root privileges.

CVE-2022-24734: MyBB is a free and open source forum software. In affected versions the Admin CP's Settings management module does not validate setting types correctly on insertion and update, making it possible to add settings of supported type `php` with PHP code, executed on on _Change Settings_ pages. This results in a Remote Code Execution (RCE) vulnerability. The vulnerable module requires Admin CP access with the `Can manage settings?` permission. MyBB's Settings module, which allows administrators to add, edit, and delete non-default settings, stores setting data in an options code string ($options_code; mybb_settings.optionscode database column) that identifies the setting type and its options, separated by a new line character (\\n). In MyBB 1.2.0, support for setting type php was added, for which the remaining part of the options code is PHP code executed on Change Settings pages (reserved for plugins and internal use). MyBB 1.8.30 resolves this issue. There are no known workarounds.

CVE-2022-24816: JAI-EXT is an open-source project which aims to extend the Java Advanced Imaging (JAI) API. Programs allowing Jiffle script to be provided via network request can lead to a Remote Code Execution as the Jiffle script is compiled into Java code via Janino, and executed. In particular, this affects the downstream GeoServer project. Version 1.2.22 will contain a patch that disables the ability to inject malicious code into the resulting script. Users unable to upgrade may negate the ability to compile Jiffle scripts from the final application, by removing janino-x.y.z.jar from the classpath.

CVE-2022-24828: Composer is a dependency manager for the PHP programming language. Integrators using Composer code to call `VcsDriver::getFileContent` can have a code injection vulnerability if the user can control the `$file` or `$identifier` argument. This leads to a vulnerability on packagist.org for example where the composer.json's `readme` field can be used as a vector for injecting parameters into hg/Mercurial via the `$file` argument, or git via the `$identifier` argument if you allow arbitrary data there (Packagist does not, but maybe other integrators do). Composer itself should not be affected by the vulnerability as it does not call `getFileContent` with arbitrary data into `$file`/`$identifier`. To the best of our knowledge this was not abused, and the vulnerability has been patched on packagist.org and Private Packagist within a day of the vulnerability report.

CVE-2021-41144: OpenMage LTS is an e-commerce platform. Prior to versions 19.4.22 and 20.0.19, a layout block was able to bypass the block blacklist to execute remote code. Versions 19.4.22 and 20.0.19 contain a patch for this issue. 

CVE-2022-20665: A vulnerability in the CLI of Cisco StarOS could allow an authenticated, local attacker to elevate privileges on an affected device. This vulnerability is due to insufficient input validation of CLI commands. An attacker could exploit this vulnerability by sending crafted commands to the CLI. A successful exploit could allow the attacker to execute arbitrary code with the privileges of the root user. To exploit this vulnerability, an attacker would need to have valid administrative credentials on an affected device.

CVE-2022-20799: Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 and RV345 Routers could allow an authenticated, remote attacker to inject and execute arbitrary commands on the underlying operating system of an affected device. These vulnerabilities are due to insufficient validation of user-supplied input. An attacker could exploit these vulnerabilities by sending malicious input to an affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux operating system of the affected device. To exploit these vulnerabilities, an attacker would need to have valid Administrator credentials on the affected device.

CVE-2022-20801: Multiple vulnerabilities in the web-based management interface of Cisco Small Business RV340 and RV345 Routers could allow an authenticated, remote attacker to inject and execute arbitrary commands on the underlying operating system of an affected device. These vulnerabilities are due to insufficient validation of user-supplied input. An attacker could exploit these vulnerabilities by sending malicious input to an affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux operating system of the affected device. To exploit these vulnerabilities, an attacker would need to have valid Administrator credentials on the affected device.

CVE-2022-20925: A vulnerability in the web management interface of the Cisco Firepower Management Center (FMC) Software could allow an authenticated, remote attacker to execute arbitrary commands on the underlying operating system. The vulnerability is due to insufficient validation of user-supplied parameters for certain API endpoints. An attacker could exploit this vulnerability by sending crafted input to an affected API endpoint. A successful exploit could allow an attacker to execute arbitrary commands on the device with low system privileges. To successfully exploit this vulnerability, an attacker would need valid credentials for a user with Device permissions: by default, only Administrators, Security Approvers and Network Admins user accounts have these permissions.

CVE-2022-20926: A vulnerability in the web management interface of the Cisco Firepower Management Center (FMC) Software could allow an authenticated, remote attacker to execute arbitrary commands on the underlying operating system. The vulnerability is due to insufficient validation of user-supplied parameters for certain API endpoints. An attacker could exploit this vulnerability by sending crafted input to an affected API endpoint. A successful exploit could allow an attacker to execute arbitrary commands on the device with low system privileges. To successfully exploit this vulnerability, an attacker would need valid credentials for a user with Device permissions: by default, only Administrators, Security Approvers and Network Admins user accounts have these permissions.

CVE-2022-22991: A malicious user on the same LAN could use DNS spoofing followed by a command injection attack to trick a NAS device into loading through an unsecured HTTP call. Addressed this vulnerability by disabling checks for internet connectivity using HTTP.

CVE-2022-24552: A flaw was found in the REST API in StarWind Stack. REST command, which manipulates a virtual disk, doesn’t check input parameters. Some of them go directly to bash as part of a script. An attacker with non-root user access can inject arbitrary data into the command that will be executed with root privileges. This affects StarWind SAN and NAS v0.2 build 1633.

CVE-2022-28171: The web module in some Hikvision Hybrid SAN/Cluster Storage products have the following security vulnerability. Due to the insufficient input validation, attacker can exploit the vulnerability to execute restricted commands by sending messages with malicious commands to the affected device.

CVE-2022-29558: Realtek rtl819x-SDK before v3.6.1 allows command injection over the web interface.

CVE-2022-36482: TOTOLINK N350RT V9.3.5u.6139_B20201216 was discovered to contain a command injection vulnerability via the lang parameter in the function setLanguageCfg.

CVE-2022-39073: There is a command injection vulnerability in ZTE MF286R, Due to insufficient validation of the input parameters, an attacker could use the vulnerability to execute arbitrary commands.

CVE-2022-41870: AP Manager in Innovaphone before 13r2 Service Release 17 allows command injection via a modified service ID during app upload.

CVE-2022-43550: A command injection vulnerability exists in Jitsi before commit 8aa7be58522f4264078d54752aae5483bfd854b2 when launching browsers on Windows which could allow an attacker to insert an arbitrary URL which opens up the opportunity to remote execution.

CVE-2022-45600: Aztech WMB250AC Mesh Routers Firmware Version 016 2020 devices improperly manage sessions, which allows remote attackers to bypass authentication in opportunistic circumstances and execute arbitrary commands with administrator privileges by leveraging an existing web portal login.

CVE-2022-46303: Command injection in SMS notifications in Tribe29 Checkmk <= 2.1.0p10, Checkmk <= 2.0.0p27, and Checkmk <= 1.6.0p29 allows an attacker with User Management permissions, as well as LDAP administrators in certain scenarios, to perform arbitrary commands within the context of the application's local permissions.

CVE-2022-29560: A vulnerability has been identified in RUGGEDCOM ROX MX5000 (All versions < 2.15.1), RUGGEDCOM ROX MX5000RE (All versions < 2.15.1), RUGGEDCOM ROX RX1400 (All versions < 2.15.1), RUGGEDCOM ROX RX1500 (All versions < 2.15.1), RUGGEDCOM ROX RX1501 (All versions < 2.15.1), RUGGEDCOM ROX RX1510 (All versions < 2.15.1), RUGGEDCOM ROX RX1511 (All versions < 2.15.1), RUGGEDCOM ROX RX1512 (All versions < 2.15.1), RUGGEDCOM ROX RX1524 (All versions < 2.15.1), RUGGEDCOM ROX RX1536 (All versions < 2.15.1), RUGGEDCOM ROX RX5000 (All versions < 2.15.1). Affected devices do not properly validate user input, making them susceptible to command injection. An attacker with access to either the shell or the web CLI with administrator privileges could access the underlying operating system as the root user.

CVE-2021-26373: Insufficient bound checks in the System Management Unit (SMU) may result in a system voltage malfunction that could result in denial of resources and/or possibly denial of service.

CVE-2021-26378: Insufficient bound checks in the System Management Unit (SMU) may result in access to an invalid address space that could result in denial of service.

CVE-2022-20017: In ion driver, there is a possible information disclosure due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05862991; Issue ID: ALPS05862991.

CVE-2022-20019: In libMtkOmxGsmDec, there is a possible information disclosure due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05917620; Issue ID: ALPS05917620.

CVE-2022-20020: In libvcodecdrv, there is a possible information disclosure due to a missing bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05943906; Issue ID: ALPS05943906.

CVE-2022-20036: In ion driver, there is a possible information disclosure due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06171689; Issue ID: ALPS06171689.

CVE-2022-20037: In ion driver, there is a possible information disclosure due to an incorrect bounds check. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06171705; Issue ID: ALPS06171705.

CVE-2022-20064: In ccci, there is a possible leak of kernel pointer due to an incorrect bounds check. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06108617; Issue ID: ALPS06108617.

CVE-2022-20507: In onMulticastListUpdateNotificationReceived of UwbEventManager.java, there is a possible arbitrary code execution due to a missing bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-246649179

CVE-2022-20683: A vulnerability in the Application Visibility and Control (AVC-FNF) feature of Cisco IOS XE Software for Cisco Catalyst 9800 Series Wireless Controllers could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient packet verification for traffic inspected by the AVC feature. An attacker could exploit this vulnerability by sending crafted packets from the wired network to a wireless client, resulting in the crafted packets being processed by the wireless controller. A successful exploit could allow the attacker to cause a crash and reload of the affected device, resulting in a DoS condition.

CVE-2022-25818: Improper boundary check in UWB stack prior to SMR Mar-2022 Release 1 allows arbitrary code execution.

CVE-2022-26763: An out-of-bounds access issue was addressed with improved bounds checking. This issue is fixed in tvOS 15.5, iOS 15.5 and iPadOS 15.5, Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4. A malicious application may be able to execute arbitrary code with system privileges.

CVE-2022-27835: Improper boundary check in UWB firmware prior to SMR Apr-2022 Release 1 allows arbitrary memory write.

CVE-2022-42396: This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of XPS files. The issue results from the lack of proper validation of a user-supplied value prior to dereferencing it as a pointer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18278.

CVE-2022-42418: This vulnerability allows remote attackers to execute arbitrary code on affected installations of PDF-XChange Editor. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists within the parsing of TIF files. The issue results from the lack of proper validation of a user-supplied value prior to dereferencing it as a pointer. An attacker can leverage this vulnerability to execute code in the context of the current process. Was ZDI-CAN-18677.

CVE-2022-44425: In wlan driver, there is a possible missing bounds check. This could lead to local denial of service in wlan services.

CVE-2022-46701: The issue was addressed with improved bounds checks. This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS Ventura 13.1, tvOS 16.2. Connecting to a malicious NFS server may lead to arbitrary code execution with kernel privileges.

CVE-2021-0013: Improper input validation for Intel(R) EMA before version 1.5.0 may allow an unauthenticated user to potentially enable denial of service via network access.

CVE-2021-0051: Improper input validation in the Intel(R) SPS versions before SPS_E5_04.04.04.023.0, SPS_E5_04.04.03.228.0 or SPS_SoC-A_05.00.03.098.0 may allow a privileged user to potentially enable denial of service via local access.

CVE-2021-0062: Improper input validation in some Intel(R) Graphics Drivers before version 27.20.100.8935 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2021-0063: Improper input validation in firmware for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi in Windows 10 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-0066: Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable escalation of privilege via local access.

CVE-2021-0069: Improper input validation in firmware for some Intel(R) PROSet/Wireless WiFi in multiple operating systems and some Killer(TM) WiFi in Windows 10 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-0070: Improper input validation in the BMC firmware for Intel(R) Server Board M10JNP2SB before version EFI BIOS 7215, BMC 8100.01.08 may allow an unauthenticated user to potentially enable an escalation of privilege via adjacent access.

CVE-2021-0071: Improper input validation in firmware for some Intel(R) PROSet/Wireless WiFi in UEFI may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2021-0072: Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable information disclosure via local access.

CVE-2021-0078: Improper input validation in software for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi in Windows 10 may allow an unauthenticated user to potentially enable denial of service or information disclosure via adjacent access.

CVE-2021-0079: Improper input validation in software for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi in Windows 10 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-0083: Improper input validation in some Intel(R) Optane(TM) PMem versions before versions 1.2.0.5446 or 2.2.0.1547 may allow a privileged user to potentially enable denial of service via local access.

CVE-2021-0084: Improper input validation in the Intel(R) Ethernet Controllers X722 and 800 series Linux RMDA driver before version 1.3.19 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2021-0126: Improper input validation for the Intel(R) Manageability Commander before version 2.2 may allow an authenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2021-0134: Improper input validation in an API for the Intel(R) Security Library before version 3.3 may allow a privileged user to potentially enable denial of service via network access.

CVE-2021-0135: Improper input validation in the Intel(R) Ethernet Diagnostic Driver for Windows before version 1.4.0.10 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-0154: Improper input validation in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable aescalation of privilege via local access.

CVE-2021-0156: Improper input validation in the firmware for some Intel(R) Processors may allow an authenticated user to potentially enable an escalation of privilege via local access.

CVE-2021-0158: Improper input validation in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-0159: Improper input validation in the BIOS authenticated code module for some Intel(R) Processors may allow a privileged user to potentially enable aescalation of privilege via local access.

CVE-2021-0161: Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-0162: Improper input validation in software for Intel(R) PROSet/Wireless Wi-Fi and Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2021-0165: Improper input validation in firmware for Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-0168: Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-0172: Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-0176: Improper input validation in firmware for some Intel(R) PROSet/Wireless Wi-Fi in multiple operating systems and some Killer(TM) Wi-Fi in Windows 10 and 11 may allow a privileged user to potentially enable denial of service via local access.

CVE-2021-0178: Improper input validation in software for Intel(R) PROSet/Wireless Wi-Fi and Killer(TM) Wi-Fi in Windows 10 and 11 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-0185: Improper input validation in the firmware for some Intel(R) Server Board M10JNP Family before version 7.216 may allow a privileged user to potentially enable an escalation of privilege via local access.

CVE-2021-0186: Improper input validation in the Intel(R) SGX SDK applications compiled for SGX2 enabled processors may allow a privileged user to potentially escalation of privilege via local access.

CVE-2021-0199: Improper input validation in the firmware for the Intel(R) Ethernet Network Controller E810 before version 1.6.0.6 may allow a privileged user to potentially enable a denial of service via local access.

CVE-2021-0208: An improper input validation vulnerability in the Routing Protocol Daemon (RPD) service of Juniper Networks Junos OS allows an attacker to send a malformed RSVP packet when bidirectional LSPs are in use, which when received by an egress router crashes the RPD causing a Denial of Service (DoS) condition. Continued receipt of the packet will sustain the Denial of Service. This issue affects: Juniper Networks Junos OS: All versions prior to 17.3R3-S10 except 15.1X49-D240 for SRX series; 17.4 versions prior to 17.4R3-S2; 18.1 versions prior to 18.1R3-S10; 18.2 versions prior to 18.2R2-S7, 18.2R3-S4; 18.3 versions prior to 18.3R3-S2; 18.4 versions prior to 18.4R1-S8, 18.4R2-S6, 18.4R3-S2; 19.1 versions prior to 19.1R1-S5, 19.1R3-S3; 19.2 versions prior to 19.2R3; 19.3 versions prior to 19.3R2-S5, 19.3R3; 19.4 versions prior to 19.4R2-S2, 19.4R3-S1; 20.1 versions prior to 20.1R1-S4, 20.1R2; 15.1X49 versions prior to 15.1X49-D240 on SRX Series. Juniper Networks Junos OS Evolved: 19.3 versions prior to 19.3R2-S5-EVO; 19.4 versions prior to 19.4R2-S2-EVO; 20.1 versions prior to 20.1R1-S4-EVO.

CVE-2021-0214: A vulnerability in the distributed or centralized periodic packet management daemon (PPMD) of Juniper Networks Junos OS may cause receipt of a malformed packet to crash and restart the PPMD process, leading to network destabilization, service interruption, and a Denial of Service (DoS) condition. Continued receipt and processing of these malformed packets will repeatedly crash the PPMD process and sustain the Denial of Service (DoS) condition. Due to the nature of the specifically crafted packet, exploitation of this issue requires direct, adjacent connectivity to the vulnerable component. This issue affects Juniper Networks Junos OS: 17.3 versions prior to 17.3R3-S11; 17.4 versions prior to 17.4R2-S12, 17.4R3-S4; 18.1 versions prior to 18.1R3-S12; 18.2 versions prior to 18.2R2-S8, 18.2R3-S7; 18.3 versions prior to 18.3R3-S4; 18.4 versions prior to 18.4R1-S8, 18.4R2-S7, 18.4R3-S6; 19.1 versions prior to 19.1R1-S6, 19.1R2-S2, 19.1R3-S4; 19.2 versions prior to 19.2R1-S5, 19.2R3-S1; 19.3 versions prior to 19.3R2-S5, 19.3R3-S1; 19.4 versions prior to 19.4R2-S2, 19.4R3; 20.1 versions prior to 20.1R2; 20.2 versions prior to 20.2R1-S2, 20.2R2.

CVE-2021-0267: An Improper Input Validation vulnerability in the active-lease query portion in JDHCPD's DHCP Relay Agent of Juniper Networks Junos OS allows an attacker to cause a Denial of Service (DoS) by sending a crafted DHCP packet to the device thereby crashing the jdhcpd DHCP service. This is typically configured for Broadband Subscriber Sessions. Continued receipt and processing of this crafted packet will create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS: 19.4 versions prior to 19.4R3-S1; 20.1 versions prior to 20.1R2-S1, 20.1R3; 20.2 versions prior to 20.2R3; 20.3 versions prior to 20.3R2. This issue does not affect Junos OS Evolved.

CVE-2021-0278: An Improper Input Validation vulnerability in J-Web of Juniper Networks Junos OS allows a locally authenticated attacker to escalate their privileges to root over the target device. junos:18.3R3-S5 junos:18.4R3-S9 junos:19.1R3-S6 junos:19.3R2-S6 junos:19.3R3-S3 junos:19.4R1-S4 junos:19.4R3-S4 junos:20.1R2-S2 junos:20.1R3 junos:20.2R3-S1 junos:20.3X75-D20 junos:20.3X75-D30 junos:20.4R2-S1 junos:20.4R3 junos:21.1R1-S1 junos:21.1R2 junos:21.2R1 junos:21.3R1 This issue affects: Juniper Networks Junos OS 19.3 versions 19.3R1 and above prior to 19.3R2-S6, 19.3R3-S3; 19.4 versions prior to 19.4R3-S5; 20.1 versions prior to 20.1R2-S2, 20.1R3-S1; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S1, 20.4R3; 21.1 versions prior to 21.1R1-S1, 21.1R2. This issue does not affect Juniper Networks Junos OS versions prior to 19.3R1.

CVE-2021-0313: In isWordBreakAfter of LayoutUtils.cpp, there is a possible way to slow or crash a TextView due to improper input validation. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android; Versions: Android-9, Android-10, Android-11, Android-8.0, Android-8.1; Android ID: A-170968514.

CVE-2021-0350: In ged, there is a possible system crash due to an improper input validation. This could lead to local denial of service with System execution privileges needed. User interaction is not needed for exploitation. Product: Android; Versions: Android-8.1, Android-9, Android-10, Android-11; Patch ID: ALPS05342338.

CVE-2021-0416: In memory management driver, there is a possible system crash due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05336700.

CVE-2021-0418: In memory management driver, there is a possible system crash due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05336706.

CVE-2021-0419: In memory management driver, there is a possible system crash due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05336713.

CVE-2021-0511: In Dex2oat of dex2oat.cc, there is a possible way to inject bytecode into an app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-9 Android-10 Android-11Android ID: A-178055795

CVE-2021-1053: NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape or IOCTL in which improper validation of a user pointer may lead to denial of service.

CVE-2021-1065: NVIDIA vGPU manager contains a vulnerability in the vGPU plugin, in which input data is not validated, which may lead to tampering of data or denial of service. This affects vGPU version 8.x (prior to 8.6) and version 11.0 (prior to 11.3).

CVE-2021-1080: NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), in which certain input data is not validated, which may lead to information disclosure, tampering of data, or denial of service. This affects vGPU version 12.x (prior to 12.2), version 11.x (prior to 11.4) and version 8.x (prior 8.7).

CVE-2021-21123: Insufficient data validation in File System API in Google Chrome prior to 88.0.4324.96 allowed a remote attacker to bypass filesystem restrictions via a crafted HTML page.

CVE-2021-22277: Improper Input Validation vulnerability in ABB 800xA, Control Software for AC 800M, Control Builder Safe, Compact Product Suite - Control and I/O, ABB Base Software for SoftControl allows an attacker to cause the denial of service.

CVE-2021-22286: Improper Input Validation vulnerability in the ABB SPIET800 and PNI800 module allows an attacker to cause the denial of service or make the module unresponsive.

CVE-2021-22288: Improper Input Validation vulnerability in the ABB SPIET800 and PNI800 module allows an attacker to cause the denial of service or make the module unresponsive.

CVE-2021-22289: Improper Input Validation vulnerability in the project upload mechanism in B&R Automation Studio version >=4.0 may allow an unauthenticated network attacker to execute code.

CVE-2021-22787: A CWE-20: Improper Input Validation vulnerability exists that could cause denial of service of the device when an attacker sends a specially crafted HTTP request to the web server of the device. Affected Product: Modicon M340 CPUs: BMXP34 (Versions prior to V3.40), Modicon M340 X80 Ethernet Communication Modules: BMXNOE0100 (H), BMXNOE0110 (H), BMXNOC0401, BMXNOR0200H RTU (All Versions), Modicon Premium Processors with integrated Ethernet (Copro): TSXP574634, TSXP575634, TSXP576634 (All Versions), Modicon Quantum Processors with Integrated Ethernet (Copro): 140CPU65xxxxx (All Versions), Modicon Quantum Communication Modules: 140NOE771x1, 140NOC78x00, 140NOC77101 (All Versions), Modicon Premium Communication Modules: TSXETY4103, TSXETY5103 (All Versions)

CVE-2021-22800: A CWE-20: Improper Input Validation vulnerability exists that could cause a Denial of Service when a crafted packet is sent to the controller over network port 1105/TCP. Affected Product: Modicon M218 Logic Controller (V5.1.0.6 and prior)

CVE-2021-22826: A CWE-20: Improper Input Validation vulnerability exists that could cause arbitrary code execution when the user visits a page containing the injected payload. This CVE is unique from CVE-2021-22827. Affected Product: EcoStruxure? Power Monitoring Expert 9.0 and prior versions

CVE-2021-22827: A CWE-20: Improper Input Validation vulnerability exists that could cause arbitrary code execution when the user visits a page containing the injected payload. This CVE is unique from CVE-2021-22826. Affected Product: EcoStruxure? Power Monitoring Expert 9.0 and prior versions

CVE-2021-24209: The WP Super Cache WordPress plugin before 1.7.2 was affected by an authenticated (admin+) RCE in the settings page due to input validation failure and weak $cache_path check in the WP Super Cache Settings -> Cache Location option. Direct access to the wp-cache-config.php file is not prohibited, so this vulnerability can be exploited for a web shell injection.

CVE-2021-25510: An improper validation vulnerability in FilterProvider prior to SMR Dec-2021 Release 1 allows local arbitrary code execution.

CVE-2021-25512: An improper validation vulnerability in telephony prior to SMR Dec-2021 Release 1 allows attackers to launch certain activities.

CVE-2021-25517: An improper input validation vulnerability in LDFW prior to SMR Dec-2021 Release 1 allows attackers to perform arbitrary code execution.

CVE-2021-25745: A security issue was discovered in ingress-nginx where a user that can create or update ingress objects can use the spec.rules[].http.paths[].path field of an Ingress object (in the networking.k8s.io or extensions API group) to obtain the credentials of the ingress-nginx controller. In the default configuration, that credential has access to all secrets in the cluster.

CVE-2021-26251: Improper input validation in the Intel(R) Distribution of OpenVINO(TM) Toolkit may allow an authenticated user to potentially enable denial of service via network access.

CVE-2021-26398: Insufficient input validation in SYS_KEY_DERIVE system call in a compromised user application or ABL may allow an attacker to corrupt ASP (AMD Secure Processor) OS memory which may lead to potential arbitrary code execution. 

CVE-2021-26404: Improper input validation and bounds checking in SEV firmware may leak scratch buffer bytes leading to potential information disclosure. 

CVE-2021-26613: improper input validation vulnerability in nexacro permits copying file to the startup folder using rename method.

CVE-2021-26617: This issues due to insufficient verification of the various input values from user’s input. The vulnerability allows remote attackers to execute malicious code in Firstmall via navercheckout_add function.

CVE-2021-26618: An improper input validation leading to arbitrary file creation was discovered in ToWord of ToOffice. Remote attackers use this vulnerability to execute arbitrary file included malicious code.

CVE-2021-26624: An local privilege escalation vulnerability due to a "runasroot" command in eScan Anti-Virus. This vulnerability is due to invalid arguments and insufficient execution conditions related to "runasroot" command. This vulnerability can induce remote attackers to exploit root privileges by manipulating parameter values.

CVE-2021-26639: This vulnerability is caused by the lack of validation of input values for specific functions if WISA Smart Wing CMS. Remote attackers can use this vulnerability to leak all files in the server without logging in system.

CVE-2021-27420: GE UR firmware versions prior to version 8.1x web server task does not properly handle receipt of unsupported HTTP verbs, resulting in the web server becoming temporarily unresponsive after receiving a series of unsupported HTTP requests. When unresponsive, the web server is inaccessible. By itself, this is not particularly significant as the relay remains effective in all other functionality and communication channels.

CVE-2021-28655: The improper Input Validation vulnerability in "”Move folder to Trash” feature of Apache Zeppelin allows an attacker to delete the arbitrary files. This issue affects Apache Zeppelin Apache Zeppelin version 0.9.0 and prior versions.

CVE-2021-29845: IBM Security Guardium Insights 3.0 could allow an authenticated user to perform unauthorized actions due to improper input validation. IBM X-Force ID: 205255.

CVE-2021-30278: Improper input validation in TrustZone memory transfer interface can lead to information disclosure in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Voice & Music, Snapdragon Wired Infrastructure and Networking

CVE-2021-30285: Improper validation of memory region in Hypervisor can lead to incorrect region mapping in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Voice & Music, Snapdragon Wired Infrastructure and Networking

CVE-2021-30338: Improper input validation in TrustZone memory transfer interface can lead to information disclosure in Snapdragon Compute

CVE-2021-32545: Pexip Infinity before 26 allows remote denial of service because of missing RTMP input validation.

CVE-2021-32586: An improper input validation vulnerability in the web server CGI facilities of FortiMail before 7.0.1 may allow an unauthenticated attacker to alter the environment of the underlying script interpreter via specifically crafted HTTP requests.

CVE-2021-32970: Data can be copied without validation in the built-in web server in Moxa NPort IAW5000A-I/O series firmware version 2.2 or earlier, which may allow a remote attacker to cause denial-of-service conditions.

CVE-2021-32974: Improper input validation in the built-in web server in Moxa NPort IAW5000A-I/O series firmware version 2.2 or earlier may allow a remote attacker to execute commands.

CVE-2021-33108: Improper input validation in the Intel(R) In-Band Manageability software before version 2.13.0 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-33110: Improper input validation for some Intel(R) Wireless Bluetooth(R) products and Killer(TM) Bluetooth(R) products in Windows 10 and 11 before version 22.80 may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-33113: Improper input validation for some Intel(R) PROSet/Wireless WiFi in multiple operating systems and Killer(TM) WiFi in Windows 10 and 11 may allow an unauthenticated user to potentially enable denial of service or information disclosure via adjacent access.

CVE-2021-33114: Improper input validation for some Intel(R) PROSet/Wireless WiFi in multiple operating systems and Killer(TM) WiFi in Windows 10 and 11 may allow an authenticated user to potentially enable denial of service via adjacent access.

CVE-2021-33115: Improper input validation for some Intel(R) PROSet/Wireless WiFi in UEFI may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2021-33155: Improper input validation in firmware for some Intel(R) Wireless Bluetooth(R) and Killer(TM) Bluetooth(R) products before version 22.100 may allow an authenticated user to potentially enable denial of service via adjacent access.

CVE-2021-33498: Pexip Infinity before 26 allows remote denial of service because of missing H.264 input validation (issue 1 of 2).

CVE-2021-33499: Pexip Infinity before 26 allows remote denial of service because of missing H.264 input validation (issue 2 of 2).

CVE-2021-3422: The lack of validation of a key-value field in the Splunk-to-Splunk protocol results in a denial-of-service in Splunk Enterprise instances configured to index Universal Forwarder traffic. The vulnerability impacts Splunk Enterprise versions before 7.3.9, 8.0 versions before 8.0.9, and 8.1 versions before 8.1.3. It does not impact Universal Forwarders. When Splunk forwarding is secured using TLS or a Token, the attack requires compromising the certificate or token, or both. Implementation of either or both reduces the severity to Medium.

CVE-2021-34994: This vulnerability allows remote attackers to execute arbitrary code on affected installations of Commvault CommCell 11.22.22. Although authentication is required to exploit this vulnerability, the existing authentication mechanism can be bypassed. The specific flaw exists within the DataProvider class. The issue results from the lack of proper validation of a user-supplied string before executing it as JavaScript code. An attacker can leverage this vulnerability to escape the JavaScript sandbox and execute Java code in the context of NETWORK SERVICE. Was ZDI-CAN-13755.

CVE-2021-35109: Possible address manipulation from APP-NS while APP-S is configuring an RG where it tries to merge the address ranges in Snapdragon Connectivity, Snapdragon Mobile

CVE-2021-35116: APK can load a crafted model into the CDSP which can lead to a compromise of CDSP and other APK`s data executing there in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2021-35122: Non-secure region can try modifying RG permissions of IO space xPUs due to improper input validation in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2021-35531: Improper Input Validation vulnerability in a particular configuration setting field of Hitachi Energy TXpert Hub CoreTec 4 product, allows an attacker with access to an authorized user with ADMIN or ENGINEER role rights to inject an OS command that is executed by the system. This issue affects: Hitachi Energy TXpert Hub CoreTec 4 version 2.0.0; 2.0.1; 2.1.0; 2.1.1; 2.1.2; 2.1.3; 2.2.0; 2.2.1.

CVE-2021-35969: Pexip Infinity before 26 allows temporary remote Denial of Service (abort) because of missing call-setup input validation.

CVE-2021-36342: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2021-36343: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2021-3675: Improper Input Validation vulnerability in synaTEE.signed.dll of Synaptics Fingerprint Driver allows a local authorized attacker to overwrite a heap tag, with potential loss of confidentiality. This issue affects: Synaptics Synaptics Fingerprint Driver 5.1.xxx.26 versions prior to xxx=340 on x86/64; 5.2.xxxx.26 versions prior to xxxx=3541 on x86/64; 5.2.2xx.26 versions prior to xx=29 on x86/64; 5.2.3xx.26 versions prior to xx=25 on x86/64; 5.3.xxxx.26 versions prior to xxxx=3543 on x86/64; 5.5.xx.1058 versions prior to xx=44 on x86/64; 5.5.xx.1102 versions prior to xx=34 on x86/64; 5.5.xx.1116 versions prior to xx=14 on x86/64; 6.0.xx.1104 versions prior to xx=50 on x86/64; 6.0.xx.1108 versions prior to xx=31 on x86/64; 6.0.xx.1111 versions prior to xx=58 on x86/64.

CVE-2021-37039: There is an Input verification vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may cause Bluetooth DoS.

CVE-2021-37047: There is an Input verification vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may cause some services to restart.

CVE-2021-37048: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to fake visitors to control PC,play a video,etc.

CVE-2021-37060: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to SAMGR Heap Address Leakage.

CVE-2021-37079: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to delete arbitrary file by system_app permission.

CVE-2021-37081: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to nearby crash.

CVE-2021-37084: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to malicious invoking other functions of the Smart Assistant through text messages.

CVE-2021-37094: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to system denial of service.

CVE-2021-37096: There is a Improper Input Validation vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to user privacy disclosed.

CVE-2021-37116: PCManager has a Weaknesses Introduced During Design vulnerability .Successful exploitation of this vulnerability may cause that the PIN of the subscriber is changed.

CVE-2021-37150: Improper Input Validation vulnerability in header parsing of Apache Traffic Server allows an attacker to request secure resources. This issue affects Apache Traffic Server 8.0.0 to 9.1.2.

CVE-2021-37788: A vulnerability in the web UI of Gurock TestRail v5.3.0.3603 could allow an unauthenticated, remote attacker to affect the integrity of a device via a clickjacking attack. The vulnerability is due to insufficient input validation of iFrame data in HTTP requests that are sent to an affected device. An attacker could exploit this vulnerability by sending crafted HTTP packets with malicious iFrame data. A successful exploit could allow the attacker to perform a clickjacking attack where the user is tricked into clicking a malicious link.

CVE-2021-3781: A trivial sandbox (enabled with the `-dSAFER` option) escape flaw was found in the ghostscript interpreter by injecting a specially crafted pipe command. This flaw allows a specially crafted document to execute arbitrary commands on the system in the context of the ghostscript interpreter. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.

CVE-2021-37863: Mattermost 6.0 and earlier fails to sufficiently validate parameters during post creation, which allows authenticated attackers to cause a client-side crash of the web application via a maliciously crafted post.

CVE-2021-37909: WriteRegistry function in TSSServiSign component does not filter and verify users’ input, remote attackers can rewrite to the registry without permissions thus perform hijack attacks to execute arbitrary code.

CVE-2021-37996: Insufficient validation of untrusted input Downloads in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to bypass navigation restrictions via a malicious file.

CVE-2021-38304: Improper input validation in the National Instruments NI-PAL driver in versions 20.0.0 and prior may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-38485: The affected product is vulnerable to improper input validation in the restore file. This enables an attacker to provide malicious config files to replace any file on disk.

CVE-2021-38910: IBM DataPower Gateway V10CD, 10.0.1, and 2108.4.1 could allow a remote attacker to bypass security restrictions, caused by the improper validation of input. By sending a specially crafted JSON message, an attacker could exploit this vulnerability to modify structure and fields. IBM X-Force ID: 209824.

CVE-2021-38957: IBM Security Verify 10.0.0, 10.0.1.0, and 10.0.2.0 could disclose sensitive information due to hazardous input validation during QR code generation. IBM X-Force ID: 212040.

CVE-2021-3943: A flaw was found in Moodle in versions 3.11 to 3.11.3, 3.10 to 3.10.7, 3.9 to 3.9.10 and earlier unsupported versions. A remote code execution risk when restoring backup files was identified.

CVE-2021-3970: A potential vulnerability in LenovoVariable SMI Handler due to insufficient validation in some Lenovo Notebook models BIOS may allow an attacker with local access and elevated privileges to execute arbitrary code.

CVE-2021-39701: In serviceConnection of ControlsProviderLifecycleManager.kt, there is a possible way to keep service running in foreground without notification or permission due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-11 Android-12Android ID: A-212286849

CVE-2021-39740: In Messaging, there is a possible way to bypass attachment restrictions due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-209965112

CVE-2021-39763: In Settings, there is a possible way to make the user enable WiFi due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-199176115

CVE-2021-39764: In Settings, there is a possible way to display an incorrect app name due to improper input validation. This could lead to local escalation of privilege via app spoofing with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-170642995

CVE-2021-39771: In Settings, there is a possible way to misrepresent which app wants to add a wifi network due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-198661951

CVE-2021-39997: There is a vulnerability of unstrict input parameter verification in the audio assembly.Successful exploitation of this vulnerability may cause out-of-bounds access.

CVE-2021-40365: Affected devices don't process correctly certain special crafted packets sent to port 102/tcp, which could allow an attacker to cause a denial of service in the device.

CVE-2021-4047: The release of OpenShift 4.9.6 included four CVE fixes for the haproxy package, however the patch for CVE-2021-39242 was missing. This issue only affects Red Hat OpenShift 4.9.

CVE-2021-4211: A potential vulnerability in the SMI callback function used in the SMBIOS event log driver in some Lenovo Desktop, ThinkStation, and ThinkEdge models may allow an attacker with local access and elevated privileges to execute arbitrary code.

CVE-2021-4212: A potential vulnerability in the SMI callback function used in the Legacy BIOS mode driver in some Lenovo Notebook models may allow an attacker with local access and elevated privileges to execute arbitrary code.

CVE-2021-42121: Insufficient Input Validation in Web Applications operating on Business-DNA Solutions GmbH’s TopEase® Platform Version <= 7.1.27 on an object’s date attribute(s) allows an authenticated remote attacker with Object Modification privileges to insert an unexpected format into date fields, which leads to breaking the object page that the date field is present.

CVE-2021-42122: Insufficient Input Validation in Web Applications operating on Business-DNA Solutions GmbH’s TopEase® Platform Version <= 7.1.27 on an object’s attributes with numeric format allows an authenticated remote attacker with Object Modification privileges to insert an unexpected format, which makes the affected attribute non-editable.

CVE-2021-4219: A flaw was found in ImageMagick. The vulnerability occurs due to improper use of open functions and leads to a denial of service. This flaw allows an attacker to crash the system.

CVE-2021-42555: Pexip Infinity before 26.2 allows temporary remote Denial of Service (abort) because of missing call-setup input validation.

CVE-2021-42786: It was discovered that the SteelCentral AppInternals Dynamic Sampling Agent (DSA) has Remote Code Execution vulnerabilities in multiple instances of the API requests. The affected endpoints do not have any input validation of the user's input that allowed a malicious payload to be injected.

CVE-2021-43548: Patient Information Center iX (PIC iX) Versions C.02 and C.03 receives input or data, but does not validate or incorrectly validates that the input has the properties required to process the data safely and correctly.

CVE-2021-43588: Dell EMC Data Protection Central version 19.5 contains an Improper Input Validation Vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to denial of service.

CVE-2021-43762: AEM's Cloud Service offering, as well as version 6.5.10.0 (and below) are affected by a dispatcher bypass vulnerability that could be abused to evade security controls. Sensitive areas of the web application may be exposed through exploitation of the vulnerability.

CVE-2021-44040: Improper Input Validation vulnerability in request line parsing of Apache Traffic Server allows an attacker to send invalid requests. This issue affects Apache Traffic Server 8.0.0 to 8.1.3 and 9.0.0 to 9.1.1.

CVE-2021-44221: A vulnerability has been identified in SIMATIC eaSie Core Package (All versions < V22.00). The affected systems do not properly validate input that is sent to the underlying message passing framework. This could allow an remote attacker to trigger a denial of service of the affected system.

CVE-2021-44454: Improper input validation in a third-party component for Intel(R) Quartus(R) Prime Pro Edition before version 21.3 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2021-44462: This vulnerability can be exploited by parsing maliciously crafted project files with Horner Automation Cscape EnvisionRV v4.50.3.1 and prior. The issues result from the lack of proper validation of user-supplied data, which can result in reads and writes past the end of allocated data structures. User interaction is required to exploit this vulnerability as an attacker must trick a valid user to open a malicious HMI project file.

CVE-2021-44545: Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2021-44734: Embedded web server input sanitization vulnerability in Lexmark devices through 2021-12-07, which can which can lead to remote code execution on the device.

CVE-2021-44769: An improper input validation vulnerability in the TLS certificate generation function allows an attacker to cause a Denial-of-Service (DoS) condition which can only be reverted via a factory reset. This issue affects: Lanner Inc IAC-AST2500A standard firmware version 1.10.0.

CVE-2021-45916: The programming function of Shockwall system has an improper input validation vulnerability. An authenticated attacker within the local area network can send malicious response to the server to disrupt the service partially.

CVE-2021-46767: Insufficient input validation in the ASP may allow an attacker with physical access, unauthorized write access to memory potentially leading to a loss of integrity or denial of service. 

CVE-2021-46779: Insufficient input validation in SVC_ECC_PRIMITIVE system call in a compromised user application or ABL may allow an attacker to corrupt ASP (AMD Secure Processor) OS memory which may lead to potential loss of integrity and availability. 

CVE-2021-46791: Insufficient input validation during parsing of the System Management Mode (SMM) binary may allow a maliciously crafted SMM executable binary to corrupt Dynamic Root of Trust for Measurement (DRTM) user application memory that may result in a potential denial of service. 

CVE-2022-0484: Lack of validation of URLs causes Mirantis Container Cloud Lens Extension before v3.1.1 to open external programs other than the default browser to perform sign on to a new cluster. An attacker could host a webserver which serves a malicious Mirantis Container Cloud configuration file and induce the victim to add a new cluster via its URL. This issue affects: Mirantis Mirantis Container Cloud Lens Extension v3 versions prior to v3.1.1.

CVE-2022-0550: Improper Input Validation vulnerability in custom report logo upload in Nozomi Networks Guardian, and CMC allows an authenticated attacker with admin or report manager roles to execute unattended commands on the appliance using web server user privileges. This issue affects: Nozomi Networks Guardian versions prior to 22.0.0. Nozomi Networks CMC versions prior to 22.0.0.

CVE-2022-0551: Improper Input Validation vulnerability in project file upload in Nozomi Networks Guardian and CMC allows an authenticated attacker with admin or import manager roles to execute unattended commands on the appliance using web server user privileges. This issue affects: Nozomi Networks Guardian versions prior to 22.0.0. Nozomi Networks CMC versions prior to 22.0.0.

CVE-2022-1406: Improper input validation in GitLab CE/EE affecting all versions from 8.12 prior to 14.8.6, all versions from 14.9.0 prior to 14.9.4, and 14.10.0 allows a Developer to read protected Group or Project CI/CD variables by importing a malicious project

CVE-2022-1727: Improper Input Validation in GitHub repository jgraph/drawio prior to 18.0.6.

CVE-2022-20129: In registerPhoneAccount of PhoneAccountRegistrar.java, there is a possible way to prevent the user from selecting a phone account due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-217934478

CVE-2022-20134: In readArguments of CallSubjectDialog.java, there is a possible way to trick the user to call the wrong phone number due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-218341397

CVE-2022-20156: In unflatten of GraphicBuffer.cpp, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-212803946References: N/A

CVE-2022-20186: In kbase_mem_alias of mali_kbase_mem_linux.c, there is a possible arbitrary code execution due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-215001024References: N/A

CVE-2022-20205: In isFileUri of FileUtil.java, there is a possible way to bypass the check for a file:// scheme due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12LAndroid ID: A-215212561

CVE-2022-20241: In Messaging, there is a possible way to attach a private file to an SMS message due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-217185011

CVE-2022-20266: In Companion, there is a possible way to keep a service running with elevated importance without showing foreground service notification due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-211757348

CVE-2022-20314: In KeyChain, there is a possible spoof keychain chooser activity request due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-191876118

CVE-2022-20338: In HierarchicalUri.readFrom of Uri.java, there is a possible way to craft a malformed Uri object due to improper input validation. This could lead to a local escalation of privilege, preventing processes from validating URIs correctly, with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11 Android-12 Android-12LAndroid ID: A-171966843

CVE-2022-20350: In onCreate of NotificationAccessConfirmationActivity.java, there is a possible way to trick the victim to grant notification access to the wrong app due to improper input validation. This could lead to local information disclosure with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-228178437

CVE-2022-20353: In onSaveRingtone of DefaultRingtonePreference.java, there is a possible inappropriate file read due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-221041256

CVE-2022-20355: In get of PacProxyService.java, there is a possible system service crash due to improper input validation. This could lead to local denial of service with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-219498290

CVE-2022-20459: In (TBD) of (TBD), there is a possible way to redirect code execution due to improper input validation. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-239556260References: N/A

CVE-2022-2047: In Eclipse Jetty versions 9.4.0 thru 9.4.46, and 10.0.0 thru 10.0.9, and 11.0.0 thru 11.0.9 versions, the parsing of the authority segment of an http scheme URI, the Jetty HttpURI class improperly detects an invalid input as a hostname. This can lead to failures in a Proxy scenario.

CVE-2022-20512: In navigateUpTo of Task.java, there is a possible way to launch an intent handler with a mismatched intent due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-238602879

CVE-2022-20584: In page_number of shared_mem.c, there is a possible code execution in secure world due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238366009References: N/A

CVE-2022-20585: In valid_out_of_special_sec_dram_addr of drm_access_control.c, there is a possible EoP due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238716781References: N/A

CVE-2022-20586: In valid_out_of_special_sec_dram_addr of drm_access_control.c, there is a possible EoP due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238718854References: N/A

CVE-2022-20587: In ppmp_validate_wsm of drm_fw.c, there is a possible EoP due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238720411References: N/A

CVE-2022-20589: In valid_va_secbuf_check of drm_access_control.c, there is a possible ID due to improper input validation. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238841928References: N/A

CVE-2022-20590: In valid_va_sec_mfc_check of drm_access_control.c, there is a possible information disclosure due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238932493References: N/A

CVE-2022-20592: In ppmp_validate_secbuf of drm_fw.c, there is a possible information disclosure due to improper input validation. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-238976908References: N/A

CVE-2022-20624: A vulnerability in the Cisco Fabric Services over IP (CFSoIP) feature of Cisco NX-OS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient validation of incoming CFSoIP packets. An attacker could exploit this vulnerability by sending crafted CFSoIP packets to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition.

CVE-2022-20676: A vulnerability in the Tool Command Language (Tcl) interpreter of Cisco IOS XE Software could allow an authenticated, local attacker to escalate from privilege level 15 to root-level privileges. This vulnerability is due to insufficient input validation of data that is passed into the Tcl interpreter. An attacker could exploit this vulnerability by loading malicious Tcl code on an affected device. A successful exploit could allow the attacker to execute arbitrary commands as root. By default, Tcl shell access requires privilege level 15.

CVE-2022-20684: A vulnerability in Simple Network Management Protocol (SNMP) trap generation for wireless clients of Cisco IOS XE Wireless Controller Software for the Catalyst 9000 Family could allow an unauthenticated, adjacent attacker to cause an affected device to unexpectedly reload, resulting in a denial of service (DoS) condition on the device. This vulnerability is due to a lack of input validation of the information used to generate an SNMP trap related to a wireless client connection event. An attacker could exploit this vulnerability by sending an 802.1x packet with crafted parameters during the wireless authentication setup phase of a connection. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition.

CVE-2022-20698: A vulnerability in the OOXML parsing module in Clam AntiVirus (ClamAV) Software version 0.104.1 and LTS version 0.103.4 and prior versions could allow an unauthenticated, remote attacker to cause a denial of service condition on an affected device. The vulnerability is due to improper checks that may result in an invalid pointer read. An attacker could exploit this vulnerability by sending a crafted OOXML file to an affected device. An exploit could allow the attacker to cause the ClamAV scanning process to crash, resulting in a denial of service condition.

CVE-2022-20715: A vulnerability in the remote access SSL VPN features of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper validation of errors that are logged as a result of client connections that are made using remote access VPN. An attacker could exploit this vulnerability by sending crafted requests to an affected system. A successful exploit could allow the attacker to cause the affected device to restart, resulting in a DoS condition.

CVE-2022-20745: A vulnerability in the web services interface for remote access VPN features of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition. This vulnerability is due to improper input validation when parsing HTTPS requests. An attacker could exploit this vulnerability by sending a crafted HTTPS request to an affected device. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition.

CVE-2022-20750: A vulnerability in the checkpoint manager implementation of Cisco Redundancy Configuration Manager (RCM) for Cisco StarOS Software could allow an unauthenticated, remote attacker to cause the checkpoint manager process to restart upon receipt of malformed TCP data. This vulnerability is due to improper input validation of an ingress TCP packet. An attacker could exploit this vulnerability by sending crafted TCP data to the affected application. A successful exploit could allow the attacker to cause a denial of service (DoS) condition due to the checkpoint manager process restarting.

CVE-2022-20761: A vulnerability in the integrated wireless access point (AP) packet processing of the Cisco 1000 Series Connected Grid Router (CGR1K) could allow an unauthenticated, adjacent attacker to cause a denial of service condition on an affected device. This vulnerability is due to insufficient input validation of received traffic. An attacker could exploit this vulnerability by sending crafted traffic to an affected device. A successful exploit could allow the attacker to cause the integrated AP to stop processing traffic, resulting in a DoS condition. It may be necessary to manually reload the CGR1K to restore AP operation.

CVE-2022-20822: A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to read and delete files on an affected device. This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by sending a crafted HTTP request that contains certain character sequences to an affected system. A successful exploit could allow the attacker to read or delete specific files on the device that their configured administrative level should not have access to. Cisco plans to release software updates that address this vulnerability.

CVE-2022-20825: A vulnerability in the web-based management interface of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause an affected device to restart unexpectedly, resulting in a denial of service (DoS) condition. This vulnerability is due to insufficient user input validation of incoming HTTP packets. An attacker could exploit this vulnerability by sending a crafted request to the web-based management interface. A successful exploit could allow the attacker to execute arbitrary commands on an affected device using root-level privileges. Cisco has not released software updates that address this vulnerability.

CVE-2022-20841: Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause a denial of service (DoS) condition on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-20842: Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an unauthenticated, remote attacker to execute arbitrary code or cause a denial of service (DoS) condition on an affected device. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-20850: A vulnerability in the CLI of stand-alone Cisco IOS XE SD-WAN Software and Cisco SD-WAN Software could allow an authenticated, local attacker to delete arbitrary files from the file system of an affected device. This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by injecting arbitrary file path information when using commands in the CLI of an affected device. A successful exploit could allow the attacker to delete arbitrary files from the file system of the affected device.

CVE-2022-20908: Multiple vulnerabilities in Cisco Nexus Dashboard could allow an authenticated, local attacker to elevate privileges on an affected device. These vulnerabilities are due to insufficient input validation during CLI command execution on an affected device. An attacker could exploit these vulnerabilities by authenticating as the rescue-user and executing vulnerable CLI commands using a malicious payload. A successful exploit could allow the attacker to elevate privileges to root on an affected device.

CVE-2022-20909: Multiple vulnerabilities in Cisco Nexus Dashboard could allow an authenticated, local attacker to elevate privileges on an affected device. These vulnerabilities are due to insufficient input validation during CLI command execution on an affected device. An attacker could exploit these vulnerabilities by authenticating as the rescue-user and executing vulnerable CLI commands using a malicious payload. A successful exploit could allow the attacker to elevate privileges to root on an affected device.

CVE-2022-20913: A vulnerability in Cisco Nexus Dashboard could allow an authenticated, remote attacker to write arbitrary files on an affected device. This vulnerability is due to insufficient input validation in the web-based management interface of Cisco Nexus Dashboard. An attacker with Administrator credentials could exploit this vulnerability by uploading a crafted file. A successful exploit could allow the attacker to overwrite arbitrary files on an affected device.

CVE-2022-20919: A vulnerability in the processing of malformed Common Industrial Protocol (CIP) packets that are sent to Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to unexpectedly reload, resulting in a denial of service (DoS) condition. This vulnerability is due to insufficient input validation during processing of CIP packets. An attacker could exploit this vulnerability by sending a malformed CIP packet to an affected device. A successful exploit could allow the attacker to cause the affected device to unexpectedly reload, resulting in a DoS condition.

CVE-2022-20924: A vulnerability in the Simple Network Management Protocol (SNMP) feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an authenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a crafted SNMP request to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition.

CVE-2022-20945: A vulnerability in the 802.11 association frame validation of Cisco Catalyst 9100 Series Access Points (APs) could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient input validation of certain parameters within association request frames received by the AP. An attacker could exploit this vulnerability by sending a crafted 802.11 association request to a nearby device. An exploit could allow the attacker to unexpectedly reload the device, resulting in a DoS condition.

CVE-2022-20962: A vulnerability in the Localdisk Management feature of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to make unauthorized changes to the file system of an affected device. This vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability by sending a crafted HTTP request with absolute path sequences. A successful exploit could allow the attacker to upload malicious files to arbitrary locations within the file system. Using this method, it is possible to access the underlying operating system and execute commands with system privileges.

CVE-2022-21136: Improper input validation for some Intel(R) Xeon(R) Processors may allow a privileged user to potentially enable denial of service via local access.

CVE-2022-21180: Improper input validation for some Intel(R) Processors may allow an authenticated user to potentially cause a denial of service via local access.

CVE-2022-21181: Improper input validation for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-21197: Improper input validation for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable denial of service via network access.

CVE-2022-21212: Improper input validation for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable denial of service via adjacent access.

CVE-2022-21933: ASUS VivoMini/Mini PC device has an improper input validation vulnerability. A local attacker with system privilege can use system management interrupt (SMI) to modify memory, resulting in arbitrary code execution for controlling the system or disrupting service.

CVE-2022-22163: An Improper Input Validation vulnerability in the Juniper DHCP daemon (jdhcpd) of Juniper Networks Junos OS allows an adjacent unauthenticated attacker to cause a crash of jdhcpd and thereby a Denial of Service (DoS). If a device is configured as DHCPv6 local server and persistent storage is enabled, jdhcpd will crash when receiving a specific DHCPv6 message. This issue affects: Juniper Networks Junos OS All versions prior to 15.1R7-S11; 18.4 versions prior to 18.4R3-S9; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2 versions prior to 19.2R1-S8, 19.2R3-S3; 19.4 versions prior to 19.4R3-S5; 20.1 versions prior to 20.1R3-S1; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R2; 21.2 versions prior to 21.2R2.

CVE-2022-22184: An Improper Input Validation vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated network-based attacker to cause a Denial of Service (DoS). If a BGP update message is received over an established BGP session, and that message contains a specific, optional transitive attribute, this session will be torn down with an update message error. This issue cannot propagate beyond an affected system as the processing error occurs as soon as the update is received. This issue is exploitable remotely as the respective attribute will propagate through unaffected systems and intermediate AS (if any). Continuous receipt of a BGP update containing this attribute will create a sustained Denial of Service (DoS) condition. Since this issue only affects 22.3R1, Juniper strongly encourages customers to move to 22.3R1-S1. Juniper SIRT felt that the need to promptly warn customers about this issue affecting the 22.3R1 versions of Junos OS and Junos OS Evolved warranted an Out of Cycle JSA. This issue affects: Juniper Networks Junos OS version 22.3R1. Juniper Networks Junos OS Evolved version 22.3R1-EVO. This issue does not affect: Juniper Networks Junos OS versions prior to 22.3R1. Juniper Networks Junos OS Evolved versions prior to 22.3R1-EVO.

CVE-2022-22214: An Improper Input Validation vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent attacker to cause a PFE crash and thereby a Denial of Service (DoS). An FPC will crash and reboot after receiving a specific transit IPv6 packet over MPLS. Continued receipt of this packet will create a sustained Denial of Service (DoS) condition. This issue does not affect systems configured for IPv4 only. This issue affects: Juniper Networks Junos OS All versions prior to 12.3R12-S21; 15.1 versions prior to 15.1R7-S10; 17.3 versions prior to 17.3R3-S12; 18.3 versions prior to 18.3R3-S6; 18.4 versions prior to 18.4R2-S9, 18.4R3-S9; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior to 19.3R2-S7, 19.3R3-S4; 19.4 versions prior to 19.4R3-S5; 20.1 versions prior to 20.1R3; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2-S2, 20.4R3; 21.1 versions prior to 21.1R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S3-EVO; 21.2 versions prior to 21.2R3-EVO; 21.3 versions prior to 21.3R2-S1-EVO, 21.3R3-EVO; 21.4 versions prior to 21.4R2-EVO.

CVE-2022-22230: An Improper Input Validation vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent unauthenticated attacker to cause DoS (Denial of Service). If another router generates more than one specific valid OSPFv3 LSA then rpd will crash while processing these LSAs. This issue only affects systems configured with OSPFv3, while OSPFv2 is not affected. This issue affects: Juniper Networks Junos OS 19.2 versions prior to 19.2R3-S6; 19.3 version 19.3R2 and later versions; 19.4 versions prior to 19.4R2-S8, 19.4R3-S9; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3-S2; 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R3-S2; 21.4 versions prior to 21.4R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S5-EVO; 21.1-EVO versions prior to 21.1R3-S2-EVO; 21.2-EVO versions prior to 21.2R3-S1-EVO; 21.3-EVO versions prior to 21.3R3-S2-EVO; 21.4-EVO versions prior to 21.4R2-EVO; 22.1-EVO versions prior to 22.1R2-EVO; 22.2-EVO versions prior to 22.2R2-EVO. This issue does not affect Juniper Networks Junos OS 19.2 versions prior to 19.2R2.

CVE-2022-22247: An Improper Input Validation vulnerability in ingress TCP segment processing of Juniper Networks Junos OS Evolved allows a network-based unauthenticated attacker to send a crafted TCP segment to the device, triggering a kernel panic, leading to a Denial of Service (DoS) condition. Continued receipt and processing of this TCP segment could create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS Evolved: 21.3 versions prior to 21.3R3-EVO; 21.4 versions prior to 21.4R2-EVO; 22.1 versions prior to 22.1R2-EVO. This issue does not affect Juniper Networks Junos OS Evolved versions prior to 21.3R1-EVO.

CVE-2022-22264: Improper sanitization of incoming intent in Dressroom prior to SMR Jan-2022 Release 1 allows local attackers to read and write arbitrary files without permission.

CVE-2022-22271: A missing input validation before memory copy in TIMA trustlet prior to SMR Jan-2022 Release 1 allows attackers to copy data from arbitrary memory.

CVE-2022-22311: IBM Security Verify Access could allow a user, using man in the middle techniques, to obtain sensitive information or possibly change some information due to improper validiation of JWT tokens.

CVE-2022-22433: IBM Robotic Process Automation 21.0.1 and 21.0.2 is vulnerable to External Service Interaction attack, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to induce the application to perform server-side DNS lookups or HTTP requests to arbitrary domain names. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. IBM X-Force ID: 224156.

CVE-2022-22525: In Carlo Gavazzi UWP3.0 in multiple versions and CPY Car Park Server in Version 2.8.3 an remote attacker with admin rights could execute arbitrary commands due to missing input sanitization in the backup restore function

CVE-2022-22538: When a user opens a manipulated Adobe Illustrator file format (.ai, ai.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application. The file format details along with their CVE relevant information can be found below.

CVE-2022-22539: When a user opens a manipulated JPEG file format (.jpg, 2d.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application. The file format details along with their CVE relevant information can be found below.

CVE-2022-22658: An input validation issue was addressed with improved input validation. This issue is fixed in iOS 16.0.3. Processing a maliciously crafted email message may lead to a denial-of-service.

CVE-2022-22726: A CWE-20: Improper Input Validation vulnerability exists that could allow arbitrary files on the server to be read by authenticated users through a limited operating system service account. Affected Product: EcoStruxure Power Monitoring Expert (Versions 2020 and prior)

CVE-2022-22727: A CWE-20: Improper Input Validation vulnerability exists that could allow an unauthenticated attacker to view data, change settings, impact availability of the software, or potentially impact a user?s local machine when the user clicks a specially crafted link. Affected Product: EcoStruxure Power Monitoring Expert (Versions 2020 and prior)

CVE-2022-23014: On versions 16.1.x before 16.1.2 and 15.1.x before 15.1.4.1, when BIG-IP APM portal access is configured on a virtual server, undisclosed requests can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-23019: On BIG-IP version 16.1.x before 16.1.2, 15.1.x before 15.1.4.1, 14.1.x before 14.1.4.4, and all versions of 13.1.x and 12.1.x, when a message routing type virtual server is configured with both Diameter Session and Router Profiles, undisclosed traffic can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-23403: Improper input validation in the Intel(R) Data Center Manager software before version 4.1 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-23425: Improper input validation in Exynos baseband prior to SMR Feb-2022 Release 1 allows attackers to send arbitrary NAS signaling messages with fake base station.

CVE-2022-23432: An improper input validation in SMC_SRPMB_WSM handler of RPMB ldfw prior to SMR Feb-2022 Release 1 allows arbitrary memory write and code execution.

CVE-2022-23623: Frourio is a full stack framework, for TypeScript. Frourio users who uses frourio version prior to v0.26.0 and integration with class-validator through `validators/` folder are subject to a input validation vulnerability. Validators do not work properly for request bodies and queries in specific situations and some input is not validated at all. Users are advised to update frourio to v0.26.0 or later and to install `class-transformer` and `reflect-metadata`.

CVE-2022-23624: Frourio-express is a minimal full stack framework, for TypeScript. Frourio-express users who uses frourio-express version prior to v0.26.0 and integration with class-validator through `validators/` folder are subject to a input validation vulnerability. Validators do not work properly for request bodies and queries in specific situations and some input is not validated at all. Users are advised to update frourio to v0.26.0 or later and to install `class-transformer` and `reflect-metadata`.

CVE-2022-24098: Adobe Photoshop versions 22.5.6 (and earlier)and 23.2.2 (and earlier) are affected by an improper input validation vulnerability when parsing a PCX file that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious PCX file.

CVE-2022-2417: Insufficient validation in GitLab CE/EE affecting all versions from 12.10 prior to 15.0.5, 15.1 prior to 15.1.4, and 15.2 prior to 15.2.1 allows an authenticated and authorised user to import a project that includes branch names which are 40 hexadecimal characters, which could be abused in supply chain attacks where a victim pinned to a specific Git commit of the project.

CVE-2022-24280: Improper Input Validation vulnerability in Proxy component of Apache Pulsar allows an attacker to make TCP/IP connection attempts that originate from the Pulsar Proxy's IP address. When the Apache Pulsar Proxy component is used, it is possible to attempt to open TCP/IP connections to any IP address and port that the Pulsar Proxy can connect to. An attacker could use this as a way for DoS attacks that originate from the Pulsar Proxy's IP address. It hasn’t been detected that the Pulsar Proxy authentication can be bypassed. The attacker will have to have a valid token to a properly secured Pulsar Proxy. This issue affects Apache Pulsar Proxy versions 2.7.0 to 2.7.4; 2.8.0 to 2.8.2; 2.9.0 to 2.9.1; 2.6.4 and earlier.

CVE-2022-25751: A vulnerability has been identified in SCALANCE X302-7 EEC (230V), SCALANCE X302-7 EEC (230V, coated), SCALANCE X302-7 EEC (24V), SCALANCE X302-7 EEC (24V, coated), SCALANCE X302-7 EEC (2x 230V), SCALANCE X302-7 EEC (2x 230V, coated), SCALANCE X302-7 EEC (2x 24V), SCALANCE X302-7 EEC (2x 24V, coated), SCALANCE X304-2FE, SCALANCE X306-1LD FE, SCALANCE X307-2 EEC (230V), SCALANCE X307-2 EEC (230V, coated), SCALANCE X307-2 EEC (24V), SCALANCE X307-2 EEC (24V, coated), SCALANCE X307-2 EEC (2x 230V), SCALANCE X307-2 EEC (2x 230V, coated), SCALANCE X307-2 EEC (2x 24V), SCALANCE X307-2 EEC (2x 24V, coated), SCALANCE X307-3, SCALANCE X307-3, SCALANCE X307-3LD, SCALANCE X307-3LD, SCALANCE X308-2, SCALANCE X308-2, SCALANCE X308-2LD, SCALANCE X308-2LD, SCALANCE X308-2LH, SCALANCE X308-2LH, SCALANCE X308-2LH+, SCALANCE X308-2LH+, SCALANCE X308-2M, SCALANCE X308-2M, SCALANCE X308-2M PoE, SCALANCE X308-2M PoE, SCALANCE X308-2M TS, SCALANCE X308-2M TS, SCALANCE X310, SCALANCE X310, SCALANCE X310FE, SCALANCE X310FE, SCALANCE X320-1 FE, SCALANCE X320-1-2LD FE, SCALANCE X408-2, SCALANCE XR324-12M (230V, ports on front), SCALANCE XR324-12M (230V, ports on front), SCALANCE XR324-12M (230V, ports on rear), SCALANCE XR324-12M (230V, ports on rear), SCALANCE XR324-12M (24V, ports on front), SCALANCE XR324-12M (24V, ports on front), SCALANCE XR324-12M (24V, ports on rear), SCALANCE XR324-12M (24V, ports on rear), SCALANCE XR324-12M TS (24V), SCALANCE XR324-12M TS (24V), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (24V, ports on front), SCALANCE XR324-4M EEC (24V, ports on front), SCALANCE XR324-4M EEC (24V, ports on rear), SCALANCE XR324-4M EEC (24V, ports on rear), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (2x 24V, ports on front), SCALANCE XR324-4M EEC (2x 24V, ports on front), SCALANCE XR324-4M EEC (2x 24V, ports on rear), SCALANCE XR324-4M EEC (2x 24V, ports on rear), SCALANCE XR324-4M PoE (230V, ports on front), SCALANCE XR324-4M PoE (230V, ports on rear), SCALANCE XR324-4M PoE (24V, ports on front), SCALANCE XR324-4M PoE (24V, ports on rear), SCALANCE XR324-4M PoE TS (24V, ports on front), SIPLUS NET SCALANCE X308-2. Affected devices do not properly validate the HTTP headers of incoming requests. This could allow an unauthenticated remote attacker to crash affected devices.

CVE-2022-25757: In Apache APISIX before 2.13.0, when decoding JSON with duplicate keys, lua-cjson will choose the last occurred value as the result. By passing a JSON with a duplicate key, the attacker can bypass the body_schema validation in the request-validation plugin. For example, `{"string_payload":"bad","string_payload":"good"}` can be used to hide the "bad" input. Systems satisfy three conditions below are affected by this attack: 1. use body_schema validation in the request-validation plugin 2. upstream application uses a special JSON library that chooses the first occurred value, like jsoniter or gojay 3. upstream application does not validate the input anymore. The fix in APISIX is to re-encode the validated JSON input back into the request body at the side of APISIX. Improper Input Validation vulnerability in __COMPONENT__ of Apache APISIX allows an attacker to __IMPACT__. This issue affects Apache APISIX Apache APISIX version 2.12.1 and prior versions.

CVE-2022-25763: Improper Input Validation vulnerability in HTTP/2 request validation of Apache Traffic Server allows an attacker to create smuggle or cache poison attacks. This issue affects Apache Traffic Server 8.0.0 to 9.1.2.

CVE-2022-25894: All versions of the package com.bstek.uflo:uflo-core are vulnerable to Remote Code Execution (RCE) in the ExpressionContextImpl class via jexl.createExpression(expression).evaluate(context); functionality, due to improper user input validation.

CVE-2022-26006: Improper input validation in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-26047: Improper input validation for some Intel(R) PROSet/Wireless WiFi, Intel vPro(R) CSME WiFi and Killer(TM) WiFi products may allow unauthenticated user to potentially enable denial of service via local access.

CVE-2022-26100: SAPCAR - version 7.22, does not contain sufficient input validation on the SAPCAR archive. As a result, the SAPCAR process may crash, and the attacker may obtain privileged access to the system.

CVE-2022-26106: When a user opens a manipulated Computer Graphics Metafile (.cgm, CgmCore.dll) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-26107: When a user opens a manipulated Jupiter Tesselation (.jt, JTReader.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-26108: When a user opens a manipulated Picture Exchange (.pcx, 2d.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-26109: When a user opens a manipulated Portable Document Format (.pdf, PDFView.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-26336: A shortcoming in the HMEF package of poi-scratchpad (Apache POI) allows an attacker to cause an Out of Memory exception. This package is used to read TNEF files (Microsoft Outlook and Microsoft Exchange Server). If an application uses poi-scratchpad to parse TNEF files and the application allows untrusted users to supply them, then a carefully crafted file can cause an Out of Memory exception. This issue affects poi-scratchpad version 5.2.0 and prior versions. Users are recommended to upgrade to poi-scratchpad 5.2.1.

CVE-2022-2636: Improper Control of Generation of Code ('Code Injection') in GitHub repository hestiacp/hestiacp prior to 1.6.6. 

CVE-2022-26655: Pexip Infinity 27.x before 27.3 has Improper Input Validation. The client API allows remote attackers to trigger a software abort via a gateway call into Teams.

CVE-2022-26780: Multiple improper input validation vulnerabilities exists in the libnvram.so nvram_import functionality of InHand Networks InRouter302 V3.5.4. A specially-crafted file can lead to remote code execution. An attacker can send a sequence of requests to trigger this vulnerability.An improper input validation vulnerability exists in the `httpd`'s `user_define_init` function. Controlling the `user_define_timeout` nvram variable can lead to remote code execution.

CVE-2022-26781: Multiple improper input validation vulnerabilities exists in the libnvram.so nvram_import functionality of InHand Networks InRouter302 V3.5.4. A specially-crafted file can lead to remote code execution. An attacker can send a sequence of requests to trigger this vulnerability.An improper input validation vulnerability exists in the `httpd`'s `user_define_print` function. Controlling the `user_define_timeout` nvram variable can lead to remote code execution.

CVE-2022-26782: Multiple improper input validation vulnerabilities exists in the libnvram.so nvram_import functionality of InHand Networks InRouter302 V3.5.4. A specially-crafted file can lead to remote code execution. An attacker can send a sequence of requests to trigger this vulnerability.An improper input validation vulnerability exists in the `httpd`'s `user_define_set_item` function. Controlling the `user_define_timeout` nvram variable can lead to remote code execution.

CVE-2022-26837: Improper input validation in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-26862: Prior Dell BIOS versions contain an Input Validation vulnerability. A locally authenticated malicious user could potentially exploit this vulnerability by sending malicious input to an SMI in order to bypass security controls in SMM.

CVE-2022-26863: Prior Dell BIOS versions contain an Input Validation vulnerability. A locally authenticated malicious user could potentially exploit this vulnerability by sending malicious input to an SMI in order to bypass security controls in SMM.

CVE-2022-26864: Prior Dell BIOS versions contain an Input Validation vulnerability. A locally authenticated malicious user could potentially exploit this vulnerability by sending malicious input to an SMI in order to bypass security controls in SMM.

CVE-2022-27228: In the vote (aka "Polls, Votes") module before 21.0.100 of Bitrix Site Manager, a remote unauthenticated attacker can execute arbitrary code.

CVE-2022-27634: On 16.1.x versions prior to 16.1.2.2 and 15.1.x versions prior to 15.1.5.1, BIG-IP APM does not properly validate configurations, allowing an authenticated attacker with high privileges to manipulate the APM policy leading to privilege escalation/remote code execution. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-27654: When a user opens a manipulated Photoshop Document (.psd, 2d.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-27655: When a user opens a manipulated Universal 3D (.u3d, 3difr.x3d) received from untrusted sources in SAP 3D Visual Enterprise Viewer - version 9.0, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-27803: Improper input validation vulnerability in Space of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to alter the data of Space.

CVE-2022-27826: Improper validation vulnerability in SemSuspendDialogInfo prior to SMR Apr-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-27827: Improper validation vulnerability in MediaMonitorDimension prior to SMR Apr-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-27828: Improper validation vulnerability in MediaMonitorEvent prior to SMR Apr-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-27829: Improper validation vulnerability in VerifyCredentialResponse prior to SMR Apr-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-27830: Improper validation vulnerability in SemBlurInfo prior to SMR Apr-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-28126: Improper input validation in some Intel(R) XMM(TM) 7560 Modem software before version M2_7560_R_01.2146.00 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-28127: A data removal vulnerability exists in the web_server /action/remove/ API functionality of Robustel R1510 3.3.0. A specially-crafted network request can lead to arbitrary file deletion. An attacker can send a sequence of requests to trigger this vulnerability.

CVE-2022-28129: Improper Input Validation vulnerability in HTTP/1.1 header parsing of Apache Traffic Server allows an attacker to send invalid headers. This issue affects Apache Traffic Server 8.0.0 to 9.1.2.

CVE-2022-28186: NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape, where the product receives input or data, but does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly, which may lead to denial of service or data tampering.

CVE-2022-28188: NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape, where the product receives input or data, but does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly, which may lead to denial of service.

CVE-2022-28190: NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape, where improper input validation can cause denial of service.

CVE-2022-28224: Clusters using Calico (version 3.22.1 and below), Calico Enterprise (version 3.12.0 and below), may be vulnerable to route hijacking with the floating IP feature. Due to insufficient validation, a privileged attacker may be able to set a floating IP annotation to a pod even if the feature is not enabled. This may allow the attacker to intercept and reroute traffic to their compromised pod.

CVE-2022-28328: A vulnerability has been identified in SCALANCE W1788-1 M12 (All versions < V3.0.0), SCALANCE W1788-2 EEC M12 (All versions < V3.0.0), SCALANCE W1788-2 M12 (All versions < V3.0.0), SCALANCE W1788-2IA M12 (All versions < V3.0.0). Affected devices do not properly handle malformed Multicast LLC frames. This could allow an attacker to trigger a denial of service condition.

CVE-2022-28329: A vulnerability has been identified in SCALANCE W1788-1 M12 (All versions < V3.0.0), SCALANCE W1788-2 EEC M12 (All versions < V3.0.0), SCALANCE W1788-2 M12 (All versions < V3.0.0), SCALANCE W1788-2IA M12 (All versions < V3.0.0). Affected devices do not properly handle malformed TCP packets received over the RemoteCapture feature. This could allow an attacker to lead to a denial of service condition which only affects the port used by the RemoteCapture feature.

CVE-2022-28611: Improper input validation in some Intel(R) XMM(TM) 7560 Modem software before version M2_7560_R_01.2146.00 may allow a privileged user to potentially enable escalation of privilege via physical access.

CVE-2022-28708: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2 and 15.1.x versions prior to 15.1.5.1, when a BIG-IP DNS resolver-enabled, HTTP-Explicit or SOCKS profile is configured on a virtual server, an undisclosed DNS response can cause the Traffic Management Microkernel (TMM) process to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-28741: aEnrich a+HRD 5.x Learning Management Key Performance Indicator System has a local file inclusion (LFI) vulnerability that occurs due to missing input validation in v5.x

CVE-2022-28781: Improper input validation in Settings prior to SMR-May-2022 Release 1 allows attackers to launch arbitrary activity with system privilege. The patch adds proper validation logic to check the caller.

CVE-2022-28783: Improper validation of removing package name in Galaxy Themes prior to SMR May-2022 Release 1 allows attackers to uninstall arbitrary packages without permission. The patch adds proper validation logic for removing package name.

CVE-2022-28791: Improper input validation vulnerability in InstallAgent in Galaxy Store prior to version 4.5.41.8 allows attacker to overwrite files stored in a specific path. The patch adds proper protection to prevent overwrite to existing files.

CVE-2022-29049: Jenkins promoted builds Plugin 873.v6149db_d64130 and earlier, except 3.10.1, does not validate the names of promotions defined in Job DSL, allowing attackers with Job/Configure permission to create a promotion with an unsafe name.

CVE-2022-30535: In versions 2.x before 2.3.0 and all versions of 1.x, An attacker authorized to create or update ingress objects can obtain the secrets available to the NGINX Ingress Controller. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-30542: Improper input validation in the firmware for some Intel(R) Server Board S2600WF, Intel(R) Server System R1000WF and Intel(R) Server System R2000WF families before version R02.01.0014 may allow a privileged user to potentially enable an escalation of privilege via local access.

CVE-2022-30709: Improper input validation check logic vulnerability in SECRIL prior to SMR Jun-2022 Release 1 allows attackers to trigger crash.

CVE-2022-30710: Improper validation vulnerability in RemoteViews prior to SMR Jun-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-30711: Improper validation vulnerability in FeedsInfo prior to SMR Jun-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-30712: Improper validation vulnerability in KfaOptions prior to SMR Jun-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-30713: Improper validation vulnerability in LSOItemData prior to SMR Jun-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-30719: Improper input validation check logic vulnerability in libsmkvextractor prior to SMR Jun-2022 Release 1 allows attackers to trigger crash.

CVE-2022-30720: Improper input validation check logic vulnerability in libsmkvextractor prior to SMR Jun-2022 Release 1 allows attackers to trigger crash.

CVE-2022-30721: Improper input validation check logic vulnerability in libsmkvextractor prior to SMR Jun-2022 Release 1 allows attackers to trigger crash.

CVE-2022-31321: The foldername parameter in Bolt 5.1.7 was discovered to have incorrect input validation, allowing attackers to perform directory enumeration or cause a Denial of Service (DoS) via a crafted input.

CVE-2022-31607: NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where a local user with basic capabilities can cause improper input validation, which may lead to denial of service, escalation of privileges, data tampering, and limited information disclosure.

CVE-2022-31762: The AMS module has a vulnerability in input validation. Successful exploitation of this vulnerability may cause privilege escalation.

CVE-2022-31766: A vulnerability has been identified in RUGGEDCOM RM1224 LTE(4G) EU (All versions < V7.1.2), RUGGEDCOM RM1224 LTE(4G) NAM (All versions < V7.1.2), SCALANCE M804PB (All versions < V7.1.2), SCALANCE M812-1 ADSL-Router (Annex A) (All versions < V7.1.2), SCALANCE M812-1 ADSL-Router (Annex B) (All versions < V7.1.2), SCALANCE M816-1 ADSL-Router (Annex A) (All versions < V7.1.2), SCALANCE M816-1 ADSL-Router (Annex B) (All versions < V7.1.2), SCALANCE M826-2 SHDSL-Router (All versions < V7.1.2), SCALANCE M874-2 (All versions < V7.1.2), SCALANCE M874-3 (All versions < V7.1.2), SCALANCE M876-3 (EVDO) (All versions < V7.1.2), SCALANCE M876-3 (ROK) (All versions < V7.1.2), SCALANCE M876-4 (All versions < V7.1.2), SCALANCE M876-4 (EU) (All versions < V7.1.2), SCALANCE M876-4 (NAM) (All versions < V7.1.2), SCALANCE MUM853-1 (EU) (All versions < V7.1.2), SCALANCE MUM856-1 (EU) (All versions < V7.1.2), SCALANCE MUM856-1 (RoW) (All versions < V7.1.2), SCALANCE S615 (All versions < V7.1.2), SCALANCE S615 EEC (All versions < V7.1.2), SCALANCE WAM763-1 (All versions >= V1.1.0 < V2.0), SCALANCE WAM766-1 (EU) (All versions >= V1.1.0 < V2.0), SCALANCE WAM766-1 (US) (All versions >= V1.1.0 < V2.0), SCALANCE WAM766-1 EEC (EU) (All versions >= V1.1.0 < V2.0), SCALANCE WAM766-1 EEC (US) (All versions >= V1.1.0 < V2.0), SCALANCE WUM763-1 (All versions >= V1.1.0 < V2.0), SCALANCE WUM763-1 (All versions >= V1.1.0 < V2.0), SCALANCE WUM766-1 (EU) (All versions >= V1.1.0 < V2.0), SCALANCE WUM766-1 (US) (All versions >= V1.1.0 < V2.0). Affected devices with TCP Event service enabled do not properly handle malformed packets. This could allow an unauthenticated remote attacker to cause a denial of service condition and reboot the device thus possibly affecting other network resources.

CVE-2022-31772:  IBM MQ 8.0, 9.0 LTS, 9.1 CD, 9.1 LTS, 9.2 CD, and 9.2 LTS could allow an authenticated and authorized user to cause a denial of service to the MQTT channels. IBM X-Force ID: 228335. 

CVE-2022-31778: Improper Input Validation vulnerability in handling the Transfer-Encoding header of Apache Traffic Server allows an attacker to poison the cache. This issue affects Apache Traffic Server 8.0.0 to 9.0.2.

CVE-2022-31779: Improper Input Validation vulnerability in HTTP/2 header parsing of Apache Traffic Server allows an attacker to smuggle requests. This issue affects Apache Traffic Server 8.0.0 to 9.1.2.

CVE-2022-31780: Improper Input Validation vulnerability in HTTP/2 frame handling of Apache Traffic Server allows an attacker to smuggle requests. This issue affects Apache Traffic Server 8.0.0 to 9.1.2.

CVE-2022-3181: An Improper Input Validation vulnerability exists in Trihedral VTScada version 12.0.38 and prior. A specifically malformed HTTP request could cause the affected VTScada to crash. Both local area network (LAN)-only and internet facing systems are affected. 

CVE-2022-3201: Insufficient validation of untrusted input in DevTools in Google Chrome on Chrome OS prior to 105.0.5195.125 allowed an attacker who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: High)

CVE-2022-32235: When a user opens manipulated AutoCAD (.dwg, TeighaTranslator.exe) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32236: When a user opens manipulated Windows Bitmap (.bmp, 2d.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32237: When a user opens manipulated Computer Graphics Metafile (.cgm, CgmCore.dll) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32238: When a user opens manipulated Encapsulated Post Script (.eps, ai.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32239: When a user opens manipulated JPEG 2000 (.jp2, jp2k.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32240: When a user opens manipulated Jupiter Tesselation (.jt, JTReader.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32241: When a user opens manipulated Portable Document Format (.pdf, PDFView.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32242: When a user opens manipulated Radiance Picture (.hdr, hdr.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32243: When a user opens manipulated Scalable Vector Graphics (.svg, svg.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application.

CVE-2022-32248: Due to missing input validation in the Manage Checkbooks component of SAP S/4HANA - version 101, 102, 103, 104, 105, 106, an attacker could insert or edit the value of an existing field in the database. This leads to an impact on the integrity of the data.

CVE-2022-32253: A vulnerability has been identified in SINEMA Remote Connect Server (All versions < V3.1). Due to improper input validation, the OpenSSL certificate's password could be printed to a file reachable by an attacker.

CVE-2022-32482:  Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user with admin privileges may potentially exploit this vulnerability in order to modify a UEFI variable. 

CVE-2022-32483: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user with admin privileges may potentially exploit this vulnerability in order to modify a UEFI variable.

CVE-2022-32484: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user with admin privileges may potentially exploit this vulnerability in order to modify a UEFI variable.

CVE-2022-32485: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-32486: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-32487: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-32488: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-32489: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-32490:  Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM. 

CVE-2022-32492: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-32591: In ril, there is a possible system crash due to an incorrect bounds check. This could lead to remote denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07257259; Issue ID: ALPS07257259.

CVE-2022-33176: Improper input validation in BIOS firmware for some Intel(R) NUC 11 Performance kits and Intel(R) NUC 11 Performance Mini PCs before version PATGL357.0042 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-33178: A vulnerability in the radius authentication system of Brocade Fabric OS before Brocade Fabric OS 9.0 could allow a remote attacker to execute arbitrary code on the Brocade switch.

CVE-2022-33190: Improper input validation in the Intel(R) SUR software before version 2.4.8902 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-33209: Improper input validation in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-33703: Improper validation vulnerability in CACertificateInfo prior to SMR Jul-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-33704: Improper validation vulnerability in ucmRetParcelable of KnoxSDK prior to SMR Jul-2022 Release 1 allows attackers to launch certain activities.

CVE-2022-33752: CA Automic Automation 12.2 and 12.3 contain an insufficient input validation vulnerability in the Automic agent that could allow a remote attacker to potentially execute arbitrary code.

CVE-2022-33754: CA Automic Automation 12.2 and 12.3 contain an insufficient input validation vulnerability in the Automic agent that could allow a remote attacker to potentially execute arbitrary code.

CVE-2022-3388:  An input validation vulnerability exists in the Monitor Pro interface of MicroSCADA Pro and MicroSCADA X SYS600. An authenticated user can launch an administrator level remote code execution irrespective of the authenticated user's role. 

CVE-2022-33964: Improper input validation in the Intel(R) SUR software before version 2.4.8902 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

CVE-2022-34152: Improper input validation in BIOS firmware for some Intel(R) NUC Boards, Intel(R) NUC Kits before version TY0070 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-34164: IBM CICS TX 11.1 could allow a local user to impersonate another legitimate user due to improper input validation. IBM X-Force ID: 229338.

CVE-2022-34345: Improper input validation in the firmware for some Intel(R) NUC Laptop Kits before version BC0076 may allow a privileged user to potentially enable escalation of privilege via physical access.

CVE-2022-34350: IBM API Connect 10.0.0.0 through 10.0.5.0, 10.0.1.0 through 10.0.1.7, and 2018.4.1.0 through 2018.4.1.20 is vulnerable to External Service Interaction attack, caused by improper validation of user-supplied input. A remote attacker could exploit this vulnerability to induce the application to perform server-side DNS lookups or HTTP requests to arbitrary domain names. By submitting suitable payloads, an attacker can cause the application server to attack other systems that it can interact with. IBM X-Force ID: 230264.

CVE-2022-34376:  Dell PowerEdge BIOS and Dell Precision BIOS contain an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by manipulating an SMI to cause a denial of service during SMM. 

CVE-2022-34393:  Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM. 

CVE-2022-34435:  Dell iDRAC9 version 6.00.02.00 and prior contain an improper input validation vulnerability in Racadm when the firmware lock-down configuration is set. A remote high privileged attacker could exploit this vulnerability to bypass the firmware lock-down configuration and perform a firmware update. 

CVE-2022-34436:  Dell iDRAC8 version 2.83.83.83 and prior contain an improper input validation vulnerability in Racadm when the firmware lock-down configuration is set. A remote high privileged attacker could exploit this vulnerability to bypass the firmware lock-down configuration and perform a firmware update. 

CVE-2022-3444: Insufficient data validation in File System API in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to bypass File System restrictions via a crafted HTML page and malicious file. (Chromium security severity: Low)

CVE-2022-34443:  Dell Rugged Control Center, versions prior to 4.5, contain an Improper Input Validation in the Service EndPoint. A Local Low Privilege attacker could potentially exploit this vulnerability, leading to an Escalation of privileges. 

CVE-2022-34460:  Prior Dell BIOS versions contain an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM. 

CVE-2022-34681: NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler, where improper input validation of a display-related data structure may lead to denial of service.

CVE-2022-34758: A CWE-20: Improper Input Validation vulnerability exists that could cause the device watchdog function to be disabled if the attacker had access to privileged user credentials. Affected Products: Easergy P5 (V01.401.102 and prior)

CVE-2022-34851: In BIG-IP Versions 17.0.x before 17.0.0.1, 16.1.x before 16.1.3.1, 15.1.x before 15.1.6.1, 14.1.x before 14.1.5.1, and all versions of 13.1.x, and BIG-IQ Centralized Management all versions of 8.x, an authenticated attacker may cause iControl SOAP to become unavailable through undisclosed requests. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-34866: Passage Drive versions v1.4.0 to v1.5.1.0 and Passage Drive for Box version v1.0.0 contain an insufficient data verification vulnerability for interprocess communication. By running a malicious program, an arbitrary OS command may be executed with LocalSystem privilege of the Windows system where the product is running.

CVE-2022-35171: When a user opens manipulated JPEG 2000 (.jp2, jp2k.x3d) files received from untrusted sources in SAP 3D Visual Enterprise Viewer, the application crashes and becomes temporarily unavailable to the user until restart of the application. The file format details along with their CVE relevant information can be found below

CVE-2022-35239: The image file management page of SolarView Compact SV-CPT-MC310 Ver.7.23 and earlier, and SV-CPT-MC310F Ver.7.23 and earlier contains an insufficient verification vulnerability when uploading files. If this vulnerability is exploited, arbitrary PHP code may be executed if a remote authenticated attacker uploads a specially crafted PHP file.

CVE-2022-35415: An improper input validation in NI System Configuration Manager before 22.5 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-35666: Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2022-35668: Adobe Acrobat Reader versions 22.001.20169 (and earlier), 20.005.30362 (and earlier) and 17.012.30249 (and earlier) are affected by an Improper Input Validation vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2022-36058: Elrond go is the go implementation for the Elrond Network protocol. In versions prior to 1.3.34, anyone who uses elrond-go to process blocks (historical or actual) could encounter a `MultiESDTNFTTransfer` transaction like this: `MultiESDTNFTTransfer` with a missing function name. Basic functionality like p2p messaging, storage, API requests and such are unaffected. Version 1.3.34 contains a fix for this issue. There are no known workarounds.

CVE-2022-36450: Obsidian 0.14.x and 0.15.x before 0.15.5 allows obsidian://hook-get-address remote code execution because window.open is used without checking the URL.

CVE-2022-37010: In JetBrains IntelliJ IDEA before 2022.2 email address validation in the "Git User Name Is Not Defined" dialog was missed

CVE-2022-37395: A Huawei device has an input verification vulnerability. Successful exploitation of this vulnerability may lead to DoS attacks.Affected product versions include:CV81-WDM FW versions 01.70.49.29.46.

CVE-2022-38385:  IBM Cloud Pak for Security (CP4S) 1.10.0.0 through 1.10.2.0 could allow an authenticated user to obtain highly sensitive information or perform unauthorized actions due to improper input validation. IBM X-Force ID: 233777. 

CVE-2022-38408: Adobe Illustrator versions 26.4 (and earlier) and 25.4.7 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file. requires user interaction in that a victim must open a malicious file.

CVE-2022-38435: Adobe Illustrator versions 26.4 (and earlier) and 25.4.7 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2022-38778: A flaw (CVE-2022-38900) was discovered in one of Kibana’s third party dependencies, that could allow an authenticated user to perform a request that crashes the Kibana server process.

CVE-2022-38985: The facial recognition module has a vulnerability in input validation.Successful exploitation of this vulnerability may affect data confidentiality.

CVE-2022-39012: Huawei Aslan Children's Watch has an improper input validation vulnerability. Successful exploitation may cause the watch's application service abnormal.

CVE-2022-39060: ChangingTech MegaServiSignAdapter component has a vulnerability of improper input validation. An unauthenticated remote attacker can exploit this vulnerability to access and modify HKEY_CURRENT_USER subkey (ex: AutoRUN) in Registry where malicious scripts can be executed to take control of the system or to terminate the service.

CVE-2022-39306: Grafana is an open-source platform for monitoring and observability. Versions prior to 9.2.4, or 8.5.15 on the 8.X branch, are subject to Improper Input Validation. Grafana admins can invite other members to the organization they are an admin for. When admins add members to the organization, non existing users get an email invite, existing members are added directly to the organization. When an invite link is sent, it allows users to sign up with whatever username/email address the user chooses and become a member of the organization. This introduces a vulnerability which can be used with malicious intent. This issue is patched in version 9.2.4, and has been backported to 8.5.15. There are no known workarounds.

CVE-2022-39318: FreeRDP is a free remote desktop protocol library and clients. Affected versions of FreeRDP are missing input validation in `urbdrc` channel. A malicious server can trick a FreeRDP based client to crash with division by zero. This issue has been addressed in version 2.9.0. All users are advised to upgrade. Users unable to upgrade should not use the `/usb` redirection switch.

CVE-2022-39338: user_oidc is an OpenID Connect user backend for Nextcloud. Versions prior to 1.2.1 did not properly validate discovery urls which may lead to a stored cross site scripting attack vector. The impact is limited due to the restrictive CSP that is applied on this endpoint. Additionally this vulnerability has only been shown to be exploitable in the Safari web browser. This issue has been addressed in version 1.2.1. Users are advised to upgrade. Users unable to upgrade should urge their users to avoid using the Safari web browser.

CVE-2022-39880: Improper input validation vulnerability in DualOutFocusViewer prior to SMR Nov-2022 Release 1 allows local attacker to perform an arbitrary code execution.

CVE-2022-40227: A vulnerability has been identified in SIMATIC HMI Comfort Panels (incl. SIPLUS variants) (All versions < V17 Update 4), SIMATIC HMI KTP Mobile Panels (All versions < V17 Update 4), SIMATIC HMI KTP1200 Basic (All versions < V17 Update 5), SIMATIC HMI KTP400 Basic (All versions < V17 Update 5), SIMATIC HMI KTP700 Basic (All versions < V17 Update 5), SIMATIC HMI KTP900 Basic (All versions < V17 Update 5), SIPLUS HMI KTP1200 BASIC (All versions < V17 Update 5), SIPLUS HMI KTP400 BASIC (All versions < V17 Update 5), SIPLUS HMI KTP700 BASIC (All versions < V17 Update 5), SIPLUS HMI KTP900 BASIC (All versions < V17 Update 5). Affected devices do not properly validate input sent to certain services over TCP. This could allow an unauthenticated remote attacker to cause a permanent denial of service condition (requiring a device reboot) by sending specially crafted TCP packets.

CVE-2022-40235: "IBM InfoSphere Information Server 11.7 could allow a user to cause a denial of service by removing the ability to run jobs due to improper input validation. IBM X-Force ID: 235725."

CVE-2022-40237: IBM MQ for HPE NonStop 8.1.0 is vulnerable to a denial of service attack due to an error within the CCDT and channel synchronization logic. IBM X-Force ID: 235727.

CVE-2022-40265: Improper Input Validation vulnerability in Mitsubishi Electric Corporation MELSEC iQ-R Series RJ71EN71 Firmware version "65" and prior and Mitsubishi Electric Corporation MELSEC iQ-R Series R04/08/16/32/120ENCPU Network Part Firmware version "65" and prior allows a remote unauthenticated attacker to cause a Denial of Service condition by sending specially crafted packets. A system reset is required for recovery.

CVE-2022-40266: Improper Input Validation vulnerability in Mitsubishi Electric GOT2000 Series GT27 model FTP server versions 01.39.000 and prior, Mitsubishi Electric GOT2000 Series GT25 model FTP server versions 01.39.000 and prior and Mitsubishi Electric GOT2000 Series GT23 model FTP server versions 01.39.000 and prior allows a remote authenticated attacker to cause a Denial of Service condition by sending specially crafted command.

CVE-2022-40276: Zettlr version 2.3.0 allows an external attacker to remotely obtain arbitrary local files on any client that attempts to view a malicious markdown file through Zettlr. This is possible because the application does not have a CSP policy (or at least not strict enough) and/or does not properly validate the contents of markdown files before rendering them.

CVE-2022-41214: Due to insufficient input validation, SAP NetWeaver Application Server ABAP and ABAP Platform allows an attacker with high level privileges to use a remote enabled function to delete a file which is otherwise restricted. On successful exploitation an attacker can completely compromise the integrity and availability of the application. 

CVE-2022-41694: In BIG-IP versions 16.1.x before 16.1.3, 15.1.x before 15.1.6.1, 14.1.x before 14.1.5, and all versions of 13.1.x, and BIG-IQ versions 8.x before 8.2.0.1 and all versions of 7.x, when an SSL key is imported on a BIG-IP or BIG-IQ system, undisclosed input can cause MCPD to terminate.

CVE-2022-41733:  IBM InfoSphere Information Server 11.7 could allow a remote attacked to cause some of the components to be unusable until the process is restarted. IBM X-Force ID: 237583. 

CVE-2022-41813: In versions 16.1.x before 16.1.3.1, 15.1.x before 15.1.6.1, 14.1.x before 14.1.5, and all versions of 13.1.x, when BIG-IP is provisioned with PEM or AFM module, an undisclosed input can cause Traffic Management Microkernel (TMM) to terminate.

CVE-2022-41888: TensorFlow is an open source platform for machine learning. When running on GPU, `tf.image.generate_bounding_box_proposals` receives a `scores` input that must be of rank 4 but is not checked. We have patched the issue in GitHub commit cf35502463a88ca7185a99daa7031df60b3c1c98. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

CVE-2022-41891: TensorFlow is an open source platform for machine learning. If `tf.raw_ops.TensorListConcat` is given `element_shape=[]`, it results segmentation fault which can be used to trigger a denial of service attack. We have patched the issue in GitHub commit fc33f3dc4c14051a83eec6535b608abe1d355fde. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

CVE-2022-41898: TensorFlow is an open source platform for machine learning. If `SparseFillEmptyRowsGrad` is given empty inputs, TensorFlow will crash. We have patched the issue in GitHub commit af4a6a3c8b95022c351edae94560acc61253a1b8. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

CVE-2022-41899: TensorFlow is an open source platform for machine learning. Inputs `dense_features` or `example_state_data` not of rank 2 will trigger a `CHECK` fail in `SdcaOptimizer`. We have patched the issue in GitHub commit 80ff197d03db2a70c6a111f97dcdacad1b0babfa. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

CVE-2022-41901: TensorFlow is an open source platform for machine learning. An input `sparse_matrix` that is not a matrix with a shape with rank 0 will trigger a `CHECK` fail in `tf.raw_ops.SparseMatrixNNZ`. We have patched the issue in GitHub commit f856d02e5322821aad155dad9b3acab1e9f5d693. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

CVE-2022-41909: TensorFlow is an open source platform for machine learning. An input `encoded` that is not a valid `CompositeTensorVariant` tensor will trigger a segfault in `tf.raw_ops.CompositeTensorVariantToComponents`. We have patched the issue in GitHub commits bf594d08d377dc6a3354d9fdb494b32d45f91971 and 660ce5a89eb6766834bdc303d2ab3902aef99d3d. The fix will be included in TensorFlow 2.11. We will also cherrypick this commit on TensorFlow 2.10.1, 2.9.3, and TensorFlow 2.8.4, as these are also affected and still in supported range.

CVE-2022-42269: NVIDIA Trusted OS contains a vulnerability in an SMC call handler, where failure to validate untrusted input may allow a highly privileged local attacker to cause information disclosure and compromise integrity. The scope of the impact can extend to other components.

CVE-2022-42340: Adobe ColdFusion versions Update 14 (and earlier) and Update 4 (and earlier) are affected by an Improper Input Validation vulnerability that could result in arbitrary file system read. Exploitation of this issue does not require user interaction.

CVE-2022-42468: Apache Flume versions 1.4.0 through 1.10.1 are vulnerable to a remote code execution (RCE) attack when a configuration uses a JMS Source with an unsafe providerURL. This issue is fixed by limiting JNDI to allow only the use of the java protocol or no protocol.

CVE-2022-42534: In trusty_ffa_mem_reclaim of shared-mem-smcall.c, there is a possible privilege escalation due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-237838301References: N/A

CVE-2022-42544: In getView of AddAppNetworksFragment.java, there is a possible way to mislead the user about network add requests due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-224545390

CVE-2022-43439: A vulnerability has been identified in POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10). Affected devices do not properly validate the Language-parameter in requests to the web interface on port 443/tcp. This could allow an authenticated remote attacker to crash the device (followed by an automatic reboot) or to execute arbitrary code on the device.

CVE-2022-43455: Sewio’s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 is vulnerable to improper input validation of user input to the service_start, service_stop, and service_restart modules of the software. This could allow an attacker to start, stop, or restart arbitrary services running on the server. 

CVE-2022-43545: A vulnerability has been identified in POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10). Affected devices do not properly validate the RecordType-parameter in requests to the web interface on port 443/tcp. This could allow an authenticated remote attacker to crash the device (followed by an automatic reboot) or to execute arbitrary code on the device.

CVE-2022-43546: A vulnerability has been identified in POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), POWER METER SICAM Q100 (All versions < V2.50), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P850 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10), SICAM P855 (All versions < V3.10). Affected devices do not properly validate the EndTime-parameter in requests to the web interface on port 443/tcp. This could allow an authenticated remote attacker to crash the device (followed by an automatic reboot) or to execute arbitrary code on the device.

CVE-2022-43563: In Splunk Enterprise versions below 8.2.9 and 8.1.12, the way that the rex search command handles field names lets an attacker bypass SPL safeguards for risky commands https://docs.splunk.com/Documentation/SplunkCloud/latest/Security/SPLsafeguards . The vulnerability requires the attacker to phish the victim by tricking them into initiating a request within their browser. The attacker cannot exploit the vulnerability at will. 

CVE-2022-43565: In Splunk Enterprise versions below 8.2.9 and 8.1.12, the way that the ‘tstats command handles Javascript Object Notation (JSON) lets an attacker bypass SPL safeguards for risky commands https://docs.splunk.com/Documentation/SplunkCloud/latest/Security/SPLsafeguards . The vulnerability requires the attacker to phish the victim by tricking them into initiating a request within their browser. 

CVE-2022-43863: IBM QRadar SIEM 7.4 and 7.5 is vulnerable to privilege escalation, allowing a user with some admin capabilities to gain additional admin capabilities. IBM X-Force ID: 239425.

CVE-2022-43875: IBM Financial Transaction Manager for SWIFT Services for Multiplatforms 3.2.4 could allow an authenticated user to lock additional RM authorizations, resulting in a denial of service on displaying or managing these authorizations. IBM X-Force ID: 240034.

CVE-2022-43929:  IBM Db2 for Linux, UNIX and Windows 11.1 and 11.5 may be vulnerable to a Denial of Service when executing a specially crafted 'Load' command. IBM X-Force ID: 241676. 

CVE-2022-4428: support_uri parameter in the WARP client local settings file (mdm.xml) lacked proper validation which allowed for privilege escalation and launching an arbitrary executable on the local machine upon clicking on the "Send feedback" option. An attacker with access to the local file system could use a crafted XML config file pointing to a malicious file or set a local path to the executable using Cloudflare Zero Trust Dashboard (for Zero Trust enrolled clients). 

CVE-2022-44756: Insights for Vulnerability Remediation (IVR) is vulnerable to improper input validation. This may lead to information disclosure. This requires privileged access.? 

CVE-2022-45088: Improper Input Validation vulnerability in Group Arge Energy and Control Systems Smartpower Web allows PHP Local File Inclusion.This issue affects Smartpower Web: before 23.01.01. 

CVE-2022-45770: Improper input validation in adgnetworkwfpdrv.sys in Adguard For Windows x86 through 7.11 allows local privilege escalation.

CVE-2022-45875: Improper validation of script alert plugin parameters in Apache DolphinScheduler to avoid remote command execution vulnerability. This issue affects Apache DolphinScheduler version 3.0.1 and prior versions; version 3.1.0 and prior versions. This attack can be performed only by authenticated users which can login to DS. 

CVE-2022-46328: Some smartphones have the input validation vulnerability. Successful exploitation of this vulnerability may affect data confidentiality.

CVE-2022-46363: A vulnerability in Apache CXF before versions 3.5.5 and 3.4.10 allows an attacker to perform a remote directory listing or code exfiltration. The vulnerability only applies when the CXFServlet is configured with both the static-resources-list and redirect-query-check attributes. These attributes are not supposed to be used together, and so the vulnerability can only arise if the CXF service is misconfigured. 

CVE-2022-46372: Alotcer - AR7088H-A firmware version 16.10.3 Command execution Improper validation of unspecified input field may allow Authenticated command execution.

CVE-2022-46705: A spoofing issue existed in the handling of URLs. This issue was addressed with improved input validation. This issue is fixed in iOS 16.2 and iPadOS 16.2, macOS Ventura 13.1, Safari 16.2. Visiting a malicious website may lead to address bar spoofing.

CVE-2022-46768: Arbitrary file read vulnerability exists in Zabbix Web Service Report Generation, which listens on the port 10053. The service does not have proper validation for URL parameters before reading the files.

CVE-2022-47917: Sewio’s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 is vulnerable to improper input validation of user input to several modules and services of the software. This could allow an attacker to delete arbitrary files and cause a denial-of-service condition. 

CVE-2022-2939: The WP Cerber Security plugin for WordPress is vulnerable to security protection bypass in versions up to, and including 9.0, that makes user enumeration possible. This is due to improper validation on the value supplied through the 'author' parameter found in the ~/cerber-load.php file. In vulnerable versions, the plugin only blocks requests if the value supplied is numeric, making it possible for attackers to supply additional non-numeric characters to bypass the protection. The non-numeric characters are stripped and the user requested is displayed. This can be used by unauthenticated attackers to gather information about users that can targeted in further attacks.

CVE-2022-32218: An information disclosure vulnerability exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 due to the actionLinkHandler method was found to allow Message ID Enumeration with Regex MongoDB queries.

CVE-2022-45103:  Dell Unisphere for PowerMax vApp, VASA Provider vApp, and Solution Enabler vApp version 9.2.3.x contain an information disclosure vulnerability. A low privileged remote attacker could potentially exploit this vulnerability, leading to read arbitrary files on the underlying file system. 

CVE-2021-1275: Multiple vulnerabilities in Cisco SD-WAN vManage Software could allow an unauthenticated, remote attacker to execute arbitrary code or gain access to sensitive information, or allow an authenticated, local attacker to gain escalated privileges or gain unauthorized access to the application. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-21698: client_golang is the instrumentation library for Go applications in Prometheus, and the promhttp package in client_golang provides tooling around HTTP servers and clients. In client_golang prior to version 1.11.1, HTTP server is susceptible to a Denial of Service through unbounded cardinality, and potential memory exhaustion, when handling requests with non-standard HTTP methods. In order to be affected, an instrumented software must use any of `promhttp.InstrumentHandler*` middleware except `RequestsInFlight`; not filter any specific methods (e.g GET) before middleware; pass metric with `method` label name to our middleware; and not have any firewall/LB/proxy that filters away requests with unknown `method`. client_golang version 1.11.1 contains a patch for this issue. Several workarounds are available, including removing the `method` label name from counter/gauge used in the InstrumentHandler; turning off affected promhttp handlers; adding custom middleware before promhttp handler that will sanitize the request method given by Go http.Request; and using a reverse proxy or web application firewall, configured to only allow a limited set of methods.

CVE-2022-22543: SAP NetWeaver Application Server for ABAP (Kernel) and ABAP Platform (Kernel) - versions KERNEL 7.22, 8.04, 7.49, 7.53, 7.77, 7.81, 7.85, 7.86, 7.87, KRNL64UC 8.04, 7.22, 7.22EXT, 7.49, 7.53, KRNL64NUC 7.22, 7.22EXT, 7.49, does not sufficiently validate sap-passport information, which could lead to a Denial-of-Service attack. This allows an unauthorized remote user to provoke a breakdown of the SAP Web Dispatcher or Kernel work process. The crashed process can be restarted immediately, other processes are not affected.

CVE-2022-22588: A resource exhaustion issue was addressed with improved input validation. This issue is fixed in iOS 15.2.1 and iPadOS 15.2.1. Processing a maliciously crafted HomeKit accessory name may cause a denial of service.

CVE-2022-22820: Due to the lack of media file checks before rendering, it was possible for an attacker to cause abnormal CPU consumption for message recipient by sending specially crafted gif image in LINE for Windows before 7.4.

CVE-2022-31110: RSSHub is an open source, extensible RSS feed generator. In commits prior to 5c4177441417 passing some special values to the `filter` and `filterout` parameters can cause an abnormally high CPU. This results in an impact on the performance of the servers and RSSHub services which may lead to a denial of service. This issue has been fixed in commit 5c4177441417 and all users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-35404: ManageEngine Password Manager Pro 12100 and prior and OPManager 126100 and prior are vulnerable to unauthorized file and directory creation on a server machine.

CVE-2022-36055: Helm is a tool for managing Charts. Charts are packages of pre-configured Kubernetes resources. Fuzz testing, provided by the CNCF, identified input to functions in the _strvals_ package that can cause an out of memory panic. The _strvals_ package contains a parser that turns strings in to Go structures. The _strvals_ package converts these strings into structures Go can work with. Some string inputs can cause array data structures to be created causing an out of memory panic. Applications that use the _strvals_ package in the Helm SDK to parse user supplied input can suffer a Denial of Service when that input causes a panic that cannot be recovered from. The Helm Client will panic with input to `--set`, `--set-string`, and other value setting flags that causes an out of memory panic. Helm is not a long running service so the panic will not affect future uses of the Helm client. This issue has been resolved in 3.9.4. SDK users can validate strings supplied by users won't create large arrays causing significant memory usage before passing them to the _strvals_ functions.

CVE-2022-24299: Improper input validation vulnerability in pfSense CE and pfSense Plus (pfSense CE software versions prior to 2.6.0 and pfSense Plus software versions prior to 22.01) allows a remote attacker with the privilege to change OpenVPN client or server settings to execute an arbitrary command.

CVE-2022-24382: Improper input validation in firmware for some Intel(R) NUCs may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-24415: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24416: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24417: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24418: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24419: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24420: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24421: Dell BIOS contains an improper input validation vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution during SMM.

CVE-2022-24423: Dell iDRAC8 versions prior to 2.83.83.83 contain a denial of service vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability to cause resource exhaustion in the webserver, resulting in a denial of service condition.

CVE-2022-24774: CycloneDX BOM Repository Server is a bill of materials (BOM) repository server for distributing CycloneDX BOMs. CycloneDX BOM Repository Server before version 2.0.1 has an improper input validation vulnerability leading to path traversal. A malicious user may potentially exploit this vulnerability to create arbitrary directories or a denial of service by deleting arbitrary directories. The vulnerability is resolved in version 2.0.1. The vulnerability is not exploitable with the default configuration with the post and delete methods disabled. This can be configured by modifying the `appsettings.json` file, or alternatively, setting the environment variables `ALLOWEDMETHODS__POST` and `ALLOWEDMETHODS__DELETE` to `false`.

CVE-2022-24861: Databasir is a team-oriented relational database model document management platform. Databasir 1.01 has remote code execution vulnerability. JDBC drivers are not validated prior to use and may be provided by users of the system. This can lead to code execution by any basic user who has access to the system. Users are advised to upgrade. There are no known workarounds to this issue.

CVE-2022-24925: Improper input validation vulnerability in SettingsProvider prior to Android S(12) allows privileged attackers to trigger a permanent denial of service attack on a victim's devices.

CVE-2022-24952: Several denial of service vulnerabilities exist in Eternal Terminal prior to version 6.2.0, including a DoS triggered remotely by an invalid sequence number and a local bug triggered by invalid input sent directly to the IPC socket.

CVE-2022-25161: Improper Input Validation vulnerability in Mitsubishi Electric MELSEC iQ-F series FX5U-xMy/z(x=32,64,80, y=T,R, z=ES,DS,ESS,DSS) with serial number 17X**** or later and versions prior to 1.270, Mitsubishi Electric Mitsubishi Electric MELSEC iQ-F series FX5U-xMy/z(x=32,64,80, y=T,R, z=ES,DS,ESS,DSS) with serial number 179**** and prior and versions prior to 1.073, MELSEC iQ-F series FX5UC-xMy/z(x=32,64,96, y=T,R, z=D,DSS) with serial number 17X**** or later and versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UC-xMy/z(x=32,64,96, y=T,R, z=D,DSS) with serial number 179**** and prior and versions prior to 1.073, Mitsubishi Electric MELSEC iQ-F series FX5UC-32MT/DS-TS versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UC-32MT/DSS-TS versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UC-32MR/DS-TS versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UJ-xMy/z(x=24,40,60, y=T,R, z=ES,ESS) versions prior to 1.030, Mitsubishi Electric MELSEC iQ-F series FX5UJ-xMy/ES-A(x=24,40,60, y=T,R) versions prior to 1.031 and Mitsubishi Electric MELSEC iQ-F series FX5S-xMy/z(x=30,40,60,80, y=T,R, z=ES,ESS) version 1.000 allows a remote unauthenticated attacker to cause a DoS condition for the product's program execution or communication by sending specially crafted packets. System reset of the product is required for recovery.

CVE-2022-25162: Improper Input Validation vulnerability in Mitsubishi Electric MELSEC iQ-F series FX5U-xMy/z(x=32,64,80, y=T,R, z=ES,DS,ESS,DSS) with serial number 17X**** or later and versions prior to 1.270, Mitsubishi Electric Mitsubishi Electric MELSEC iQ-F series FX5U-xMy/z(x=32,64,80, y=T,R, z=ES,DS,ESS,DSS) with serial number 179**** and prior and versions prior to 1.073, MELSEC iQ-F series FX5UC-xMy/z(x=32,64,96, y=T,R, z=D,DSS) with serial number 17X**** or later and versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UC-xMy/z(x=32,64,96, y=T,R, z=D,DSS) with serial number 179**** and prior and versions prior to 1.073, Mitsubishi Electric MELSEC iQ-F series FX5UC-32MT/DS-TS versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UC-32MT/DSS-TS versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UC-32MR/DS-TS versions prior to 1.270, Mitsubishi Electric MELSEC iQ-F series FX5UJ-xMy/z(x=24,40,60, y=T,R, z=ES,ESS) versions prior to 1.030, Mitsubishi Electric MELSEC iQ-F series FX5UJ-xMy/ES-A(x=24,40,60, y=T,R) versions prior to 1.031 and Mitsubishi Electric MELSEC iQ-F series FX5S-xMy/z(x=30,40,60,80, y=T,R, z=ES,ESS) version 1.000 allows a remote unauthenticated attacker to cause a temporary DoS condition for the product's communication by sending specially crafted packets.

CVE-2022-25163: Improper Input Validation vulnerability in Mitsubishi Electric MELSEC-Q Series QJ71E71-100 first 5 digits of serial number "24061" or prior, Mitsubishi Electric MELSEC-L series LJ71E71-100 first 5 digits of serial number "24061" or prior and Mitsubishi Electric MELSEC iQ-R Series RD81MES96N firmware version "08" or prior allows a remote unauthenticated attacker to cause a denial of service (DoS) condition or execute malicious code on the target products by sending specially crafted packets.

CVE-2022-25271: Drupal core's form API has a vulnerability where certain contributed or custom modules' forms may be vulnerable to improper input validation. This could allow an attacker to inject disallowed values or overwrite data. Affected forms are uncommon, but in certain cases an attacker could alter critical or sensitive data.

CVE-2022-25595: ASUS RT-AC86U has improper user request handling, which allows an unauthenticated LAN attacker to cause a denial of service by sending particular request a server-to-client reply attempt.

CVE-2021-40712: Adobe Experience Manager version 6.5.9.0 (and earlier) is affected by a improper input validation vulnerability via the path parameter. An authenticated attacker can send a malformed POST request to achieve server-side denial of service.

CVE-2021-41114: TYPO3 is an open source PHP based web content management system released under the GNU GPL. It has been discovered that TYPO3 CMS is susceptible to host spoofing due to improper validation of the HTTP Host header. TYPO3 uses the HTTP Host header, for example, to generate absolute URLs during the frontend rendering process. Since the host header itself is provided by the client, it can be forged to any value, even in a name-based virtual hosts environment. This vulnerability is the same as described in TYPO3-CORE-SA-2014-001 (CVE-2014-3941). A regression, introduced during TYPO3 v11 development, led to this situation. The already existing setting $GLOBALS['TYPO3_CONF_VARS']['SYS']['trustedHostsPattern'] (used as an effective mitigation strategy in previous TYPO3 versions) was not evaluated anymore, and reintroduced the vulnerability.

CVE-2021-41138: Frontier is Substrate's Ethereum compatibility layer. In the newly introduced signed Frontier-specific extrinsic for `pallet-ethereum`, a large part of transaction validation logic was only called in transaction pool validation, but not in block execution. Malicious validators can take advantage of this to put invalid transactions into a block. The attack is limited in that the signature is always validated, and the majority of the validation is done again in the subsequent `pallet-evm` execution logic. However, do note that a chain ID replay attack was possible. In addition, spamming attacks are of main concerns, while they are limited by Substrate block size limits and other factors. The issue is patched in commit `146bb48849e5393004be5c88beefe76fdf009aba`.

CVE-2021-4120: snapd 2.54.2 fails to perform sufficient validation of snap content interface and layout paths, resulting in the ability for snaps to inject arbitrary AppArmor policy rules via malformed content interface and layout declarations and hence escape strict snap confinement. Fixed in snapd versions 2.54.3+18.04, 2.54.3+20.04 and 2.54.3+21.10.1

CVE-2021-41561: Improper Input Validation vulnerability in Parquet-MR of Apache Parquet allows an attacker to DoS by malicious Parquet files. This issue affects Apache Parquet-MR version 1.9.0 and later versions.

CVE-2021-41583: vpn-user-portal (aka eduVPN or Let's Connect!) before 2.3.14, as packaged for Debian 10, Debian 11, and Fedora, allows remote authenticated users to obtain OS filesystem access, because of the interaction of QR codes with an exec that uses the -r option. This can be leveraged to obtain additional VPN access.

CVE-2021-41585: Improper Input Validation vulnerability in accepting socket connections in Apache Traffic Server allows an attacker to make the server stop accepting new connections. This issue affects Apache Traffic Server 5.0.0 to 9.1.0.

CVE-2021-41769: A vulnerability has been identified in SIPROTEC 5 6MD85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 6MD86 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 6MD89 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 6MU85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7KE85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SA82 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7SA86 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SA87 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SD82 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7SD86 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SD87 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SJ81 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7SJ82 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7SJ85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SJ86 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SK82 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7SK85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SL82 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7SL86 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SL87 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SS85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7ST85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7SX85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7UM85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7UT82 devices (CPU variant CP100) (All versions < V8.83), SIPROTEC 5 7UT85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7UT86 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7UT87 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7VE85 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 7VK87 devices (CPU variant CP300) (All versions < V8.83), SIPROTEC 5 Compact 7SX800 devices (CPU variant CP050) (All versions < V8.83). An improper input validation vulnerability in the web server could allow an unauthenticated user to access device information.

CVE-2021-41772: Go before 1.16.10 and 1.17.x before 1.17.3 allows an archive/zip Reader.Open panic via a crafted ZIP archive containing an invalid name or an empty filename field.

CVE-2021-41788: MediaTek microchips, as used in NETGEAR devices through 2021-12-13 and other devices, mishandle attempts at Wi-Fi authentication flooding. (Affected Chipsets MT7603E, MT7612, MT7613, MT7615, MT7622, MT7628, MT7629, MT7915; Affected Software Versions 7.4.0.0).

CVE-2021-41789: In wifi driver, there is a possible system crash due to a missing validation check. This could lead to remote denial of service from a proximal attacker with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: GN20190426015; Issue ID: GN20190426015.

CVE-2021-41844: Crocoblock JetEngine before 2.9.1 does not properly validate and sanitize form data.

CVE-2021-42009: An authenticated Apache Traffic Control Traffic Ops user with Portal-level privileges can send a request with a specially-crafted email subject to the /deliveryservices/request Traffic Ops endpoint to send an email, from the Traffic Ops server, with an arbitrary body to an arbitrary email address. Apache Traffic Control 5.1.x users should upgrade to 5.1.3 or 6.0.0. 4.1.x users should upgrade to 5.1.3.

CVE-2021-4204: An out-of-bounds (OOB) memory access flaw was found in the Linux kernel's eBPF due to an Improper Input Validation. This flaw allows a local attacker with a special privilege to crash the system or leak internal information.

CVE-2021-0417: In memory management driver, there is a possible system crash due to improper input validation. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05403499; Issue ID: ALPS05336702.

CVE-2021-0933: In onCreate of CompanionDeviceActivity.java or DeviceChooserActivity.java, there is a possible way for HTML tags to interfere with a consent dialog due to improper input validation. This could lead to remote escalation of privilege, confusing the user into accepting pairing of a malicious Bluetooth device, with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-172251622

CVE-2021-32697: neos/forms is an open source framework to build web forms. By crafting a special `GET` request containing a valid form state, a form can be submitted without invoking any validators. Form state is secured with an HMAC that is still verified. That means that this issue can only be exploited if Form Finishers cause side effects even if no form values have been sent. Form Finishers can be adjusted in a way that they only execute an action if the submitted form contains some expected data. Alternatively a custom Finisher can be added as first finisher. This regression was introduced with https://github.com/neos/form/commit/049d415295be8d4a0478ccba97dba1bb81649567

CVE-2021-26316: Failure to validate the communication buffer and communication service in the BIOS may allow an attacker to tamper with the buffer resulting in potential SMM (System Management Mode) arbitrary code execution.

CVE-2022-31041: Open Forms is an application for creating and publishing smart forms. Open Forms supports file uploads as one of the form field types. These fields can be configured to allow only certain file extensions to be uploaded by end users (e.g. only PDF / Excel / ...). The input validation of uploaded files is insufficient in versions prior to 1.0.9 and 1.1.1. Users could alter or strip file extensions to bypass this validation. This results in files being uploaded to the server that are of a different file type than indicated by the file name extension. These files may be downloaded (manually or automatically) by staff and/or other applications for further processing. Malicious files can therefore find their way into internal/trusted networks. Versions 1.0.9 and 1.1.1 contain patches for this issue. As a workaround, an API gateway or intrusion detection solution in front of open-forms may be able to scan for and block malicious content before it reaches the Open Forms application.

CVE-2022-29206: TensorFlow is an open source platform for machine learning. Prior to versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4, the implementation of `tf.raw_ops.SparseTensorDenseAdd` does not fully validate the input arguments. In this case, a reference gets bound to a `nullptr` during kernel execution. This is undefined behavior. Versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4 contain a patch for this issue.

CVE-2022-20250: In Messaging, there is a possible way to attach files to a message without proper access checks due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-226134095

CVE-2022-20470: In bindRemoteViewsService of AppWidgetServiceImpl.java, there is a possible way to bypass background activity launch due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-234013191

CVE-2022-38123: Improper Input Validation of plugin files in Administrator Interface of Secomea GateManager allows a server administrator to inject code into the GateManager interface. This issue affects: Secomea GateManager versions prior to 10.0. 

CVE-2022-4186: Insufficient validation of untrusted input in Downloads in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to install a malicious extension to bypass Downloads restrictions via a crafted HTML page. (Chromium security severity: Medium)

CVE-2022-29201: TensorFlow is an open source platform for machine learning. Prior to versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4, the implementation of `tf.raw_ops.QuantizedConv2D` does not fully validate the input arguments. In this case, references get bound to `nullptr` for each argument that is empty. Versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4 contain a patch for this issue.

CVE-2022-29213: TensorFlow is an open source platform for machine learning. Prior to versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4, the `tf.compat.v1.signal.rfft2d` and `tf.compat.v1.signal.rfft3d` lack input validation and under certain condition can result in crashes (due to `CHECK`-failures). Versions 2.9.0, 2.8.1, 2.7.2, and 2.6.4 contain a patch for this issue.

CVE-2022-29281: Notable before 1.9.0-beta.8 doesn't effectively prevent the opening of executable files when clicking on a link. There is improper validation of the file URI scheme. A hyperlink to an SMB share could lead to execution of an arbitrary program (or theft of NTLM credentials via an SMB relay attack, because the application resolves UNC paths).

CVE-2022-29466: Improper input validation in firmware for Intel(R) SPS before version SPS_E3_04.01.04.700.0 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-29479: On F5 BIG-IP 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all versions of 12.1.x and 11.6.x, and F5 BIG-IQ Centralized Management all versions of 8.x and 7.x, when an IPv6 self IP address is configured and the ipv6.strictcompliance database key is enabled (disabled by default) on a BIG-IP system, undisclosed packets may cause decreased performance. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-29492: Improper Input Validation vulnerability in the handling of a malformed IEC 104 TCP packet in the Hitachi Energy MicroSCADA X SYS600, MicroSCADA Pro SYS600. Upon receiving a malformed IEC 104 TCP packet, the malformed packet is dropped, however the TCP connection is left open. This may cause a denial-of-service if the affected connection is left open. This issue affects: Hitachi Energy MicroSCADA Pro SYS600 version 9.4 FP2 Hotfix 4 and earlier versions Hitachi Energy MicroSCADA X SYS600 version 10 to version 10.3.1. cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.0:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.2:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.3:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3.1:*:*:*:*:*:*:*

CVE-2022-29613: Due to insufficient input validation, SAP Employee Self Service allows an authenticated attacker with user privileges to alter employee number. On successful exploitation, the attacker can view personal details of other users causing a limited impact on confidentiality of the application.

CVE-2022-29872: A vulnerability has been identified in SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00). Affected devices do not properly validate parameters of POST requests. This could allow an authenticated attacker to set the device to a denial of service state or to control the program counter and, thus, execute arbitrary code on the device.

CVE-2022-29897: On various RAD-ISM-900-EN-* devices by PHOENIX CONTACT an admin user could use the traceroute utility integrated in the WebUI to execute arbitrary code with root privileges on the OS due to an improper input validation in all versions of the firmware.

CVE-2022-29922: Improper Input Validation vulnerability in the handling of a specially crafted IEC 61850 packet with a valid data item but with incorrect data type in the IEC 61850 OPC Server in the Hitachi Energy MicroSCADA X SYS600, MicroSCADA Pro SYS600. The vulnerability may cause a denial-of-service on the IEC 61850 OPC Server part of the SYS600 product. This issue affects: Hitachi Energy MicroSCADA Pro SYS600 version 9.4 FP2 Hotfix 4 and earlier versions Hitachi Energy MicroSCADA X SYS600 version 10 to version 10.3.1. cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.0:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.2:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.3:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_pro_sys600:9.4:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3.1:*:*:*:*:*:*:*

CVE-2022-3001: This vulnerability exists in Milesight Video Management Systems (VMS), all firmware versions prior to 40.7.0.79-r1, due to improper input handling at camera’s web-based management interface. A remote attacker could exploit this vulnerability by sending a specially crafted http request on the targeted network camera. Successful exploitation of this vulnerability could allow the attacker to cause a Denial of Service condition on the targeted device.

CVE-2022-30232: A CWE-20: Improper Input Validation vulnerability exists that could cause potential remote code execution when an attacker is able to intercept and modify a request on the same network or has configuration access to an ION device on the network. Affected Products: Wiser Smart, EER21000 & EER21001 (V4.5 and prior)

CVE-2022-30233: A CWE-20: Improper Input Validation vulnerability exists that could allow the product to be maliciously manipulated when the user is tricked into performing certain actions on a webpage. Affected Products: Wiser Smart, EER21000 & EER21001 (V4.5 and prior)

# CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

## Description

The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. Some kinds of sensitive information include:


  - private, personal information, such as personal messages, financial data, health records, geographic location, or contact details

  - system status and environment, such as the operating system and installed packages

  - business secrets and intellectual property

  - network status and configuration

  - the product's own code or internal state

  - metadata, e.g. logging of connections or message headers

  - indirect information, such as a discrepancy between two internal operations that can be observed by an outsider

Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include:

  - the product's own users

  - people or organizations whose information is created or used by the product, even if they are not direct product users

  - the product's administrators, including the admins of the system(s) and/or networks on which the product operates

  - the developer

Information exposures can occur in different ways:

  - the code  **explicitly inserts**  sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information - i.e., the information should have been "scrubbed" or "sanitized"

  - a different weakness or mistake  **indirectly inserts**  the sensitive information into resources, such as a web script error revealing the full system path of the program.

  - the code manages resources that intentionally contain sensitive information, but the resources are  **unintentionally made accessible**  to unauthorized actors. In this case, the information exposure is resultant - i.e., a different weakness enabled the access to the information in the first place.

It is common practice to describe any loss of confidentiality as an "information exposure," but this can lead to overuse of CWE-200 in CWE mapping. From the CWE perspective, loss of confidentiality is a technical impact that can arise from dozens of different weaknesses, such as insecure file permissions or out-of-bounds read. CWE-200 and its lower-level descendants are intended to cover the mistakes that occur in behaviors that explicitly manage, store, transfer, or cleanse sensitive information.

## Observed Examples

CVE-2022-31162: Rust library leaks Oauth client details in application debug logs

CVE-2021-25476: Digital Rights Management (DRM) capability for mobile platform leaks pointer information, simplifying ASLR bypass

CVE-2001-1483: Enumeration of valid usernames based on inconsistent responses

CVE-2001-1528: Account number enumeration via inconsistent responses.

CVE-2004-2150: User enumeration via discrepancies in error messages.

CVE-2005-1205: Telnet protocol allows servers to obtain sensitive environment information from clients.

CVE-2002-1725: Script calls phpinfo(), revealing system configuration to web user

CVE-2002-0515: Product sets a different TTL when a port is being filtered than when it is not being filtered, which allows remote attackers to identify filtered ports by comparing TTLs.

CVE-2004-0778: Version control system allows remote attackers to determine the existence of arbitrary files and directories via the -X command for an alternate history file, which causes different error messages to be returned.

CVE-2000-1117: Virtual machine allows malicious web site operators to determine the existence of files on the client by measuring delays in the execution of the getSystemResource method.

CVE-2003-0190: Product immediately sends an error message when a user does not exist, which allows remote attackers to determine valid usernames via a timing attack.

CVE-2008-2049: POP3 server reveals a password in an error message after multiple APOP commands are sent. Might be resultant from another weakness.

CVE-2007-5172: Program reveals password in error message if attacker can trigger certain database errors.

CVE-2008-4638: Composite: application running with high privileges (CWE-250) allows user to specify a restricted file to process, which generates a parsing error that leaks the contents of the file (CWE-209).

CVE-2007-1409: Direct request to library file in web application triggers pathname leak in error message.

CVE-2005-0603: Malformed regexp syntax leads to information exposure in error message.

CVE-2004-2268: Password exposed in debug information.

CVE-2003-1078: FTP client with debug option enabled shows password to the screen.

CVE-2022-0708: Collaboration platform does not clear team emails in a response, allowing leak of email addresses

## Top 25 Examples

CVE-2022-29241: Jupyter Server provides the backend (i.e. the core services, APIs, and REST endpoints) for Jupyter web applications like Jupyter Notebook. Prior to version 1.17.1, if notebook server is started with a value of `root_dir` that contains the starting user's home directory, then the underlying REST API can be used to leak the access token assigned at start time by guessing/brute forcing the PID of the jupyter server. While this requires an authenticated user session, this URL can be used from a cross-site scripting payload or from a hooked or otherwise compromised browser to leak this access token to a malicious third party. This token can be used along with the REST API to interact with Jupyter services/notebooks such as modifying or overwriting critical files, such as .bashrc or .ssh/authorized_keys, allowing a malicious user to read potentially sensitive data and possibly gain control of the impacted system. This issue is patched in version 1.17.1.

CVE-2021-4076: A flaw exists in tang, a network-based cryptographic binding server, which could result in leak of private keys.

CVE-2022-32540: Information Disclosure in Operator Client application in BVMS 10.1.1, 11.0 and 11.1.0 and VIDEOJET Decoder VJD-7513 versions 10.23 and 10.30 allows man-in-the-middle attacker to compromise confidential video stream. This is only applicable for UDP encryption when target system contains cameras with platform CPP13 or CPP14 and firmware version 8.x.

CVE-2022-33878: An exposure of sensitive information to an unauthorized actor vulnerabiltiy [CWE-200] in FortiClient for Mac versions 7.0.0 through 7.0.5 may allow a local authenticated attacker to obtain the SSL-VPN password in cleartext via running a logstream for the FortiTray process in the terminal.

CVE-2022-35169: SAP BusinessObjects Business Intelligence Platform (LCM) - versions 420, 430, allows an attacker with an admin privilege to read and decrypt LCMBIAR file's password under certain conditions, enabling the attacker to modify the password or import the file into another system causing high impact on confidentiality but a limited impact on the availability and integrity of the application.

CVE-2022-35842: An exposure of sensitive information to an unauthorized actor vulnerabiltiy [CWE-200] in FortiOS SSL-VPN versions 7.2.0, versions 7.0.0 through 7.0.6 and versions 6.4.0 through 6.4.9 may allow a remote unauthenticated attacker to gain information about LDAP and SAML settings configured in FortiOS.

CVE-2022-22680: Exposure of sensitive information to an unauthorized actor vulnerability in Web Server in Synology DiskStation Manager (DSM) before 7.0.1-42218-2 allows remote attackers to obtain sensitive information via unspecified vectors.

CVE-2022-27490: A exposure of sensitive information to an unauthorized actor in Fortinet FortiManager version 6.0.0 through 6.0.4, FortiAnalyzer version 6.0.0 through 6.0.4, FortiPortal version 6.0.0 through 6.0.9, 5.3.0 through 5.3.8, 5.2.x, 5.1.0, 5.0.x, 4.2.x, 4.1.x, FortiSwitch version 7.0.0 through 7.0.4, 6.4.0 through 6.4.10, 6.2.x, 6.0.x allows an attacker which has obtained access to a restricted administrative account to obtain sensitive information via `diagnose debug` commands.

CVE-2022-29512: Exposure of sensitive information to an unauthorized actor issue in multiple applications of Cybozu Garoon 4.0.0 to 5.9.1 allows a remote authenticated attacker to obtain the data without the viewing privilege.

CVE-2022-39913: Exposure of Sensitive Information to an Unauthorized Actor in Persona Manager prior to Android T(13) allows local attacker to access user profiles information.

CVE-2022-46355: A vulnerability has been identified in SCALANCE X204RNA (HSR) (All versions < V3.2.7), SCALANCE X204RNA (PRP) (All versions < V3.2.7), SCALANCE X204RNA EEC (HSR) (All versions < V3.2.7), SCALANCE X204RNA EEC (PRP) (All versions < V3.2.7), SCALANCE X204RNA EEC (PRP/HSR) (All versions < V3.2.7). The affected products are vulnerable to an "Exposure of Sensitive Information to an Unauthorized Actor" vulnerability by leaking sensitive data in the HTTP Referer.

CVE-2022-1332: One of the API in Mattermost version 6.4.1 and earlier fails to properly protect the permissions, which allows the authenticated members with restricted custom admin role to bypass the restrictions and view the server logs and server config.json file contents.

CVE-2021-27424: GE UR firmware versions prior to version 8.1x shares MODBUS memory map as part of the communications guide. GE was made aware a “Last-key pressed” MODBUS register can be used to gain unauthorized information.

CVE-2021-36198: Successful exploitation of this vulnerability could allow an unauthorized user to access sensitive data.

CVE-2021-43536: Under certain circumstances, asynchronous functions could have caused a navigation to fail but expose the target URL. This vulnerability affects Thunderbird < 91.4.0, Firefox ESR < 91.4.0, and Firefox < 95.

CVE-2022-29467: Address information disclosure vulnerability in Cybozu Garoon 4.2.0 to 5.5.1 allows a remote authenticated attacker to obtain some data of Address.

CVE-2022-37438: In Splunk Enterprise versions in the following table, an authenticated user can craft a dashboard that could potentially leak information (for example, username, email, and real name) about Splunk users, when visited by another user through the drilldown component. The vulnerability requires user access to create and share dashboards using Splunk Web.

CVE-2022-38400: Mailform Pro CGI 4.3.1 and earlier allow a remote unauthenticated attacker to obtain the user input data by having a use of the product to access a specially crafted URL.

CVE-2021-24775: The Document Embedder WordPress plugin before 1.7.5 contains a REST endpoint, which could allow unauthenticated users to enumerate the title of arbitrary private and draft posts.

CVE-2021-24868: The Document Embedder WordPress plugin before 1.7.9 contains a AJAX action endpoint, which could allow any authenticated user, such as subscriber to enumerate the title of arbitrary private and draft posts.

CVE-2021-30314: Lack of validation for third party application accessing the service can lead to information disclosure in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-1911: Error in parser function in M-Files Server versions before 22.6.11534.1 and before 22.6.11505.0 allowed unauthenticated access to some information of the underlying operating system. 

CVE-2022-26869: Dell PowerStore versions 2.0.0.x, 2.0.1.x and 2.1.0.x contains an open port vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to information disclosure and arbitrary code execution.

CVE-2022-27576: Information exposure vulnerability in Samsung DeX Home prior to SMR April-2022 Release 1 allows to access currently launched foreground app information without permission

CVE-2022-43901:  IBM WebSphere Automation for IBM Cloud Pak for Watson AIOps 1.4.3 could disclose sensitive information. An authenticated local attacker could exploit this vulnerability to possibly gain information to other IBM WebSphere Automation for IBM Cloud Pak for Watson AIOps components. IBM X-Force ID: 240829. 

CVE-2022-30607: IBM Robotic Process Automation 20.10.0, 20.12.5, 21.0.0, 21.0.1, and 21.0.2 contains a vulnerability that could allow a user to obtain sensitive information due to information properly masked in the control center UI. IBM X-Force ID: 227294.

CVE-2022-30732: Exposure of Sensitive Information vulnerability in Samsung Account prior to version 13.2.00.6 allows attacker to access sensitive information via onActivityResult.

CVE-2022-30734: Sensitive information exposure in Sign-out log in Samsung Account prior to version 13.2.00.6 allows attackers to get an user email or phone number without permission.

CVE-2022-33698: Exposure of Sensitive Information in Telecom application prior to SMR Jul-2022 Release 1 allows local attackers to access ICCID via log.

CVE-2022-33699: Exposure of Sensitive Information in getDsaSimImsi in TelephonyUI prior to SMR Jul-2022 Release 1 allows local attacker to access imsi via log.

CVE-2022-33700: Exposure of Sensitive Information in putDsaSimImsi in TelephonyUI prior to SMR Jul-2022 Release 1 allows local attacker to access imsi via log.

CVE-2022-23726: PingCentral versions prior to listed versions expose Spring Boot actuator endpoints that with administrative authentication return large amounts of sensitive environmental and application information.

CVE-2022-39914: Exposure of Sensitive Information from an Unauthorized Actor vulnerability in Samsung DisplayManagerService prior to Android T(13) allows local attacker to access connected DLNA device information.

CVE-2021-25392: Improper protection of backup path configuration in Samsung Dex prior to SMR MAY-2021 Release 1 allows local attackers to get sensitive information via changing the path.

CVE-2022-46825: In JetBrains IntelliJ IDEA before 2022.3 the built-in web server leaked information about open projects.

CVE-2021-39089: IBM Cloud Pak for Security (CP4S) 1.10.0.0 through 1.10.6.0 could allow an authenticated user to obtain sensitive information from a specially crafted HTTP request. IBM X-Force ID: 216387.

CVE-2021-45475: Yordam Library Information Document Automation product before version 19.02 has an unauthenticated Information disclosure vulnerability. 

CVE-2022-0708: Mattermost 6.3.0 and earlier fails to protect email addresses of the creator of the team via one of the APIs, which allows authenticated team members to access this information resulting in sensitive & private information disclosure.

CVE-2022-0813: PhpMyAdmin 5.1.1 and before allows an attacker to retrieve potentially sensitive information by creating invalid requests. This affects the lang parameter, the pma_parameter, and the cookie section.

CVE-2022-1004: Accounted time is shown in the Ticket Detail View (External Interface), even if ExternalFrontend::TicketDetailView###AccountedTimeDisplay is disabled.

CVE-2022-1186: The WordPress plugin Be POPIA Compliant exposed sensitive information to unauthenticated users consisting of site visitors emails and usernames via an API route, in versions up to an including 1.1.5.

CVE-2022-2117: The GiveWP plugin for WordPress is vulnerable to Sensitive Information Disclosure in versions up to, and including, 2.20.2 via the /donor-wall REST-API endpoint which provides unauthenticated users with donor information even when the donor wall is not enabled. This functionality has been completely removed in version 2.20.2.

CVE-2022-22276: A vulnerability in SonicOS SNMP service resulting exposure of sensitive information to an unauthorized user.

CVE-2022-22287: Abitrary file access vulnerability in Samsung Email prior to 6.1.60.16 allows attacker to read isolated data in sandbox.

CVE-2022-22542: S/4HANA Supplier Factsheet exposes the private address and bank details of an Employee Business Partner with Supplier Role, AND Enterprise Search for Customer, Supplier and Business Partner objects exposes the private address fields of Employee Business Partners, to an actor that is not explicitly authorized to have access to that information, which could compromise Confidentiality.

CVE-2022-22545: A high privileged user who has access to transaction SM59 can read connection details stored with the destination for http calls in SAP NetWeaver Application Server ABAP and ABAP Platform - versions 700, 701, 702, 710, 711, 730, 731, 740, 750, 751, 752, 753, 754, 755, 756.

CVE-2022-22733: Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Apache ShardingSphere ElasticJob-UI allows an attacker who has guest account to do privilege escalation. This issue affects Apache ShardingSphere ElasticJob-UI Apache ShardingSphere ElasticJob-UI 3.x version 3.0.0 and prior versions.

CVE-2022-23157: Wyse Device Agent version 14.6.1.4 and below contain a sensitive data exposure vulnerability. A authenticated malicious user could potentially exploit this vulnerability in order to view sensitive information from the WMS Server.

CVE-2022-23648: containerd is a container runtime available as a daemon for Linux and Windows. A bug was found in containerd prior to versions 1.6.1, 1.5.10, and 1.14.12 where containers launched through containerd’s CRI implementation on Linux with a specially-crafted image configuration could gain access to read-only copies of arbitrary files and directories on the host. This may bypass any policy-based enforcement on container setup (including a Kubernetes Pod Security Policy) and expose potentially sensitive information. Kubernetes and crictl can both be configured to use containerd’s CRI implementation. This bug has been fixed in containerd 1.6.1, 1.5.10, and 1.4.12. Users should update to these versions to resolve the issue.

CVE-2022-23982: The vulnerability discovered in WordPress Perfect Brands for WooCommerce plugin (versions <= 2.0.4) allows server information exposure.

CVE-2022-23984: Sensitive information disclosure discovered in wpDiscuz WordPress plugin (versions <= 7.3.11).

CVE-2022-2401: Unrestricted information disclosure of all users in Mattermost version 6.7.0 and earlier allows team members to access some sensitive information by directly accessing the APIs.

CVE-2022-24850: Discourse is an open source platform for community discussion. A category's group permissions settings can be viewed by anyone that has access to the category. As a result, a normal user is able to see whether a group has read/write permissions in the category even though the information should only be available to the users that can manage a category. This issue is patched in the latest stable, beta and tests-passed versions of Discourse. There are no workarounds for this problem.

CVE-2022-25248: When connecting to a certain port Axeda agent (All versions) and Axeda Desktop Server for Windows (All versions) supplies the event log of the specific service.

CVE-2022-25990: On 1.0.x versions prior to 1.0.1, systems running F5OS-A software may expose certain registry ports externally. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-27241: A vulnerability has been identified in Mendix Applications using Mendix 7 (All versions < V7.23.31), Mendix Applications using Mendix 8 (All versions < V8.18.18), Mendix Applications using Mendix 9 (All versions < V9.11), Mendix Applications using Mendix 9 (V9.6) (All versions < V9.6.12). Applications built with an affected system publicly expose the internal project structure. This could allow an unauthenticated remote attacker to read confidential information.

CVE-2022-27614: Exposure of sensitive information to an unauthorized actor vulnerability in web server in Synology Media Server before 1.8.1-2876 allows remote attackers to obtain sensitive information via unspecified vectors.

CVE-2022-27667: Under certain conditions, SAP BusinessObjects Business Intelligence platform, Client Management Console (CMC) - version 430, allows an attacker to access information which would otherwise be restricted, leading to Information Disclosure.

CVE-2022-27849: Sensitive Information Disclosure (sac-export.csv) in Simple Ajax Chat (WordPress plugin) <= 20220115

CVE-2022-27875: On F5 Access for Android 3.x versions prior to 3.0.8, a Task Hijacking vulnerability exists in the F5 Access for Android application, which may allow an attacker to steal sensitive user information. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-29244: npm pack ignores root-level .gitignore and .npmignore file exclusion directives when run in a workspace or with a workspace flag (ie. `--workspaces`, `--workspace=<name>`). Anyone who has run `npm pack` or `npm publish` inside a workspace, as of v7.9.0 and v7.13.0 respectively, may be affected and have published files into the npm registry they did not intend to include. Users should upgrade to the latest, patched version of npm v8.11.0, run: npm i -g npm@latest . Node.js versions v16.15.1, v17.19.1, and v18.3.0 include the patched v8.11.0 version of npm.

CVE-2022-29567: The default configuration of a TreeGrid component uses Object::toString as a key on the client-side and server communication in Vaadin 14.8.5 through 14.8.9, 22.0.6 through 22.0.14, 23.0.0.beta2 through 23.0.8 and 23.1.0.alpha1 through 23.1.0.alpha4, resulting in potential information disclosure of values that should not be available on the client-side.

CVE-2022-30693: Information disclosure vulnerability in the system configuration of Cybozu Office 10.0.0 to 10.8.5 allows a remote attacker to obtain the data of the product via unspecified vectors.

CVE-2022-3091: RONDS EPM version 1.19.5 has a vulnerability in which a function could allow unauthenticated users to leak credentials. In some circumstances, an attacker can exploit this vulnerability to execute operating system (OS) commands. 

CVE-2022-31221: Dell BIOS versions contain an Information Exposure vulnerability. A local authenticated administrator user could potentially exploit this vulnerability in order access sensitive state information on the system.

CVE-2022-34659: A vulnerability has been identified in Simcenter STAR-CCM+ (All versions only if the Power-on-Demand public license server is used). Affected applications expose user, host and display name of users, when the public license server is used. This could allow an attacker to retrieve this information.

CVE-2022-35296: Under certain conditions, the application SAP BusinessObjects Business Intelligence Platform (Version Management System) exposes sensitive information to an actor over the network with high privileges that is not explicitly authorized to have access to that information, leading to a high impact on Confidentiality.

CVE-2022-36834: Exposure of Sensitive Information vulnerability in Game Launcher prior to version 6.0.07 allows local attacker to access app data with user interaction.

CVE-2022-36878: Exposure of Sensitive Information in Find My Mobile prior to version 7.2.25.14 allows local attacker to access IMEI via log.

CVE-2022-38456: Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Ernest Marcinko Ajax Search Lite plugin <= 4.10.3 versions.

CVE-2022-39230: fhir-works-on-aws-authz-smart is an implementation of the authorization interface from the FHIR Works interface. Versions 3.1.1 and 3.1.2 are subject to Exposure of Sensitive Information to an Unauthorized Actor. This issue allows a client of the API to retrieve more information than the client’s OAuth scope permits when making “search-type” requests. This issue would not allow a client to retrieve information about individuals other than those the client was already authorized to access. Users of fhir-works-on-aws-authz-smart 3.1.1 or 3.1.2 should upgrade to version 3.1.3 or higher immediately. Versions 3.1.0 and below are unaffected. There is no workaround for this issue.

CVE-2022-39904: Exposure of Sensitive Information vulnerability in Samsung Settings prior to SMR Dec-2022 Release 1 allows local attackers to access the Network Access Identifier via log.

CVE-2022-40177: A vulnerability has been identified in Desigo PXM30-1 (All versions < V02.20.126.11-41), Desigo PXM30.E (All versions < V02.20.126.11-41), Desigo PXM40-1 (All versions < V02.20.126.11-41), Desigo PXM40.E (All versions < V02.20.126.11-41), Desigo PXM50-1 (All versions < V02.20.126.11-41), Desigo PXM50.E (All versions < V02.20.126.11-41), PXG3.W100-1 (All versions < V02.20.126.11-37), PXG3.W100-2 (All versions < V02.20.126.11-41), PXG3.W200-1 (All versions < V02.20.126.11-37), PXG3.W200-2 (All versions < V02.20.126.11-41). Endpoints of the “Operation” web application that interpret and execute Axon language queries allow file read access to the device file system with root privileges. By supplying specific I/O related Axon queries, a remote low-privileged attacker can read sensitive files on the device.

CVE-2022-40194: Unauthenticated Sensitive Information Disclosure vulnerability in Customer Reviews for WooCommerce plugin <= 5.3.5 at WordPress

CVE-2022-41329: An exposure of sensitive information to an unauthorized actor vulnerability [CWE-200] in Fortinet FortiProxy version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.7, FortiOS version 7.2.0 through 7.2.3 and 7.0.0 through 7.0.9 allows an unauthenticated attackers to obtain sensitive logging informations on the device via crafted HTTP GET requests.

CVE-2022-42266: NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for DxgkDdiEscape, where an unprivileged regular user can cause exposure of sensitive information to an actor that is not explicitly authorized to have access to that information, which may lead to limited information disclosure.

CVE-2022-43573: IBM Robotic Process Automation 20.12 through 21.0.6 is vulnerable to exposure of the name and email for the creator/modifier of platform level objects. IBM X-Force ID: 238678.

CVE-2022-46650: Acemanager in ALEOS before version 4.16 allows a user with valid credentials to reconfigure the device to expose the ACEManager credentials on the pre-login status page.

CVE-2021-22786: A CWE-200: Information Exposure vulnerability exists that could cause the exposure of sensitive information stored on the memory of the controller when communicating over the Modbus TCP protocol. Affected Products: Modicon M340 CPU (part numbers BMXP34*) (Versions prior to V3.30), Modicon M580 CPU (part numbers BMEP* and BMEH*) (Versions prior to SV3.20), Modicon MC80 (BMKC80) (Versions prior to V1.6), Modicon M580 CPU Safety (part numbers BMEP58*S and BMEH58*S) (All Versions), Modicon Momentum MDI (171CBU*) (Versions prior to V2.3), Legacy Modicon Quantum (All Versions)

CVE-2021-34749: A vulnerability in Server Name Identification (SNI) request filtering of Cisco Web Security Appliance (WSA), Cisco Firepower Threat Defense (FTD), and the Snort detection engine could allow an unauthenticated, remote attacker to bypass filtering technology on an affected device and exfiltrate data from a compromised host. This vulnerability is due to inadequate filtering of the SSL handshake. An attacker could exploit this vulnerability by using data from the SSL client hello packet to communicate with an external server. A successful exploit could allow the attacker to execute a command-and-control attack on a compromised host and perform additional data exfiltration attacks.

CVE-2021-35070: RPM secure Stream can access any secure resource due to improper SMMU configuration and can lead to information disclosure in Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2021-35080: Disabled SMMU from secure side while RPM is assigned a secure stream can lead to information disclosure in Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2021-3677: A flaw was found in postgresql. A purpose-crafted query can read arbitrary bytes of server memory. In the default configuration, any authenticated database user can complete this attack at will. The attack does not require the ability to create objects. If server settings include max_worker_processes=0, the known versions of this attack are infeasible. However, undiscovered variants of the attack may be independent of that setting.

# CWE-201 Insertion of Sensitive Information Into Sent Data

## Description

The code transmits data to another actor, but a portion of the data includes sensitive information that should not be accessible to that actor.

Sensitive information could include data that is sensitive in and of itself (such as credentials or private messages), or otherwise useful in the further exploitation of the system (such as internal file system structure).

## Observed Examples

CVE-2022-0708: Collaboration platform does not clear team emails in a response, allowing leak of email addresses

## Top 25 Examples

CVE-2022-27671: A CSRF token visible in the URL may possibly lead to information disclosure vulnerability.

CVE-2021-31955: Windows Kernel Information Disclosure Vulnerability

CVE-2022-36101: Shopware is an open source e-commerce software. In affected versions the request for the customer detail view in the backend administration contained sensitive data like the hashed password and the session ID. These fields are now explicitly unset in version 5.7.15. Users are advised to update and may get the update either via the Auto-Updater or directly via the download overview. There are no known workarounds for this issue.

CVE-2022-0654: Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository fgribreau/node-request-retry prior to 7.0.0.

CVE-2022-0577: Exposure of Sensitive Information to an Unauthorized Actor in GitHub repository scrapy/scrapy prior to 2.6.1.

CVE-2022-30334: Brave before 1.34, when a Private Window with Tor Connectivity is used, leaks .onion URLs in Referer and Origin headers. NOTE: although this was fixed by Brave, the Brave documentation still advises "Note that Private Windows with Tor Connectivity in Brave are just regular private windows that use Tor as a proxy. Brave does NOT implement most of the privacy protections from Tor Browser."

CVE-2022-39193: An issue was discovered in the CheckUser extension for MediaWiki through 1.39.x. Various components of this extension can expose information on the performer of edits and logged actions. This information should not allow public viewing: it is supposed to be viewable only by users with suppression rights.

CVE-2022-31308: A vulnerability in live_mfg.shtml of WAVLINK AERIAL X 1200M M79X3.V5030.191012 allows attackers to obtain sensitive router information via execution of the exec cmd function.

CVE-2022-31309: A vulnerability in live_check.shtml of WAVLINK AERIAL X 1200M M79X3.V5030.180719 allows attackers to obtain sensitive router information via execution of the exec cmd function.

CVE-2022-35147: DoraCMS v2.18 and earlier allows attackers to bypass login authentication via a crafted HTTP request.

CVE-2021-20260: A flaw was found in the Foreman project. The Datacenter plugin exposes the password through the API to an authenticated local attacker with view_hosts permission. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

CVE-2022-23538: github.com/sylabs/scs-library-client is the Go client for the Singularity Container Services (SCS) Container Library Service. When the scs-library-client is used to pull a container image, with authentication, the HTTP Authorization header sent by the client to the library service may be incorrectly leaked to an S3 backing storage provider. This occurs in a specific flow, where the library service redirects the client to a backing S3 storage server, to perform a multi-part concurrent download. Depending on site configuration, the S3 service may be provided by a third party. An attacker with access to the S3 service may be able to extract user credentials, allowing them to impersonate the user. The vulnerable multi-part concurrent download flow, with redirect to S3, is only used when communicating with a Singularity Enterprise 1.x installation, or third party server implementing this flow. Interaction with Singularity Enterprise 2.x, and Singularity Container Services (cloud.sylabs.io), does not trigger the vulnerable flow. We encourage all users to update. Users who interact with a Singularity Enterprise 1.x installation, using a 3rd party S3 storage service, are advised to revoke and recreate their authentication tokens within Singularity Enterprise. There is no workaround available at this time.

CVE-2022-31130: Grafana is an open source observability and data visualization platform. Versions of Grafana for endpoints prior to 9.1.8 and 8.5.14 could leak authentication tokens to some destination plugins under some conditions. The vulnerability impacts data source and plugin proxy endpoints with authentication tokens. The destination plugin could receive a user's Grafana authentication token. Versions 9.1.8 and 8.5.14 contain a patch for this issue. As a workaround, do not use API keys, JWT authentication, or any HTTP Header based authentication.

CVE-2022-42132: The Test LDAP Users functionality in Liferay Portal 7.0.0 through 7.4.3.4, and Liferay DXP 7.0 fix pack 102 and earlier, 7.1 before fix pack 27, 7.2 before fix pack 17, 7.3 before update 4, and DXP 7.4 GA includes the LDAP credential in the page URL when paginating through the list of users, which allows man-in-the-middle attackers or attackers with access to the request logs to see the LDAP credential.

CVE-2022-31746: Internal URLs are protected by a secret UUID key, which could have been leaked to web page through the Referrer header. This vulnerability affects Firefox for iOS < 102.

CVE-2021-23937: A DNS proxy and possible amplification attack vulnerability in WebClientInfo of Apache Wicket allows an attacker to trigger arbitrary DNS lookups from the server when the X-Forwarded-For header is not properly sanitized. This DNS lookup can be engineered to overload an internal DNS server or to slow down request processing of the Apache Wicket application causing a possible denial of service on either the internal infrastructure or the web application itself. This issue affects Apache Wicket Apache Wicket 9.x version 9.2.0 and prior versions; Apache Wicket 8.x version 8.11.0 and prior versions; Apache Wicket 7.x version 7.17.0 and prior versions and Apache Wicket 6.x version 6.2.0 and later versions.

CVE-2022-0474: Full list of recipients from customer users in a contact field could be disclosed in notification emails event when the notification is set to be sent to each recipient individually. This issue affects: OTRS AG OTRSCustomContactFields 8.0.x version: 8.0.11 and prior versions.

CVE-2022-1595: The HC Custom WP-Admin URL WordPress plugin through 1.4 leaks the secret login URL when sending a specific crafted request

CVE-2022-21642: Discourse is an open source platform for community discussion. In affected versions when composing a message from topic the composer user suggestions reveals whisper participants. The issue has been patched in stable version 2.7.13 and beta version 2.8.0.beta11. There is no workaround for this issue and users are advised to upgrade.

CVE-2022-21712: twisted is an event-driven networking engine written in Python. In affected versions twisted exposes cookies and authorization headers when following cross-origin redirects. This issue is present in the `twited.web.RedirectAgent` and `twisted.web. BrowserLikeRedirectAgent` functions. Users are advised to upgrade. There are no known workarounds.

CVE-2022-24737: HTTPie is a command-line HTTP client. HTTPie has the practical concept of sessions, which help users to persistently store some of the state that belongs to the outgoing requests and incoming responses on the disk for further usage. Before 3.1.0, HTTPie didn‘t distinguish between cookies and hosts they belonged. This behavior resulted in the exposure of some cookies when there are redirects originating from the actual host to a third party website. Users are advised to upgrade. There are no known workarounds.

CVE-2022-27630: An information disclosure vulnerability exists in the confctl_get_master_wlan functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted network packet can lead to information disclosure. An attacker can send packets to trigger this vulnerability.

CVE-2022-27633: An information disclosure vulnerability exists in the confctl_get_guest_wlan functionality of TCL LinkHub Mesh Wifi MS1G_00_01.00_14. A specially-crafted network packet can lead to information disclosure. An attacker can send packets to trigger this vulnerability.

CVE-2022-29232: BigBlueButton is an open source web conferencing system. Starting with version 2.2 and prior to versions 2.3.9 and 2.4-beta-1, an attacker can circumvent access controls to obtain the content of public chat messages from different meetings on the server. The attacker must be a participant in a meeting on the server. BigBlueButton versions 2.3.9 and 2.4-beta-1 contain a patch for this issue. There are currently no known workarounds.

CVE-2022-31069: NestJS Proxy is a NestJS module to decorate and proxy calls. Prior to version 0.7.0, the nestjs-proxy library did not have a way to control when Authorization headers should should be forwarded for specific backend services configured by the application developer. This could have resulted in sensitive information such as OAuth bearer access tokens being inadvertently exposed to such services that should not see them. A new feature has been introduced in the patched version of nestjs-proxy that allows application developers to opt out of forwarding the Authorization headers on a per service basis using the `forwardToken` config setting. Developers are advised to review the README for this library on Github or NPM for further details on how this configuration can be applied. This issue has been fixed in version 0.7.0 of `@finastra/nestjs-proxy`. Users of `@ffdc/nestjs-proxy` are advised that this package has been deprecated and is no longer being maintained or receiving updates. Such users should update their package.json file to use `@finastra/nestjs-proxy` instead.

CVE-2022-31070: NestJS Proxy is a NestJS module to decorate and proxy calls. Prior to version 0.7.0, the nestjs-proxy library did not have a way to block sensitive cookies (e.g. session cookies) from being forwarded to backend services configured by the application developer. This could have led to sensitive cookies being inadvertently exposed to such services that should not see them. The patched version now blocks cookies from being forwarded by default. However developers can configure an allow-list of cookie names by using the `allowedCookies` config setting. This issue has been fixed in version 0.7.0 of `@finastra/nestjs-proxy`. Users of `@ffdc/nestjs-proxy` are advised that this package has been deprecated and is no longer being maintained or receiving updates. Such users should update their package.json file to use `@finastra/nestjs-proxy` instead.

CVE-2022-3348: Just like in the previous report, an attacker could steal the account of different users. But in this case, it's a little bit more specific, because it is needed to be an editor in the same app as the victim.

CVE-2022-38113: This vulnerability discloses build and services versions in the server response header. 

CVE-2022-46150: Discourse is an open-source discussion platform. Prior to version 2.8.13 of the `stable` branch and version 2.9.0.beta14 of the `beta` and `tests-passed` branches, unauthorized users may learn of the existence of hidden tags and that they have been applied to topics that they have access to. This issue is patched in version 2.8.13 of the `stable` branch and version 2.9.0.beta14 of the `beta` and `tests-passed` branches. As a workaround, use the `disable_email` site setting to disable all emails to non-staff users.

# CWE-202 Exposure of Sensitive Information Through Data Queries

## Description

When trying to keep information confidential, an attacker can often infer some of the information by using statistics.

In situations where data should not be tied to individual users, but a large number of users should be able to make queries that "scrub" the identity of users, it may be possible to get information about a user -- e.g., by specifying search terms that are known to be unique to that user.

## Observed Examples

CVE-2022-41935: Wiki product allows an adversary to discover filenames via a series of queries starting with one letter and then iteratively extending the match.

## Top 25 Examples

CVE-2022-31177: Flask-AppBuilder is an application development framework built on top of Flask python framework. In versions prior to 4.1.3 an authenticated Admin user could query other users by their salted and hashed passwords strings. These filters could be made by using partial hashed password strings. The response would not include the hashed passwords, but an attacker could infer partial password hashes and their respective users. This issue has been fixed in version 4.1.3. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-41935: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Users without the right to view documents can deduce their existence by repeated Livetable queries. The issue has been patched in XWiki 14.6RC1, 13.10.8, and 14.4.3, the response is not properly cleaned up of obfuscated entries. As a workaround, The patch for the document `XWiki.LiveTableResultsMacros` can be manually applied or a XAR archive of a patched version can be imported, on versions 12.10.11, 13.9-rc-1, and 13.4.4. There are no known workarounds for this issue.

# CWE-203 Observable Discrepancy

## Description

The product behaves differently or sends different responses under different circumstances in a way that is observable to an unauthorized actor, which exposes security-relevant information about the state of the product, such as whether a particular operation was successful or not.

Discrepancies can take many forms, and variations may be detectable in timing, control flow, communications such as replies or requests, or general behavior. These discrepancies can reveal information about the product's operation or internal state to an unauthorized actor. In some cases, discrepancies can be used by attackers to form a side channel.

## Observed Examples

CVE-2020-8695: Observable discrepancy in the RAPL interface for some Intel processors allows information disclosure.

CVE-2019-14353: Crypto hardware wallet's power consumption relates to total number of pixels illuminated, creating a side channel in the USB connection that allows attackers to determine secrets displayed such as PIN numbers and passwords

CVE-2019-10071: Java-oriented framework compares HMAC signatures using String.equals() instead of a constant-time algorithm, causing timing discrepancies

CVE-2002-2094: This, and others, use ".." attacks and monitor error responses, so there is overlap with directory traversal.

CVE-2001-1483: Enumeration of valid usernames based on inconsistent responses

CVE-2001-1528: Account number enumeration via inconsistent responses.

CVE-2004-2150: User enumeration via discrepancies in error messages.

CVE-2005-1650: User enumeration via discrepancies in error messages.

CVE-2004-0294: Bulletin Board displays different error messages when a user exists or not, which makes it easier for remote attackers to identify valid users and conduct a brute force password guessing attack.

CVE-2004-0243: Operating System, when direct remote login is disabled, displays a different message if the password is correct, which allows remote attackers to guess the password via brute force methods.

CVE-2002-0514: Product allows remote attackers to determine if a port is being filtered because the response packet TTL is different than the default TTL.

CVE-2002-0515: Product sets a different TTL when a port is being filtered than when it is not being filtered, which allows remote attackers to identify filtered ports by comparing TTLs.

CVE-2002-0208: Product modifies TCP/IP stack and ICMP error messages in unusual ways that show the product is in use.

CVE-2004-2252: Behavioral infoleak by responding to SYN-FIN packets.

CVE-2001-1387: Product may generate different responses than specified by the administrator, possibly leading to an information leak.

CVE-2004-0778: Version control system allows remote attackers to determine the existence of arbitrary files and directories via the -X command for an alternate history file, which causes different error messages to be returned.

CVE-2004-1428: FTP server generates an error message if the user name does not exist instead of prompting for a password, which allows remote attackers to determine valid usernames.

CVE-2003-0078: SSL implementation does not perform a MAC computation if an incorrect block cipher padding is used, which causes an information leak (timing discrepancy) that may make it easier to launch cryptographic attacks that rely on distinguishing between padding and MAC verification errors, possibly leading to extraction of the original plaintext, aka the "Vaudenay timing attack."

CVE-2000-1117: Virtual machine allows malicious web site operators to determine the existence of files on the client by measuring delays in the execution of the getSystemResource method.

CVE-2003-0637: Product uses a shorter timeout for a non-existent user than a valid user, which makes it easier for remote attackers to guess usernames and conduct brute force password guessing.

CVE-2003-0190: Product immediately sends an error message when a user does not exist, which allows remote attackers to determine valid usernames via a timing attack.

CVE-2004-1602: FTP server responds in a different amount of time when a given username exists, which allows remote attackers to identify valid usernames by timing the server response.

CVE-2005-0918: Browser allows remote attackers to determine the existence of arbitrary files by setting the src property to the target filename and using Javascript to determine if the web page immediately stops loading, which indicates whether the file exists or not.

## Top 25 Examples

CVE-2021-39021: IBM Guardium Data Encryption (GDE) 5.0.0.2 behaves differently or sends different responses under different circumstances in a way that is observable to an unauthorized actor, which could facilitate username enumeration. IBM X-Force ID: 213856.

CVE-2021-46744: An attacker with access to a malicious hypervisor may be able to infer data values used in a SEV guest on AMD CPUs by monitoring ciphertext values over time.

CVE-2022-1318: Hills ComNav version 3002-19 suffers from a weak communication channel. Traffic across the local network for the configuration pages can be viewed by a malicious actor. The size of certain communications packets are predictable. This would allow an attacker to learn the state of the system if they can observe the traffic. This would be possible even if the traffic were encrypted, e.g., using WPA2, as the packet sizes would remain observable. The communication encryption scheme is theoretically sound, but is not strong enough for the level of protection required.

CVE-2022-20866: A vulnerability in the handling of RSA keys on devices running Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to retrieve an RSA private key. This vulnerability is due to a logic error when the RSA key is stored in memory on a hardware platform that performs hardware-based cryptography. An attacker could exploit this vulnerability by using a Lenstra side-channel attack against the targeted device. A successful exploit could allow the attacker to retrieve the RSA private key. The following conditions may be observed on an affected device: This vulnerability will apply to approximately 5 percent of the RSA keys on a device that is running a vulnerable release of Cisco ASA Software or Cisco FTD Software; not all RSA keys are expected to be affected due to mathematical calculations applied to the RSA key. The RSA key could be valid but have specific characteristics that make it vulnerable to the potential leak of the RSA private key. If an attacker obtains the RSA private key, they could use the key to impersonate a device that is running Cisco ASA Software or Cisco FTD Software or to decrypt the device traffic. See the Indicators of Compromise section for more information on the detection of this type of RSA key. The RSA key could be malformed and invalid. A malformed RSA key is not functional, and a TLS client connection to a device that is running Cisco ASA Software or Cisco FTD Software that uses the malformed RSA key will result in a TLS signature failure, which means a vulnerable software release created an invalid RSA signature that failed verification. If an attacker obtains the RSA private key, they could use the key to impersonate a device that is running Cisco ASA Software or Cisco FTD Software or to decrypt the device traffic.

CVE-2022-20940: A vulnerability in the TLS handler of Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to gain access to sensitive information. This vulnerability is due to improper implementation of countermeasures against a Bleichenbacher attack on a device that uses SSL decryption policies. An attacker could exploit this vulnerability by sending crafted TLS messages to an affected device, which would act as an oracle and allow the attacker to carry out a chosen-ciphertext attack. A successful exploit could allow the attacker to perform cryptanalytic operations that may allow decryption of previously captured TLS sessions to the affected device.

CVE-2022-27221: A vulnerability has been identified in SINEMA Remote Connect Server (All versions < V3.1). An attacker in machine-in-the-middle could obtain plaintext secret values by observing length differences during a series of guesses in which a string in an HTTP request URL potentially matches an unknown string in an HTTP response body, aka a "BREACH" attack.

CVE-2022-20275: In DevicePolicyManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-205836975

CVE-2022-20276: In DevicePolicyManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-205706731

CVE-2022-20277: In DevicePolicyManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-205145497

CVE-2022-20279: In DevicePolicyManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204877302

CVE-2022-4087: A vulnerability was found in iPXE. It has been declared as problematic. This vulnerability affects the function tls_new_ciphertext of the file src/net/tls.c of the component TLS. The manipulation of the argument pad_len leads to information exposure through discrepancy. The name of the patch is 186306d6199096b7a7c4b4574d4be8cdb8426729. It is recommended to apply a patch to fix this issue. VDB-214054 is the identifier assigned to this vulnerability.

CVE-2021-33838: Luca through 1.7.4 on Android allows remote attackers to obtain sensitive information about COVID-19 tracking because requests related to Check-In State occur shortly after requests for Phone Number Registration.

# CWE-204 Observable Response Discrepancy

## Description

The product provides different responses to incoming requests in a way that reveals internal state information to an unauthorized actor outside of the intended control sphere.

This issue frequently occurs during authentication, where a difference in failed-login messages could allow an attacker to determine if the username is valid or not. These exposures can be inadvertent (bug) or intentional (design).

## Observed Examples

CVE-2002-2094: This, and others, use ".." attacks and monitor error responses, so there is overlap with directory traversal.

CVE-2001-1483: Enumeration of valid usernames based on inconsistent responses

CVE-2001-1528: Account number enumeration via inconsistent responses.

CVE-2004-2150: User enumeration via discrepancies in error messages.

CVE-2005-1650: User enumeration via discrepancies in error messages.

CVE-2004-0294: Bulletin Board displays different error messages when a user exists or not, which makes it easier for remote attackers to identify valid users and conduct a brute force password guessing attack.

CVE-2004-0243: Operating System, when direct remote login is disabled, displays a different message if the password is correct, which allows remote attackers to guess the password via brute force methods.

CVE-2002-0514: Product allows remote attackers to determine if a port is being filtered because the response packet TTL is different than the default TTL.

CVE-2002-0515: Product sets a different TTL when a port is being filtered than when it is not being filtered, which allows remote attackers to identify filtered ports by comparing TTLs.

CVE-2001-1387: Product may generate different responses than specified by the administrator, possibly leading to an information leak.

CVE-2004-0778: Version control system allows remote attackers to determine the existence of arbitrary files and directories via the -X command for an alternate history file, which causes different error messages to be returned.

CVE-2004-1428: FTP server generates an error message if the user name does not exist instead of prompting for a password, which allows remote attackers to determine valid usernames.

## Top 25 Examples

CVE-2022-24784: Statamic is a Laravel and Git powered CMS. Before versions 3.2.39 and 3.3.2, it is possible to confirm a single character of a user's password hash using a specially crafted regular expression filter in the users endpoint of the REST API. Multiple such requests can eventually uncover the entire hash. The hash is not present in the response, however the presence or absence of a result confirms if the character is in the right position. The API has throttling enabled by default, making this a time intensive task. Both the REST API and the users endpoint need to be enabled, as they are disabled by default. The issue has been fixed in versions 3.2.39 and above, and 3.3.2 and above.

CVE-2021-20147: ManageEngine ADSelfService Plus below build 6116 contains an observable response discrepancy in the UMCP operation of the ChangePasswordAPI. This allows an unauthenticated remote attacker to determine whether a Windows domain user exists.

CVE-2021-38009: Inappropriate implementation in cache in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

CVE-2022-1139: Inappropriate implementation in Background Fetch API in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

CVE-2022-27814: SWHKD 1.1.5 allows arbitrary file-existence tests via the -c option.

CVE-2022-47952: lxc-user-nic in lxc through 5.0.1 is installed setuid root, and may allow local users to infer whether any file exists, even within a protected directory tree, because "Failed to open" often indicates that a file does not exist, whereas "does not refer to a network namespace path" often indicates that a file exists. NOTE: this is different from CVE-2018-6556 because the CVE-2018-6556 fix design was based on the premise that "we will report back to the user that the open() failed but the user has no way of knowing why it failed"; however, in many realistic cases, there are no plausible reasons for failing except that the file does not exist.

CVE-2022-24032: Adenza AxiomSL ControllerView through 10.8.1 is vulnerable to user enumeration. An attacker can identify valid usernames on the platform because a failed login attempt produces a different error message when the username is valid.

CVE-2022-0569: Observable Discrepancy in Packagist snipe/snipe-it prior to v5.3.9. 

# CWE-205 Observable Behavioral Discrepancy

## Description

The product's behaviors indicate important differences that may be observed by unauthorized actors in a way that reveals (1) its internal state or decision process, or (2) differences from other products with equivalent functionality.

Ideally, a product should provide as little information about its internal operations as possible. Otherwise, attackers could use knowledge of these internal operations to simplify or optimize their attack. In some cases, behavioral discrepancies can be used by attackers to form a side channel.

## Observed Examples

CVE-2002-0208: Product modifies TCP/IP stack and ICMP error messages in unusual ways that show the product is in use.

CVE-2004-2252: Behavioral infoleak by responding to SYN-FIN packets.

## Top 25 Examples

CVE-2021-32528: Observable behavioral discrepancy vulnerability in QSAN Storage Manager allows remote attackers to obtain the system information without permissions. Suggest contacting with QSAN and refer to recommendations in QSAN Document.

# CWE-206 Observable Internal Behavioral Discrepancy

## Description

The product performs multiple behaviors that are combined to produce a single result, but the individual behaviors are observable separately in a way that allows attackers to reveal internal state or internal decision points.

Ideally, a product should provide as little information as possible to an attacker. Any hints that the attacker may be making progress can then be used to simplify or optimize the attack. For example, in a login procedure that requires a username and password, ultimately there is only one decision: success or failure. However, internally, two separate actions are performed: determining if the username exists, and checking if the password is correct. If the product behaves differently based on whether the username exists or not, then the attacker only needs to concentrate on the password.

## Observed Examples

CVE-2002-2031: File existence via infoleak monitoring whether "onerror" handler fires or not.

CVE-2005-2025: Valid groupname enumeration via behavioral infoleak (sends response if valid, doesn't respond if not).

CVE-2001-1497: Behavioral infoleak in GUI allows attackers to distinguish between alphanumeric and non-alphanumeric characters in a password, thus reducing the search space.

CVE-2003-0190: Product immediately sends an error message when user does not exist instead of waiting until the password is provided, allowing username enumeration.

# CWE-207 Observable Behavioral Discrepancy With Equivalent Products

## Description

The product operates in an environment in which its existence or specific identity should not be known, but it behaves differently than other products with equivalent functionality, in a way that is observable to an attacker.

For many kinds of products, multiple products may be available that perform the same functionality, such as a web server, network interface, or intrusion detection system. Attackers often perform "fingerprinting," which uses discrepancies in order to identify which specific product is in use. Once the specific product has been identified, the attacks can be made more customized and efficient. Often, an organization might intentionally allow the specific product to be identifiable. However, in some environments, the ability to identify a distinct product is unacceptable, and it is expected that every product would behave in exactly the same way. In these more restricted environments, a behavioral difference might pose an unacceptable risk if it makes it easier to identify the product's vendor, model, configuration, version, etc.

## Observed Examples

CVE-2002-0208: Product modifies TCP/IP stack and ICMP error messages in unusual ways that show the product is in use.

CVE-2004-2252: Behavioral infoleak by responding to SYN-FIN packets.

CVE-2000-1142: Honeypot generates an error with a "pwd" command in a particular directory, allowing attacker to know they are in a honeypot system.

# CWE-208 Observable Timing Discrepancy

## Description

Two separate operations in a product require different amounts of time to complete, in a way that is observable to an actor and reveals security-relevant information about the state of the product, such as whether a particular operation was successful or not.

In security-relevant contexts, even small variations in timing can be exploited by attackers to indirectly infer certain details about the product's internal operations. For example, in some cryptographic algorithms, attackers can use timing differences to infer certain properties about a private key, making the key easier to guess. Timing discrepancies effectively form a timing side channel.

## Observed Examples

CVE-2019-10071: Java-oriented framework compares HMAC signatures using String.equals() instead of a constant-time algorithm, causing timing discrepancies

CVE-2019-10482: Smartphone OS uses comparison functions that are not in constant time, allowing side channels

CVE-2014-0984: Password-checking function in router terminates validation of a password entry when it encounters the first incorrect character, which allows remote attackers to obtain passwords via a brute-force attack that relies on timing differences in responses to incorrect password guesses, aka a timing side-channel attack.

CVE-2003-0078: SSL implementation does not perform a MAC computation if an incorrect block cipher padding is used, which causes an information leak (timing discrepancy) that may make it easier to launch cryptographic attacks that rely on distinguishing between padding and MAC verification errors, possibly leading to extraction of the original plaintext, aka the "Vaudenay timing attack."

CVE-2000-1117: Virtual machine allows malicious web site operators to determine the existence of files on the client by measuring delays in the execution of the getSystemResource method.

CVE-2003-0637: Product uses a shorter timeout for a non-existent user than a valid user, which makes it easier for remote attackers to guess usernames and conduct brute force password guessing.

CVE-2003-0190: Product immediately sends an error message when a user does not exist, which allows remote attackers to determine valid usernames via a timing attack.

CVE-2004-1602: FTP server responds in a different amount of time when a given username exists, which allows remote attackers to identify valid usernames by timing the server response.

CVE-2005-0918: Browser allows remote attackers to determine the existence of arbitrary files by setting the src property to the target filename and using Javascript to determine if the web page immediately stops loading, which indicates whether the file exists or not.

## Top 25 Examples

CVE-2021-42016: A vulnerability has been identified in RUGGEDCOM i800, RUGGEDCOM i801, RUGGEDCOM i802, RUGGEDCOM i803, RUGGEDCOM M2100, RUGGEDCOM M2100F, RUGGEDCOM M2200, RUGGEDCOM M2200F, RUGGEDCOM M969, RUGGEDCOM M969F, RUGGEDCOM RMC30, RUGGEDCOM RMC8388 V4.X, RUGGEDCOM RMC8388 V5.X, RUGGEDCOM RP110, RUGGEDCOM RS1600, RUGGEDCOM RS1600F, RUGGEDCOM RS1600T, RUGGEDCOM RS400, RUGGEDCOM RS400F, RUGGEDCOM RS401, RUGGEDCOM RS416, RUGGEDCOM RS416F, RUGGEDCOM RS416P, RUGGEDCOM RS416PF, RUGGEDCOM RS416Pv2 V4.X, RUGGEDCOM RS416Pv2 V5.X, RUGGEDCOM RS416v2 V4.X, RUGGEDCOM RS416v2 V5.X, RUGGEDCOM RS8000, RUGGEDCOM RS8000A, RUGGEDCOM RS8000H, RUGGEDCOM RS8000T, RUGGEDCOM RS900, RUGGEDCOM RS900 (32M) V4.X, RUGGEDCOM RS900 (32M) V5.X, RUGGEDCOM RS900F, RUGGEDCOM RS900G, RUGGEDCOM RS900G (32M) V4.X, RUGGEDCOM RS900G (32M) V5.X, RUGGEDCOM RS900GF, RUGGEDCOM RS900GP, RUGGEDCOM RS900GPF, RUGGEDCOM RS900L, RUGGEDCOM RS900M-GETS-C01, RUGGEDCOM RS900M-GETS-XX, RUGGEDCOM RS900M-STND-C01, RUGGEDCOM RS900M-STND-XX, RUGGEDCOM RS900W, RUGGEDCOM RS910, RUGGEDCOM RS910L, RUGGEDCOM RS910W, RUGGEDCOM RS920L, RUGGEDCOM RS920W, RUGGEDCOM RS930L, RUGGEDCOM RS930W, RUGGEDCOM RS940G, RUGGEDCOM RS940GF, RUGGEDCOM RS969, RUGGEDCOM RSG2100, RUGGEDCOM RSG2100 (32M) V4.X, RUGGEDCOM RSG2100 (32M) V5.X, RUGGEDCOM RSG2100F, RUGGEDCOM RSG2100P, RUGGEDCOM RSG2100PF, RUGGEDCOM RSG2200, RUGGEDCOM RSG2200F, RUGGEDCOM RSG2288 V4.X, RUGGEDCOM RSG2288 V5.X, RUGGEDCOM RSG2300 V4.X, RUGGEDCOM RSG2300 V5.X, RUGGEDCOM RSG2300F, RUGGEDCOM RSG2300P V4.X, RUGGEDCOM RSG2300P V5.X, RUGGEDCOM RSG2300PF, RUGGEDCOM RSG2488 V4.X, RUGGEDCOM RSG2488 V5.X, RUGGEDCOM RSG2488F, RUGGEDCOM RSG907R, RUGGEDCOM RSG908C, RUGGEDCOM RSG909R, RUGGEDCOM RSG910C, RUGGEDCOM RSG920P V4.X, RUGGEDCOM RSG920P V5.X, RUGGEDCOM RSL910, RUGGEDCOM RST2228, RUGGEDCOM RST2228P, RUGGEDCOM RST916C, RUGGEDCOM RST916P. A timing attack, in a third-party component, could make the retrieval of the private key possible, used for encryption of sensitive data. If a threat actor were to exploit this, the data integrity and security could be compromised.

CVE-2022-4304: A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient to recover a plaintext across a network in a Bleichenbacher style attack. To achieve a successful decryption an attacker would have to be able to send a very large number of trial messages for decryption. The vulnerability affects all RSA padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS connection, RSA is commonly used by a client to send an encrypted pre-master secret to the server. An attacker that had observed a genuine connection between a client and a server could use this flaw to send trial messages to the server and record the time taken to process them. After a sufficiently large number of messages the attacker could recover the pre-master secret used for the original connection and thus be able to decrypt the application data sent over that connection. 

CVE-2021-33880: The aaugustin websockets library before 9.1 for Python has an Observable Timing Discrepancy on servers when HTTP Basic Authentication is enabled with basic_auth_protocol_factory(credentials=...). An attacker may be able to guess a password via a timing attack.

CVE-2021-4294: A vulnerability was found in OpenShift OSIN. It has been classified as problematic. This affects the function ClientSecretMatches/CheckClientSecret. The manipulation of the argument secret leads to observable timing discrepancy. The name of the patch is 8612686d6dda34ae9ef6b5a974e4b7accb4fea29. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-216987.

CVE-2022-34174: In Jenkins 2.355 and earlier, LTS 2.332.3 and earlier, an observable timing discrepancy on the login form allows distinguishing between login attempts with an invalid username, and login attempts with a valid username and wrong password, when using the Jenkins user database security realm.

CVE-2022-4823: A vulnerability, which was classified as problematic, was found in InSTEDD Nuntium. Affected is an unknown function of the file app/controllers/geopoll_controller.rb. The manipulation of the argument signature leads to observable timing discrepancy. It is possible to launch the attack remotely. The name of the patch is 77236f7fd71a0e2eefeea07f9866b069d612cf0d. It is recommended to apply a patch to fix this issue. VDB-217002 is the identifier assigned to this vulnerability.

CVE-2021-26314: Potential floating point value injection in all supported CPU products, in conjunction with software vulnerabilities relating to speculative execution with incorrect floating point results, may cause the use of incorrect data from FPVI and may result in data leakage.

CVE-2022-1146: Inappropriate implementation in Resource Timing in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to leak cross-origin data via a crafted HTML page.

CVE-2022-37146: The PlexTrac platform prior to version 1.28.0 allows for username enumeration via HTTP response times on invalid login attempts for users configured to use the PlexTrac authentication provider. Login attempts for valid, unlocked users configured to use PlexTrac as their authentication provider take significantly longer than those for invalid users, allowing for valid users to be enumerated by an unauthenticated remote attacker. Note that the lockout policy implemented in Plextrac version 1.17.0 makes it impossible to distinguish between valid, locked user accounts and user accounts that do not exist, but does not prevent valid, unlocked users from being enumerated.

CVE-2022-2891: The WP 2FA WordPress plugin before 2.3.0 uses comparison operators that don't mitigate time-based attacks, which could be abused to leak information about the authentication codes being compared.

CVE-2022-3907: The Clerk WordPress plugin before 4.0.0 is affected by time-based attacks in the validation function for all API requests due to the usage of comparison operators to verify API keys against the ones stored in the site options.

# CWE-209 Generation of Error Message Containing Sensitive Information

## Description

The product generates an error message that includes sensitive information about its environment, users, or associated data.

The sensitive information may be valuable information on its own (such as a password), or it may be useful for launching other, more serious attacks. The error message may be created in different ways:


  - self-generated: the source code explicitly constructs the error message and delivers it

  - externally-generated: the external environment, such as a language interpreter, handles the error and constructs its own message, whose contents are not under direct control by the programmer

An attacker may use the contents of error messages to help launch another, more focused attack. For example, an attempt to exploit a path traversal weakness (CWE-22) might yield the full pathname of the installed application. In turn, this could be used to select the proper number of ".." sequences to navigate to the targeted file. An attack using SQL injection (CWE-89) might not initially succeed, but an error message could reveal the malformed query, which would expose query logic and possibly even passwords or other sensitive information used within the query.

## Observed Examples

CVE-2008-2049: POP3 server reveals a password in an error message after multiple APOP commands are sent. Might be resultant from another weakness.

CVE-2007-5172: Program reveals password in error message if attacker can trigger certain database errors.

CVE-2008-4638: Composite: application running with high privileges (CWE-250) allows user to specify a restricted file to process, which generates a parsing error that leaks the contents of the file (CWE-209).

CVE-2008-1579: Existence of user names can be determined by requesting a nonexistent blog and reading the error message.

CVE-2007-1409: Direct request to library file in web application triggers pathname leak in error message.

CVE-2008-3060: Malformed input to login page causes leak of full path when IMAP call fails.

CVE-2005-0603: Malformed regexp syntax leads to information exposure in error message.

CVE-2017-9615: verbose logging stores admin credentials in a world-readablelog file

CVE-2018-1999036: SSH password for private key stored in build log

## Top 25 Examples

CVE-2021-39023: IBM Guardium Data Encryption (GDE) 4.0.0 and 5.0.0 could allow a remote attacker to obtain sensitive information when a detailed technical error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 213860.

CVE-2022-31047: TYPO3 is an open source web content management system. Prior to versions 7.6.57 ELTS, 8.7.47 ELTS, 9.5.34 ELTS, 10.4.29, and 11.5.11, system internal credentials or keys (e.g. database credentials) can be logged as plaintext in exception handlers, when logging the complete exception stack trace. TYPO3 versions 7.6.57 ELTS, 8.7.47 ELTS, 9.5.34 ELTS, 10.4.29, 11.5.11 contain a fix for the problem.

CVE-2022-2062: Generation of Error Message Containing Sensitive Information in GitHub repository nocodb/nocodb prior to 0.91.7+.

CVE-2021-38924: IBM Maximo Asset Management 7.6.1.1 and 7.6.1.2 could allow a remote attacker to obtain sensitive information when a detailed technical error message is returned in the browser. This information could be used in further attacks against the system. IBM X-Force ID: 210163.

CVE-2022-39315: Kirby is a Content Management System. Prior to versions 3.5.8.2, 3.6.6.2, 3.7.5.1, and 3.8.1, a user enumeration vulnerability affects all Kirby sites with user accounts unless Kirby's API and Panel are disabled in the config. It can only be exploited for targeted attacks because the attack does not scale to brute force. The problem has been patched in Kirby 3.5.8.2, Kirby 3.6.6.2, Kirby 3.7.5.1, and Kirby 3.8.1. In all of the mentioned releases, the maintainers have rewritten the affected code so that the delay is also inserted after the brute force limit is reached.

CVE-2022-20525: In enforceVisualVoicemailPackage of PhoneInterfaceManager.java, there is a possible leak of visual voicemail package name due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-229742768

CVE-2022-24906: Nextcloud Deck is a Kanban-style project & personal management tool for Nextcloud, similar to Trello. The full path of the application is exposed to unauthorized users. It is recommended that the Nextcloud Deck app is upgraded to 1.2.11, 1.4.6, or 1.5.4. There is no workaround available.

CVE-2022-39307: Grafana is an open-source platform for monitoring and observability. When using the forget password on the login page, a POST request is made to the `/api/user/password/sent-reset-email` URL. When the username or email does not exist, a JSON response contains a “user not found” message. This leaks information to unauthenticated users and introduces a security risk. This issue has been patched in 9.2.4 and backported to 8.5.15. There are no known workarounds.

# CWE-210 Self-generated Error Message Containing Sensitive Information

## Description

The product identifies an error condition and creates its own diagnostic or error messages that contain sensitive information.

## Observed Examples

CVE-2005-1745: Infoleak of sensitive information in error message (physical access required).

# CWE-211 Externally-Generated Error Message Containing Sensitive Information

## Description

The product performs an operation that triggers an external diagnostic or error message that is not directly generated or controlled by the product, such as an error generated by the programming language interpreter that a software application uses. The error can contain sensitive system information.

## Observed Examples

CVE-2004-1581: chain: product does not protect against direct request of an include file, leading to resultant path disclosure when the include file does not successfully execute.

CVE-2004-1579: Single "'" inserted into SQL query leads to invalid SQL query execution, triggering full path disclosure. Possibly resultant from more general SQL injection issue.

CVE-2005-0459: chain: product does not protect against direct request of a library file, leading to resultant path disclosure when the file does not successfully execute.

CVE-2005-0443: invalid parameter triggers a failure to find an include file, leading to infoleak in error message.

CVE-2005-0433: Various invalid requests lead to information leak in verbose error messages describing the failure to instantiate a class, open a configuration file, or execute an undefined function.

CVE-2004-1101: Improper handling of filename request with trailing "/" causes multiple consequences, including information leak in Visual Basic error message.

# CWE-212 Improper Removal of Sensitive Information Before Storage or Transfer

## Description

The product stores, transfers, or shares a resource that contains sensitive information, but it does not properly remove that information before the product makes the resource available to unauthorized actors.

Resources that may contain sensitive data include documents, packets, messages, databases, etc. While this data may be useful to an individual user or small set of users who share the resource, it may need to be removed before the resource can be shared outside of the trusted group. The process of removal is sometimes called cleansing or scrubbing.


For example, a product for editing documents might not remove sensitive data such as reviewer comments or the local pathname where the document is stored. Or, a proxy might not remove an internal IP address from headers before making an outgoing request to an Internet site.

## Observed Examples

CVE-2019-3733: Cryptography library does not clear heap memory before release

CVE-2005-0406: Some image editors modify a JPEG image, but the original EXIF thumbnail image is left intact within the JPEG. (Also an interaction error).

CVE-2002-0704: NAT feature in firewall leaks internal IP addresses in ICMP error messages.

## Top 25 Examples

CVE-2022-24719: Fluture-Node is a FP-style HTTP and streaming utils for Node based on Fluture. Using `followRedirects` or `followRedirectsWith` with any of the redirection strategies built into fluture-node 4.0.0 or 4.0.1, paired with a request that includes confidential headers such as Authorization or Cookie, exposes you to a vulnerability where, if the destination server were to redirect the request to a server on a third-party domain, or the same domain over unencrypted HTTP, the headers would be included in the follow-up request and be exposed to the third party, or potential http traffic sniffing. The redirection strategies made available in version 4.0.2 automatically redact confidential headers when a redirect is followed across to another origin. A workaround has been identified by using a custom redirection strategy via the `followRedirectsWith` function. The custom strategy can be based on the new strategies available in fluture-node@4.0.2.

CVE-2022-24798: Internet Routing Registry daemon version 4 is an IRR database server, processing IRR objects in the RPSL format. IRRd did not always filter password hashes in query responses relating to `mntner` objects and database exports. This may have allowed adversaries to retrieve some of these hashes, perform a brute-force search for the clear-text passphrase, and use these to make unauthorised changes to affected IRR objects. This issue only affected instances that process password hashes, which means it is limited to IRRd instances that serve authoritative databases. IRRd instances operating solely as mirrors of other IRR databases are not affected. This has been fixed in IRRd 4.2.3 and the main branch. Versions in the 4.1.x series never were affected. Users of the 4.2.x series are strongly recommended to upgrade. There are no known workarounds for this issue.

CVE-2022-2818: Improper Removal of Sensitive Information Before Storage or Transfer in GitHub repository cockpit-hq/cockpit prior to 2.2.2. 

CVE-2022-25187: Jenkins Support Core Plugin 2.79 and earlier does not redact some sensitive information in the support bundle.

CVE-2022-0355: Improper Removal of Sensitive Information Before Storage or Transfer in NPM simple-get prior to 4.0.1. 

CVE-2022-0536: Improper Removal of Sensitive Information Before Storage or Transfer in NPM follow-redirects prior to 1.14.8. 

CVE-2022-1650: Improper Removal of Sensitive Information Before Storage or Transfer in GitHub repository eventsource/eventsource prior to v2.0.2. 

CVE-2022-1893: Improper Removal of Sensitive Information Before Storage or Transfer in GitHub repository polonel/trudesk prior to 1.2.3.

CVE-2022-31042: Guzzle is an open source PHP HTTP client. In affected versions the `Cookie` headers on requests are sensitive information. On making a request using the `https` scheme to a server which responds with a redirect to a URI with the `http` scheme, or on making a request to a server which responds with a redirect to a a URI to a different host, we should not forward the `Cookie` header on. Prior to this fix, only cookies that were managed by our cookie middleware would be safely removed, and any `Cookie` header manually added to the initial request would not be stripped. We now always strip it, and allow the cookie middleware to re-add any cookies that it deems should be there. Affected Guzzle 7 users should upgrade to Guzzle 7.4.4 as soon as possible. Affected users using any earlier series of Guzzle should upgrade to Guzzle 6.5.7 or 7.4.4. Users unable to upgrade may consider an alternative approach to use your own redirect middleware, rather than ours. If you do not require or expect redirects to be followed, one should simply disable redirects all together.

CVE-2022-31043: Guzzle is an open source PHP HTTP client. In affected versions `Authorization` headers on requests are sensitive information. On making a request using the `https` scheme to a server which responds with a redirect to a URI with the `http` scheme, we should not forward the `Authorization` header on. This is much the same as to how we don't forward on the header if the host changes. Prior to this fix, `https` to `http` downgrades did not result in the `Authorization` header being removed, only changes to the host. Affected Guzzle 7 users should upgrade to Guzzle 7.4.4 as soon as possible. Affected users using any earlier series of Guzzle should upgrade to Guzzle 6.5.7 or 7.4.4. Users unable to upgrade may consider an alternative approach which would be to use their own redirect middleware. Alternately users may simply disable redirects all together if redirects are not expected or required.

CVE-2022-31090: Guzzle, an extensible PHP HTTP client. `Authorization` headers on requests are sensitive information. In affected versions when using our Curl handler, it is possible to use the `CURLOPT_HTTPAUTH` option to specify an `Authorization` header. On making a request which responds with a redirect to a URI with a different origin (change in host, scheme or port), if we choose to follow it, we should remove the `CURLOPT_HTTPAUTH` option before continuing, stopping curl from appending the `Authorization` header to the new request. Affected Guzzle 7 users should upgrade to Guzzle 7.4.5 as soon as possible. Affected users using any earlier series of Guzzle should upgrade to Guzzle 6.5.8 or 7.4.5. Note that a partial fix was implemented in Guzzle 7.4.2, where a change in host would trigger removal of the curl-added Authorization header, however this earlier fix did not cover change in scheme or change in port. If you do not require or expect redirects to be followed, one should simply disable redirects all together. Alternatively, one can specify to use the Guzzle steam handler backend, rather than curl.

CVE-2022-31112: Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. In affected versions parse Server LiveQuery does not remove protected fields in classes, passing them to the client. The LiveQueryController now removes protected fields from the client response. Users are advised to upgrade. Users unable t upgrade should use `Parse.Cloud.afterLiveQueryEvent` to manually remove protected fields.

CVE-2022-33740: Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740). Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend (CVE-2022-33741, CVE-2022-33742).

CVE-2022-3460: In affected versions of Octopus Deploy it is possible for certain types of sensitive variables to inadvertently become unmasked when viewed in variable preview.

CVE-2022-4734: Improper Removal of Sensitive Information Before Storage or Transfer in GitHub repository usememos/memos prior to 0.9.1. 

# CWE-213 Exposure of Sensitive Information Due to Incompatible Policies

## Description

The product's intended functionality exposes information to certain actors in accordance with the developer's security policy, but this information is regarded as sensitive according to the intended security policies of other stakeholders such as the product's administrator, users, or others whose information is being processed.

When handling information, the developer must consider whether the information is regarded as sensitive by different stakeholders, such as users or administrators. Each stakeholder effectively has its own intended security policy that the product is expected to uphold. When a developer does not treat that information as sensitive, this can introduce a vulnerability that violates the expectations of the product's users.

## Observed Examples

CVE-2002-1725: Script calls phpinfo()

CVE-2004-0033: Script calls phpinfo()

CVE-2003-1181: Script calls phpinfo()

CVE-2004-1422: Script calls phpinfo()

CVE-2004-1590: Script calls phpinfo()

CVE-2003-1038: Product lists DLLs and full pathnames.

CVE-2005-1205: Telnet protocol allows servers to obtain sensitive environment information from clients.

CVE-2005-0488: Telnet protocol allows servers to obtain sensitive environment information from clients.

## Top 25 Examples

CVE-2022-28794: Sensitive information exposure in low-battery dumpstate log prior to SMR Jun-2022 Release 1 allows local attackers to get SIM card information.

CVE-2022-30714: Information exposure vulnerability in SemIWCMonitor prior to SMR Jun-2022 Release 1 allows local attackers to get MAC address information.

CVE-2022-30728: Information exposure vulnerability in ScanPool prior to SMR Jun-2022 Release 1 allows local attackers to get MAC address information.

CVE-2022-33692: Exposure of Sensitive Information in Messaging application prior to SMR Jul-2022 Release 1 allows local attacker to access imsi and iccid via log.

CVE-2022-33694: Exposure of Sensitive Information in CSC application prior to SMR Jul-2022 Release 1 allows local attacker to access wifi information via unprotected intent broadcasting.

CVE-2022-33696: Exposure of Sensitive Information in Telephony service prior to SMR Jul-2022 Release 1 allows local attacker to access imsi and iccid via log.

CVE-2022-39848: Exposure of sensitive information in AT_Distributor prior to SMR Oct-2022 Release 1 allows local attacker to access SerialNo via log.

# CWE-214 Invocation of Process Using Visible Sensitive Information

## Description

A process is invoked with sensitive command-line arguments, environment variables, or other elements that can be seen by other processes on the operating system.

Many operating systems allow a user to list information about processes that are owned by other users. Other users could see information such as command line arguments or environment variable settings. When this data contains sensitive information such as credentials, it might allow other users to launch an attack against the product or related resources.

## Observed Examples

CVE-2005-1387: password passed on command line

CVE-2005-2291: password passed on command line

CVE-2001-1565: username/password on command line allows local users to view via "ps" or other process listing programs

CVE-2004-1948: Username/password on command line allows local users to view via "ps" or other process listing programs.

CVE-1999-1270: PGP passphrase provided as command line argument.

CVE-2004-1058: Kernel race condition allows reading of environment variables of a process that is still spawning.

CVE-2021-32638: Code analysis product passes access tokens as a command-line parameter or through an environment variable, making them visible to other processes via the ps command.

## Top 25 Examples

CVE-2022-31238: Dell PowerScale OneFS, versions 9.0.0 up to and including 9.1.0.19, 9.2.1.12, 9.3.0.6, and 9.4.0.2, contain a process invoked with sensitive information vulnerability. A CLI user may potentially exploit this vulnerability, leading to information disclosure.

CVE-2022-30586: Gradle Enterprise through 2022.2.2 has Incorrect Access Control that leads to code execution.

CVE-2022-0235: node-fetch is vulnerable to Exposure of Sensitive Information to an Unauthorized Actor

CVE-2022-0851: There is a flaw in convert2rhel. When the --activationkey option is used with convert2rhel, the activation key is subsequently passed to subscription-manager via the command line, which could allow unauthorized users locally on the machine to view the activation key via the process command line via e.g. htop or ps. The specific impact varies upon the subscription, but generally this would allow an attacker to register systems purchased by the victim until discovered; a form of fraud. This could occur regardless of how the activation key is supplied to convert2rhel because it involves how convert2rhel provides it to subscription-manager.

CVE-2022-1662: In convert2rhel, there's an ansible playbook named ansible/run-convert2rhel.yml which passes the Red Hat Subscription Manager user password via the CLI to convert2rhel. This could allow unauthorized local users to view the password via the process list while convert2rhel is running. However, this ansible playbook is only an example in the upstream repository and it is not shipped in officially supported versions of convert2rhel.

# CWE-215 Insertion of Sensitive Information Into Debugging Code

## Description

The product inserts sensitive information into debugging code, which could expose this information if the debugging code is not disabled in production.

When debugging, it may be necessary to report detailed information to the programmer. However, if the debugging code is not disabled when the product is operating in a production environment, then this sensitive information may be exposed to attackers.

## Observed Examples

CVE-2004-2268: Password exposed in debug information.

CVE-2002-0918: CGI script includes sensitive information in debug messages when an error is triggered.

CVE-2003-1078: FTP client with debug option enabled shows password to the screen.

## Top 25 Examples

CVE-2022-0721: Insertion of Sensitive Information Into Debugging Code in GitHub repository microweber/microweber prior to 1.3.

CVE-2022-27912: An issue was discovered in Joomla! 4.0.0 through 4.2.3. Sites with publicly enabled debug mode exposed data of previous requests.

# CWE-219 Storage of File with Sensitive Data Under Web Root

## Description

The product stores sensitive data under the web document root with insufficient access control, which might make it accessible to untrusted parties.

Besides public-facing web pages and code, products may store sensitive data, code that is not directly invoked, or other files under the web document root of the web server. If the server is not configured or otherwise used to prevent direct access to those files, then attackers may obtain this sensitive data.

## Observed Examples

CVE-2005-1835: Data file under web root.

CVE-2005-2217: Data file under web root.

CVE-2002-1449: Username/password in data file under web root.

CVE-2002-0943: Database file under web root.

CVE-2005-1645: database file under web root.

## Top 25 Examples

CVE-2021-20148: ManageEngine ADSelfService Plus below build 6116 stores the password policy file for each domain under the html/ web root with a predictable filename based on the domain name. When ADSSP is configured with multiple Windows domains, a user from one domain can obtain the password policy for another domain by authenticating to the service and then sending a request specifying the password policy file of the other domain.

# CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Description

The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.

Many file operations are intended to take place within a restricted directory. By using special elements such as ".." and "/" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the "../" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as "/usr/local/bin" to access unexpected files. This is referred to as absolute path traversal.

## Observed Examples

CVE-2024-37032: Large language model (LLM) management tool does not validate the format of a digest value (CWE-1287) from a private, untrusted model registry, enabling relative path traversal (CWE-23), a.k.a. Probllama

CVE-2024-4315: Chain: API for text generation using Large Language Models (LLMs) does not include the "\" Windows folder separator in its denylist (CWE-184) when attempting to prevent Local File Inclusion via path traversal (CWE-22), allowing deletion of arbitrary files on Windows systems.

CVE-2022-45918: Chain: a learning management tool debugger uses external input to locate previous session logs (CWE-73) and does not properly validate the given path (CWE-20), allowing for filesystem path traversal using "../" sequences (CWE-24)

CVE-2019-20916: Python package manager does not correctly restrict the filename specified in a Content-Disposition header, allowing arbitrary file read using path traversal sequences such as "../"

CVE-2022-31503: Python package constructs filenames using an unsafe os.path.join call on untrusted input, allowing absolute path traversal because os.path.join resets the pathname to an absolute path that is specified as part of the input.

CVE-2022-24877: directory traversal in Go-based Kubernetes operator app allows accessing data from the controller's pod file system via ../ sequences in a yaml file

CVE-2021-21972: Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV.

CVE-2020-4053: a Kubernetes package manager written in Go allows malicious plugins to inject path traversal sequences into a plugin archive ("Zip slip") to copy a file outside the intended directory

CVE-2020-3452: Chain: security product has improper input validation (CWE-20) leading to directory traversal (CWE-22), as exploited in the wild per CISA KEV.

CVE-2019-10743: Go-based archive library allows extraction of files to locations outside of the target folder with "../" path traversal sequences in filenames in a zip file, aka "Zip Slip"

CVE-2010-0467: Newsletter module allows reading arbitrary files using "../" sequences.

CVE-2006-7079: Chain: PHP app uses extract for register_globals compatibility layer (CWE-621), enabling path traversal (CWE-22)

CVE-2009-4194: FTP server allows deletion of arbitrary files using ".." in the DELE command.

CVE-2009-4053: FTP server allows creation of arbitrary directories using ".." in the MKD command.

CVE-2009-0244: FTP service for a Bluetooth device allows listing of directories, and creation or reading of files using ".." sequences.

CVE-2009-4013: Software package maintenance program allows overwriting arbitrary files using "../" sequences.

CVE-2009-4449: Bulletin board allows attackers to determine the existence of files using the avatar.

CVE-2009-4581: PHP program allows arbitrary code execution using ".." in filenames that are fed to the include() function.

CVE-2010-0012: Overwrite of files using a .. in a Torrent file.

CVE-2010-0013: Chat program allows overwriting files using a custom smiley request.

CVE-2008-5748: Chain: external control of values for user's desired language and theme enables path traversal.

CVE-2009-1936: Chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal.

## Top 25 Examples

CVE-2022-1390: The Admin Word Count Column WordPress plugin through 2.2 does not validate the path parameter given to readfile(), which could allow unauthenticated attackers to read arbitrary files on server running old version of PHP susceptible to the null byte technique. This could also lead to RCE by using a Phar Deserialization technique

CVE-2022-20721: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-20722: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-34254: Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability that could be abused by an attacker to inject malicious scripts into the vulnerable endpoint. A low privileged attacker could leverage this vulnerability to read local files and to perform Stored XSS. Exploitation of this issue does not require user interaction.

CVE-2022-34426: Dell Container Storage Modules 1.2 contains an Improper Limitation of a Pathname to a Restricted Directory in goiscsi and gobrick libraries which could lead to OS command injection. A remote unauthenticated attacker could exploit this vulnerability leading to unintentional access to path outside of restricted directory.

CVE-2022-20723: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-45427: Emerson XWEB 300D EVO 3.0.7--3ee403 is affected by: unauthenticated arbitrary file deletion due to path traversal. An attacker can browse and delete files without any authentication due to incorrect access control and directory traversal.

CVE-2022-22914: An incorrect access control issue in the component FileManager of Ovidentia CMS 6.0 allows authenticated attackers to to view and download content in the upload directory via path traversal.

CVE-2022-24730: Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Argo CD starting with version 1.3.0 but before versions 2.1.11, 2.2.6, and 2.3.0 is vulnerable to a path traversal bug, compounded by an improper access control bug, allowing a malicious user with read-only repository access to leak sensitive files from Argo CD's repo-server. A malicious Argo CD user who has been granted `get` access for a repository containing a Helm chart can craft an API request to the `/api/v1/repositories/{repo_url}/appdetails` endpoint to leak the contents of out-of-bounds files from the repo-server. The malicious payload would reference an out-of-bounds file, and the contents of that file would be returned as part of the response. Contents from a non-YAML file may be returned as part of an error message. The attacker would have to know or guess the location of the target file. Sensitive files which could be leaked include files from other Applications' source repositories or any secrets which have been mounted as files on the repo-server. This vulnerability is patched in Argo CD versions 2.1.11, 2.2.6, and 2.3.0. The patches prevent path traversal and limit access to users who either A) have been granted Application `create` privileges or B) have been granted Application `get` privileges and are requesting details for a `repo_url` that has already been used for the given Application. There are currently no known workarounds.

CVE-2022-27925: Zimbra Collaboration (aka ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. An authenticated user with administrator rights has the ability to upload arbitrary files to the system, leading to directory traversal.

CVE-2022-29836: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability was discovered via an HTTP API on Western Digital My Cloud Home; My Cloud Home Duo; and SanDisk ibi devices that could allow an attacker to abuse certain parameters to point to random locations on the file system. This could also allow the attacker to initiate the installation of custom packages at these locations. This can only be exploited once the attacker has been authenticated to the device. This issue affects: Western Digital My Cloud Home and My Cloud Home Duo versions prior to 8.11.0-113 on Linux; SanDisk ibi versions prior to 8.11.0-113 on Linux.

CVE-2022-3090: Red Lion Controls Crimson 3.0 versions 707.000 and prior, Crimson 3.1 versions 3126.001 and prior, and Crimson 3.2 versions 3.2.0044.0 and prior are vulnerable to path traversal. When attempting to open a file using a specific path, the user's password hash is sent to an arbitrary host. This could allow an attacker to obtain user credential hashes.

CVE-2022-31255: An Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to read files available to the user running the process, typically tomcat. This issue affects: SUSE Linux Enterprise Module for SUSE Manager Server 4.2 hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-formula-0.3-150300.3.3.2, py27-compat-salt-3000.3-150300.7.7.26.2, python-urlgrabber-3.10.2.1py2_3-150300.3.3.2, spacecmd-4.2.20-150300.4.30.2, spacewalk-backend-4.2.25-150300.4.32.4, spacewalk-client-tools-4.2.21-150300.4.27.3, spacewalk-java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2, spacewalk-web-4.2.30-150300.3.30.3, susemanager-4.2.38-150300.3.44.3, susemanager-doc-indexes-4.2-150300.12.36.3, susemanager-docs_en-4.2-150300.12.36.2, susemanager-schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to 4.2.28. SUSE Linux Enterprise Module for SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39. SUSE Manager Server 4.2 release-notes-susemanager versions prior to 4.2.10.

CVE-2022-3560: A flaw was found in pesign. The pesign package provides a systemd service used to start the pesign daemon. This service unit runs a script to set ACLs for /etc/pki/pesign and /run/pesign directories to grant access privileges to users in the 'pesign' group. However, the script doesn't check for symbolic links. This could allow an attacker to gain access to privileged files and directories via a path traversal attack.

CVE-2022-42280: NVIDIA BMC contains a vulnerability in SPX REST auth handler, where an un-authorized attacker can exploit a path traversal, which may lead to authentication bypass.

CVE-2021-1256: A vulnerability in the CLI of Cisco Firepower Threat Defense (FTD) Software could allow an authenticated, local attacker to overwrite files on the file system of an affected device by using directory traversal techniques. A successful exploit could cause system instability if important system files are overwritten. This vulnerability is due to insufficient validation of user input for the file path in a specific CLI command. An attacker could exploit this vulnerability by logging in to a targeted device and issuing a specific CLI command with crafted user input. A successful exploit could allow the attacker to overwrite arbitrary files on the file system of the affected device. The attacker would need valid user credentials on the device.

CVE-2022-29580: There exists a path traversal vulnerability in the Android Google Search app. This is caused by the incorrect usage of uri.getLastPathSegment. A symbolic encoded string can bypass the path logic to get access to unintended directories. An attacker can manipulate paths that could lead to code execution on the device. We recommend upgrading beyond version 13.41

CVE-2021-20023: SonicWall Email Security version 10.0.9.x contains a vulnerability that allows a post-authenticated attacker to read an arbitrary file on the remote host.

CVE-2021-20090: A path traversal vulnerability in the web interfaces of Buffalo WSR-2533DHPL2 firmware version <= 1.02 and WSR-2533DHP3 firmware version <= 1.24 could allow unauthenticated remote attackers to bypass authentication.

CVE-2022-30333: RARLAB UnRAR before 6.12 on Linux and UNIX allows directory traversal to write to files during an extract (aka unpack) operation, as demonstrated by creating a ~/.ssh/authorized_keys file. NOTE: WinRAR and Android RAR are unaffected.

CVE-2022-41328: A improper limitation of a pathname to a restricted directory vulnerability ('path traversal') [CWE-22] in Fortinet FortiOS version 7.2.0 through 7.2.3, 7.0.0 through 7.0.9 and before 6.4.11 allows a privileged attacker to read and write files on the underlying Linux system via crafted CLI commands.

CVE-2021-41773: A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

CVE-2022-41352: An issue was discovered in Zimbra Collaboration (ZCS) 8.8.15 and 9.0. An attacker can upload arbitrary files through amavis via a cpio loophole (extraction to /opt/zimbra/jetty/webapps/zimbra/public) that can lead to incorrect access to any other user accounts. Zimbra recommends pax over cpio. Also, pax is in the prerequisites of Zimbra on Ubuntu; however, pax is no longer part of a default Red Hat installation after RHEL 6 (or CentOS 6). Once pax is installed, amavis automatically prefers it over cpio.

CVE-2022-3966: A vulnerability, which was classified as critical, has been found in Ultimate Member Plugin up to 2.5.0. This issue affects the function load_template of the file includes/core/class-shortcodes.php of the component Template Handler. The manipulation of the argument tpl leads to pathname traversal. The attack may be initiated remotely. Upgrading to version 2.5.1 is able to address this issue. The name of the patch is e1bc94c1100f02a129721ba4be5fbc44c3d78ec4. It is recommended to upgrade the affected component. The identifier VDB-213545 was assigned to this vulnerability.

CVE-2021-37126: Arbitrary file has a Exposure of Sensitive Information to an Unauthorized Actor vulnerability .Successful exploitation of this vulnerability may cause the directory is traversed.

CVE-2022-0902: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'), Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability in flow computer and remote controller products of ABB ( RMC-100 (Standard), RMC-100-LITE, XIO, XFCG5 , XRCG5 , uFLOG5 , UDC) allows an attacker who successfully exploited this vulnerability could insert and run arbitrary code in an affected system node.

CVE-2021-23484: The package zip-local before 0.3.5 are vulnerable to Arbitrary File Write via Archive Extraction (Zip Slip) which can lead to an extraction of a crafted file outside the intended extraction directory.

CVE-2022-37703: In Amanda 3.5.1, an information leak vulnerability was found in the calcsize SUID binary. An attacker can abuse this vulnerability to know if a directory exists or not anywhere in the fs. The binary will use `opendir()` as root directly without checking the path, letting the attacker provide an arbitrary path.

CVE-2022-24897: APIs to evaluate content with Velocity is a package for APIs to evaluate content with Velocity. Starting with version 2.3 and prior to 12.6.7, 12.10.3, and 13.0, the velocity scripts are not properly sandboxed against using the Java File API to perform read or write operations on the filesystem. Writing an attacking script in Velocity requires the Script rights in XWiki so not all users can use it, and it also requires finding an XWiki API which returns a File. The problem has been patched in versions 12.6.7, 12.10.3, and 13.0. There is no easy workaround for fixing this vulnerability other than upgrading and being careful when giving Script rights.

CVE-2022-31475: Authenticated (custom plugin role) Arbitrary File Read via Export function vulnerability in GiveWP's GiveWP plugin <= 2.20.2 at WordPress.

CVE-2022-35235: Authenticated (admin+) Arbitrary File Read vulnerability in XplodedThemes WPide plugin <= 2.6 at WordPress.

CVE-2022-4779: StreamX applications from versions 6.02.01 to 6.04.34 are affected by a logic bug that allows to bypass the implemented authentication scheme. StreamX applications using StreamView HTML component with the public web server feature activated are affected. 

CVE-2022-25371: Apache OFBiz uses the Birt project plugin (https://eclipse.github.io/birt-website/) to create data visualizations and reports. By leveraging a bug in Birt (https://bugs.eclipse.org/bugs/show_bug.cgi?id=538142) it is possible to perform a remote code execution (RCE) attack in Apache OFBiz, release 18.12.05 and earlier.

CVE-2022-41158: Remote code execution vulnerability can be achieved by using cookie values as paths to a file by this builder program. A remote attacker could exploit the vulnerability to execute or inject malicious code.

CVE-2021-41143: OpenMage LTS is an e-commerce platform. Prior to versions 19.4.22 and 20.0.19, Magento admin users with access to the customer media could execute code on the server. Versions 19.4.22 and 20.0.19 contain a patch for this issue. 

CVE-2021-21469: When security guidelines for SAP NetWeaver Master Data Management running on windows have not been thoroughly reviewed, it might be possible for an external operator to try and set custom paths in the MDS server configuration. When no adequate protection has been enforced on any level (e.g., MDS Server password not set, network and OS configuration not properly secured, etc.), a malicious user might define UNC paths which could then be exploited to put the system at risk using a so-called SMB relay attack and obtain highly sensitive data, which leads to Information Disclosure.

CVE-2021-41277: Metabase is an open source data analytics platform. In affected versions a security issue has been discovered with the custom GeoJSON map (`admin->settings->maps->custom maps->add a map`) support and potential local file inclusion (including environment variables). URLs were not validated prior to being loaded. This issue is fixed in a new maintenance release (0.40.5 and 1.40.5), and any subsequent release after that. If you’re unable to upgrade immediately, you can mitigate this by including rules in your reverse proxy or load balancer or WAF to provide a validation filter before the application.

# CWE-220 Storage of File With Sensitive Data Under FTP Root

## Description

The product stores sensitive data under the FTP server root with insufficient access control, which might make it accessible to untrusted parties.

Various Unix FTP servers require a password file that is under the FTP root, due to use of chroot.

# CWE-221 Information Loss or Omission

## Description

The product does not record, or improperly records, security-relevant information that leads to an incorrect decision or hampers later analysis.

This can be resultant, e.g. a buffer overflow might trigger a crash before the product can log the event.

## Observed Examples

CVE-2004-2227: Web browser's filename selection dialog only shows the beginning portion of long filenames, which can trick users into launching executables with dangerous extensions.

CVE-2003-0412: application server does not log complete URI of a long request (truncation).

CVE-1999-1029: Login attempts are not recorded if the user disconnects before the maximum number of tries.

CVE-2002-0725: Attacker performs malicious actions on a hard link to a file, obscuring the real target file.

CVE-1999-1055: Product does not warn user when document contains certain dangerous functions or macros.

# CWE-222 Truncation of Security-relevant Information

## Description

The product truncates the display, recording, or processing of security-relevant information in a way that can obscure the source or nature of an attack.

## Observed Examples

CVE-2005-0585: Web browser truncates long sub-domains or paths, facilitating phishing.

CVE-2004-2032: Bypass URL filter via a long URL with a large number of trailing hex-encoded space characters.

CVE-2003-0412: application server does not log complete URI of a long request (truncation).

# CWE-223 Omission of Security-relevant Information

## Description

The product does not record or display information that would be important for identifying the source or nature of an attack, or determining if an action is safe.

## Observed Examples

CVE-1999-1029: Login attempts are not recorded if the user disconnects before the maximum number of tries.

CVE-2002-1839: Sender's IP address not recorded in outgoing e-mail.

CVE-2000-0542: Failed authentication attempts are not recorded if later attempt succeeds.

## Top 25 Examples

CVE-2021-45289: A vulnerability exists in GPAC 1.0.1 due to an omission of security-relevant Information, which could cause a Denial of Service. The program terminates with signal SIGKILL.

# CWE-224 Obscured Security-relevant Information by Alternate Name

## Description

The product records security-relevant information according to an alternate name of the affected entity, instead of the canonical name.

## Observed Examples

CVE-2002-0725: Attacker performs malicious actions on a hard link to a file, obscuring the real target file.

# CWE-226 Sensitive Information in Resource Not Removed Before Reuse

## Description

The product releases a resource such as memory or a file so that it can be made available for reuse, but it does not clear or "zeroize" the information contained in the resource before the product performs a critical state transition or makes the resource available for reuse by other entities.

When resources are released, they can be made available for reuse. For example, after memory is de-allocated, an operating system may make the memory available to another process, or disk space may be reallocated when a file is deleted. As removing information requires time and additional resources, operating systems do not usually clear the previously written information.


Even when the resource is reused by the same process, this weakness can arise when new data is not as large as the old data, which leaves portions of the old data still available. Equivalent errors can occur in other situations where the length of data is variable but the associated data structure is not. If memory is not cleared after use, the information may be read by less trustworthy parties when the memory is reallocated.


This weakness can apply in hardware, such as when a device or system switches between power, sleep, or debug states during normal operation, or when execution changes to different users or privilege levels.

## Observed Examples

CVE-2019-3733: Cryptography library does not clear heap memory before release

CVE-2003-0001: Ethernet NIC drivers do not pad frames with null bytes, leading to infoleak from malformed packets.

CVE-2003-0291: router does not clear information from DHCP packets that have been previously used

CVE-2005-1406: Products do not fully clear memory buffers when less data is stored into the buffer than previous.

CVE-2005-1858: Products do not fully clear memory buffers when less data is stored into the buffer than previous.

CVE-2005-3180: Products do not fully clear memory buffers when less data is stored into the buffer than previous.

CVE-2005-3276: Product does not clear a data structure before writing to part of it, yielding information leak of previously used memory.

CVE-2002-2077: Memory not properly cleared before reuse.

## Top 25 Examples

CVE-2022-0171: A flaw was found in the Linux kernel. The existing KVM SEV API has a vulnerability that allows a non-root (host) user-level application to crash the host kernel by creating a confidential guest VM instance in AMD CPU that supports Secure Encrypted Virtualization (SEV).

CVE-2022-22779: The Keybase Clients for macOS and Windows before version 5.9.0 fails to properly remove exploded messages initiated by a user. This can occur if the receiving user switches to a non-chat feature and places the host in a sleep state before the sending user explodes the messages. This could lead to disclosure of sensitive information which was meant to be deleted from a user’s filesystem.

CVE-2022-23633: Action Pack is a framework for handling and responding to web requests. Under certain circumstances response bodies will not be closed. In the event a response is *not* notified of a `close`, `ActionDispatch::Executor` will not know to reset thread local state for the next request. This can lead to data being leaked to subsequent requests.This has been fixed in Rails 7.0.2.1, 6.1.4.5, 6.0.4.5, and 5.2.6.1. Upgrading is highly recommended, but to work around this problem a middleware described in GHSA-wh98-p28r-vrc9 can be used.

# CWE-228 Improper Handling of Syntactically Invalid Structure

## Description

The product does not handle or incorrectly handles input that is not syntactically well-formed with respect to the associated specification.

## Observed Examples

CVE-2004-0270: Anti-virus product has assert error when line length is non-numeric.

## Top 25 Examples

CVE-2022-38381: An improper handling of malformed request vulnerability [CWE-228] exists in FortiADC 5.0 all versions, 6.0.0 all versions, 6.1.0 all versions, 6.2.0 through 6.2.3, and 7.0.0 through 7.0.2. This may allow a remote attacker without privileges to bypass some Web Application Firewall (WAF) protection such as the SQL Injection and XSS filters via a malformed HTTP request.

CVE-2022-41783: tdpServer of TP-Link RE300 V1 improperly processes its input, which may allow an attacker to cause a denial-of-service (DoS) condition of the product's OneMesh function.

CVE-2022-38100: The CMS800 device fails while attempting to parse malformed network data sent by a threat actor. A threat actor with network access can remotely issue a specially formatted UDP request that will cause the entire device to crash and require a physical reboot. A UDP broadcast request could be sent that causes a mass denial-of-service attack on all CME8000 devices connected to the same network.

# CWE-229 Improper Handling of Values

## Description

The product does not properly handle when the expected number of values for parameters, fields, or arguments is not provided in input, or if those values are undefined.

# CWE-23 Relative Path Traversal

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.

## Observed Examples

CVE-2024-37032: Large language model (LLM) management tool does not validate the format of a digest value (CWE-1287) from a private, untrusted model registry, enabling relative path traversal (CWE-23), a.k.a. Probllama

CVE-2022-45918: Chain: a learning management tool debugger uses external input to locate previous session logs (CWE-73) and does not properly validate the given path (CWE-20), allowing for filesystem path traversal using "../" sequences (CWE-24)

CVE-2019-20916: Python package manager does not correctly restrict the filename specified in a Content-Disposition header, allowing arbitrary file read using path traversal sequences such as "../"

CVE-2022-24877: directory traversal in Go-based Kubernetes operator app allows accessing data from the controller's pod file system via ../ sequences in a yaml file

CVE-2020-4053: a Kubernetes package manager written in Go allows malicious plugins to inject path traversal sequences into a plugin archive ("Zip slip") to copy a file outside the intended directory

CVE-2021-21972: Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV.

CVE-2019-10743: Go-based archive library allows extraction of files to locations outside of the target folder with "../" path traversal sequences in filenames in a zip file, aka "Zip Slip"

CVE-2002-0298: Server allows remote attackers to cause a denial of service via certain HTTP GET requests containing a %2e%2e (encoded dot-dot), several "/../" sequences, or several "../" in a URI.

CVE-2002-0661: "\" not in denylist for web server, allowing path traversal attacks when the server is run in Windows and other OSes.

CVE-2002-0946: Arbitrary files may be read files via ..\ (dot dot) sequences in an HTTP request.

CVE-2002-1042: Directory traversal vulnerability in search engine for web server allows remote attackers to read arbitrary files via "..\" sequences in queries.

CVE-2002-1209: Directory traversal vulnerability in FTP server allows remote attackers to read arbitrary files via "..\" sequences in a GET request.

CVE-2002-1178: Directory traversal vulnerability in servlet allows remote attackers to execute arbitrary commands via "..\" sequences in an HTTP request.

CVE-2002-1987: Protection mechanism checks for "/.." but doesn't account for Windows-specific "\.." allowing read of arbitrary files.

CVE-2005-2142: Directory traversal vulnerability in FTP server allows remote authenticated attackers to list arbitrary directories via a "\.." sequence in an LS command.

CVE-2002-0160: The administration function in Access Control Server allows remote attackers to read HTML, Java class, and image files outside the web root via a "..\.." sequence in the URL to port 2002.

CVE-2001-0467: "\..." in web server

CVE-2001-0963: "..." in cd command in FTP server

CVE-2001-1193: "..." in cd command in FTP server

CVE-2001-1131: "..." in cd command in FTP server

CVE-2001-0480: read of arbitrary files and directories using GET or CD with "..." in Windows-based FTP server.

CVE-2002-0288: read files using "." and Unicode-encoded "/" or "\" characters in the URL.

CVE-2003-0313: Directory listing of web server using "..."

CVE-2005-1658: Triple dot

CVE-2000-0240: read files via "/........../" in URL

CVE-2000-0773: read files via "...." in web server

CVE-1999-1082: read files via "......" in web server (doubled triple dot?)

CVE-2004-2121: read files via "......" in web server (doubled triple dot?)

CVE-2001-0491: multiple attacks using "..", "...", and "...." in different commands

CVE-2001-0615: "..." or "...." in chat server

CVE-2005-2169: chain: ".../...//" bypasses protection mechanism using regexp's that remove "../" resulting in collapse into an unsafe value "../" (CWE-182) and resultant path traversal.

CVE-2005-0202: ".../....///" bypasses regexp's that remove "./" and "../"

CVE-2004-1670: Mail server allows remote attackers to create arbitrary directories via a ".." or rename arbitrary files via a "....//" in user supplied parameters.

## Top 25 Examples

CVE-2022-20719: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-32964: The AGG Software Web Server version 4.0.40.1014 and prior is vulnerable to a path traversal attack, which may allow an attacker to read arbitrary files from the file system.

CVE-2021-38399: Honeywell Experion PKS C200, C200E, C300, and ACE controllers are vulnerable to relative path traversal, which may allow an attacker access to unauthorized files and directories.

CVE-2021-41031: A relative path traversal vulnerability [CWE-23] in FortiClient for Windows versions 7.0.2 and prior, 6.4.6 and prior and 6.2.9 and below may allow a local unprivileged attacker to escalate their privileges to SYSTEM via the named pipe responsible for FortiESNAC service.

CVE-2022-1648: Pandora FMS v7.0NG.760 and below allows a relative path traversal in File Manager where a privileged user could upload a .php file outside the intended images directory which is restricted to execute the .php file. The impact could lead to a Remote Code Execution with running application privilege.

CVE-2022-1661: The affected products are vulnerable to directory traversal, which may allow an attacker to obtain arbitrary operating system files.

CVE-2022-2106: Elcomplus SmartICS v2.3.4.0 does not validate the filenames sufficiently, which enables authenticated administrator-level users to perform path traversal attacks and specify arbitrary files.

CVE-2022-2120: OFFIS DCMTK's (All versions prior to 3.6.7) service class user (SCU) is vulnerable to relative path traversal, allowing an attacker to write DICOM files into arbitrary directories under controlled names. This could allow remote code execution.

CVE-2022-23531: GuardDog is a CLI tool to identify malicious PyPI packages. Versions prior to 0.1.5 are vulnerable to Relative Path Traversal when scanning a specially-crafted local PyPI package. Running GuardDog against a specially-crafted package can allow an attacker to write an arbitrary file on the machine where GuardDog is executed due to a path traversal vulnerability when extracting the .tar.gz file of the package being scanned, which exists by design in the tarfile.TarFile.extractall function. This issue is patched in version 0.1.5.

CVE-2022-23732: A path traversal vulnerability was identified in GitHub Enterprise Server management console that allowed the bypass of CSRF protections. This could potentially lead to privilege escalation. To exploit this vulnerability, an attacker would need to target a user that was actively logged into the management console. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.5 and was fixed in versions 3.1.19, 3.2.11, 3.3.6, 3.4.1. This vulnerability was reported via the GitHub Bug Bounty program.

CVE-2022-23854:  AVEVA InTouch Access Anywhere versions 2020 R2 and older are vulnerable to a path traversal exploit that could allow an unauthenticated user with network access to read files on the system outside of the secure gateway web server. 

CVE-2022-25856: The package github.com/argoproj/argo-events/sensors/artifacts before 1.7.1 are vulnerable to Directory Traversal in the (g *GitArtifactReader).Read() API in git.go. This could allow arbitrary file reads if the GitArtifactReader is provided a pathname containing a symbolic link or an implicit directory name such as ...

CVE-2022-2712: In Eclipse GlassFish versions 5.1.0 to 6.2.5, there is a vulnerability in relative path traversal because it does not filter request path starting with './'. Successful exploitation could allow an remote unauthenticated attacker to access critical data, such as configuration files and deployed application source code.

CVE-2022-28814: Carlo Gavazzi UWP3.0 in multiple versions and CPY Car Park Server in Version 2.8.3 was discovered to be vulnerable to a relative path traversal vulnerability which enables remote attackers to read arbitrary files and gain full control of the device.

CVE-2022-29062: Multiple relative path traversal vulnerabilities [CWE-23] in Fortinet FortiSOAR before 7.2.1 allows an authenticated attacker to write to the underlying filesystem with nginx permissions via crafted HTTP requests.

CVE-2022-2922: Relative Path Traversal in GitHub repository dnnsoftware/dnn.platform prior to 9.11.0.

CVE-2022-30299: A path traversal vulnerability [CWE-23] in the API of FortiWeb 7.0.0 through 7.0.1, 6.3.0 through 6.3.19, 6.4 all versions, 6.2 all versions, 6.1 all versions, 6.0 all versions may allow an authenticated attacker to retrieve specific parts of files from the underlying file system via specially crafted web requests.

CVE-2022-30300: A relative path traversal vulnerability [CWE-23] in FortiWeb 7.0.0 through 7.0.1, 6.3.6 through 6.3.18, 6.4 all versions may allow an authenticated attacker to obtain unauthorized access to files and data via specifically crafted HTTP GET requests.

CVE-2022-30302: Multiple relative path traversal vulnerabilities [CWE-23] in FortiDeceptor management interface 1.0.0 through 3.2.x, 3.3.0 through 3.3.2, 4.0.0 through 4.0.1 may allow a remote and authenticated attacker to retrieve and delete arbitrary files from the underlying filesystem via specially crafted web requests.

CVE-2022-31582: The shaolo1/VideoServer repository through 2019-09-21 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-32199: db_convert.php in ScriptCase through 9.9.008 is vulnerable to Arbitrary File Deletion by an admin via a directory traversal sequence in the file parameter.

CVE-2022-32287: A relative path traversal vulnerability in a FileUtil class used by the PEAR management component of Apache UIMA allows an attacker to create files outside the designated target directory using carefully crafted ZIP entry names. This issue affects Apache UIMA Apache UIMA version 3.3.0 and prior versions. Note that PEAR files should never be installed into an UIMA installation from untrusted sources because PEAR archives are executable plugins that will be able to perform any actions with the same privileges as the host Java Virtual Machine.

CVE-2022-34378: Dell PowerScale OneFS, versions 9.0.0 up to and including 9.1.0.20, 9.2.1.13, 9.3.0.6, and 9.4.0.3, contain a relative path traversal vulnerability. A low privileged local attacker could potentially exploit this vulnerability, leading to denial of service.

CVE-2022-34836: Relative Path Traversal vulnerability in ABB Zenon 8.20 allows the user to access files on the Zenon system and user also can add own log messages and e.g., flood the log entries. An attacker who successfully exploit the vulnerability could access the Zenon runtime activities such as the start and stop of various activity and the last error code etc.

CVE-2022-40713: An issue was discovered in NOKIA 1350OMS R14.2. Multiple Relative Path Traversal issues exist in different specific endpoints via the file parameter, allowing a remote authenticated attacker to read files on the filesystem arbitrarily.

CVE-2022-41335: A relative path traversal vulnerability [CWE-23] in Fortinet FortiOS version 7.2.0 through 7.2.2, 7.0.0 through 7.0.8 and before 6.4.10, FortiProxy version 7.2.0 through 7.2.1, 7.0.0 through 7.0.7 and before 2.0.10, FortiSwitchManager 7.2.0 and before 7.0.0 allows an authenticated attacker to read and write files on the underlying Linux system via crafted HTTP requests.

CVE-2022-42188: In Lavalite 9.0.0, the XSRF-TOKEN cookie is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server.

CVE-2022-42476: A relative path traversal vulnerability [CWE-23] in Fortinet FortiOS version 7.2.0 through 7.2.2, 7.0.0 through 7.0.8 and before 6.4.11, FortiProxy version 7.2.0 through 7.2.2 and 7.0.0 through 7.0.8 allows privileged VDOM administrators to escalate their privileges to super admin of the box via crafted CLI requests.

CVE-2022-43753: A Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in spacewalk/Uyuni of SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Module for SUSE Manager Server 4.3, SUSE Manager Server 4.2 allows remote attackers to read files available to the user running the process, typically tomcat. This issue affects: SUSE Linux Enterprise Module for SUSE Manager Server 4.2 hub-xmlrpc-api-0.7-150300.3.9.2, inter-server-sync-0.2.4-150300.8.25.2, locale-formula-0.3-150300.3.3.2, py27-compat-salt-3000.3-150300.7.7.26.2, python-urlgrabber-3.10.2.1py2_3-150300.3.3.2, spacecmd-4.2.20-150300.4.30.2, spacewalk-backend-4.2.25-150300.4.32.4, spacewalk-client-tools-4.2.21-150300.4.27.3, spacewalk-java-4.2.43-150300.3.48.2, spacewalk-utils-4.2.18-150300.3.21.2, spacewalk-web-4.2.30-150300.3.30.3, susemanager-4.2.38-150300.3.44.3, susemanager-doc-indexes-4.2-150300.12.36.3, susemanager-docs_en-4.2-150300.12.36.2, susemanager-schema-4.2.25-150300.3.30.3, susemanager-sls versions prior to 4.2.28. SUSE Linux Enterprise Module for SUSE Manager Server 4.3 spacewalk-java versions prior to 4.3.39. SUSE Manager Server 4.2 release-notes-susemanager versions prior to 4.2.10.

CVE-2022-29464: Certain WSO2 products allow unrestricted file upload with resultant remote code execution. The attacker must use a /fileupload endpoint with a Content-Disposition directory traversal sequence to reach a directory under the web root, such as a ../../../../repository/deployment/server/webapps directory. This affects WSO2 API Manager 2.2.0 up to 4.0.0, WSO2 Identity Server 5.2.0 up to 5.11.0, WSO2 Identity Server Analytics 5.4.0, 5.4.1, 5.5.0 and 5.6.0, WSO2 Identity Server as Key Manager 5.3.0 up to 5.11.0, WSO2 Enterprise Integrator 6.2.0 up to 6.6.0, WSO2 Open Banking AM 1.4.0 up to 2.0.0 and WSO2 Open Banking KM 1.4.0, up to 2.0.0.

CVE-2022-37042: Zimbra Collaboration Suite (ZCS) 8.8.15 and 9.0 has mboximport functionality that receives a ZIP archive and extracts files from it. By bypassing authentication (i.e., not having an authtoken), an attacker can upload arbitrary files to the system, leading to directory traversal and remote code execution. NOTE: this issue exists because of an incomplete fix for CVE-2022-27925.

CVE-2021-21972: The vSphere Client (HTML5) contains a remote code execution vulnerability in a vCenter Server plugin. A malicious actor with network access to port 443 may exploit this issue to execute commands with unrestricted privileges on the underlying operating system that hosts vCenter Server. This affects VMware vCenter Server (7.x before 7.0 U1c, 6.7 before 6.7 U3l and 6.5 before 6.5 U3n) and VMware Cloud Foundation (4.x before 4.2 and 3.x before 3.10.1.2).

CVE-2021-22005: The vCenter Server contains an arbitrary file upload vulnerability in the Analytics service. A malicious actor with network access to port 443 on vCenter Server may exploit this issue to execute code on vCenter Server by uploading a specially crafted file.

CVE-2021-38163: SAP NetWeaver (Visual Composer 7.0 RT) versions - 7.30, 7.31, 7.40, 7.50, without restriction, an attacker authenticated as a non-administrative user can upload a malicious file over a network and trigger its processing, which is capable of running operating system commands with the privilege of the Java Server process. These commands can be used to read or modify any information on the server or shut the server down making it unavailable. 

CVE-2021-3856: ClassLoaderTheme and ClasspathThemeResourceProviderFactory allows reading any file available as a resource to the classloader. By sending requests for theme resources with a relative path from an external HTTP client, the client will receive the content of random files if available.

CVE-2022-30804: elitecms v1.01 is vulnerable to Delete any file via /admin/delete_image.php?file=.

CVE-2022-38258: A local file inclusion (LFI) vulnerability in D-Link DIR 819 v1.06 allows attackers to cause a Denial of Service (DoS) or access sensitive server information via manipulation of the getpage parameter in a crafted web request.

CVE-2022-22279: A post-authentication arbitrary file read vulnerability impacting end-of-life Secure Remote Access (SRA) products and older firmware versions of Secure Mobile Access (SMA) 100 series products, specifically the SRA appliances running all 8.x, 9.0.0.5-19sv and earlier versions and Secure Mobile Access (SMA) 100 series products running older firmware 9.0.0.9-26sv and earlier versions

CVE-2022-23602: Nimforum is a lightweight alternative to Discourse written in Nim. In versions prior to 2.2.0 any forum user can create a new thread/post with an include referencing a file local to the host operating system. Nimforum will render the file if able. This can also be done silently by using NimForum's post "preview" endpoint. Even if NimForum is running as a non-critical user, the forum.json secrets can be stolen. Version 2.2.0 of NimForum includes patches for this vulnerability. Users are advised to upgrade as soon as is possible. There are no known workarounds for this issue.

CVE-2022-38638: Casdoor v1.97.3 was discovered to contain an arbitrary file write vulnerability via the fullFilePath parameter at /api/upload-resource.

CVE-2022-42977: The Netic User Export add-on before 1.3.5 for Atlassian Confluence has the functionality to generate a list of users in the application, and export it. During export, the HTTP request has a fileName parameter that accepts any file on the system (e.g., an SSH private key) to be downloaded.

# CWE-230 Improper Handling of Missing Values

## Description

The product does not handle or incorrectly handles when a parameter, field, or argument name is specified, but the associated value is missing, i.e. it is empty, blank, or null.

## Observed Examples

CVE-2002-0422: Blank Host header triggers resultant infoleak.

CVE-2000-1006: Blank "charset" attribute in MIME header triggers crash.

CVE-2004-1504: Blank parameter causes external error infoleak.

CVE-2005-2053: Blank parameter causes external error infoleak.

## Top 25 Examples

CVE-2022-22562: Dell PowerScale OneFS, versions 8.2.0-9.3.0, contain a improper handling of missing values exploit. An unauthenticated network attacker could potentially exploit this denial-of-service vulnerability.

CVE-2021-40866: Certain NETGEAR smart switches are affected by a remote admin password change by an unauthenticated attacker via the (disabled by default) /sqfs/bin/sccd daemon, which fails to check authentication when the authentication TLV is missing from a received NSDP packet. This affects GC108P before 1.0.8.2, GC108PP before 1.0.8.2, GS108Tv3 before 7.0.7.2, GS110TPP before 7.0.7.2, GS110TPv3 before 7.0.7.2, GS110TUP before 1.0.5.3, GS308T before 1.0.3.2, GS310TP before 1.0.3.2, GS710TUP before 1.0.5.3, GS716TP before 1.0.4.2, GS716TPP before 1.0.4.2, GS724TPP before 2.0.6.3, GS724TPv2 before 2.0.6.3, GS728TPPv2 before 6.0.8.2, GS728TPv2 before 6.0.8.2, GS750E before 1.0.1.10, GS752TPP before 6.0.8.2, GS752TPv2 before 6.0.8.2, MS510TXM before 1.0.4.2, and MS510TXUP before 1.0.4.2.

CVE-2022-24882: FreeRDP is a free implementation of the Remote Desktop Protocol (RDP). In versions prior to 2.7.0, NT LAN Manager (NTLM) authentication does not properly abort when someone provides and empty password value. This issue affects FreeRDP based RDP Server implementations. RDP clients are not affected. The vulnerability is patched in FreeRDP 2.7.0. There are currently no known workarounds.

CVE-2022-25226: ThinVNC version 1.0b1 allows an unauthenticated user to bypass the authentication process via 'http://thin-vnc:8080/cmd?cmd=connect' by obtaining a valid SID without any kind of authentication. It is possible to achieve code execution on the server by sending keyboard or mouse events to the server.

CVE-2022-47003: A vulnerability in the Remember Me function of Mura CMS before v10.0.580 allows attackers to bypass authentication via a crafted web request.

# CWE-231 Improper Handling of Extra Values

## Description

The product does not handle or incorrectly handles when more values are provided than expected.

# CWE-232 Improper Handling of Undefined Values

## Description

The product does not handle or incorrectly handles when a value is not defined or supported for the associated parameter, field, or argument name.

## Observed Examples

CVE-2000-1003: Client crash when server returns unknown driver type.

# CWE-233 Improper Handling of Parameters

## Description

The product does not properly handle when the expected number of parameters, fields, or arguments is not provided in input, or if those parameters are undefined.

## Top 25 Examples

CVE-2022-22792: MobiSoft - MobiPlus User Take Over and Improper Handling of url Parameters Attacker can navigate to specific url which will expose all the users and password in clear text. http://IP/MobiPlusWeb/Handlers/MainHandler.ashx?MethodName=GridData&amp;GridName=Users

CVE-2021-45477: Improper Handling of Parameters vulnerability in Bordam Information Technologies Library Automation System allows Collect Data as Provided by Users.This issue affects Library Automation System: before 19.2. 

CVE-2021-45478: Improper Handling of Parameters vulnerability in Bordam Information Technologies Library Automation System allows Collect Data as Provided by Users.This issue affects Library Automation System: before 19.2. 

CVE-2021-4105: Improper Handling of Parameters vulnerability in BG-TEK COSLAT Firewall allows Remote Code Inclusion.This issue affects COSLAT Firewall: from 5.24.0.R.20180630 before 5.24.0.R.20210727. 

# CWE-234 Failure to Handle Missing Parameter

## Description

If too few arguments are sent to a function, the function will still pop the expected number of arguments from the stack. Potentially, a variable number of arguments could be exhausted in a function as well.

## Observed Examples

CVE-2004-0276: Server earlier allows remote attackers to cause a denial of service (crash) via an HTTP request with a sequence of "%" characters and a missing Host field.

CVE-2002-1488: Chat client allows remote malicious IRC servers to cause a denial of service (crash) via a PART message with (1) a missing channel or (2) a channel that the user is not in.

CVE-2002-1169: Proxy allows remote attackers to cause a denial of service (crash) via an HTTP request to helpout.exe with a missing HTTP version numbers.

CVE-2000-0521: Web server allows disclosure of CGI source code via an HTTP request without the version number.

CVE-2001-0590: Application server allows a remote attacker to read the source code to arbitrary 'jsp' files via a malformed URL request which does not end with an HTTP protocol specification.

CVE-2003-0239: Chat software allows remote attackers to cause a denial of service via malformed GIF89a headers that do not contain a GCT (Global Color Table) or an LCT (Local Color Table) after an Image Descriptor.

CVE-2002-1023: Server allows remote attackers to cause a denial of service (crash) via an HTTP GET request without a URI.

CVE-2002-1236: CGI crashes when called without any arguments.

CVE-2003-0422: CGI crashes when called without any arguments.

CVE-2002-1531: Crash in HTTP request without a Content-Length field.

CVE-2002-1077: Crash in HTTP request without a Content-Length field.

CVE-2002-1358: Empty elements/strings in protocol test suite affect many SSH2 servers/clients.

CVE-2003-0477: FTP server crashes in PORT command without an argument.

CVE-2002-0107: Resultant infoleak in web server via GET requests without HTTP/1.0 version string.

CVE-2002-0596: GET request with empty parameter leads to error message infoleak (path disclosure).

# CWE-235 Improper Handling of Extra Parameters

## Description

The product does not handle or incorrectly handles when the number of parameters, fields, or arguments with the same name exceeds the expected amount.

## Observed Examples

CVE-2003-1014: MIE. multiple gateway/security products allow restriction bypass using multiple MIME fields with the same name, which are interpreted differently by clients.

## Top 25 Examples

CVE-2022-31683: Concourse (7.x.y prior to 7.8.3 and 6.x.y prior to 6.7.9) contains an authorization bypass issue. A Concourse user can send a request with body including :team_name=team2 to bypass team scope check to gain access to certain resources belong to any other team.

# CWE-236 Improper Handling of Undefined Parameters

## Description

The product does not handle or incorrectly handles when a particular parameter, field, or argument name is not defined or supported by the product.

## Observed Examples

CVE-2002-1488: Crash in IRC client via PART message from a channel the user is not in.

CVE-2001-0650: Router crash or bad route modification using BGP updates with invalid transitive attribute.

# CWE-237 Improper Handling of Structural Elements

## Description

The product does not handle or incorrectly handles inputs that are related to complex structures.

# CWE-238 Improper Handling of Incomplete Structural Elements

## Description

The product does not handle or incorrectly handles when a particular structural element is not completely specified.

# CWE-239 Failure to Handle Incomplete Element

## Description

The product does not properly handle when a particular element is not completely specified.

## Observed Examples

CVE-2002-1532: HTTP GET without \r\n\r\n CRLF sequences causes product to wait indefinitely and prevents other users from accessing it.

CVE-2003-0195: Partial request is not timed out.

CVE-2005-2526: MFV. CPU exhaustion in printer via partial printing request then early termination of connection.

CVE-2002-1906: CPU consumption by sending incomplete HTTP requests and leaving the connections open.

# CWE-24 Path Traversal: '../filedir'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize "../" sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The "../" manipulation is the canonical manipulation for operating systems that use "/" as directory separators, such as UNIX- and Linux-based systems. In some cases, it is useful for bypassing protection schemes in environments for which "/" is supported but not the primary separator, such as Windows, which uses "\" but can also accept "/".

## Observed Examples

CVE-2022-45918: Chain: a learning management tool debugger uses external input to locate previous session logs (CWE-73) and does not properly validate the given path (CWE-20), allowing for filesystem path traversal using "../" sequences (CWE-24)

## Top 25 Examples

CVE-2022-47945: ThinkPHP Framework before 6.0.14 allows local file inclusion via the lang parameter when the language pack feature is enabled (lang_switch_on=true). An unauthenticated and remote attacker can exploit this to execute arbitrary operating system commands, as demonstrated by including pearcmd.php.

CVE-2022-2945: The WordPress Infinite Scroll – Ajax Load More plugin for WordPress is vulnerable to Directory Traversal in versions up to, and including, 5.5.3 via the 'type' parameter found in the alm_get_layout() function. This makes it possible for authenticated attackers, with administrative permissions, to read the contents of arbitrary files on the server, which can contain sensitive information.

CVE-2022-36065: GrowthBook is an open-source platform for feature flagging and A/B testing. With some self-hosted configurations in versions prior to 2022-08-29, attackers can register new accounts and upload files to arbitrary directories within the container. If the attacker uploads a Python script to the right location, they can execute arbitrary code within the container. To be affected, ALL of the following must be true: Self-hosted deployment (GrowthBook Cloud is unaffected); using local file uploads (as opposed to S3 or Google Cloud Storage); NODE_ENV set to a non-production value and JWT_SECRET set to an easily guessable string like `dev`. This issue is patched in commit 1a5edff8786d141161bf880c2fd9ccbe2850a264 (2022-08-29). As a workaround, set `JWT_SECRET` environment variable to a long random string. This will stop arbitrary file uploads, but the only way to stop attackers from registering accounts is by updating to the latest build.

CVE-2022-3060: Improper control of a resource identifier in Error Tracking in GitLab CE/EE affecting all versions from 12.7 allows an authenticated attacker to generate content which could cause a victim to make unintended arbitrary requests

CVE-2022-32409: A local file inclusion (LFI) vulnerability in the component codemirror.php of Portal do Software Publico Brasileiro i3geo v7.0.5 allows attackers to execute arbitrary PHP code via a crafted HTTP request.

# CWE-240 Improper Handling of Inconsistent Structural Elements

## Description

The product does not handle or incorrectly handles when two or more structural elements should be consistent, but are not.

## Observed Examples

CVE-2014-0160: Chain: "Heartbleed" bug receives an inconsistent length parameter (CWE-130) enabling an out-of-bounds read (CWE-126), returning memory that could include private cryptographic keys and other sensitive data.

CVE-2009-2299: Web application firewall consumes excessive memory when an HTTP request contains a large Content-Length value but no POST data.

# CWE-241 Improper Handling of Unexpected Data Type

## Description

The product does not handle or incorrectly handles when a particular element is not the expected type, e.g. it expects a digit (0-9) but is provided with a letter (A-Z).

## Observed Examples

CVE-1999-1156: FTP server crash via PORT command with non-numeric character.

CVE-2004-0270: Anti-virus product has assert error when line length is non-numeric.

# CWE-242 Use of Inherently Dangerous Function

## Description

The product calls a function that can never be guaranteed to work safely.

Certain functions behave in dangerous ways regardless of how they are used. Functions in this category were often implemented without taking security concerns into account. The gets() function is unsafe because it does not perform bounds checking on the size of its input. An attacker can easily send arbitrarily-sized input to gets() and overflow the destination buffer. Similarly, the >> operator is unsafe to use when reading into a statically-allocated character array because it does not perform bounds checking on the size of its input. An attacker can easily send arbitrarily-sized input to the >> operator and overflow the destination buffer.

## Observed Examples

CVE-2007-4004: FTP client uses inherently insecure gets() function and is setuid root on some systems, allowing buffer overflow

# CWE-243 Creation of chroot Jail Without Changing Working Directory

## Description

The product uses the chroot() system call to create a jail, but does not change the working directory afterward. This does not prevent access to files outside of the jail.

Improper use of chroot() may allow attackers to escape from the chroot jail. The chroot() function call does not change the process's current working directory, so relative paths may still refer to file system resources outside of the chroot jail after chroot() has been called.

The chroot() system call allows a process to change its perception of the root directory of the file system. After properly invoking chroot(), a process cannot access any files outside the directory tree defined by the new root directory. Such an environment is called a chroot jail and is commonly used to prevent the possibility that a processes could be subverted and used to access unauthorized files. For instance, many FTP servers run in chroot jails to prevent an attacker who discovers a new vulnerability in the server from being able to download the password file or other sensitive files on the system.

# CWE-244 Improper Clearing of Heap Memory Before Release ('Heap Inspection')

## Description

Using realloc() to resize buffers that store sensitive information can leave the sensitive information exposed to attack, because it is not removed from memory.

When sensitive data such as a password or an encryption key is not removed from memory, it could be exposed to an attacker using a "heap inspection" attack that reads the sensitive data using memory dumps or other methods. The realloc() function is commonly used to increase the size of a block of allocated memory. This operation often requires copying the contents of the old memory block into a new and larger block. This operation leaves the contents of the original block intact but inaccessible to the program, preventing the program from being able to scrub sensitive data from memory. If an attacker can later examine the contents of a memory dump, the sensitive data could be exposed.

## Observed Examples

CVE-2019-3733: Cryptography library does not clear heap memory before release

# CWE-245 J2EE Bad Practices: Direct Management of Connections

## Description

The J2EE application directly manages connections, instead of using the container's connection management facilities.

The J2EE standard forbids the direct management of connections. It requires that applications use the container's resource management facilities to obtain connections to resources. Every major web application container provides pooled database connection management as part of its resource management framework. Duplicating this functionality in an application is difficult and error prone, which is part of the reason it is forbidden under the J2EE standard.

# CWE-246 J2EE Bad Practices: Direct Use of Sockets

## Description

The J2EE application directly uses sockets instead of using framework method calls.

The J2EE standard permits the use of sockets only for the purpose of communication with legacy systems when no higher-level protocol is available. Authoring your own communication protocol requires wrestling with difficult security issues.


Without significant scrutiny by a security expert, chances are good that a custom communication protocol will suffer from security problems. Many of the same issues apply to a custom implementation of a standard protocol. While there are usually more resources available that address security concerns related to implementing a standard protocol, these resources are also available to attackers.

# CWE-248 Uncaught Exception

## Description

An exception is thrown from a function, but it is not caught.

When an exception is not caught, it may cause the program to crash or expose sensitive information.

## Observed Examples

CVE-2023-41151: SDK for OPC Unified Architecture (OPC UA) server has uncaught exception when a socket is blocked for writing but the server tries to send an error

CVE-2023-21087: Java code in a smartphone OS can encounter a "boot loop" due to an uncaught exception

## Top 25 Examples

CVE-2021-0478: In updateDrawable of StatusBarIconView.java, there is a possible permission bypass due to an uncaught exception. This could lead to local escalation of privilege by running foreground services without notifying the user, with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-8.1 Android-9Android ID: A-169255797

CVE-2021-22406: There is an Uncaught Exception vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability will cause the app to exit unexpectedly.

CVE-2021-25971: In Camaleon CMS, versions 2.0.1 to 2.6.0 are vulnerable to an Uncaught Exception. The app's media upload feature crashes permanently when an attacker with a low privileged access uploads a specially crafted .svg file

CVE-2021-37078: There is a Uncaught Exception vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may lead to remote Denial of Service.

CVE-2022-20253: In Bluetooth, there is a possible cleanup failure due to an uncaught exception. This could lead to remote denial of service in Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-224545125

CVE-2022-20414: In setImpl of AlarmManagerService.java, there is a possible way to put a device into a boot loop due to an uncaught exception. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-234441463

CVE-2022-20500: In loadFromXml of ShortcutPackage.java, there is a possible crash on boot due to an uncaught exception. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-246540168

CVE-2022-21218: Uncaught exception in the Intel(R) Trace Analyzer and Collector before version 2021.5 may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-21676: Engine.IO is the implementation of transport-based cross-browser/cross-device bi-directional communication layer for Socket.IO. A specially crafted HTTP request can trigger an uncaught exception on the Engine.IO server, thus killing the Node.js process. This impacts all the users of the `engine.io` package starting from version `4.0.0`, including those who uses depending packages like `socket.io`. Versions prior to `4.0.0` are not impacted. A fix has been released for each major branch, namely `4.1.2` for the `4.x.x` branch, `5.2.1` for the `5.x.x` branch, and `6.1.1` for the `6.x.x` branch. There is no known workaround except upgrading to a safe version.

CVE-2022-25917: Uncaught exception in the firmware for some Intel(R) Server Board M50CYP Family before version R01.01.0005 may allow a privileged user to potentially enable a denial of service via local access.

CVE-2022-29493: Uncaught exception in webserver for the Integrated BMC in some Intel(R) platforms before versions 2.86, 2.09 and 2.78 may allow a privileged user to potentially enable denial of service via network access.

CVE-2022-34849: Uncaught exception in the Intel(R) Iris(R) Xe MAX drivers for Windows before version 100.0.5.1436(v2) may allow a privileged user to potentially enable denial of service via local access.

CVE-2022-36287: Uncaught exception in the FCS Server software maintained by Intel before version 1.1.79.3 may allow a privileged user to potentially enable denial of service via physical access.

CVE-2022-47933: Brave Browser before 1.42.51 allowed a remote attacker to cause a denial of service via a crafted HTML file that references the IPFS scheme. This vulnerability is caused by an uncaught exception in the function ipfs::OnBeforeURLRequest_IPFSRedirectWork() in ipfs_redirect_network_delegate_helper.cc.

# CWE-25 Path Traversal: '/../filedir'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize "/../" sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


Sometimes a program checks for "../" at the beginning of the input, so a "/../" can bypass that check.

## Observed Examples

CVE-2022-20775: A cloud management tool allows attackers to bypass the restricted shell using path traversal sequences like "/../" in the USER environment variable.

## Top 25 Examples

CVE-2022-20775: Multiple vulnerabilities in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to gain elevated privileges. These vulnerabilities are due to improper access controls on commands within the application CLI. An attacker could exploit these vulnerabilities by running a malicious command on the application CLI. A successful exploit could allow the attacker to execute arbitrary commands as the root user.

CVE-2022-20818: Multiple vulnerabilities in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to gain elevated privileges. These vulnerabilities are due to improper access controls on commands within the application CLI. An attacker could exploit these vulnerabilities by running a malicious command on the application CLI. A successful exploit could allow the attacker to execute arbitrary commands as the root user.

CVE-2022-29596: MicroStrategy Enterprise Manager 2022 allows authentication bypass by triggering a login failure and then entering the Uid=/../../../../../../../../../../../windows/win.ini%00.jpg&Pwd=_any_password_&ConnMode=1&3054=Login substring for directory traversal.

CVE-2021-40870: An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.

# CWE-250 Execution with Unnecessary Privileges

## Description

The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.

New weaknesses can be exposed because running with extra privileges, such as root or Administrator, can disable the normal security checks being performed by the operating system or surrounding environment. Other pre-existing weaknesses can turn into security vulnerabilities if they occur while operating at raised privileges.


Privilege management functions can behave in some less-than-obvious ways, and they have different quirks on different platforms. These inconsistencies are particularly pronounced if you are transitioning from one non-root user to another. Signal handlers and spawned processes run at the privilege of the owning process, so if a process is running as root when a signal fires or a sub-process is executed, the signal handler or sub-process will operate with root privileges.

## Observed Examples

CVE-2007-4217: FTP client program on a certain OS runs with setuid privileges and has a buffer overflow. Most clients do not need extra privileges, so an overflow is not a vulnerability for those clients.

CVE-2008-1877: Program runs with privileges and calls another program with the same privileges, which allows read of arbitrary files.

CVE-2007-5159: OS incorrectly installs a program with setuid privileges, allowing users to gain privileges.

CVE-2008-4638: Composite: application running with high privileges (CWE-250) allows user to specify a restricted file to process, which generates a parsing error that leaks the contents of the file (CWE-209).

CVE-2008-0162: Program does not drop privileges before calling another program, allowing code execution.

CVE-2008-0368: setuid root program allows creation of arbitrary files through command line argument.

CVE-2007-3931: Installation script installs some programs as setuid when they shouldn't be.

CVE-2020-3812: mail program runs as root but does not drop its privileges before attempting to access a file. Attacker can use a symlink from their home directory to a directory only readable by root, then determine whether the file exists based on the response.

CVE-2003-0908: Product launches Help functionality while running with raised privileges, allowing command execution using Windows message to access "open file" dialog.

## Top 25 Examples

CVE-2022-20701: Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-37167: An insecure permissions issue was discovered in HMI3 Control Panel in Swisslog Healthcare Nexus Panel operated by released versions of software before Nexus Software 7.2.5.7. A user logged in using the default credentials can gain root access to the device, which provides permissions for all of the functionality of the device.

CVE-2022-26113: An execution with unnecessary privileges vulnerability [CWE-250] in FortiClientWindows 7.0.0 through 7.0.3, 6.4.0 through 6.4.7, 6.2.0 through 6.2.9, 6.0.0 through 6.0.10 may allow a local attacker to perform an arbitrary file write on the system.

CVE-2022-22239: An Execution with Unnecessary Privileges vulnerability in Management Daemon (mgd) of Juniper Networks Junos OS Evolved allows a locally authenticated attacker with low privileges to escalate their privileges on the device and potentially remote systems. This vulnerability allows a locally authenticated attacker with access to the ssh operational command to escalate their privileges on the system to root, or if there is user interaction on the local device to potentially escalate privileges on a remote system to root. This issue affects Juniper Networks Junos OS Evolved: All versions prior to 20.4R3-S5-EVO; 21.1-EVO versions prior to 21.1R3-EVO; 21.2-EVO versions prior to 21.2R2-S1-EVO, 21.2R3-EVO; 21.3-EVO versions prior to 21.3R2-EVO. This issue does not affect Juniper Networks Junos OS.

CVE-2022-1808: Execution with Unnecessary Privileges in GitHub repository polonel/trudesk prior to 1.2.3.

CVE-2022-25372: Pritunl Client through 1.2.3019.52 on Windows allows local privilege escalation, related to an ACL entry for CREATOR OWNER in platform_windows.go.

CVE-2022-30526: A privilege escalation vulnerability was identified in the CLI command of Zyxel USG FLEX 100(W) firmware versions 4.50 through 5.30, USG FLEX 200 firmware versions 4.50 through 5.30, USG FLEX 500 firmware versions 4.50 through 5.30, USG FLEX 700 firmware versions 4.50 through 5.30, USG FLEX 50(W) firmware versions 4.16 through 5.30, USG20(W)-VPN firmware versions 4.16 through 5.30, ATP series firmware versions 4.32 through 5.30, VPN series firmware versions 4.30 through 5.30, USG/ZyWALL series firmware versions 4.09 through 4.72, which could allow a local attacker to execute some OS commands with root privileges in some directories on a vulnerable device.

CVE-2022-30695: Local privilege escalation due to excessive permissions assigned to child processes. The following products are affected: Acronis Snap Deploy (Windows) before build 3640

CVE-2022-32535: The Bosch Ethernet switch PRA-ES8P2S with software version 1.01.05 runs its web server with root privilege. In combination with CVE-2022-23534 this could give an attacker root access to the switch.

CVE-2022-34384:  Dell SupportAssist Client Consumer (version 3.11.1 and prior), SupportAssist Client Commercial (version 3.2 and prior), Dell Command | Update, Dell Update, and Alienware Update versions before 4.5 contain a Local Privilege Escalation Vulnerability in the Advanced Driver Restore component. A local malicious user may potentially exploit this vulnerability, leading to privilege escalation. 

CVE-2022-3569: Due to an issue with incorrect sudo permissions, Zimbra Collaboration Suite (ZCS) suffers from a local privilege escalation issue in versions 9.0.0 and prior, where the 'zimbra' user can effectively coerce postfix into running arbitrary commands as 'root'.

CVE-2022-41290: IBM AIX 7.1, 7.2, 7.3, and VIOS 3.1 could allow a non-privileged local user to exploit a vulnerability in the rm_rlcache_file command to obtain root privileges. IBM X-Force ID: 236690.

CVE-2022-29587: Konica Minolta bizhub MFP devices before 2022-04-14 have an internal Chromium browser that executes with root (aka superuser) access privileges.

CVE-2022-34006: An issue was discovered in TitanFTP (aka Titan FTP) NextGen before 1.2.1050. When installing, Microsoft SQL Express 2019 installs by default with an SQL instance running as SYSTEM with BUILTIN\\Users as sysadmin, thus enabling unprivileged Windows users to execute commands locally as NT AUTHORITY\\SYSTEM, aka NX-I674 (sub-issue 2). NOTE: as of 2022-06-21, the 1.2.1050 release corrects this vulnerability in a new installation, but not in an upgrade installation.

CVE-2022-38065: A privilege escalation vulnerability exists in the oslo.privsep functionality of OpenStack git master 05194e7618 and prior. Overly permissive functionality within tools leveraging this library within a container can lead increased privileges.

CVE-2022-1517: LRM utilizes elevated privileges. An unauthenticated malicious actor can upload and execute code remotely at the operating system level, which can allow an attacker to change settings, configurations, software, or access sensitive data on the affected produc. An attacker could also exploit this vulnerability to access APIs not intended for general use and interact through the network.

CVE-2021-3020: An issue was discovered in ClusterLabs Hawk (aka HA Web Konsole) through 2.3.0-15. It ships the binary hawk_invoke (built from tools/hawk_invoke.c), intended to be used as a setuid program. This allows the hacluster user to invoke certain commands as root (with an attempt to limit this to safe combinations). This user is able to execute an interactive "shell" that isn't limited to the commands specified in hawk_invoke, allowing escalation to root.

# CWE-252 Unchecked Return Value

## Description

The product does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions.

Two common programmer assumptions are "this function call can never fail" and "it doesn't matter if this function call fails". If an attacker can force the function to fail or otherwise return a value that is not expected, then the subsequent program logic could lead to a vulnerability, because the product is not in a state that the programmer assumes. For example, if the program calls a function to drop privileges but does not check the return code to ensure that privileges were successfully dropped, then the program will continue to operate with the higher privileges.

Many functions will return some value about the success of their actions. This will alert the program whether or not to handle any errors caused by that function.

## Observed Examples

CVE-2020-17533: Chain: unchecked return value (CWE-252) of some functions for policy enforcement leads to authorization bypass (CWE-862)

CVE-2020-6078: Chain: The return value of a function returning a pointer is not checked for success (CWE-252) resulting in the later use of an uninitialized variable (CWE-456) and a null pointer dereference (CWE-476)

CVE-2019-15900: Chain: sscanf() call is used to check if a username and group exists, but the return value of sscanf() call is not checked (CWE-252), causing an uninitialized variable to be checked (CWE-457), returning success to allow authorization bypass for executing a privileged (CWE-863).

CVE-2007-3798: Unchecked return value leads to resultant integer overflow and code execution.

CVE-2006-4447: Program does not check return value when invoking functions to drop privileges, which could leave users with higher privileges than expected by forcing those functions to fail.

CVE-2006-2916: Program does not check return value when invoking functions to drop privileges, which could leave users with higher privileges than expected by forcing those functions to fail.

CVE-2008-5183: chain: unchecked return value can lead to NULL dereference

CVE-2010-0211: chain: unchecked return value (CWE-252) leads to free of invalid, uninitialized pointer (CWE-824).

CVE-2017-6964: Linux-based device mapper encryption program does not check the return value of setuid and setgid allowing attackers to execute code with unintended privileges.

CVE-2002-1372: Chain: Return values of file/socket operations are not checked (CWE-252), allowing resultant consumption of file descriptors (CWE-772).

## Top 25 Examples

CVE-2021-32845: HyperKit is a toolkit for embedding hypervisor capabilities in an application. In versions 0.20210107 and prior of HyperKit, the implementation of `qnotify` at `pci_vtrnd_notify` fails to check the return value of `vq_getchain`. This leads to `struct iovec iov;` being uninitialized and used to read memory in `len = (int) read(sc->vrsc_fd, iov.iov_base, iov.iov_len);` when an attacker is able to make `vq_getchain` fail. This issue may lead to a guest crashing the host causing a denial of service and, under certain circumstance, memory corruption. This issue is fixed in commit 41272a980197917df8e58ff90642d14dec8fe948.

CVE-2021-40401: A use-after-free vulnerability exists in the RS-274X aperture definition tokenization functionality of Gerbv 2.7.0 and dev (commit b5f1eacd) and Gerbv forked 2.7.1. A specially-crafted gerber file can lead to code execution. An attacker can provide a malicious file to trigger this vulnerability.

CVE-2022-25718: Cryptographic issue in WLAN due to improper check on return value while authentication handshake in Snapdragon Auto, Snapdragon Connectivity, Snapdragon Consumer Electronics Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon IoT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables, Snapdragon Wired Infrastructure and Networking

CVE-2021-34405: NVIDIA Linux distributions contain a vulnerability in TrustZone’s TEE_Malloc function, where an unchecked return value causing a null pointer dereference may lead to denial of service.

CVE-2022-0907: Unchecked Return Value to NULL Pointer Dereference in tiffcrop in libtiff 4.3.0 allows attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit f2b656e2.

CVE-2022-22231: An Unchecked Return Value to NULL Pointer Dereference vulnerability in Packet Forwarding Engine (PFE) of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause a Denial of Service (DoS). On SRX Series if Unified Threat Management (UTM) Enhanced Content Filtering (CF) and AntiVirus (AV) are enabled together and the system processes specific valid transit traffic the Packet Forwarding Engine (PFE) will crash and restart. This issue affects Juniper Networks Junos OS 21.4 versions prior to 21.4R1-S2, 21.4R2 on SRX Series. This issue does not affect Juniper Networks Junos OS versions prior to 21.4R1.

CVE-2022-22233: An Unchecked Return Value to NULL Pointer Dereference vulnerability in Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows a locally authenticated attacker with low privileges to cause a Denial of Service (DoS). In Segment Routing (SR) to Label Distribution Protocol (LDP) interworking scenario, configured with Segment Routing Mapping Server (SRMS) at any node, when an Area Border Router (ABR) leaks the SRMS entries having "S" flag set from IS-IS Level 2 to Level 1, an rpd core might be observed when a specific low privileged CLI command is issued. This issue affects: Juniper Networks Junos OS 21.4 versions prior to 21.4R1-S2, 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R2. Juniper Networks Junos OS Evolved 21.4-EVO versions prior to 21.4R1-S2-EVO, 21.4R2-S1-EVO, 21.4R3-EVO; 22.1-EVO versions prior to 22.1R2-EVO. This issue does not affect: Juniper Networks Junos OS versions prior to 21.4R1. Juniper Networks Junos OS Evolved versions prior to 21.4R1-EVO.

CVE-2022-23626: m1k1o/blog is a lightweight self-hosted facebook-styled PHP blog. Errors from functions `imagecreatefrom*` and `image*` have not been checked properly. Although PHP issued warnings and the upload function returned `false`, the original file (that could contain a malicious payload) was kept on the disk. Users are advised to upgrade as soon as possible. There are no known workarounds for this issue.

CVE-2022-3807: A vulnerability was found in Axiomatic Bento4. It has been rated as problematic. Affected by this issue is some unknown functionality of the component Incomplete Fix CVE-2019-13238. The manipulation leads to resource consumption. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-212660.

# CWE-253 Incorrect Check of Function Return Value

## Description

The product incorrectly checks a return value from a function, which prevents it from detecting errors or exceptional conditions.

Important and common functions will return some value about the success of its actions. This will alert the program whether or not to handle any errors caused by that function.

## Observed Examples

CVE-2023-49286: Chain: function in web caching proxy does not correctly check a return value (CWE-253) leading to a reachable assertion (CWE-617)

## Top 25 Examples

CVE-2022-32590: In wlan, there is a possible use after free due to an incorrect status check. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07299425; Issue ID: ALPS07299425.

# CWE-256 Plaintext Storage of a Password

## Description

Storing a password in plaintext may result in a system compromise.

Password management issues occur when a password is stored in plaintext in an application's properties, configuration file, or memory. Storing a plaintext password in a configuration file allows anyone who can read the file access to the password-protected resource. In some contexts, even storage of a plaintext password in memory is considered a security risk if the password is not cleared immediately after it is used.

## Observed Examples

CVE-2022-30275: Remote Terminal Unit (RTU) uses a driver that relies on a password stored in plaintext.

## Top 25 Examples

CVE-2022-31085: LDAP Account Manager (LAM) is a webfrontend for managing entries (e.g. users, groups, DHCP settings) stored in an LDAP directory. In versions prior to 8.0 the session files include the LDAP user name and password in clear text if the PHP OpenSSL extension is not installed or encryption is disabled by configuration. This issue has been fixed in version 8.0. Users unable to upgrade should install the PHP OpenSSL extension and make sure session encryption is enabled in LAM main configuration.

CVE-2021-28498: In Arista's MOS (Metamako Operating System) software which is supported on the 7130 product line, user enable passwords set in clear text could result in unprivileged users getting complete access to the systems. This issue affects: Arista Metamako Operating System MOS-0.13 and post releases in the MOS-0.1x train MOS-0.26.6 and prior releases in the MOS-0.2x train MOS-0.31.1 and prior releases in the MOS-0.3x train

CVE-2021-42913: The SyncThru Web Service on Samsung SCX-6x55X printers allows an attacker to gain access to a list of SMB users and cleartext passwords by reading the HTML source code. Authentication is not required.

CVE-2022-28167: Brocade SANnav before Brocade SANvav v. 2.2.0.2 and Brocade SANanv v.2.1.1.8 logs the Brocade Fabric OS switch password in plain text in asyncjobscheduler-manager.log

CVE-2022-39816: In NOKIA 1350 OMS R14.2, Insufficiently Protected Credentials (cleartext administrator password) occur in the edit configuration page. Exploitation requires an authenticated attacker.

CVE-2022-41575: A credential-exposure vulnerability in the support-bundle mechanism in Gradle Enterprise 2022.3 through 2022.3.3 allows remote attackers to access a subset of application data (e.g., cleartext credentials). This is fixed in 2022.3.3.

CVE-2022-41933: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. When the `reset a forgotten password` feature of XWiki was used, the password was then stored in plain text in database. This only concerns XWiki 13.1RC1 and newer versions. Note that it only concerns the reset password feature available from the "Forgot your password" link in the login view: the features allowing a user to change their password, or for an admin to change a user password are not impacted. This vulnerability is particularly dangerous in combination with other vulnerabilities allowing to perform data leak of personal data from users, such as GHSA-599v-w48h-rjrm. Note that this vulnerability only concerns the users of the main wiki: in case of farms, the users registered on subwiki are not impacted thanks to a bug we discovered when investigating this. The problem has been patched in version 14.6RC1, 14.4.3 and 13.10.8. The patch involves a migration of the impacted users as well as the history of the page, to ensure no password remains in plain text in the database. This migration also involves to inform the users about the possible disclosure of their passwords: by default, two emails are automatically sent to the impacted users. A first email to inform about the possibility that their password have been leaked, and a second email using the reset password feature to ask them to set a new password. It's also possible for administrators to set some properties for the migration: it's possible to decide if the user password should be reset (default) or if the passwords should be kept but only hashed. Note that in the first option, the users won't be able to login anymore until they set a new password if they were impacted. Note that in both options, mails will be sent to users to inform them and encourage them to change their passwords.

CVE-2022-4312:  A cleartext storage of sensitive information vulnerability exists in PcVue versions 8.10 through 15.2.3. This could allow an unauthorized user with access the email and short messaging service (SMS) accounts configuration files to discover the associated simple mail transfer protocol (SMTP) account credentials and the SIM card PIN code. Successful exploitation of this vulnerability could allow an unauthorized user access to the underlying email account and SIM card. 

CVE-2022-1794: The CODESYS OPC DA Server prior V3.5.18.20 stores PLC passwords as plain text in its configuration file so that it is visible to all authorized Microsoft Windows users of the system.

CVE-2022-22458:  IBM Security Verify Governance, Identity Manager 10.0.1 stores user credentials in plain clear text which can be read by a remote authenticated user. IBM X-Force ID: 225009. 

CVE-2022-23114: Jenkins Publish Over SSH Plugin 1.22 and earlier stores password unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2022-27206: Jenkins GitLab Authentication Plugin 1.13 and earlier stores the GitLab client secret unencrypted in the global config.xml file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2022-27216: Jenkins dbCharts Plugin 0.5.2 and earlier stores JDBC connection passwords unencrypted in its global configuration file on the Jenkins controller where they can be viewed by users with access to the Jenkins controller file system.

CVE-2022-27217: Jenkins Vmware vRealize CodeStream Plugin 1.2 and earlier stores passwords unencrypted in job config.xml files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access to the Jenkins controller file system.

CVE-2022-27548: HCL Launch stores user credentials in plain clear text which can be read by a local user.

CVE-2022-28135: Jenkins instant-messaging Plugin 1.41 and earlier stores passwords for group chats unencrypted in the global configuration file of plugins based on Jenkins instant-messaging Plugin on the Jenkins controller where they can be viewed by users with access to the Jenkins controller file system.

CVE-2022-28141: Jenkins Proxmox Plugin 0.5.0 and earlier stores the Proxmox Datacenter password unencrypted in the global config.xml file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2022-29052: Jenkins Google Compute Engine Plugin 4.3.8 and earlier stores private keys unencrypted in cloud agent config.xml files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access to the Jenkins controller file system.

CVE-2022-29085: Dell Unity, Dell UnityVSA, and Dell Unity XT versions prior to 5.2.0.0.5.173 contain a plain-text password storage vulnerability when certain off-array tools are run on the system. The credentials of a user with high privileges are stored in plain text. A local malicious user with high privileges may use the exposed password to gain access with the privileges of the compromised user.

CVE-2022-29588: Konica Minolta bizhub MFP devices before 2022-04-14 use cleartext password storage for the /var/log/nginx/html/ADMINPASS and /etc/shadow files.

CVE-2022-34199: Jenkins Convertigo Mobile Platform Plugin 1.1 and earlier stores passwords unencrypted in job config.xml files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access to the Jenkins controller file system.

CVE-2022-34807: Jenkins Elasticsearch Query Plugin 1.2 and earlier stores a password unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2022-41732:  IBM Maximo Mobile 8.7 and 8.8 stores user credentials in plain clear text which can be read by a local user. IBM X-Force ID: 237407. 

CVE-2022-43419: Jenkins Katalon Plugin 1.0.32 and earlier stores API keys unencrypted in job config.xml files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access to the Jenkins controller file system.

CVE-2022-43442: Plaintext storage of a password vulnerability exists in +F FS040U software versions v2.3.4 and earlier, which may allow an attacker to obtain the login password of +F FS040U and log in to the management console.

CVE-2022-45384: Jenkins Reverse Proxy Auth Plugin 1.7.3 and earlier stores the LDAP manager password unencrypted in the global config.xml file on the Jenkins controller where it can be viewed by attackers with access to the Jenkins controller file system.

CVE-2022-45392: Jenkins NS-ND Integration Performance Publisher Plugin 4.8.0.143 and earlier stores passwords unencrypted in job config.xml files on the Jenkins controller where they can be viewed by attackers with Extended Read permission, or access to the Jenkins controller file system.

CVE-2022-22554: Dell EMC System Update, version 1.9.2 and prior, contain an Unprotected Storage of Credentials vulnerability. A local attacker with user privleges could potentially exploit this vulnerability leading to the disclosure of user passwords.

CVE-2022-22983: VMware Workstation (16.x prior to 16.2.4) contains an unprotected storage of credentials vulnerability. A malicious actor with local user privileges to the victim machine may exploit this vulnerability leading to the disclosure of user passwords of the remote server connected through VMware Workstation.

CVE-2022-22557: PowerStore contains Plain-Text Password Storage Vulnerability in PowerStore X & T environments running versions 2.0.0.x and 2.0.1.x A locally authenticated attacker could potentially exploit this vulnerability, leading to the disclosure of certain user credentials. The attacker may be able to use the exposed credentials to access the vulnerable application with privileges of the compromised account.

CVE-2021-36317: Dell EMC Avamar Server version 19.4 contains a plain-text password storage vulnerability in AvInstaller. A local attacker could potentially exploit this vulnerability, leading to the disclosure of certain user credentials. The attacker may be able to use the exposed credentials to access the vulnerable application with privileges of the compromised account.

CVE-2022-1766: Anchore Enterprise anchorectl version 0.1.4 improperly stored credentials when generating a Software Bill of Materials. anchorectl will add the credentials used to access Anchore Enterprise API in the Software Bill of Materials (SBOM) generated by anchorectl. Users of anchorectl version 0.1.4 should upgrade to anchorectl version 0.1.5 to resolve this issue.

CVE-2022-26856: Dell EMC Repository Manager version 3.4.0 contains a plain-text password storage vulnerability. A local attacker could potentially exploit this vulnerability, leading to the disclosure of certain user credentials. The attacker may be able to use the exposed credentials to access the vulnerable application's database with privileges of the compromised account.

CVE-2022-3781: Dashlane password and Keepass Server password in My Account Settings are not encrypted in the database in Devolutions Remote Desktop Manager 2022.2.26 and prior versions and Devolutions Server 2022.3.1 and prior versions which allows database users to read the data. This issue affects : Remote Desktop Manager 2022.2.26 and prior versions. Devolutions Server 2022.3.1 and prior versions. 

CVE-2022-3206: The Passster WordPress plugin before 3.5.5.5.2 stores the password inside a cookie named "passster" using base64 encoding method which is easy to decode. This puts the password at risk in case the cookies get leaked.

# CWE-257 Storing Passwords in a Recoverable Format

## Description

The storage of passwords in a recoverable format makes them subject to password reuse attacks by malicious users. In fact, it should be noted that recoverable encrypted passwords provide no significant benefit over plaintext passwords since they are subject not only to reuse by malicious attackers but also by malicious insiders. If a system administrator can recover a password directly, or use a brute force search on the available information, the administrator can use the password on other accounts.

## Observed Examples

CVE-2022-30018: A messaging platform serializes all elements of User/Group objects, making private information available to adversaries

## Top 25 Examples

CVE-2022-43460: Driver Distributor v2.2.3.1 and earlier contains a vulnerability where passwords are stored in a recoverable format. If an attacker obtains a configuration file of Driver Distributor, the encrypted administrator's credentials may be decrypted.

CVE-2022-46142: Affected devices store the CLI user passwords encrypted in flash memory. Attackers with physical access to the device could retrieve the file and decrypt the CLI user passwords.

CVE-2022-32519: A CWE-257: Storing Passwords in a Recoverable Format vulnerability exists that could result in unwanted access to a DCE instance when performed over a network by a malicious third-party. Affected Products: Data Center Expert (Versions prior to V7.9.0)

CVE-2022-22251: On cSRX Series devices software permission issues in the container filesystem and stored files combined with storing passwords in a recoverable format in Juniper Networks Junos OS allows a local, low-privileged attacker to elevate their permissions to take control of any instance of a cSRX software deployment. This issue affects Juniper Networks Junos OS 20.2 version 20.2R1 and later versions prior to 21.2R1 on cSRX Series.

CVE-2022-30018: Mobotix Control Center (MxCC) through 2.5.4.5 has Insufficiently Protected Credentials, Storing Passwords in a Recoverable Format via the MxCC.ini config file. The credential storage method in this software enables an attacker/user of the machine to gain admin access to the software and gain access to recordings/recording locations.

CVE-2022-34837: Storing Passwords in a Recoverable Format vulnerability in ABB Zenon 8.20 allows an attacker who successfully exploit the vulnerability may add more network clients that may monitor various activities of the Zenon.

CVE-2022-34838: Storing Passwords in a Recoverable Format vulnerability in ABB Zenon 8.20 allows an attacker who successfully exploit the vulnerability may add or alter data points and corresponding attributes. Once such engineering data is used the data visualization will be altered for the end user.

# CWE-258 Empty Password in Configuration File

## Description

Using an empty string as a password is insecure.

## Observed Examples

CVE-2022-26117: Network access control (NAC) product has a configuration file with an empty password

## Top 25 Examples

CVE-2022-26117: An empty password in configuration file vulnerability [CWE-258] in FortiNAC version 8.3.7 and below, 8.5.2 and below, 8.5.4, 8.6.0, 8.6.5 and below, 8.7.6 and below, 8.8.11 and below, 9.1.5 and below, 9.2.3 and below may allow an authenticated attacker to access the MySQL databases via the CLI.

# CWE-259 Use of Hard-coded Password

## Description

The product contains a hard-coded password, which it uses for its own inbound authentication or for outbound communication to external components.

A hard-coded password typically leads to a significant authentication failure that can be difficult for the system administrator to detect. Once detected, it can be difficult to fix, so the administrator may be forced into disabling the product entirely. There are two main variations:

```
		Inbound: the product contains an authentication mechanism that checks for a hard-coded password.
		Outbound: the product connects to another system or component, and it contains hard-coded password for connecting to that component.
```
In the Inbound variant, a default administration account is created, and a simple password is hard-coded into the product and associated with that account. This hard-coded password is the same for each installation of the product, and it usually cannot be changed or disabled by system administrators without manually modifying the program, or otherwise patching the product. If the password is ever discovered or published (a common occurrence on the Internet), then anybody with knowledge of this password can access the product. Finally, since all installations of the product will have the same password, even across different organizations, this enables massive attacks such as worms to take place.

The Outbound variant applies to front-end systems that authenticate with a back-end service. The back-end service may require a fixed password which can be easily discovered. The programmer may simply hard-code those back-end credentials into the front-end product. Any user of that program may be able to extract the password. Client-side systems with hard-coded passwords pose even more of a threat, since the extraction of a password from a binary is usually very simple.

## Observed Examples

CVE-2022-29964: Distributed Control System (DCS) has hard-coded passwords for local shell access

CVE-2021-37555: Telnet service for IoT feeder for dogs and cats has hard-coded password [REF-1288]

CVE-2021-35033: Firmware for a WiFi router uses a hard-coded password for a BusyBox shell, allowing bypass of authentication through the UART port

## Top 25 Examples

CVE-2022-26138: The Atlassian Questions For Confluence app for Confluence Server and Data Center creates a Confluence user account in the confluence-users group with the username disabledsystemuser and a hardcoded password. A remote, unauthenticated attacker with knowledge of the hardcoded password could exploit this to log into Confluence and access all content accessible to users in the confluence-users group. This user account is created when installing versions 2.7.34, 2.7.35, and 3.0.2 of the app.

CVE-2021-31477: This vulnerability allows remote attackers to execute arbitrary code on affected installations of GE Reason RPV311 14A03. Authentication is not required to exploit this vulnerability. The specific flaw exists within the firmware and filesystem of the device. The firmware and filesystem contain hard-coded default credentials. An attacker can leverage this vulnerability to execute code in the context of the download user. Was ZDI-CAN-11852.

CVE-2022-1162: A hardcoded password was set for accounts registered using an OmniAuth provider (e.g. OAuth, LDAP, SAML) in GitLab CE/EE versions 14.7 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allowing attackers to potentially take over accounts

CVE-2022-22144: A hard-coded password vulnerability exists in the libcommonprod.so prod_change_root_passwd functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. During system startup this functionality is always called, leading to a known root password. An attacker does not have to do anything to trigger this vulnerability.

CVE-2022-25577: ALF-BanCO v8.2.5 and below was discovered to use a hardcoded password to encrypt the SQLite database containing the user's data. Attackers who are able to gain remote or local access to the system are able to read and modify the data.

CVE-2022-26119: A improper authentication vulnerability in Fortinet FortiSIEM before 6.5.0 allows a local attacker with CLI access to perform operations on the Glassfish server directly via a hardcoded password.

CVE-2022-27172: A hard-coded password vulnerability exists in the console infactory functionality of InHand Networks InRouter302 V3.5.37. A specially-crafted network request can lead to privileged operation execution. An attacker can send a sequence of requests to trigger this vulnerability.

CVE-2022-29644: TOTOLINK A3100R V4.1.2cu.5050_B20200504 and V4.1.2cu.5247_B20211129 were discovered to contain a hard coded password for the telnet service stored in the component /web_cste/cgi-bin/product.ini.

CVE-2022-29645: TOTOLINK A3100R V4.1.2cu.5050_B20200504 and V4.1.2cu.5247_B20211129 were discovered to contain a hard coded password for root stored in the component /etc/shadow.sample.

CVE-2022-29825: Use of Hard-coded Password vulnerability in Mitsubishi Electric GX Works3 versions from 1.000A to 1.090U and GT Designer3 Version1 (GOT2000) versions from 1.122C to 1.290C allows an unauthenticated attacker to disclose sensitive information. As a result, unauthenticated users may view programs and project files or execute programs illegally.

CVE-2022-29831: Use of Hard-coded Password vulnerability in Mitsubishi Electric Corporation GX Works3 versions from 1.015R to 1.095Z allows a remote unauthenticated attacker to obtain information about the project file for MELSEC safety CPU modules.

CVE-2022-29889: A hard-coded password vulnerability exists in the telnet functionality of Abode Systems, Inc. iota All-In-One Security Kit 6.9Z. Use of a hard-coded root password can lead to arbitrary command execution. An attacker can authenticate with hard-coded credentials to trigger this vulnerability.

CVE-2022-32967: RTL8111EP-CG/RTL8111FP-CG DASH function has hard-coded password. An unauthenticated physical attacker can use the hard-coded default password during system reboot triggered by other user, to acquire partial system information such as serial number and server information.

CVE-2022-34005: An issue was discovered in TitanFTP (aka Titan FTP) NextGen before 1.2.1050. There is Remote Code Execution due to a hardcoded password for the sa account on the Microsoft SQL Express 2019 instance installed by default during TitanFTP NextGen installation, aka NX-I674 (sub-issue 1). NOTE: as of 2022-06-21, the 1.2.1050 release corrects this vulnerability in a new installation, but not in an upgrade installation.

CVE-2022-34462:  Dell EMC SCG Policy Manager, versions from 5.10 to 5.12, contain(s) a Hard-coded Password Vulnerability. An attacker, with the knowledge of the hard-coded credentials, could potentially exploit this vulnerability to login to the system to gain admin privileges. 

CVE-2022-35491: TOTOLINK A3002RU V3.0.0-B20220304.1804 has a hardcoded password for root in /etc/shadow.sample.

CVE-2022-35866: This vulnerability allows remote attackers to bypass authentication on affected installations of Vinchin Backup and Recovery 6.5.0.17561. Authentication is not required to exploit this vulnerability. The specific flaw exists within the configuration of the MySQL server. The server uses a hard-coded password for the administrator user. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-17139.

CVE-2022-36610: TOTOLINK A720R V4.1.5cu.532_B20210610 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-36611: TOTOLINK A800R V4.1.2cu.5137_B20200730 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-36612: TOTOLINK A950RG V4.1.2cu.5204_B20210112 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-36613: TOTOLINK N600R V4.3.0cu.7647_B20210106 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-36614: TOTOLINK A860R V4.1.2cu.5182_B20201027 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-36615: TOTOLINK A3000RU V4.1.2cu.5185_B20201128 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-36616: TOTOLINK A810R V4.1.2cu.5182_B20201026 and V5.9c.4050_B20190424 was discovered to contain a hardcoded password for root at /etc/shadow.sample.

CVE-2022-37841: In TOTOLINK A860R V4.1.2cu.5182_B20201027 there is a hard coded password for root in /etc/shadow.sample.

CVE-2022-37857: bilde2910 Hauk v1.6.1 requires a hardcoded password which by default is blank. This hardcoded password is hashed but stored within the config.php file server-side as well as in clear-text on the android client device by default.

CVE-2022-38823: In TOTOLINK T6 V4.1.5cu.709_B20210518, there is a hard coded password for root in /etc/shadow.sample.

CVE-2022-45444: Sewio’s Real-Time Location System (RTLS) Studio version 2.0.0 up to and including version 2.6.2 contains hard-coded passwords for select users in the application’s database. This could allow a remote attacker to login to the database with unrestricted access. 

CVE-2022-36159: Contec FXA3200 version 1.13 and under were discovered to contain a hard coded hash password for root stored in the component /etc/shadow. As the password strength is weak, it can be cracked in few minutes. Through this credential, a malicious actor can access the Wireless LAN Manager interface and open the telnet port then sniff the traffic or inject any malware.

CVE-2022-41653: Daikin SVMPC1 version 2.1.22 and prior and SVMPC2 version 1.2.3 and prior are vulnerable to an attacker obtaining user login credentials and control the system.

CVE-2022-48067: An information disclosure vulnerability in Totolink A830R V4.1.2cu.5182 allows attackers to obtain the root password via a brute-force attack.

# CWE-26 Path Traversal: '/dir/../filename'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize "/dir/../filename" sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The '/dir/../filename' manipulation is useful for bypassing some path traversal protection schemes. Sometimes a program only checks for "../" at the beginning of the input, so a "/../" can bypass that check.

# CWE-260 Password in Configuration File

## Description

The product stores a password in a configuration file that might be accessible to actors who do not know the password.

This can result in compromise of the system for which the password is used. An attacker could gain access to this file and learn the stored password or worse yet, change the password to one of their choosing.

## Observed Examples

CVE-2022-38665: A continuous delivery pipeline management tool stores an unencypted password in a configuration file.

## Top 25 Examples

CVE-2022-34213: Jenkins Squash TM Publisher (Squash4Jenkins) Plugin 1.0.0 and earlier stores passwords unencrypted in its global configuration file on the Jenkins controller where they can be viewed by users with access to the Jenkins controller file system.

CVE-2022-38121: UPSMON PRO configuration file stores user password in plaintext under public user directory. A remote attacker with general user privilege can access all users‘ and administrators' account names and passwords via this unprotected configuration file.

CVE-2022-38665: Jenkins CollabNet Plugins Plugin 2.0.8 and earlier stores a RabbitMQ password unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2022-41247: Jenkins BigPanda Notifier Plugin 1.4.0 and earlier stores the BigPanda API key unencrypted in its global configuration file on the Jenkins controller where they can be viewed by users with access to the Jenkins controller file system.

# CWE-261 Weak Encoding for Password

## Description

Obscuring a password with a trivial encoding does not protect the password.

Password management issues occur when a password is stored in plaintext in an application's properties or configuration file. A programmer can attempt to remedy the password management problem by obscuring the password with an encoding function, such as base 64 encoding, but this effort does not adequately protect the password.

## Top 25 Examples

CVE-2022-38469:  An unauthorized user with network access and the decryption key could decrypt sensitive data, such as usernames and passwords. 

CVE-2022-34445:  Dell PowerScale OneFS, versions 8.2.x through 9.3.x contain a weak encoding for a password. A malicious local privileged attacker may potentially exploit this vulnerability, leading to information disclosure. 

# CWE-262 Not Using Password Aging

## Description

The product does not have a mechanism in place for managing password aging.

Password aging (or password rotation) is a policy that forces users to change their passwords after a defined time period passes, such as every 30 or 90 days. Without mechanisms such as aging, users might not change their passwords in a timely manner.


Note that while password aging was once considered an important security feature, it has since fallen out of favor by many, because it is not as effective against modern threats compared to other mechanisms such as slow hashes. In addition, forcing frequent changes can unintentionally encourage users to select less-secure passwords. However, password aging is still in use due to factors such as compliance requirements, e.g., Payment Card Industry Data Security Standard (PCI DSS).

# CWE-263 Password Aging with Long Expiration

## Description

The product supports password aging, but the expiration period is too long.

Password aging (or password rotation) is a policy that forces users to change their passwords after a defined time period passes, such as every 30 or 90 days. A long expiration provides more time for attackers to conduct password cracking before users are forced to change to a new password.


Note that while password aging was once considered an important security feature, it has since fallen out of favor by many, because it is not as effective against modern threats compared to other mechanisms such as slow hashes. In addition, forcing frequent changes can unintentionally encourage users to select less-secure passwords. However, password aging is still in use due to factors such as compliance requirements, e.g., Payment Card Industry Data Security Standard (PCI DSS).

# CWE-266 Incorrect Privilege Assignment

## Description

A product incorrectly assigns a privilege to a particular actor, creating an unintended sphere of control for that actor.

## Observed Examples

CVE-1999-1193: untrusted user placed in unix "wheel" group

CVE-2005-2741: Product allows users to grant themselves certain rights that can be used to escalate privileges.

CVE-2005-2496: Product uses group ID of a user instead of the group, causing it to run with different privileges. This is resultant from some other unknown issue.

CVE-2004-0274: Product mistakenly assigns a particular status to an entity, leading to increased privileges.

## Top 25 Examples

CVE-2022-3496: A vulnerability was found in SourceCodester Human Resource Management System 1.0 and classified as critical. This issue affects some unknown processing of the file employeeadd.php of the component Admin Panel. The manipulation leads to improper access controls. The attack may be initiated remotely. The identifier VDB-210785 was assigned to this vulnerability.

CVE-2021-24859: The User Meta Shortcodes WordPress plugin through 0.5 registers a shortcode that allows any user with a role as low as contributor to access other users metadata by specifying the user login as a parameter. This makes the WP instance vulnerable to data extrafiltration, including password hashes

CVE-2022-1606: Incorrect privilege assignment in M-Files Server versions before 22.3.11164.0 and before 22.3.11237.1 allows user to read unmanaged objects.

CVE-2022-20051: In ims service, there is a possible unexpected application behavior due to incorrect privilege assignment. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06219127; Issue ID: ALPS06219127.

CVE-2022-22509: In Phoenix Contact FL SWITCH Series 2xxx in version 3.00 an incorrect privilege assignment allows an low privileged user to enable full access to the device configuration.

CVE-2022-2637: Incorrect Privilege Assignment vulnerability in Hitachi Hitachi Storage Plug-in for VMware vCenter allows remote authenticated users to cause privilege escalation.This issue affects Hitachi Storage Plug-in for VMware vCenter: from 04.8.0 before 04.9.0. 

CVE-2022-29526: Go before 1.17.10 and 1.18.x before 1.18.2 has Incorrect Privilege Assignment. When called with a non-zero flags parameter, the Faccessat function could incorrectly report that a file is accessible.

CVE-2022-4041: Incorrect Privilege Assignment vulnerability in Hitachi Storage Plug-in for VMware vCenter allows remote authenticated users to cause privilege escalation. This issue affects Hitachi Storage Plug-in for VMware vCenter: from 04.8.0 before 04.9.1. 

CVE-2022-4264: Incorrect Privilege Assignment in M-Files Web (Classic) in M-Files before 22.8.11691.0 allows low privilege user to change some configuration.

CVE-2022-4270: Incorrect privilege assignment issue in M-Files Web in M-Files Web versions before 22.5.11436.1 could have changed permissions accidentally.

CVE-2022-4441: Incorrect Privilege Assignment vulnerability in Hitachi Storage Plug-in for VMware vCenter allows remote authenticated users to cause privilege escalation. This issue affects Hitachi Storage Plug-in for VMware vCenter: from 04.9.0 before 04.9.1. 

CVE-2022-48283: A piece of Huawei whole-home intelligence software has an Incorrect Privilege Assignment vulnerability. Successful exploitation of this vulnerability could allow attackers to access restricted functions.

CVE-2022-48284: A piece of Huawei whole-home intelligence software has an Incorrect Privilege Assignment vulnerability. Successful exploitation of this vulnerability could allow attackers to access restricted functions.

CVE-2022-23296: Windows Installer Elevation of Privilege Vulnerability

CVE-2022-21946: A Incorrect Permission Assignment for Critical Resource vulnerability in the sudoers configuration in cscreen of openSUSE Factory allows any local users to gain the privileges of the tty and dialout groups and access and manipulate any running cscreen seesion. This issue affects: openSUSE Factory cscreen version 1.2-1.3 and prior versions.

# CWE-267 Privilege Defined With Unsafe Actions

## Description

A particular privilege, role, capability, or right can be used to perform unsafe actions that were not intended, even when it is assigned to the correct entity.

## Observed Examples

CVE-2002-1981: Roles have access to dangerous procedures (Accessible entities).

CVE-2002-1671: Untrusted object/method gets access to clipboard (Accessible entities).

CVE-2004-2204: Gain privileges using functions/tags that should be restricted (Accessible entities).

CVE-2000-0315: Traceroute program allows unprivileged users to modify source address of packet (Accessible entities).

CVE-2004-0380: Bypass domain restrictions using a particular file that references unsafe URI schemes (Accessible entities).

CVE-2002-1154: Script does not restrict access to an update command, leading to resultant disk consumption and filled error logs (Accessible entities).

CVE-2002-1145: "public" database user can use stored procedure to modify data controlled by the database owner (Unsafe privileged actions).

CVE-2000-0506: User with capability can prevent setuid program from dropping privileges (Unsafe privileged actions).

CVE-2002-2042: Allows attachment to and modification of privileged processes (Unsafe privileged actions).

CVE-2000-1212: User with privilege can edit raw underlying object using unprotected method (Unsafe privileged actions).

CVE-2005-1742: Inappropriate actions allowed by a particular role(Unsafe privileged actions).

CVE-2001-1480: Untrusted entity allowed to access the system clipboard (Unsafe privileged actions).

CVE-2001-1551: Extra Linux capability allows bypass of system-specified restriction (Unsafe privileged actions).

CVE-2001-1166: User with debugging rights can read entire process (Unsafe privileged actions).

CVE-2005-1816: Non-root admins can add themselves or others to the root admin group (Unsafe privileged actions).

CVE-2005-2173: Users can change certain properties of objects to perform otherwise unauthorized actions (Unsafe privileged actions).

CVE-2005-2027: Certain debugging commands not restricted to just the administrator, allowing registry modification and infoleak (Unsafe privileged actions).

## Top 25 Examples

CVE-2022-38124: Debug tool in Secomea SiteManager allows logged-in administrator to modify system state in an unintended manner.

# CWE-268 Privilege Chaining

## Description

Two distinct privileges, roles, capabilities, or rights can be combined in a way that allows an entity to perform unsafe actions that would not be allowed without that combination.

## Observed Examples

CVE-2005-1736: Chaining of user rights.

CVE-2002-1772: Gain certain rights via privilege chaining in alternate channel.

CVE-2005-1973: Application is allowed to assign extra permissions to itself.

CVE-2003-0640: "operator" user can overwrite usernames and passwords to gain admin privileges.

## Top 25 Examples

CVE-2022-1003: One of the API in Mattermost version 6.3.0 and earlier fails to properly protect the permissions, which allows the system administrators to combine the two distinct privileges/capabilities in a way that allows them to override certain restricted configurations like EnableUploads.

# CWE-269 Improper Privilege Management

## Description

The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Observed Examples

CVE-2001-1555: Terminal privileges are not reset when a user logs out.

CVE-2001-1514: Does not properly pass security context to child processes in certain cases, allows privilege escalation.

CVE-2001-0128: Does not properly compute roles.

CVE-1999-1193: untrusted user placed in unix "wheel" group

CVE-2005-2741: Product allows users to grant themselves certain rights that can be used to escalate privileges.

CVE-2005-2496: Product uses group ID of a user instead of the group, causing it to run with different privileges. This is resultant from some other unknown issue.

CVE-2004-0274: Product mistakenly assigns a particular status to an entity, leading to increased privileges.

CVE-2007-4217: FTP client program on a certain OS runs with setuid privileges and has a buffer overflow. Most clients do not need extra privileges, so an overflow is not a vulnerability for those clients.

CVE-2007-5159: OS incorrectly installs a program with setuid privileges, allowing users to gain privileges.

CVE-2008-4638: Composite: application running with high privileges (CWE-250) allows user to specify a restricted file to process, which generates a parsing error that leaks the contents of the file (CWE-209).

CVE-2007-3931: Installation script installs some programs as setuid when they shouldn't be.

CVE-2002-1981: Roles have access to dangerous procedures (Accessible entities).

CVE-2002-1671: Untrusted object/method gets access to clipboard (Accessible entities).

CVE-2000-0315: Traceroute program allows unprivileged users to modify source address of packet (Accessible entities).

CVE-2000-0506: User with capability can prevent setuid program from dropping privileges (Unsafe privileged actions).

## Top 25 Examples

CVE-2021-20021: A vulnerability in the SonicWall Email Security version 10.0.9.x allows an attacker to create an administrative account by sending a crafted HTTP request to the remote host.

CVE-2021-25337: Improper access control in clipboard service in Samsung mobile devices prior to SMR Mar-2021 Release 1 allows untrusted applications to read or write certain local files.

CVE-2022-27840: Improper access control vulnerability in SamsungRecovery prior to version 8.1.43.0 allows local attckers to delete arbitrary files as SamsungRecovery permission.

CVE-2022-22483: IBM Db2 for Linux, UNIX and Windows 9.7, 10.1, 10.5, 11.1, and 11.5 is vulnerable to an information disclosure in some scenarios due to unauthorized access caused by improper privilege management when CREATE OR REPLACE command is used. IBM X-Force ID: 225979.

CVE-2022-42735: Improper Privilege Management vulnerability in Apache Software Foundation Apache ShenYu. ShenYu Admin allows low-privilege low-level administrators create users with higher privileges than their own. This issue affects Apache ShenYu: 2.5.0. Upgrade to Apache ShenYu 2.5.1 or apply patch https://github.com/apache/shenyu/pull/3958 https://github.com/apache/shenyu/pull/3958 . 

CVE-2022-43927: IBM Db2 for Linux, UNIX and Windows 10.5, 11.1, and 11.5 is vulnerable to information Disclosure due to improper privilege management when a specially crafted table access is used. IBM X-Force ID: 241671.

CVE-2021-43076: An improper privilege management vulnerability [CWE-269] in FortiADC versions 6.2.1 and below, 6.1.5 and below, 6.0.4 and below, 5.4.5 and below and 5.3.7 and below may allow a remote authenticated attacker with restricted user profile to modify the system files using the shell access.

CVE-2022-0222: A CWE-269: Improper Privilege Management vulnerability exists that could cause a denial of service of the Ethernet communication of the controller when sending a specific request over SNMP. Affected products: Modicon M340 CPUs(BMXP34* versions prior to V3.40), Modicon M340 X80 Ethernet Communication modules:BMXNOE0100 (H), BMXNOE0110 (H), BMXNOR0200H RTU(BMXNOE* all versions)(BMXNOR* versions prior to v1.7 IR24)

CVE-2022-1823: Improper privilege management vulnerability in McAfee Consumer Product Removal Tool prior to version 10.4.128 could allow a local user to modify a configuration file and perform a LOLBin (Living off the land) attack. This could result in the user gaining elevated permissions and being able to execute arbitrary code, through not correctly checking the integrity of the configuration file.

CVE-2022-20739: A vulnerability in the CLI of Cisco SD-WAN vManage Software could allow an authenticated, local attacker to execute arbitrary commands on the underlying operating system as the root user. The attacker must be authenticated on the affected system as a low-privileged user to exploit this vulnerability. This vulnerability exists because a file leveraged by a root user is executed when a low-privileged user runs specific commands on an affected system. An attacker could exploit this vulnerability by injecting arbitrary commands to a specific file as a lower-privileged user and then waiting until an admin user executes specific commands. The commands would then be executed on the device by the root user. A successful exploit could allow the attacker to escalate their privileges on the affected system from a low-privileged user to the root user.

CVE-2022-22263: Unprotected dynamic receiver in SecSettings prior to SMR Jan-2022 Release 1 allows untrusted applications to launch arbitrary activity.

CVE-2022-22266: (Applicable to China models only) Unprotected WifiEvaluationService in TencentWifiSecurity application prior to SMR Jan-2022 Release 1 allows untrusted applications to get WiFi information without proper permission.

CVE-2022-22390: IBM Db2 for Linux, UNIX and Windows 9.7, 10.1, 10.5, 11.1, and 11.5 may be vulnerable to an information disclosure caused by improper privilege management when table function is used. IBM X-Force ID: 221973.

CVE-2022-2249: Privilege escalation related vulnerabilities were discovered in Avaya Aura Communication Manager that may allow local administrative users to escalate their privileges. This issue affects Communication Manager versions 8.0.0.0 through 8.1.3.3 and 10.1.0.0.

CVE-2022-23737: An improper privilege management vulnerability was identified in GitHub Enterprise Server that allowed users with improper privileges to create or delete pages via the API. To exploit this vulnerability, an attacker would need to be added to an organization's repo with write permissions. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.7 and was fixed in versions 3.2.20, 3.3.15, 3.4.10, 3.5.7, and 3.6.3. This vulnerability was reported via the GitHub Bug Bounty program.

CVE-2022-30298: An improper privilege management vulnerability [CWE-269] in Fortinet FortiSOAR before 7.2.1 allows a GUI user who has already found a way to modify system files (via another, unrelated and hypothetical exploit) to execute arbitrary Python commands as root.

CVE-2022-3068: Improper Privilege Management in GitHub repository octoprint/octoprint prior to 1.8.3.

CVE-2022-30735: Improper privilege management vulnerability in Samsung Account prior to 13.2.00.6 allows attackers to get the access_token without permission.

CVE-2022-30736: Improper privilege management vulnerability in Samsung Account prior to 13.2.00.6 allows attackers to get the data of contact and gallery without permission.

CVE-2022-30739: Improper privilege management vulnerability in Samsung Account prior to 13.2.00.6 allows attackers to get an user email or phone number with a normal level permission.

CVE-2022-30743: Improper privilege management vulnerability in Samsung Account prior to 13.2.00.6 allows attackers to get the data of contact and gallery without permission.

CVE-2022-32536: The user access rights validation in the web server of the Bosch Ethernet switch PRA-ES8P2S with software version 1.01.05 was insufficient. This would allow a non-administrator user to obtain administrator user access rights.

CVE-2022-33962: In BIG-IP Versions 17.0.x before 17.0.0.1, 16.1.x before 16.1.3.1, 15.1.x before 15.1.6.1, 14.1.x before 14.1.5.1, and all versions of 13.1.x, certain iRules commands may allow an attacker to bypass the access control restrictions for a self IP address, regardless of the port lockdown settings. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-34338: IBM Robotic Process Automation 21.0.0, 21.0.1, and 21.0.2 could disclose sensitive information due to improper privilege management for storage provider types. IBM X-Force ID: 229962.

CVE-2022-34754: A CWE-269: Improper Privilege Management vulnerability exists that could allow elevated functionality when guessing credentials. Affected Products: Acti9 PowerTag Link C (A9XELC10-A) (V1.7.5 and prior), Acti9 PowerTag Link C (A9XELC10-B) (V2.12.0 and prior)

CVE-2022-35243: In BIG-IP Versions 16.1.x before 16.1.3, 15.1.x before 15.1.5.1, 14.1.x before 14.1.5, and all versions of 13.1.x, when running in Appliance mode, an authenticated user assigned the Administrator role may be able to bypass Appliance mode restrictions, using an undisclosed iControl REST endpoint. A successful exploit can allow the attacker to cross a security boundary. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-35291: Due to misconfigured application endpoints, SAP SuccessFactors attachment APIs allow attackers with user privileges to perform activities with admin privileges over the network. These APIs were consumed in the SF Mobile application for Time Off, Time Sheet, EC Workflow, and Benefits. On successful exploitation, the attacker can read/write attachments. Thus, compromising the confidentiality and integrity of the application

CVE-2022-36833: Improper Privilege Management vulnerability in Game Optimizing Service prior to versions 3.3.04.0 in Android 10, and 3.5.04.8 in Android 11 and above allows local attacker to execute hidden function for developer by changing package name.

CVE-2022-37025: An improper privilege management vulnerability in McAfee Security Scan Plus (MSS+) before 4.1.262.1 could allow a local user to modify a configuration file and perform a LOLBin (Living off the land) attack. This could result in the user gaining elevated permissions and being able to execute arbitrary code due to lack of an integrity check of the configuration file.

CVE-2022-37929: Improper Privilege Management vulnerability in Hewlett Packard Enterprise Nimble Storage Hybrid Flash Arrays and Nimble Storage Secondary Flash Arrays. 

CVE-2022-38378: An improper privilege management vulnerability [CWE-269] in Fortinet FortiOS version 7.2.0 and before 7.0.7 and FortiProxy version 7.2.0 through 7.2.1 and before 7.0.7 allows an attacker that has access to the admin profile section (System subsection Administrator Users) to modify their own profile and upgrade their privileges to Read Write via CLI or GUI commands.

CVE-2022-38757: A vulnerability has been identified in Micro Focus ZENworks 2020 Update 3a and prior versions. This vulnerability allows administrators with rights to perform actions (e.g., install a bundle) on a set of managed devices, to be able to exercise these rights on managed devices in the ZENworks zone but which are outside the scope of the administrator. This vulnerability does not result in the administrators gaining additional rights on the managed devices, either in the scope or outside the scope of the administrator.

CVE-2022-38777: An issue was discovered in the rollback feature of Elastic Endpoint Security for Windows, which could allow unprivileged users to elevate their privileges to those of the LocalSystem account.

CVE-2022-39032: Smart eVision has an improper privilege management vulnerability. A remote attacker with general user privilege can exploit this vulnerability to escalate to administrator privilege, and then perform arbitrary system command or disrupt service.

CVE-2022-39953: A improper privilege management in Fortinet FortiNAC version 9.4.0 through 9.4.1, FortiNAC version 9.2.0 through 9.2.6, FortiNAC version 9.1.0 through 9.1.8, FortiNAC all versions 8.8, FortiNAC all versions 8.7, FortiNAC all versions 8.6, FortiNAC all versions 8.5, FortiNAC version 8.3.7 allows attacker to escalation of privilege via specially crafted commands.

CVE-2022-41268: In some SAP standard roles in SAP Business Planning and Consolidation - versions - SAP_BW 750, 751, 752, 753, 754, 755, 756, 757, DWCORE 200, 300, CPMBPC 810, a transaction code reserved for the customer is used. By implementing such transaction code, a malicious user may execute unauthorized transaction functionality. Under specific circumstances, a successful attack could enable an adversary to escalate their privileges to be able to read, change or delete system data.

CVE-2022-4173: A vulnerability within the malware removal functionality of Avast and AVG Antivirus allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avast and AVG Antivirus version 22.10. 

CVE-2022-42459: Auth. WordPress Options Change vulnerability in Image Hover Effects Ultimate plugin <= 9.7.1 on WordPress.

CVE-2022-42888: Unauth. Privilege Escalation vulnerability in ARMember premium plugin <= 5.5.1 on WordPress.

CVE-2022-4314: Improper Privilege Management in GitHub repository ikus060/rdiffweb prior to 2.5.2.

CVE-2022-43749: Improper privilege management vulnerability in summary report management in Synology Presto File Server before 2.1.2-1601 allows remote authenticated users to bypass security constraint via unspecified vectors.

CVE-2022-46334: Proofpoint Enterprise Protection (PPS/PoD) contains a vulnerability which allows the pps user to escalate to root privileges due to unnecessary permissions. This affects all versions 8.19.0 and below. 

CVE-2022-48365: An issue was discovered in eZ Platform Ibexa Kernel before 1.3.26. The Company admin role gives excessive privileges.

CVE-2022-21827: An improper privilege vulnerability has been discovered in Citrix Gateway Plug-in for Windows (Citrix Secure Access for Windows) <21.9.1.2 what could allow an attacker who has gained local access to a computer with Citrix Gateway Plug-in installed, to corrupt or delete files as SYSTEM.

CVE-2022-29179: Cilium is open source software for providing and securing network connectivity and loadbalancing between application workloads. Prior to versions 1.9.16, 1.10.11, and 1.11.15, if an attacker is able to perform a container escape of a container running as root on a host where Cilium is installed, the attacker can escalate privileges to cluster admin by using Cilium's Kubernetes service account. The problem has been fixed and the patch is available in versions 1.9.16, 1.10.11, and 1.11.5. There are no known workarounds available.

CVE-2022-29614: SAP startservice - of SAP NetWeaver Application Server ABAP, Application Server Java, ABAP Platform and HANA Database - versions KERNEL 7.22, 7.49, 7.53, 7.77, 7.81, 7.85, 7.86, 7.87, 7.88, KRNL64NUC 7.22, 7.22EXT, 7.49, KRNL64UC 7.22, 7.22EXT, 7.49, 7.53, SAPHOSTAGENT 7.22, - on Unix systems, s-bit helper program sapuxuserchk, can be abused physically resulting in a privilege escalation of an attacker leading to low impact on confidentiality and integrity, but a profound impact on availability.

CVE-2022-23921: Exploitation of this vulnerability may result in local privilege escalation and code execution. GE maintains exploitation of this vulnerability is only possible if the attacker has login access to a machine actively running CIMPLICITY, the CIMPLICITY server is not already running a project, and the server is licensed for multiple projects.

CVE-2022-24408: A vulnerability has been identified in SINUMERIK MC (All versions < V1.15 SP1), SINUMERIK ONE (All versions < V6.15 SP1). The sc SUID binary on affected devices provides several commands that are used to execute system commands or modify system files. A specific set of operations using sc could allow local attackers to escalate their privileges to root.

CVE-2022-24927: Improper privilege management vulnerability in Samsung Video Player prior to version 7.3.15.30 allows attackers to execute video files without permission.

CVE-2022-26057: Vulnerabilities in the Mint WorkBench allow a low privileged attacker to create and write to a file anywhere on the file system as SYSTEM with arbitrary content as long as the file does not already exist. The Mint WorkBench installer file allows a low-privileged user to run a "repair" operation on the product

CVE-2022-27659: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, and 14.1.x versions prior to 14.1.4.6, an authenticated attacker can modify or delete Dashboards created by other BIG-IP users in the Traffic Management User Interface (TMUI). Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-46172: authentik is an open-source Identity provider focused on flexibility and versatility. In versions prior to 2022.10.4, and 2022.11.4, any authenticated user can create an arbitrary number of accounts through the default flows. This would circumvent any policy in a situation where it is undesirable for users to create new accounts by themselves. This may also affect other applications as these new basic accounts would exist throughout the SSO infrastructure. By default the newly created accounts cannot be logged into as no password reset exists by default. However password resets are likely to be enabled by most installations. This vulnerability pertains to the user context used in the default-user-settings-flow, /api/v3/flows/instances/default-user-settings-flow/execute/. This issue has been fixed in versions 2022.10.4 and 2022.11.4.

CVE-2022-2975: A vulnerability related to weak permissions was detected in Avaya Aura Application Enablement Services web application, allowing an administrative user to modify accounts leading to execution of arbitrary code as the root user. This issue affects Application Enablement Services versions 8.0.0.0 through 8.1.3.4 and 10.1.0.0 through 10.1.0.1. Versions prior to 8.0.0.0 are end of manufacturing support and were not evaluated.

CVE-2022-26676: aEnrich a+HRD has inadequate privilege restrictions, an unauthenticated remote attacker can use the API function to upload and execute malicious scripts to control the system or disrupt service.

CVE-2022-1901: In affected versions of Octopus Deploy it is possible to unmask sensitive variables by using variable preview.

# CWE-27 Path Traversal: 'dir/../../filename'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize multiple internal "../" sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The 'directory/../../filename' manipulation is useful for bypassing some path traversal protection schemes. Sometimes a program only removes one "../" sequence, so multiple "../" can bypass that check. Alternately, this manipulation could be used to bypass a check for "../" at the beginning of the pathname, moving up more than one directory level.

## Observed Examples

CVE-2002-0298: Server allows remote attackers to cause a denial of service via certain HTTP GET requests containing a %2e%2e (encoded dot-dot), several "/../" sequences, or several "../" in a URI.

## Top 25 Examples

CVE-2022-30508: DedeCMS v5.7.93 was discovered to contain arbitrary file deletion vulnerability in upload.php via the delete parameter.

# CWE-270 Privilege Context Switching Error

## Description

The product does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control.

## Observed Examples

CVE-2002-1688: Web browser cross domain problem when user hits "back" button.

CVE-2003-1026: Web browser cross domain problem when user hits "back" button.

CVE-2002-1770: Cross-domain issue - third party product passes code to web browser, which executes it in unsafe zone.

CVE-2005-2263: Run callback in different security context after it has been changed from untrusted to trusted. * note that "context switch before actions are completed" is one type of problem that happens frequently, espec. in browsers.

## Top 25 Examples

CVE-2022-34438: Dell PowerScale OneFS, versions 8.2.x-9.4.0.x, contain a privilege context switching error. A local authenticated malicious user with high privileges could potentially exploit this vulnerability, leading to full system compromise. This impacts compliance mode clusters.

# CWE-271 Privilege Dropping / Lowering Errors

## Description

The product does not drop privileges before passing control of a resource to an actor that does not have those privileges.

In some contexts, a system executing with elevated permissions will hand off a process/file/etc. to another process or user. If the privileges of an entity are not reduced, then elevated privileges are spread throughout a system and possibly to an attacker.

## Observed Examples

CVE-2000-1213: Program does not drop privileges after acquiring the raw socket.

CVE-2001-0559: Setuid program does not drop privileges after a parsing error occurs, then calls another program to handle the error.

CVE-2001-0787: Does not drop privileges in related groups when lowering privileges.

CVE-2002-0080: Does not drop privileges in related groups when lowering privileges.

CVE-2001-1029: Does not drop privileges before determining access to certain files.

CVE-1999-0813: Finger daemon does not drop privileges when executing programs on behalf of the user being fingered.

CVE-1999-1326: FTP server does not drop privileges if a connection is aborted during file transfer.

CVE-2000-0172: Program only uses seteuid to drop privileges.

CVE-2004-2504: Windows program running as SYSTEM does not drop privileges before executing other programs (many others like this, especially involving the Help facility).

CVE-2004-0213: Utility Manager launches winhlp32.exe while running with raised privileges, which allows local users to gain system privileges.

CVE-2004-0806: Setuid program does not drop privileges before executing program specified in an environment variable.

CVE-2004-0828: Setuid program does not drop privileges before processing file specified on command line.

CVE-2004-2070: Service on Windows does not drop privileges before using "view file" option, allowing code execution.

# CWE-272 Least Privilege Violation

## Description

The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.

# CWE-273 Improper Check for Dropped Privileges

## Description

The product attempts to drop privileges but does not check or incorrectly checks to see if the drop succeeded.

If the drop fails, the product will continue to run with the raised privileges, which might provide additional access to unprivileged users.

In Windows based environments that have access control, impersonation is used so that access checks can be performed on a client identity by a server with higher privileges. By impersonating the client, the server is restricted to client-level security -- although in different threads it may have much higher privileges.

## Observed Examples

CVE-2006-4447: Program does not check return value when invoking functions to drop privileges, which could leave users with higher privileges than expected by forcing those functions to fail.

CVE-2006-2916: Program does not check return value when invoking functions to drop privileges, which could leave users with higher privileges than expected by forcing those functions to fail.

# CWE-274 Improper Handling of Insufficient Privileges

## Description

The product does not handle or incorrectly handles when it has insufficient privileges to perform an operation, leading to resultant weaknesses.

## Observed Examples

CVE-2001-1564: System limits are not properly enforced after privileges are dropped.

CVE-2005-3286: Firewall crashes when it can't read a critical memory block that was protected by a malicious process.

CVE-2005-1641: Does not give admin sufficient privileges to overcome otherwise legitimate user actions.

## Top 25 Examples

CVE-2022-41049: Windows Mark of the Web Security Feature Bypass Vulnerability

CVE-2022-41091: Windows Mark of the Web Security Feature Bypass Vulnerability

CVE-2022-0668: JFrog Artifactory prior to 7.37.13 is vulnerable to Authentication Bypass, which can lead to Privilege Escalation when a specially crafted request is sent by an unauthenticated user.

CVE-2022-25782: Improper Handling of Insufficient Privileges vulnerability in Web UI of Secomea GateManager allows logged in user to access and update privileged information. This issue affects: Secomea GateManager versions prior to 9.7.

CVE-2022-45101:  Dell PowerScale OneFS 9.0.0.x - 9.4.0.x, contains an Improper Handling of Insufficient Privileges vulnerability in NFS. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to information disclosure and remote execution. 

CVE-2022-23160: Dell PowerScale OneFS, versions 8.2.0-9.3.0, contains an Improper Handling of Insufficient Permissions vulnerability. An remote malicious user could potentially exploit this vulnerability, leading to gaining write permissions on read-only files.

# CWE-276 Incorrect Default Permissions

## Description

During installation, installed file permissions are set to allow anyone to modify those files.

## Observed Examples

CVE-2005-1941: Executables installed world-writable.

CVE-2002-1713: Home directories installed world-readable.

CVE-2001-1550: World-writable log files allow information loss; world-readable file has cleartext passwords.

CVE-2002-1711: World-readable directory.

CVE-2002-1844: Windows product uses insecure permissions when installing on Solaris (genesis: port error).

CVE-2001-0497: Insecure permissions for a shared secret key file. Overlaps cryptographic problem.

CVE-1999-0426: Default permissions of a device allow IP spoofing.

## Top 25 Examples

CVE-2022-46774: IBM Manage Application 8.8.0 and 8.9.0 in the IBM Maximo Application Suite is vulnerable to incorrect default permissions which could give access to a user to actions that they should not have access to. IBM X-Force ID: 242953.

CVE-2021-3981: A flaw in grub2 was found where its configuration file, known as grub.cfg, is being created with the wrong permission set allowing non privileged users to read its content. This represents a low severity confidentiality issue, as those users can eventually read any encrypted passwords present in grub.cfg. This flaw affects grub2 2.06 and previous versions. This issue has been fixed in grub upstream but no version with the fix is currently released.

CVE-2021-41637: Weak access control permissions in MELAG FTP Server 2.2.0.4 allow the "Everyone" group to read the local FTP configuration file, which includes among other information the unencrypted passwords of all FTP users.

CVE-2021-45083: An issue was discovered in Cobbler before 3.3.1. Files in /etc/cobbler are world readable. Two of those files contain some sensitive information that can be exposed to a local user who has non-privileged access to the server. The users.digest file contains the sha2-512 digest of users in a Cobbler local installation. In the case of an easy-to-guess password, it's trivial to obtain the plaintext string. The settings.yaml file contains secrets such as the hashed default password.

CVE-2022-27919: Gradle Enterprise before 2022.1 allows remote code execution if the installation process did not specify an initial configuration file. The configuration allows certain anonymous access to administration and an API.

CVE-2022-25364: In Gradle Enterprise before 2021.4.2, the default built-in build cache configuration allowed anonymous write access. If this was not manually changed, a malicious actor with network access to the build cache could potentially populate it with manipulated entries that execute malicious code as part of a build. As of 2021.4.2, the built-in build cache is inaccessible-by-default, requiring explicit configuration of its access-control settings before it can be used. (Remote build cache nodes are unaffected as they are inaccessible-by-default.)

# CWE-277 Insecure Inherited Permissions

## Description

A product defines a set of insecure permissions that are inherited by objects that are created by the program.

## Observed Examples

CVE-2005-1841: User's umask is used when creating temp files.

CVE-2002-1786: Insecure umask for core dumps [is the umask preserved or assigned?].

## Top 25 Examples

CVE-2022-38170: In Apache Airflow prior to 2.3.4, an insecure umask was configured for numerous Airflow components when running with the `--daemon` flag which could result in a race condition giving world-writable files in the Airflow home directory and allowing local users to expose arbitrary file contents via the webserver.

CVE-2022-48257: In Eternal Terminal 6.2.1, etserver and etclient have predictable logfile names in /tmp.

CVE-2021-0056: Insecure inherited permissions for the Intel(R) NUC M15 Laptop Kit Driver Pack software before updated version 1.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2021-0109: Insecure inherited permissions for the Intel(R) SOC driver package for STK1A32SC before version 604 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-25992: Insecure inherited permissions in the Intel(R) oneAPI Toolkits oneapi-cli before version 0.2.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-40298: Crestron AirMedia for Windows before 5.5.1.84 has insecure inherited permissions, which leads to a privilege escalation vulnerability found in the AirMedia Windows Application, version 4.3.1.39. A low privileged user can initiate a repair of the system and gain a SYSTEM level shell.

CVE-2022-24769: Moby is an open-source project created by Docker to enable and accelerate software containerization. A bug was found in Moby (Docker Engine) prior to version 20.10.14 where containers were incorrectly started with non-empty inheritable Linux process capabilities, creating an atypical Linux environment and enabling programs with inheritable file capabilities to elevate those capabilities to the permitted set during `execve(2)`. Normally, when executable programs have specified permitted file capabilities, otherwise unprivileged users and processes can execute those programs and gain the specified file capabilities up to the bounding set. Due to this bug, containers which included executable programs with inheritable file capabilities allowed otherwise unprivileged users and processes to additionally gain these inheritable file capabilities up to the container's bounding set. Containers which use Linux users and groups to perform privilege separation inside the container are most directly impacted. This bug did not affect the container security sandbox as the inheritable set never contained more capabilities than were included in the container's bounding set. This bug has been fixed in Moby (Docker Engine) 20.10.14. Running containers should be stopped, deleted, and recreated for the inheritable capabilities to be reset. This fix changes Moby (Docker Engine) behavior such that containers are started with a more typical Linux environment. As a workaround, the entry point of a container can be modified to use a utility like `capsh(1)` to drop inheritable capabilities prior to the primary process starting.

# CWE-278 Insecure Preserved Inherited Permissions

## Description

A product inherits a set of insecure permissions for an object, e.g. when copying from an archive file, without user awareness or involvement.

## Observed Examples

CVE-2005-1724: Does not obey specified permissions when exporting.

## Top 25 Examples

CVE-2021-45492: In Sage 300 ERP (formerly accpac) through 6.8.x, the installer configures the C:\\Sage\\Sage300\\Runtime directory to be the first entry in the system-wide PATH environment variable. However, this directory is writable by unprivileged users because the Sage installer fails to set explicit permissions and therefore inherits weak permissions from the C:\\ folder. Because entries in the system-wide PATH variable are included in the search order for DLLs, an attacker could perform DLL search-order hijacking to escalate their privileges to SYSTEM. Furthermore, if the Global Search or Web Screens functionality is enabled, then privilege escalation is possible via the GlobalSearchService and Sage.CNA.WindowsService services, again via DLL search-order hijacking because unprivileged users would have modify permissions on the application directory. Note that while older versions of the software default to installing in %PROGRAMFILES(X86)% (which would allow the Sage folder to inherit strong permissions, making the installation not vulnerable), the official Sage 300 installation guides for those versions recommend installing in C:\\Sage, which would make the installation vulnerable.

# CWE-279 Incorrect Execution-Assigned Permissions

## Description

While it is executing, the product sets the permissions of an object in a way that violates the intended permissions that have been specified by the user.

## Observed Examples

CVE-2002-0265: Log files opened read/write.

CVE-2003-0876: Log files opened read/write.

CVE-2002-1694: Log files opened read/write.

# CWE-28 Path Traversal: '..\filedir'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize "..\" sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The '..\' manipulation is the canonical manipulation for operating systems that use "\" as directory separators, such as Windows. However, it is also useful for bypassing path traversal protection schemes that only assume that the "/" separator is valid.

## Observed Examples

CVE-2002-0661: "\" not in denylist for web server, allowing path traversal attacks when the server is run in Windows and other OSes.

CVE-2002-0946: Arbitrary files may be read files via ..\ (dot dot) sequences in an HTTP request.

CVE-2002-1042: Directory traversal vulnerability in search engine for web server allows remote attackers to read arbitrary files via "..\" sequences in queries.

CVE-2002-1209: Directory traversal vulnerability in FTP server allows remote attackers to read arbitrary files via "..\" sequences in a GET request.

CVE-2002-1178: Directory traversal vulnerability in servlet allows remote attackers to execute arbitrary commands via "..\" sequences in an HTTP request.

## Top 25 Examples

CVE-2022-1373: The “restore configuration” feature of Softing Secure Integration Server V1.22 is vulnerable to a directory traversal vulnerability when processing zip files. An attacker can craft a zip file to load an arbitrary dll and execute code. Using the "restore configuration" feature to upload a zip file containing a path traversal file may cause a file to be created and executed upon touching the disk.

# CWE-280 Improper Handling of Insufficient Permissions or Privileges 

## Description

The product does not handle or incorrectly handles when it has insufficient privileges to access resources or functionality as specified by their permissions. This may cause it to follow unexpected code paths that may leave the product in an invalid state.

## Observed Examples

CVE-2003-0501: Special file system allows attackers to prevent ownership/permission change of certain entries by opening the entries before calling a setuid program.

CVE-2004-0148: FTP server places a user in the root directory when the user's permissions prevent access to the their own home directory.

## Top 25 Examples

CVE-2022-39885: Improper access control vulnerability in BootCompletedReceiver_CMCC in DeviceManagement prior to SMR Nov-2022 Release 1 allows local attacker to access to Device information.

CVE-2022-39886: Improper access control vulnerability in IpcRxServiceModeBigDataInfo in RIL prior to SMR Nov-2022 Release 1 allows local attacker to access Device information.

CVE-2022-21813: NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel driver, where improper handling of insufficient permissions or privileges may allow an unprivileged local user limited write access to protected memory, which can lead to denial of service.

CVE-2022-21814: NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel driver package, where improper handling of insufficient permissions or privileges may allow an unprivileged local user limited write access to protected memory, which can lead to denial of service.

CVE-2022-22300: A improper handling of insufficient permissions or privileges in Fortinet FortiAnalyzer version 5.6.0 through 5.6.11, FortiAnalyzer version 6.0.0 through 6.0.11, FortiAnalyzer version 6.2.0 through 6.2.9, FortiAnalyzer version 6.4.0 through 6.4.7, FortiAnalyzer version 7.0.0 through 7 .0.2, FortiManager version 5.6.0 through 5.6.11, FortiManager version 6.0.0 through 6.0.11, FortiManager version 6.2.0 through 6.2.9, FortiManager version 6.4.0 through 6.4.7, FortiManager version 7.0.0 through 7.0.2 allows attacker to bypass the device policy and force the password-change action for its user.

CVE-2022-34368: Dell EMC NetWorker 19.2.1.x 19.3.x, 19.4.x, 19.5.x, 19.6.x and 19.7.0.0 contain an Improper Handling of Insufficient Permissions or Privileges vulnerability. Authenticated non admin user could exploit this vulnerability and gain access to restricted resources.

CVE-2022-36874: Improper Handling of Insufficient Permissions or Privileges vulnerability in Waterplugin prior to 2.2.11.22040751 allows attacker to access device IMEI and Serial number.

# CWE-281 Improper Preservation of Permissions

## Description

The product does not preserve permissions or incorrectly preserves permissions when copying, restoring, or sharing objects, which can cause them to have less restrictive permissions than intended.

## Observed Examples

CVE-2002-2323: Incorrect ACLs used when restoring backups from directories that use symbolic links.

CVE-2001-1515: Automatic modification of permissions inherited from another file system.

CVE-2005-1920: Permissions on backup file are created with defaults, possibly less secure than original file.

CVE-2001-0195: File is made world-readable when being cloned.

## Top 25 Examples

CVE-2022-0330: A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or escalate their privileges on the system.

CVE-2021-45446: A vulnerability in Hitachi Vantara Pentaho Business Analytics Server versions before 9.2.0.2 and 8.3.0.25 does not cascade the hidden property to the children of the Home folder. This directory listing provides an attacker with the complete index of all the resources located inside the directory. 

# CWE-282 Improper Ownership Management

## Description

The product assigns the wrong ownership, or does not properly verify the ownership, of an object or resource.

## Observed Examples

CVE-1999-1125: Program runs setuid root but relies on a configuration file owned by a non-root user.

## Top 25 Examples

CVE-2022-3706: Improper authorization in GitLab CE/EE affecting all versions from 7.14 prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allows a user retrying a job in a downstream pipeline to take ownership of the retried jobs in the upstream pipeline even if the user doesn't have access to that project.

# CWE-283 Unverified Ownership

## Description

The product does not properly verify that a critical resource is owned by the proper entity.

## Observed Examples

CVE-2001-0178: Program does not verify the owner of a UNIX socket that is used for sending a password.

CVE-2004-2012: Owner of special device not checked, allowing root.

## Top 25 Examples

CVE-2022-31154: Sourcegraph is an opensource code search and navigation engine. It is possible for an authenticated Sourcegraph user to edit the Code Monitors owned by any other Sourcegraph user. This includes being able to edit both the trigger and the action of the monitor in question. An attacker is not able to read contents of existing code monitors, only override the data. The issue is fixed in Sourcegraph 3.42. There are no workaround for the issue and patching is highly recommended.

# CWE-284 Improper Access Control

## Description

The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

Access control involves the use of several protection mechanisms such as:


  - Authentication (proving the identity of an actor)

  - Authorization (ensuring that a given actor can access a resource), and

  - Accountability (tracking of activities that were performed)

When any mechanism is not applied or otherwise fails, attackers can compromise the security of the product by gaining privileges, reading sensitive information, executing commands, evading detection, etc.

There are two distinct behaviors that can introduce access control weaknesses:


  - Specification: incorrect privileges, permissions, ownership, etc. are explicitly specified for either the user or the resource (for example, setting a password file to be world-writable, or giving administrator capabilities to a guest user). This action could be performed by the program or the administrator.

  - Enforcement: the mechanism contains errors that prevent it from properly enforcing the specified access control requirements (e.g., allowing the user to specify their own privileges, or allowing a syntactically-incorrect ACL to produce insecure settings). This problem occurs within the program itself, in that it does not actually enforce the intended security policy that the administrator specifies.

## Observed Examples

CVE-2022-24985: A form hosting website only checks the session authentication status for a single form, making it possible to bypass authentication when there are multiple forms

CVE-2022-29238: Access-control setting in web-based document collaboration tool is not properly implemented by the code, which prevents listing hidden directories but does not prevent direct requests to files in those directories.

CVE-2022-23607: Python-based HTTP library did not scope cookies to a particular domain such that "supercookies" could be sent to any domain on redirect

CVE-2021-21972: Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV.

CVE-2021-37415: IT management product does not perform authentication for some REST API requests, as exploited in the wild per CISA KEV.

CVE-2021-35033: Firmware for a WiFi router uses a hard-coded password for a BusyBox shell, allowing bypass of authentication through the UART port

CVE-2020-10263: Bluetooth speaker does not require authentication for the debug functionality on the UART port, allowing root shell access

CVE-2020-13927: Default setting in workflow management product allows all API requests without authentication, as exploited in the wild per CISA KEV.

CVE-2010-4624: Bulletin board applies restrictions on number of images during post creation, but does not enforce this on editing.

## Top 25 Examples

CVE-2021-30349: Improper access control sequence for AC database after memory allocation can lead to possible memory corruption in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Voice & Music, Snapdragon Wearables, Snapdragon Wired Infrastructure and Networking

CVE-2022-33243: Memory corruption due to improper access control in Qualcomm IPC.

CVE-2022-25681: Possible memory corruption in kernel while performing memory access due to hypervisor not correctly invalidated the processor translation caches in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2022-42221: Netgear R6220 v1.1.0.114_1.0.1 suffers from Incorrect Access Control, resulting in a command injection vulnerability.

CVE-2022-42460: Broken Access Control vulnerability leading to Stored Cross-Site Scripting (XSS) in Traffic Manager plugin <= 1.4.5 on WordPress.

CVE-2022-33715: Improper access control and path traversal vulnerability in LauncherProvider prior to SMR Aug-2022 Release 1 allow local attacker to access files of One UI.

CVE-2022-45475: Tiny File Manager version 2.4.8 allows an unauthenticated remote attacker to access the application's internal files. This is possible because the application is vulnerable to broken access control. 

CVE-2022-30750: Improper access control vulnerability in updateLastConnectedClientInfo function of SemWifiApClient prior to SMR Jul-2022 Release 1 allows attacker to access wifi ap client mac address that connected.

CVE-2022-30751: Improper access control vulnerability in sendDHCPACKBroadcast function of SemWifiApClient prior to SMR Jul-2022 Release 1 allows attacker to access wifi ap client mac address that connected by using WIFI_AP_STA_DHCPACK_EVENT action.

CVE-2022-30752: Improper access control vulnerability in sendDHCPACKBroadcast function of SemWifiApClient prior to SMR Jul-2022 Release 1 allows attacker to access wifi ap client mac address that connected by using WIFI_AP_STA_STATE_CHANGED action.

CVE-2021-22941: Improper Access Control in Citrix ShareFile storage zones controller before 5.11.20 may allow an unauthenticated attacker to remotely compromise the storage zones controller.

CVE-2021-25369: An improper access control vulnerability in sec_log file prior to SMR MAR-2021 Release 1 exposes sensitive kernel information to userspace.

CVE-2021-0187: Improper access control in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable an escalation of privilege via local access.

CVE-2021-1070: NVIDIA Jetson AGX Xavier Series, Jetson Xavier NX, TX1, TX2, Nano and Nano 2GB, L4T versions prior to 32.5, contains a vulnerability in the apply_binaries.sh script used to install NVIDIA components into the root file system image, in which improper access control is applied, which may lead to an unprivileged user being able to modify system device tree files, leading to denial of service.

CVE-2021-1071: NVIDIA Tegra kernel in Jetson AGX Xavier Series, Jetson Xavier NX, TX1, TX2, Nano and Nano 2GB, all L4T versions prior to r32.5, contains a vulnerability in the INA3221 driver in which improper access control may lead to unauthorized users gaining access to system power usage data, which may lead to information disclosure.

CVE-2021-21471: In CLA-Assistant, versions before 2.8.5, due to improper access control an authenticated user could access API endpoints which are not intended to be used by the user. This could impact the integrity of the application.

CVE-2021-23921: An issue was discovered in Devolutions Server before 2020.3. There is broken access control on Password List entry elements.

CVE-2021-26733: A broken access control vulnerability in the FirstReset_handler_func function of spx_restservice allows an attacker to arbitrarily send reboot commands to the BMC, causing a Denial-of-Service (DoS) condition. This issue affects: Lanner Inc IAC-AST2500A standard firmware version 1.10.0.

CVE-2021-28147: The team sync HTTP API in Grafana Enterprise 6.x before 6.7.6, 7.x before 7.3.10, and 7.4.x before 7.4.5 has an Incorrect Access Control issue. On Grafana instances using an external authentication service and having the EditorsCanAdmin feature enabled, this vulnerability allows any authenticated user to add external groups to any existing team. This can be used to grant a user team permissions that the user isn't supposed to have.

CVE-2021-33104: Improper access control in the Intel(R) OFU software before version 14.1.28 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2021-33126: Improper access control in the firmware for some Intel(R) 700 and 722 Series Ethernet Controllers and Adapters before versions 8.5 and 1.5.5 may allow a privileged user to potentially enable denial of service via local access.

CVE-2021-33128: Improper access control in the firmware for some Intel(R) E810 Ethernet Controllers before version 1.6.0.6 may allow a privileged user to potentially enable denial of service via local access.

CVE-2021-33164: Improper access control in BIOS firmware for some Intel(R) NUCs before version INWHL357.0046 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2021-34401: NVIDIA Linux kernel distributions contain a vulnerability in nvmap NVGPU_IOCTL_CHANNEL_SET_ERROR_NOTIFIER, where improper access control may lead to code execution, compromised integrity, or denial of service.

CVE-2021-34782: A vulnerability in the API endpoints for Cisco DNA Center could allow an authenticated, remote attacker to gain access to sensitive information that should be restricted. The attacker must have valid device credentials. This vulnerability is due to improper access controls on API endpoints. An attacker could exploit the vulnerability by sending a specific API request to an affected application. A successful exploit could allow the attacker to obtain sensitive information about other users who are configured with higher privileges on the application.

CVE-2021-36792: The dated_news (aka Dated News) extension through 5.1.1 for TYPO3 has incorrect Access Control for confirming various applications.

CVE-2021-38417: VISAM VBASE version 11.6.0.6 is vulnerable to improper access control via the web-remote endpoint, which may allow an unauthenticated user viewing access to folders and files in the directory listing.

CVE-2021-39017: IBM Engineering Lifecycle Optimization - Publishing 6.0.6, 6.0.6.1, 7.0, 7.0.1, and 7.0.2 could allow a remote attacker to upload arbitrary files, caused by improper access controls. IBM X-Force ID: 213725.

CVE-2021-42808: Improper Access Control in Thales Sentinel Protection Installer could allow a local user to escalate privileges.

CVE-2021-43996: The Ignition component before 1.16.15, and 2.0.x before 2.0.6, for Laravel has a "fix variable names" feature that can lead to incorrect access control.

CVE-2021-44467: A broken access control vulnerability in the KillDupUsr_func function of spx_restservice allows an attacker to arbitrarily terminate active sessions of other users, causing a Denial-of-Service (DoS) condition. This issue affects: Lanner Inc IAC-AST2500A standard firmware version 1.10.0.

CVE-2021-44719: Docker Desktop 4.3.0 has Incorrect Access Control.

CVE-2021-44776: A broken access control vulnerability in the SubNet_handler_func function of spx_restservice allows an attacker to arbitrarily change the security access rights to KVM and Virtual Media functionalities. This issue affects: Lanner Inc IAC-AST2500A standard firmware version 1.10.0.

CVE-2021-46270: JFrog Artifactory before 7.31.10, is vulnerable to Broken Access Control where a project admin user is able to list all available repository names due to insufficient permission validation.

CVE-2022-20104: In aee daemon, there is a possible information disclosure due to improper access control. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06419017; Issue ID: ALPS06284104.

CVE-2022-20716: A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to gain escalated privileges. This vulnerability is due to improper access control on files within the affected system. A local attacker could exploit this vulnerability by modifying certain files on the vulnerable device. If successful, the attacker could gain escalated privileges and take actions on the system with the privileges of the root user.

CVE-2022-20956: A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow an authenticated, remote attacker to bypass authorization and access system files. This vulnerability is due to improper access control in the web-based management interface of an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to list, download, and delete certain files that they should not have access to. Cisco plans to release software updates that address this vulnerability. https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-access-contol-EeufSUCx ["https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-access-contol-EeufSUCx"] 

CVE-2022-20965: A vulnerability in the web-based management interface of Cisco Identity Services Engine could allow an authenticated, remote attacker to take privileges actions within the web-based management interface. This vulnerability is due to improper access control on a feature within the web-based management interface of the affected system. An attacker could exploit this vulnerability by accessing features through direct requests, bypassing checks within the application. A successful exploit could allow the attacker to take privileged actions within the web-based management interface that should be otherwise restricted. {{value}} ["%7b%7bvalue%7d%7d"])}]] 

CVE-2022-21131: Improper access control for some Intel(R) Xeon(R) Processors may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-21152: Improper access control in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-21163: Improper access control in the Crypto API Toolkit for Intel(R) SGX before version 2.0 commit ID 91ee496 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-22127: Tableau is aware of a broken access control vulnerability present in Tableau Server affecting Tableau Server customers using Local Identity Store for managing users. The vulnerability allows a malicious site administrator to change passwords for users in different sites hosted on the same Tableau Server, resulting in the potential for unauthorized access to data.Tableau Server versions affected are:2020.4.16, 2021.1.13, 2021.2.10, 2021.3.9, 2021.4.4 and earlierNote: All future releases of Tableau Server will address this security issue. Versions that are no longer supported are not tested and may be vulnerable.

CVE-2022-22442: "IBM InfoSphere Information Server 11.7 could allow an authenticated user to access information restricted to users with elevated privileges due to improper access controls. IBM X-Force ID: 224427."

CVE-2022-23144: There is a broken access control vulnerability in ZTE ZXvSTB product. Due to improper permission control, attackers could use this vulnerability to delete the default application type, which affects normal use of system.

CVE-2022-23442: An improper access control vulnerability [CWE-284] in FortiOS versions 6.2.0 through 6.2.11, 6.4.0 through 6.4.8 and 7.0.0 through 7.0.5 may allow an authenticated attacker with a restricted user profile to gather the checksum information about the other VDOMs via CLI commands.

CVE-2022-25338: ownCloud owncloud/android before 2.20 has Incorrect Access Control for physically proximate attackers.

CVE-2022-25339: ownCloud owncloud/android 2.20 has Incorrect Access Control for local attackers.

CVE-2022-25357: Pexip Infinity 27.x before 27.2 has Improper Access Control. An attacker can sometimes join a conference (call join) if it has a lock but not a PIN.

CVE-2022-25679: Denial of service in video due to improper access control in broadcast receivers in Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-25824: Improper access control vulnerability in BixbyTouch prior to version 2.2.00.6 in China models allows untrusted applications to load arbitrary URL and local files in webview.

CVE-2022-25831: Improper access control vulnerability in S Secure prior to SMR Apr-2022 Release 1 allows physical attackers to access secured data in certain conditions.

CVE-2022-25915: Improper access control vulnerability in ELECOM LAN routers (WRC-1167GST2 firmware v1.25 and prior, WRC-1167GST2A firmware v1.25 and prior, WRC-1167GST2H firmware v1.25 and prior, WRC-2533GS2-B firmware v1.52 and prior, WRC-2533GS2-W firmware v1.52 and prior, WRC-1750GS firmware v1.03 and prior, WRC-1750GSV firmware v2.11 and prior, WRC-1900GST firmware v1.03 and prior, WRC-2533GST firmware v1.03 and prior, WRC-2533GSTA firmware v1.03 and prior, WRC-2533GST2 firmware v1.25 and prior, WRC-2533GST2SP firmware v1.25 and prior, WRC-2533GST2-G firmware v1.25 and prior, and EDWRC-2533GST2 firmware v1.25 and prior) allows a network-adjacent authenticated attacker to bypass access restriction and to access the management screen of the product via unspecified vectors.

CVE-2022-26024: Improper access control in the Intel(R) NUC HDMI Firmware Update Tool for NUC7i3DN, NUC7i5DN and NUC7i7DN before version 1.78.2.0.7 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-26090: Improper access control vulnerability in SamsungContacts prior to SMR Apr-2022 Release 1 allows that attackers can access contact information without permission.

CVE-2022-2630: An improper access control issue in GitLab CE/EE affecting all versions starting from 15.2 before 15.2.4, all versions from 15.3 before 15.3.2 allows disclosure of confidential information via the Incident timeline events.

CVE-2022-26308: Pandora FMS v7.0NG.760 and below allows an improper access control in Configuration (Credential store) where a user with the role of Operator (Write) could create, delete, view existing keys which are outside the intended role.

CVE-2022-26343: Improper access control in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-27235: Multiple Broken Access Control vulnerabilities in Social Share Buttons by Supsystic plugin <= 2.2.3 at WordPress.

CVE-2022-27673: Insufficient access controls in the AMD Link Android app may potentially result in information disclosure.

CVE-2022-2792: Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulenrable to CWE-284 Improper Access Control, and stores project data in a directory with improper access control lists.

CVE-2022-28709: Improper access control in the firmware for some Intel(R) E810 Ethernet Controllers before version 1.6.1.9 may allow a privileged user to potentially enable denial of service via local access.

CVE-2022-28758: Zoom On-Premise Meeting Connector MMR before version 4.8.20220815.130 contains an improper access control vulnerability. As a result, a malicious actor could obtain the audio and video feed of a meeting they were not authorized to join and cause other meeting disruptions.

CVE-2022-28759: Zoom On-Premise Meeting Connector MMR before version 4.8.20220815.130 contains an improper access control vulnerability. As a result, a malicious actor could obtain the audio and video feed of a meeting they were not authorized to join and cause other meeting disruptions.

CVE-2022-28760: Zoom On-Premise Meeting Connector MMR before version 4.8.20220815.130 contains an improper access control vulnerability. As a result, a malicious actor could obtain the audio and video feed of a meeting they were not authorized to join and cause other meeting disruptions.

CVE-2022-28761: Zoom On-Premise Meeting Connector MMR before version 4.8.20220916.131 contains an improper access control vulnerability. As a result, a malicious actor in a meeting or webinar they are authorized to join could prevent participants from receiving audio and video causing meeting disruptions.

CVE-2022-28780: Improper access control vulnerability in Weather prior to SMR May-2022 Release 1 allows that attackers can access location information that set in Weather without permission. The patch adds proper protection to prevent access to location information.

CVE-2022-29500: SchedMD Slurm 21.08.x through 20.11.x has Incorrect Access Control that leads to Information Disclosure.

CVE-2022-29501: SchedMD Slurm 21.08.x through 20.11.x has Incorrect Access Control that leads to Escalation of Privileges and code execution.

CVE-2022-29502: SchedMD Slurm 21.08.x through 20.11.x has Incorrect Access Control that leads to Escalation of Privileges.

CVE-2022-29514: Improper access control in the Intel(R) SUR software before version 2.4.8902 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

CVE-2022-3030: An improper access control issue in GitLab CE/EE affecting all versions starting before 15.1.6, all versions from 15.2 before 15.2.4, all versions from 15.3 before 15.3.2 allows disclosure of pipeline status to unauthorized users.

CVE-2022-31476: Improper access control in the Intel(R) SUR software before version 2.4.8902 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-31687: VMware Workspace ONE Assist prior to 22.10 contains a Broken Access Control vulnerability. A malicious actor with network access to Workspace ONE Assist may be able to obtain administrative access without the need to authenticate to the application.

CVE-2022-31704: The vRealize Log Insight contains a broken access control vulnerability. An unauthenticated malicious actor can remotely inject code into sensitive files of an impacted appliance which can result in remote code execution.

CVE-2022-31708: vRealize Operations (vROps) contains a broken access control vulnerability. VMware has evaluated the severity of this issue to be in the Moderate severity range with a maximum CVSSv3 base score of 4.4.

CVE-2022-3182: Improper Access Control vulnerability in the Duo SMS two-factor of Devolutions Remote Desktop Manager 2022.2.14 and earlier allows attackers to bypass the application lock. This issue affects: Devolutions Remote Desktop Manager version 2022.2.14 and prior versions.

CVE-2022-33701: Improper access control vulnerability in KnoxCustomManagerService prior to SMR Jul-2022 Release 1 allows attacker to call PowerManaer.goToSleep method which is protected by system permission by sending braodcast intent.

CVE-2022-33706: Improper access control vulnerability in Samsung Gallery prior to version 13.1.05.8 allows physical attackers to access the pictures using S Pen air gesture.

CVE-2022-33714: Improper access control vulnerability in SemWifiApBroadcastReceiver prior to SMR Aug-2022 Release 1 allows attacker to reset a setting value related to mobile hotspot.

CVE-2022-33718: An improper access control vulnerability in Wi-Fi Service prior to SMR AUG-2022 Release 1 allows untrusted applications to manipulate the list of apps that can use mobile data.

CVE-2022-33731: Improper access control vulnerability in DesktopSystemUI prior to SMR Aug-2022 Release 1 allows attackers to enable and disable arbitrary components.

CVE-2022-33924: Dell Wyse Management Suite 3.6.1 and below contains an Improper Access control vulnerability with which an attacker with no access to create rules could potentially exploit this vulnerability and create rules.

CVE-2022-33925: Dell Wyse Management Suite 3.6.1 and below contains an Improper Access control vulnerability in UI. An remote authenticated attacker could potentially exploit this vulnerability by bypassing access controls in order to download reports containing sensitive information.

CVE-2022-33926: Dell Wyse Management Suite 3.6.1 and below contains an improper access control vulnerability. A remote malicious user could exploit this vulnerability in order to retain access to a file repository after it has been revoked.

CVE-2022-33931: Dell Wyse Management Suite 3.6.1 and below contains an Improper Access control vulnerability in UI. An attacker with no access to Alert Classification page could potentially exploit this vulnerability, leading to the change the alert categories.

CVE-2022-33973: Improper access control in the Intel(R) WAPI Security software for Windows 10/11 before version 22.2150.0.1 may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-34102: Insufficient access control vulnerability was discovered in the Crestron AirMedia Windows Application, version 4.3.1.39, in which a user can pause the uninstallation of an executable to gain a SYSTEM level command prompt.

CVE-2022-34157: Improper access control in the Intel(R) FPGA SDK for OpenCL(TM) with Intel(R) Quartus(R) Prime Pro Edition software before version 22.1 may allow authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-34259: Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An attacker could leverage this vulnerability to impact the availability of a user's minor feature. Exploitation of this issue does not require user interaction.

CVE-2022-34854: Improper access control in the Intel(R) SUR software before version 2.4.8902 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-34894: In JetBrains Hub before 2022.2.14799, insufficient access control allowed the hijacking of untrusted services

CVE-2022-35276: Improper access control in BIOS firmware for some Intel(R) NUC 8 Compute Elements before version CBWHL357.0096 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-35689: Adobe Commerce versions 2.4.4-p1 (and earlier) and 2.4.5 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An attacker could leverage this vulnerability to impact the availability of a user's minor feature. Exploitation of this issue does not require user interaction.

CVE-2022-36369: Improper access control in some QATzip software maintained by Intel(R) before version 1.0.9 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-36425: Broken Access Control vulnerability in Beaver Builder plugin <= 2.5.4.3 at WordPress.

CVE-2022-36789: Improper access control in BIOS firmware for some Intel(R) NUC 10 Performance Kits and Intel(R) NUC 10 Performance Mini PCs before version FNCML357.0053 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-36851: Improper access control vulnerability in Samsung pass prior to version 4.0.03.1 allow physical attackers to access data of Samsung pass on a certain state of an unlocked device.

CVE-2022-36864: Improper access control and intent redirection in Samsung Email prior to 6.1.70.20 allows attacker to access specific formatted file and execute privileged behavior.

CVE-2022-36865: Improper access control in Group Sharing prior to versions 13.0.6.15 in Android S(12), 13.0.6.14 in Android R(11) and below allows attackers to access device information.

CVE-2022-36866: Improper access control vulnerability in Broadcaster in Group Sharing prior to versions 13.0.6.15 in Android S(12), 13.0.6.14 in Android R(11) and below allows attackers to identify the device.

CVE-2022-36867: Improper access control vulnerability in Editor Lite prior to version 4.0.40.14 allows attackers to access sensitive information.

CVE-2022-36869: Improper access control vulnerability in ContactsDumpActivity of?Contacts Provider prior to version 12.7.59 allows attacker to access the file without permission.

CVE-2022-38134: Authenticated (subscriber+) Broken Access Control vulnerability in Customer Reviews for WooCommerce plugin <= 5.3.5 at WordPress.

CVE-2022-38135: Broken Access Control vulnerability in Dean Oakley's Photospace Gallery plugin <= 2.3.5 at WordPress allows users with subscriber or higher role to change plugin settings.

CVE-2022-38184: There is an improper access control vulnerability in Portal for ArcGIS versions 10.8.1 and below which could allow a remote, unauthenticated attacker to access an API that may induce Esri Portal for ArcGIS to read arbitrary URLs.

CVE-2022-38377: An improper access control vulnerability [CWE-284] in FortiManager 7.2.0, 7.0.0 through 7.0.3, 6.4.0 through 6.4.7, 6.2.0 through 6.2.9, 6.0.0 through 6.0.11 and FortiAnalyzer 7.2.0, 7.0.0 through 7.0.3, 6.4.0 through 6.4.8, 6.2.0 through 6.2.10, 6.0.0 through 6.0.12 may allow a remote and authenticated admin user assigned to a specific ADOM to access other ADOMs information such as device information and dashboard information.

CVE-2022-38380: An improper access control [CWE-284] vulnerability in FortiOS version 7.2.0 and versions 7.0.0 through 7.0.7 may allow a remote authenticated read-only user to modify the interface settings via the API.

CVE-2022-38743: Rockwell Automation FactoryTalk VantagePoint versions 8.0, 8.10, 8.20, 8.30, 8.31 are vulnerable to an improper access control vulnerability. The FactoryTalk VantagePoint SQL Server account could allow a malicious user with read-only privileges to execute SQL statements in the back-end database. If successfully exploited, this could allow the attacker to execute arbitrary code and gain access to restricted data.

CVE-2022-38974: Broken Access Control vulnerability in WPML Multilingual CMS premium plugin <= 4.5.10 on WordPress allows users with subscriber or higher user roles to change the status of the translation jobs.

CVE-2022-39019:  Broken access controls on PDFtron WebviewerUI in M-Files Hubshare before 3.3.11.3 allows unauthenticated attackers to upload malicious files to the application server. 

CVE-2022-39070: There is an access control vulnerability in some ZTE PON OLT products. Due to improper access control settings, remote attackers could use the vulnerability to log in to the device and execute any operation.

CVE-2022-3917: Improper access control of bootloader function was discovered in Motorola Mobility Motorola e20 prior to version RONS31.267-38-8 allows attacker with local access to read partition or RAM data.

CVE-2022-39849: Improper access control in knox_vpn_policy service prior to SMR Oct-2022 Release 1 allows allows unauthorized read of configuration data.

CVE-2022-39850: Improper access control in mum_container_policy service prior to SMR Oct-2022 Release 1 allows allows unauthorized read of configuration data.

CVE-2022-39851: Improper access control vulnerability in CocktailBarService prior to SMR Oct-2022 Release 1 allows local attacker to bind service that require BIND_REMOTEVIEWS permission.

CVE-2022-39855: Improper access control vulnerability in FACM application prior to SMR Oct-2022 Release 1 allows a local attacker to connect arbitrary AP and Bluetooth devices.

CVE-2022-39856: Improper access control vulnerability in imsservice application prior to SMR Oct-2022 Release 1 allows local attackers to access call information.

CVE-2022-39857: Improper access control vulnerability in CameraTestActivity in FactoryCameraFB prior to version 3.5.51 allows attackers to access broadcasting Intent as system uid privilege.

CVE-2022-39860: Improper access control vulnerability in QuickShare prior to version 13.2.3.5 allows attackers to access sensitive information via implicit broadcast.

CVE-2022-39864: Improper access control vulnerability in WifiSetupLaunchHelper in SmartThings prior to version 1.7.89.25 allows attackers to access sensitive information via implicit intent.

CVE-2022-39865: Improper access control vulnerability in ContentsSharingActivity.java SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via implicit broadcast.

CVE-2022-39866: Improper access control vulnerability in RegisteredEventMediator.kt SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via implicit broadcast.

CVE-2022-39867: Improper access control vulnerability in cloudNotificationManager.java SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via SHOW_PERSISTENT_BANNER broadcast.

CVE-2022-39868: Improper access control vulnerability in GedSamsungAccount.kt SmartThings prior to version 1.7.89.0 allows attackers to access sensitive information via implicit broadcast.

CVE-2022-39884: Improper access control vulnerability in IImsService prior to SMR Nov-2022 Release 1 allows local attacker to access to Call information.

CVE-2022-39889: Improper access control vulnerability in GalaxyWatch4Plugin prior to versions 2.2.11.22101351 and 2.2.12.22101351 allows attackers to access wearable device information.

CVE-2022-39898: Improper access control vulnerability in IIccPhoneBook prior to SMR Dec-2022 Release 1 allows attackers to access some information of usim.

CVE-2022-39900: Improper access control vulnerability in Nice Catch prior to SMR Dec-2022 Release 1 allows physical attackers to access contents of all toast generated in the application installed in Secure Folder through Nice Catch.

CVE-2022-39906: Improper access control vulnerability in SecTelephonyProvider prior to SMR Dec-2022 Release 1 allows attackers to access message information.

CVE-2022-39910: Improper access control vulnerability in Samsung Pass prior to version 4.0.06.7 allow physical attackers to access data of Samsung Pass on a certain state of an unlocked device using pop-up view.

CVE-2022-40196: Improper access control in the Intel(R) oneAPI DPC++/C++ Compiler before version 2022.2.1 and Intel C++ Compiler Classic before version 2021.7.1 for some Intel(R) oneAPI Toolkits before version 2022.3.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-40231: IBM Sterling B2B Integrator Standard Edition 6.0.0.0 through 6.0.3.7 and 6.1.0.0 through 6.1.2.0 could allow an authenticated user to perform unauthorized actions due to improper access controls. IBM X-Force ID: 235533.

CVE-2022-41781: Broken Access Control vulnerability in Permalink Manager Lite plugin <= 2.2.20 on WordPress.

CVE-2022-41839: Broken Access Control vulnerability in WordPress LoginPress plugin <= 1.6.2 on WordPress leading to unauth. changing of Opt-In or Opt-Out tracking settings.

CVE-2022-42461: Broken Access Control vulnerability in miniOrange's Google Authenticator plugin <= 5.6.1 on WordPress.

CVE-2022-44211: In GL.iNet Goodcloud 1.1 Incorrect access control allows a remote attacker to access/change devices' settings.

CVE-2022-44801: D-Link DIR-878 1.02B05 is vulnerable to Incorrect Access Control.

CVE-2022-45066: Auth. (subscriber+) Broken Access Control vulnerability in WooSwipe WooCommerce Gallery plugin <= 2.0.1 on WordPress.

CVE-2022-45369: Auth. (subscriber+) Broken Access Control vulnerability in Plugin for Google Reviews plugin <= 2.2.2 on WordPress.

CVE-2022-46676:  Wyse Management Suite 3.8 and below contain an improper access control vulnerability. A malicious admin user can disable or delete users under administration and unassigned admins for which the group admin is not authorized. 

CVE-2022-46677:  Wyse Management Suite 3.8 and below contain an improper access control vulnerability with which an custom group admin can create a subgroup under a group for which the admin is not authorized. 

CVE-2022-46678:  Wyse Management Suite 3.8 and below contain an improper access control vulnerability. A authenticated malicious admin user can edit general client policy for which the user is not authorized. 

CVE-2022-46754:  Wyse Management Suite 3.8 and below contain an improper access control vulnerability. A authenticated malicious admin user might access certain pro license features for which this admin is not authorized in order to configure user controlled external entities. 

CVE-2022-46755:  Wyse Management Suite 3.8 and below contain an improper access control vulnerability. A authenticated malicious admin user can edit general client policy for which the user is not authorized. 

CVE-2022-46892: In Ampere AltraMax and Ampere Altra before 2.10c, improper access controls allows the OS to reinitialize a disabled root complex.

CVE-2022-47070: NVS365 V01 is vulnerable to Incorrect Access Control. After entering a wrong password, the url will be sent to the server twice. In the second package, the server will return the correct password information.

CVE-2022-48305: There is an identity authentication bypass vulnerability in Huawei Children Smart Watch (Simba-AL00) 1.1.1.274. Successful exploitation of this vulnerability may cause the access control function of specific applications to fail.

CVE-2021-1957: Improper Access Control when ACL link encryption is failed and ACL link is not disconnected during reconnection with paired device in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music

CVE-2022-38769: The mobile application in Transtek Mojodat FAM (Fixed Asset Management) 2.4.6 allows remote attackers to fetch cleartext passwords upon a successful login request.

CVE-2022-22183: An Improper Access Control vulnerability in Juniper Networks Junos OS Evolved allows a network-based unauthenticated attacker who is able to connect to a specific open IPv4 port, which in affected releases should otherwise be unreachable, to cause the CPU to consume all resources as more traffic is sent to the port to create a Denial of Service (DoS) condition. Continued receipt and processing of these packets will create a sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS Evolved 20.4 versions prior to 20.4R3-S2-EVO; 21.1 versions prior to 21.1R3-S1-EVO; 21.2 versions prior to 21.2R3-EVO; 21.3 versions prior to 21.3R2-EVO; 21.4 versions prior to 21.4R2-EVO. This issue does not affect Junos OS.

CVE-2022-33969: Authenticated WordPress Options Change vulnerability in Biplob Adhikari's Flipbox plugin <= 2.6.0 at WordPress.

CVE-2022-33970: Authenticated WordPress Options Change vulnerability in Biplob018 Shortcode Addons plugin <= 3.1.2 at WordPress.

CVE-2022-34868: Authenticated Arbitrary Settings Update vulnerability in YooMoney ?Kassa ??? WooCommerce plugin <= 2.3.0 at WordPress.

CVE-2022-35242: Unauthenticated plugin settings change vulnerability in 59sec THE Leads Management System: 59sec LITE plugin <= 3.4.1 at WordPress.

CVE-2022-36375: Authenticated (high role user) WordPress Options Change vulnerability in Biplob Adhikari's Tabs plugin <= 3.6.0 at WordPress.

CVE-2022-35238: Unauthenticated Plugin Settings Change vulnerability in Awesome Filterable Portfolio plugin <= 1.9.7 at WordPress.

CVE-2021-23188: Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-1105: An improper access control vulnerability in GitLab CE/EE affecting all versions from 13.11 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allows an unauthorized user to access pipeline analytics even when public pipelines are disabled

CVE-2022-21140: Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi products may allow a privileged user to potentially enable information disclosure via local access.

CVE-2022-21148: Improper access control in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-21153: Improper access control in the Intel(R) Capital Global Summit Android application may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-21157: Improper access control in the Intel(R) Smart Campus Android application before version 6.1 may allow authenticated user to potentially enable information disclosure via local access.

CVE-2022-21174: Improper access control in a third-party component of Intel(R) Quartus(R) Prime Pro Edition before version 21.3 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-21812: Improper access control in the Intel(R) HAXM software before version 7.7.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-21825: An Improper Access Control vulnerability exists in Citrix Workspace App for Linux 2012 - 2111 with App Protection installed that can allow an attacker to perform local privilege escalation.

CVE-2022-22282: SonicWall SMA1000 series firmware 12.4.0, 12.4.1-02965 and earlier versions incorrectly restricts access to a resource using HTTP connections from an unauthorized actor leading to Improper Access Control vulnerability.

CVE-2022-23182: Improper access control in the Intel(R) Data Center Manager software before version 4.1 may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2022-23433: Improper access control vulnerability in Reminder prior to versions 12.3.01.3000 in Android S(12), 12.2.05.6000 in Android R(11) and 11.6.08.6000 in Andoid Q(10) allows attackers to register reminders or execute exporeted activities remotely.

CVE-2022-23443: An improper access control in Fortinet FortiSOAR before 7.2.0 allows unauthenticated attackers to access gateway API data via crafted HTTP GET requests.

CVE-2022-23994: An Improper access control vulnerability in StBedtimeModeReceiver in Wear OS 3.0 prior to Firmware update Feb-2022 Release allows untrusted applications to change bedtime mode without a proper permission.

CVE-2022-24923: Improper access control vulnerability in Samsung SearchWidget prior to versions 2.3.00.6 in China models allows untrusted applications to load arbitrary URL and local files in webview.

CVE-2022-24924: An improper access control in LiveWallpaperService prior to versions 3.0.9.0 allows to create a specific named system directory without a proper permission.

CVE-2022-24930: An Improper access control vulnerability in StRetailModeReceiver in Wear OS 3.0 prior to Firmware update MAR-2022 Release allows untrusted applications to reset default app settings without a proper permission

CVE-2022-24931: Improper access control vulnerability in dynamic receiver in ApkInstaller prior to SMR MAR-2022 Release allows unauthorized attackers to execute arbitrary activity without a proper permission

CVE-2022-25214: Improper access control on the LocalClientList.asp interface allows an unauthenticated remote attacker to obtain sensitive information concerning devices on the local area network, including IP and MAC addresses. Improper access control on the wirelesssetup.asp interface allows an unauthenticated remote attacker to obtain the WPA passphrases for the 2.4GHz and 5.0GHz wireless networks. This is particularly dangerous given that the K2G setup wizard presents the user with the option of using the same password for the 2.4Ghz network and the administrative interface, by clicking a checkbox. When Remote Managment is enabled, these endpoints are exposed to the WAN.

CVE-2022-25215: Improper access control on the LocalMACConfig.asp interface allows an unauthenticated remote attacker to add (or remove) client MAC addresses to (or from) a list of banned hosts. Clients with those MAC addresses are then prevented from accessing either the WAN or the router itself.

CVE-2022-25649: Multiple Improper Access Control vulnerabilities in StoreApps Affiliate For WooCommerce premium plugin <= 4.7.0 at WordPress.

CVE-2022-25966: Improper access control in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-26017: Improper access control in the Intel(R) DSA software for before version 22.2.14 may allow an authenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2022-26949: Archer 6.x through 6.9 SP2 P1 (6.9.2.1) contains an improper access control vulnerability on attachments. A remote authenticated malicious user could potentially exploit this vulnerability to gain access to files that should only be allowed by extra privileges.

CVE-2022-27838: Improper access control vulnerability in FactoryCamera prior to version 2.1.96 allows attacker to access the file with system privilege.

CVE-2022-28704: Improper access control vulnerability in Rakuten Casa version AP_F_V1_4_1 or AP_F_V2_0_0 allows a remote attacker to log in with the root privilege and perform an arbitrary operation if the product is in its default settings in which is set to accept SSH connections from the WAN side, and is also connected to the Internet with the authentication information unchanged from the default settings.

CVE-2022-28753: Zoom On-Premise Meeting Connector MMR before version 4.8.129.20220714 contains an improper access control vulnerability. As a result, a malicious actor can join a meeting which they are authorized to join without appearing to the other participants, can admit themselves into the meeting from the waiting room, and can become host and cause other meeting disruptions.

CVE-2022-28754: Zoom On-Premise Meeting Connector MMR before version 4.8.129.20220714 contains an improper access control vulnerability. As a result, a malicious actor can join a meeting which they are authorized to join without appearing to the other participants, can admit themselves into the meeting from the waiting room, and can become host and cause other meeting disruptions.

CVE-2022-28775: Improper access control vulnerability in Samsung Flow prior to version 4.8.06.5 allows attacker to write the file without Samsung Flow permission.

CVE-2022-28776: Improper access control vulnerability in Galaxy Store prior to version 4.5.36.4 allows attacker to install applications from Galaxy Store without user interactions.

CVE-2022-28777: Improper access control vulnerability in Samsung Members prior to version 13.6.08.5 allows local attacker to execute call function without CALL_PHONE permission.

CVE-2022-28778: Improper access control vulnerability in Samsung Security Supporter prior to version 1.2.40.0 allows attacker to set the arbitrary folder as Secret Folder without Samsung Security Supporter permission

CVE-2022-28782: Improper access control vulnerability in Contents To Window prior to SMR May-2022 Release 1 allows physical attacker to install package before completion of Setup wizard. The patch blocks entry point of the vulnerability.

CVE-2022-30584: Archer Platform 6.3 before 6.11 (6.11.0.0) contains an Improper Access Control Vulnerability within SSO ADFS functionality that could potentially be exploited by malicious users to compromise the affected system. 6.10 P3 (6.10.0.3) and 6.9 SP3 P4 (6.9.3.4) are also fixed releases.

CVE-2022-30731: Improper access control vulnerability in My Files prior to version 13.1.00.193 allows attackers to access arbitrary private files in My Files application.

CVE-2022-30745: Improper access control vulnerability in Quick Share prior to version 13.1.2.4 allows attacker to access internal files in Quick Share.

CVE-2022-31884: Marval MSM v14.19.0.12476 has an Improper Access Control vulnerability which allows a low privilege user to delete other users API Keys including high privilege and the Administrator users API Keys.

CVE-2022-3325: Improper access control in the GitLab CE/EE API affecting all versions starting from 12.8 before 15.2.5, all versions starting from 15.3 before 15.3.4, all versions starting from 15.4 before 15.4.1. Allowed for editing the approval rules via the API by an unauthorised user.

CVE-2022-33689: Improper access control vulnerability in TelephonyUI prior to SMR Jul-2022 Release 1 allows attackers to change preferred network type by unprotected binder call.

CVE-2022-34434: Cloud Mobility for Dell Storage versions 1.3.0 and earlier contains an Improper Access Control vulnerability within the Postgres database. A threat actor with root level access to either the vApp or containerized versions of Cloud Mobility may potentially exploit this vulnerability, leading to the modification or deletion of tables that are required for many of the core functionalities of Cloud Mobility. Exploitation may lead to the compromise of integrity and availability of the normal functionality of the Cloud Mobility application.

CVE-2022-34827: Carel Boss Mini 1.5.0 has Improper Access Control.

CVE-2022-36832: Improper access control vulnerability in WebApp in Cameralyzer prior to versions 3.2.22, 3.3.22, 3.4.22 and 3.5.51 allows attackers to access external storage as Cameralyzer privilege.

CVE-2022-38388: IBM Navigator Mobile Android 3.4.1.1 and 3.4.1.2 app could allow a local user to obtain sensitive information due to improper access control. IBM X-Force ID: 233968.

CVE-2022-39877: Improper access control vulnerability in ProfileSharingAccount in Group Sharing prior to versions 13.0.6.15 in Android S(12), 13.0.6.14 in Android R(11) and below allows attackers to identify the device.

CVE-2022-41799: Improper access control vulnerability in GROWI prior to v5.1.4 (v5 series) and versions prior to v4.5.25 (v4 series) allows a remote authenticated attacker to bypass access restriction and download the markdown data from the pages set to private by the other users.

CVE-2022-39887: Improper access control vulnerability in clearAllGlobalProxy in MiscPolicy prior to SMR Nov-2022 Release 1 allows local attacker to configure EDM setting.

CVE-2022-21182: A privilege escalation vulnerability exists in the router configuration import functionality of InHand Networks InRouter302 V3.5.4. A specially-crafted HTTP request can lead to increased privileges. An attacker can send an HTTP request to trigger this vulnerability.

CVE-2022-22394: The IBM Spectrum Protect 8.1.14.000 server could allow a remote attacker to bypass security restrictions, caused by improper enforcement of access controls. By signing in, an attacker could exploit this vulnerability to bypass security and gain unauthorized administrator or node access to the vulnerable server.

CVE-2022-23708: A flaw was discovered in Elasticsearch 7.17.0’s upgrade assistant, in which upgrading from version 6.x to 7.x would disable the in-built protections on the security index, allowing authenticated users with “*” index permissions access to this index.

CVE-2022-31257: A vulnerability has been identified in Mendix Applications using Mendix 7 (All versions < V7.23.31), Mendix Applications using Mendix 8 (All versions < V8.18.18), Mendix Applications using Mendix 9 (All versions < V9.14.0), Mendix Applications using Mendix 9 (V9.12) (All versions < V9.12.2), Mendix Applications using Mendix 9 (V9.6) (All versions < V9.6.12). In case of access to an active user session in an application that is built with an affected version, it’s possible to change that user’s password bypassing password validations within a Mendix application. This could allow to set weak passwords.

CVE-2022-31496: LibreHealth EHR Base 2.0.0 allows incorrect interface/super/manage_site_files.php access.

CVE-2022-38058: Authenticated (subscriber+) Plugin Setting change vulnerability in WP Shamsi plugin <= 4.1.1 at WordPress.

CVE-2022-38070: Privilege Escalation (subscriber+) vulnerability in Pop-up plugin <= 1.1.5 at WordPress.

CVE-2022-28612: Improper Access Control vulnerability leading to multiple Authenticated (contributor or higher user role) Stored Cross-Site Scripting (XSS) vulnerabilities in Muneeb's Custom Popup Builder plugin <= 1.3.1 at WordPress.

CVE-2022-29417: Plugin Settings Update vulnerability in ShortPixel's ShortPixel Adaptive Images plugin <= 3.3.1 at WordPress allows an attacker with a low user role like a subscriber or higher to change the plugin settings.

CVE-2022-3186: Dataprobe iBoot-PDU FW versions prior to 1.42.06162022 contain a vulnerability where the affected product allows an attacker to access the device’s main management page from the cloud. This feature enables users to remotely connect devices, however, the current implementation permits users to access other device's information. 

CVE-2022-3735: A vulnerability was found in seccome Ehoney. It has been rated as critical. This issue affects some unknown processing of the file /api/public/signup. The manipulation leads to improper access controls. The identifier VDB-212417 was assigned to this vulnerability.

CVE-2022-41261: SAP Solution Manager (Diagnostic Agent) - version 7.20, allows an authenticated attacker on Windows system to access a file containing sensitive data which can be used to access a configuration file which contains credentials to access other system files. Successful exploitation can make the attacker access files and systems for which he/she is not authorized.

CVE-2022-43494:  An unauthorized user could be able to read any file on the system, potentially exposing sensitive information. 

CVE-2022-46331:  An unauthorized user could possibly delete any file on the system. 

CVE-2022-46664: A vulnerability has been identified in Mendix Workflow Commons (All versions < V2.4.0), Mendix Workflow Commons V2.1 (All versions < V2.1.4), Mendix Workflow Commons V2.3 (All versions < V2.3.2). Affected versions of the module improperly handle access control for some module entities. This could allow authenticated remote attackers to read or delete sensitive information.

CVE-2022-4700: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_activate_required_theme' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to activate the 'royal-elementor-kit' theme. If no such theme is installed doing so can also impact site availability as the site attempts to load a nonexistent theme.

CVE-2022-4702: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_fix_royal_compatibility' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to deactivate every plugin on the site unless it is part of an extremely limited hardcoded selection. This also switches the site to the 'royal-elementor-kit' theme, potentially resulting in availability issues.

CVE-2022-4703: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_reset_previous_import' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to reset previously imported data.

CVE-2022-4704: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_import_templates_kit' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to import preset site configuration templates including images and settings.

CVE-2022-4705: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_final_settings_setup' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to finalize activation of preset site configuration templates, which can be chosen and imported via a separate action documented in CVE-2022-4704.

CVE-2022-4708: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_save_template_conditions' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to modify the conditions under which templates are displayed.

CVE-2022-4709: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_import_library_template' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to import and activate templates from the plugin's template library.

CVE-2022-4711: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_save_mega_menu_settings' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to enable and modify Mega Menu settings for any menu item.

CVE-2021-30947: An access issue was addressed with additional sandbox restrictions. This issue is fixed in macOS Big Sur 11.6.2, tvOS 15.2, macOS Monterey 12.1, iOS 15.2 and iPadOS 15.2, watchOS 8.3. An application may be able to access a user's files.

CVE-2021-30988: Description: A permissions issue was addressed with improved validation. This issue is fixed in iOS 15.2 and iPadOS 15.2. A malicious application may be able to identify what other applications a user has installed.

CVE-2021-40005: The distributed data service component has a vulnerability in data access control. Successful exploitation of this vulnerability may affect data confidentiality.

CVE-2022-25986: Browse restriction bypass vulnerability in Scheduler of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to obtain the data of Scheduler.

CVE-2022-29471: Browse restriction bypass vulnerability in Bulletin of Cybozu Garoon allows a remote authenticated attacker to obtain the data of Bulletin.

CVE-2022-38770: The mobile application in Transtek Mojodat FAM (Fixed Asset Management) 2.4.6 allows remote attackers to fetch other users' data upon a successful login request.

CVE-2022-44929: An access control issue in D-Link DVG-G5402SP GE_1.03 allows unauthenticated attackers to escalate privileges via arbitrarily editing VoIP SIB profiles.

CVE-2022-32430: An access control issue in Lin CMS Spring Boot v0.2.1 allows attackers to access the backend information and functions within the application.

CVE-2022-0541: The flo-launch WordPress plugin before 2.4.1 injects code into wp-config.php when creating a cloned site, allowing any attacker to initiate a new site install by setting the flo_custom_table_prefix cookie to an arbitrary value.

CVE-2022-1656: Vulnerable versions of the JupiterX Theme (<=2.0.6) allow any logged-in user, including subscriber-level users, to access any of the functions registered in lib/api/api/ajax.php, which also grant access to the jupiterx_api_ajax_ actions registered by the JupiterX Core Plugin (<=2.0.6). This includes the ability to deactivate arbitrary plugins as well as update the theme’s API key.

CVE-2022-2088: An authenticated user with admin privileges may be able to terminate any process on the system running Elcomplus SmartICS v2.3.4.0.

CVE-2022-27660: A denial of service vulnerability exists in the confctl_set_guest_wlan functionality of TCL LinkHub Mesh Wi-Fi MS1G_00_01.00_14. A specially-crafted network packet can lead to denial of service. An attacker can send packets to trigger this vulnerability.

CVE-2022-20696: A vulnerability in the binding configuration of Cisco SD-WAN vManage Software containers could allow an unauthenticated, adjacent attacker who has access to the VPN0 logical network to also access the messaging service ports on an affected system. This vulnerability exists because the messaging server container ports on an affected system lack sufficient protection mechanisms. An attacker could exploit this vulnerability by connecting to the messaging service ports of the affected system. To exploit this vulnerability, the attacker must be able to send network traffic to interfaces within the VPN0 logical network. This network may be restricted to protect logical or physical adjacent networks, depending on device deployment configuration. A successful exploit could allow the attacker to view and inject messages into the messaging service, which can cause configuration changes or cause the system to reload.

CVE-2022-25650: A vulnerability has been identified in Mendix Applications using Mendix 7 (All versions < V7.23.27), Mendix Applications using Mendix 8 (All versions < V8.18.14), Mendix Applications using Mendix 9 (All versions < V9.12.0), Mendix Applications using Mendix 9 (V9.6) (All versions < V9.6.3). When querying the database, it is possible to sort the results using a protected field. With this an authenticated attacker could extract information about the contents of a protected field.

CVE-2022-25755: A vulnerability has been identified in SCALANCE X302-7 EEC (230V), SCALANCE X302-7 EEC (230V, coated), SCALANCE X302-7 EEC (24V), SCALANCE X302-7 EEC (24V, coated), SCALANCE X302-7 EEC (2x 230V), SCALANCE X302-7 EEC (2x 230V, coated), SCALANCE X302-7 EEC (2x 24V), SCALANCE X302-7 EEC (2x 24V, coated), SCALANCE X304-2FE, SCALANCE X306-1LD FE, SCALANCE X307-2 EEC (230V), SCALANCE X307-2 EEC (230V, coated), SCALANCE X307-2 EEC (24V), SCALANCE X307-2 EEC (24V, coated), SCALANCE X307-2 EEC (2x 230V), SCALANCE X307-2 EEC (2x 230V, coated), SCALANCE X307-2 EEC (2x 24V), SCALANCE X307-2 EEC (2x 24V, coated), SCALANCE X307-3, SCALANCE X307-3, SCALANCE X307-3LD, SCALANCE X307-3LD, SCALANCE X308-2, SCALANCE X308-2, SCALANCE X308-2LD, SCALANCE X308-2LD, SCALANCE X308-2LH, SCALANCE X308-2LH, SCALANCE X308-2LH+, SCALANCE X308-2LH+, SCALANCE X308-2M, SCALANCE X308-2M, SCALANCE X308-2M PoE, SCALANCE X308-2M PoE, SCALANCE X308-2M TS, SCALANCE X308-2M TS, SCALANCE X310, SCALANCE X310, SCALANCE X310FE, SCALANCE X310FE, SCALANCE X320-1 FE, SCALANCE X320-1-2LD FE, SCALANCE X408-2, SCALANCE XR324-12M (230V, ports on front), SCALANCE XR324-12M (230V, ports on front), SCALANCE XR324-12M (230V, ports on rear), SCALANCE XR324-12M (230V, ports on rear), SCALANCE XR324-12M (24V, ports on front), SCALANCE XR324-12M (24V, ports on front), SCALANCE XR324-12M (24V, ports on rear), SCALANCE XR324-12M (24V, ports on rear), SCALANCE XR324-12M TS (24V), SCALANCE XR324-12M TS (24V), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (24V, ports on front), SCALANCE XR324-4M EEC (24V, ports on front), SCALANCE XR324-4M EEC (24V, ports on rear), SCALANCE XR324-4M EEC (24V, ports on rear), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on front), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (2x 100-240VAC/60-250VDC, ports on rear), SCALANCE XR324-4M EEC (2x 24V, ports on front), SCALANCE XR324-4M EEC (2x 24V, ports on front), SCALANCE XR324-4M EEC (2x 24V, ports on rear), SCALANCE XR324-4M EEC (2x 24V, ports on rear), SCALANCE XR324-4M PoE (230V, ports on front), SCALANCE XR324-4M PoE (230V, ports on rear), SCALANCE XR324-4M PoE (24V, ports on front), SCALANCE XR324-4M PoE (24V, ports on rear), SCALANCE XR324-4M PoE TS (24V, ports on front), SIPLUS NET SCALANCE X308-2. The webserver of an affected device is missing specific security headers. This could allow an remote attacker to extract confidential session information under certain circumstances.

CVE-2022-27822: Information exposure vulnerability in ril property setting prior to SMR April-2022 Release 1 allows access to EF_RUIMID value without permission.

CVE-2022-36875: Improper restriction of broadcasting Intent in SaWebViewRelayActivity of?Waterplugin prior to version 2.2.11.22081151 allows attacker to access the file without permission.

CVE-2022-47410: An issue was discovered in the fp_newsletter (aka Newsletter subscriber management) extension before 1.1.1, 1.2.0, 2.x before 2.1.2, 2.2.1 through 2.4.0, and 3.x before 3.2.6 for TYPO3. Data about subscribers may be obtained via createAction operations.

CVE-2022-47411: An issue was discovered in the fp_newsletter (aka Newsletter subscriber management) extension before 1.1.1, 1.2.0, 2.x before 2.1.2, 2.2.1 through 2.4.0, and 3.x before 3.2.6 for TYPO3. Data about subscribers may be obtained via unsubscribeAction operations.

CVE-2022-24309: A vulnerability has been identified in Mendix Applications using Mendix 7 (All versions < V7.23.29), Mendix Applications using Mendix 8 (All versions < V8.18.16), Mendix Applications using Mendix 9 (All versions < V9.13 only with Runtime Custom Setting *DataStorage.UseNewQueryHandler* set to False). If an entity has an association readable by the user, then in some cases, Mendix Runtime may not apply checks for XPath constraints that parse said associations, within apps running on affected versions. A malicious user could use this to dump and manipulate sensitive data.

CVE-2021-46304: A vulnerability has been identified in CP-8000 MASTER MODULE WITH I/O -25/+70°C (All versions), CP-8000 MASTER MODULE WITH I/O -40/+70°C (All versions), CP-8021 MASTER MODULE (All versions), CP-8022 MASTER MODULE WITH GPRS (All versions). The component allows to activate a web server module which provides unauthenticated access to its web pages. This could allow an attacker to retrieve debug-level information from the component such as internal network topology or connected systems.

CVE-2022-1716: Keep My Notes v1.80.147 allows an attacker with physical access to the victim's device to bypass the application's password/pin lock to access user data. This is possible due to lack of adequate security controls to prevent dynamic code manipulation.

CVE-2022-44037: An access control issue in APsystems ENERGY COMMUNICATION UNIT (ECU-C) Power Control Software V4.1NA, V3.11.4, W2.1NA, V4.1SAA, C1.2.2 allows attackers to access sensitive data and execute specific commands and functions with full admin rights without authenticating allows him to perform multiple attacks, such as attacking wireless network in the product's range.

CVE-2022-33311: Browse restriction bypass vulnerability in Address Book of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to obtain the data of Address Book via unspecified vectors.

CVE-2022-38461: Broken Access Control vulnerability in WPML Multilingual CMS premium plugin <= 4.5.10 on WordPress allows users with a subscriber or higher user role to change plugin settings (selected language for legacy widgets, the default behavior for media content).

CVE-2021-26732: A broken access control vulnerability in the First_network_func function of spx_restservice allows an attacker to arbitrarily change the network configuration of the BMC. This issue affects: Lanner Inc IAC-AST2500A standard firmware version 1.10.0.

CVE-2022-24595: Automotive Grade Linux Kooky Koi 11.0.0, 11.0.1, 11.0.2, 11.0.3, 11.0.4, and 11.0.5 is affected by Incorrect Access Control in usr/bin/afb-daemon. To exploit the vulnerability, an attacker should send a well-crafted HTTP (or WebSocket) request to the socket listened by the afb-daemon process. No credentials nor user interactions are required.

CVE-2022-28165: A vulnerability in the role-based access control (RBAC) functionality of the Brocade SANNav before 2.2.0 could allow an authenticated, remote attacker to access resources that they should not be able to access and perform actions that they should not be able to perform. The vulnerability exists because restrictions are not performed on Server side to ensure the user has required permission before processing requests.

CVE-2022-36427: Missing Access Control vulnerability in About Rentals. Inc. About Rentals plugin <= 1.5 at WordPress.

CVE-2022-37344: Missing Access Control vulnerability in PHP Crafts Accommodation System plugin <= 1.0.1 at WordPress.

CVE-2021-33504: Couchbase Server before 7.1.0 has Incorrect Access Control.

CVE-2022-20777: Multiple vulnerabilities in Cisco Enterprise NFV Infrastructure Software (NFVIS) could allow an attacker to escape from the guest virtual machine (VM) to the host machine, inject commands that execute at the root level, or leak system data from the host to the VM. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-21706: Zulip is an open-source team collaboration tool with topic-based threading. Zulip Server version 2.0.0 and above are vulnerable to insufficient access control with multi-use invitations. A Zulip Server deployment which hosts multiple organizations is vulnerable to an attack where an invitation created in one organization (potentially as a role with elevated permissions) can be used to join any other organization. This bypasses any restrictions on required domains on users' email addresses, may be used to gain access to organizations which are only accessible by invitation, and may be used to gain access with elevated privileges. This issue has been patched in release 4.10. There are no known workarounds for this issue. ### Patches _Has the problem been patched? What versions should users upgrade to?_ ### Workarounds _Is there a way for users to fix or remediate the vulnerability without upgrading?_ ### References _Are there any links users can visit to find out more?_ ### For more information If you have any questions or comments about this advisory, you can discuss them on the [developer community Zulip server](https://zulip.com/developer-community/), or email the [Zulip security team](mailto:security@zulip.com).

CVE-2022-23775: TrueStack Direct Connect 1.4.7 has Incorrect Access Control.

CVE-2022-2512: An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.0 before 15.0.5, all versions starting from 15.1 before 15.1.4, all versions starting from 15.2 before 15.2.1. Membership changes are not reflected in TODO for confidential notes, allowing a former project members to read updates via TODOs.

CVE-2022-25402: An incorrect access control issue in HMS v1.0 allows unauthenticated attackers to read and modify all PHP files.

CVE-2022-26572: Xerox ColorQube 8580 was discovered to contain an access control issue which allows attackers to print, view the status, and obtain sensitive information.

CVE-2022-27128: An incorrect access control issue at /admin/run_ajax.php in zbzcms v1.0 allows attackers to arbitrarily add administrator accounts.

CVE-2022-27511: Corruption of the system by a remote, unauthenticated user. The impact of this can include the reset of the administrator password at the next device reboot, allowing an attacker with ssh access to connect with the default administrator credentials after the device has rebooted.

CVE-2022-28067: An incorrect access control issue in Sandboxie Classic v5.55.13 allows attackers to cause a Denial of Service (DoS) in the Sandbox via a crafted executable.

CVE-2022-29423: Pro Features Lock Bypass vulnerability in Countdown & Clock plugin <= 2.3.2 at WordPress.

CVE-2022-29564: Jamf Private Access before 2022-05-16 has Incorrect Access Control, in which an unauthorized user can reach a system in the internal infrastructure, aka WND-44801.

CVE-2022-29633: An access control issue in Linglong v1.0 allows attackers to access the background of the application via a crafted cookie.

CVE-2022-29773: An access control issue in aleksis/core/util/auth_helpers.py: ClientProtectedResourceMixin of AlekSIS-Core v2.8.1 and below allows attackers to access arbitrary scopes if no allowed scopes are specifically set.

CVE-2022-30290: In OpenCTI through 5.2.4, a broken access control vulnerability has been identified in the profile endpoint. An attacker can abuse the identified vulnerability in order to arbitrarily change their registered e-mail address as well as their API key, even though such action is not possible through the interface, legitimately.

CVE-2022-31876: netgear wnap320 router WNAP320_V2.0.3_firmware is vulnerable to Incorrect Access Control via /recreate.php, which can leak all users cookies.

CVE-2022-32945: An access issue was addressed with additional sandbox restrictions on third-party apps. This issue is fixed in macOS Ventura 13. An app may be able to record audio with paired AirPods.

CVE-2022-33198: Unauthenticated WordPress Options Change vulnerability in Biplob Adhikari's Accordions plugin <= 2.0.2 at WordPress.

CVE-2022-34487: Unauthenticated Arbitrary Option Update vulnerability in biplob018's Shortcode Addons plugin <= 3.0.2 at WordPress.

CVE-2022-36387: Broken Access Control vulnerability in Alessio Caiazza's About Me plugin <= 1.0.12 at WordPress.

CVE-2022-3740: An issue has been discovered in GitLab CE/EE affecting all versions starting from 12.9 prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2. A group owner may be able to bypass External Authorization check, if it is enabled, to access git repositories and package registries by using Deploy tokens or Deploy keys .

CVE-2022-38768: The mobile application in Transtek Mojodat FAM (Fixed Asset Management) 2.4.6 allows remote attackers to bypass authorization.

CVE-2022-39370: GLPI stands for Gestionnaire Libre de Parc Informatique. GLPI is a Free Asset and IT Management Software package that provides ITIL Service Desk features, licenses tracking and software auditing. Connected users may gain access to debug panel through the GLPI update script. This issue has been patched, please upgrade to 10.0.4. As a workaround, delete the `install/update.php` script.

CVE-2022-40216: Auth. (subscriber+) Messaging Block Bypass vulnerability in Better Messages plugin <= 1.9.10.69 on WordPress.

CVE-2022-44565: An improper access validation vulnerability exists in airMAX AC <8.7.11, airFiber 60/LR <2.6.2, airFiber 60 XG/HD <v1.0.0 and airFiber GBE <1.4.1 that allows a malicious actor to retrieve status and usage data from the UISP device.

CVE-2022-45778: https://www.hillstonenet.com.cn/ Hillstone Firewall SG-6000 <= 5.0.4.0 is vulnerable to Incorrect Access Control. There is a permission bypass vulnerability in the Hillstone WEB application firewall. An attacker can enter the background of the firewall with super administrator privileges through a configuration error in report.m.

CVE-2022-38355: Daikin SVMPC1 version 2.1.22 and prior and SVMPC2 version 1.2.3 and prior are vulnerable to attackers with access to the local area network (LAN) to disclose sensitive information stored by the affected product without requiring authentication. 

CVE-2021-31001: An access issue was addressed with improved access restrictions. This issue is fixed in iOS 15 and iPadOS 15. An attacker in a privileged network position may be able to leak sensitive user information.

CVE-2022-20762: A vulnerability in the Common Execution Environment (CEE) ConfD CLI of Cisco Ultra Cloud Core - Subscriber Microservices Infrastructure (SMI) software could allow an authenticated, local attacker to escalate privileges on an affected device. This vulnerability is due to insufficient access control in the affected CLI. An attacker could exploit this vulnerability by authenticating as a CEE ConfD CLI user and executing a specific CLI command. A successful exploit could allow an attacker to access privileged containers with root privileges.

CVE-2022-20859: A vulnerability in the Disaster Recovery framework of Cisco Unified Communications Manager (Unified CM), Cisco Unified Communications Manager IM &amp; Presence Service (Unified CM IM&amp;P), and Cisco Unity Connection could allow an authenticated, remote attacker to perform certain administrative actions they should not be able to. This vulnerability is due to insufficient access control checks on the affected device. An attacker with read-only privileges could exploit this vulnerability by executing a specific vulnerable command on an affected device. A successful exploit could allow the attacker to perform a set of administrative actions they should not be able to.

CVE-2022-2155:  A vulnerability exists in the affected versions of Lumada APM’s User Asset Group feature due to a flaw in access control mechanism implementation on the “Limited Engineer” role, granting it access to the embedded Power BI reports feature. An attacker that manages to exploit the vulnerability on a customer’s Lumada APM could access unauthorized information by gaining unauthorized access to any Power BI reports installed by the customer. Furthermore, the vulnerability enables an attacker to manipulate asset issue comments on assets, which should not be available to the attacker. Affected versions * Lumada APM on-premises version 6.0.0.0 - 6.4.0.* List of CPEs: * cpe:2.3:a:hitachienergy:lumada_apm:6.0.0.0:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:lumada_apm:6.1.0.0:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:lumada_apm:6.2.0.0:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:lumada_apm:6.3.0.0:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:lumada_apm:6.4.0.0:*:*:*:*:*:*:* 

CVE-2022-22798: Sysaid – Pro Plus Edition, SysAid Help Desk Broken Access Control v20.4.74 b10, v22.1.20 b62, v22.1.30 b49 - An attacker needs to log in as a guest after that the system redirects him to the service portal or EndUserPortal.JSP, then he needs to change the path in the URL to /ConcurrentLogin%2ejsp after that he will receive an error message with a login button, by clicking on it, he will connect to the system dashboard. The attacker can receive sensitive data like server details, usernames, workstations, etc. He can also perform actions such as uploading files, deleting calls from the system.

CVE-2022-23730: The public API error causes for the attacker to be able to bypass API access control.

CVE-2022-32255: A vulnerability has been identified in SINEMA Remote Connect Server (All versions < V3.1). The affected application consists of a web service that lacks proper access control for some of the endpoints. This could lead to unauthorized access to limited information.

CVE-2022-36263: StreamLabs Desktop Application 1.9.0 is vulnerable to Incorrect Access Control via obs64.exe. An attacker can execute arbitrary code via a crafted .exe file.

CVE-2022-36562: Incorrect access control in the install directory (C:\\Ruby31-x64) of Rubyinstaller2 v3.1.2 and below allows authenticated attackers to execute arbitrary code via overwriting binaries located in the directory.

CVE-2022-36563: Incorrect access control in the install directory (C:\\RailsInstaller) of Rubyinstaller2 v3.1.2 and below allows authenticated attackers to execute arbitrary code via overwriting binaries located in the directory.

CVE-2022-36564: Incorrect access control in the install directory (C:\\Strawberry) of StrawberryPerl v5.32.1.1 and below allows authenticated attackers to execute arbitrary code via overwriting binaries located in the directory.

CVE-2022-36565: Incorrect access control in the install directory (C:\\Wamp64) of Wamp v3.2.6 and below allows authenticated attackers to execute arbitrary code via overwriting binaries located in the directory.

CVE-2022-37172: Incorrect access control in the install directory (C:\\msys64) of Msys2 v20220603 and below allows authenticated attackers to execute arbitrary code via overwriting binaries located in the directory.

CVE-2022-3780: Database connections on deleted users could stay active on MySQL data sources in Remote Desktop Manager 2022.3.7 and below which allow deleted users to access unauthorized data. This issue affects : Remote Desktop Manager 2022.3.7 and prior versions. 

CVE-2022-0093: An issue has been discovered affecting GitLab versions prior to 14.4.5, between 14.5.0 and 14.5.3, and between 14.6.0 and 14.6.1. GitLab allows a user with an expired password to access sensitive information through RSS feeds.

# CWE-285 Improper Authorization

## Description

The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.

Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-control specifications that apply to the resource.


When access control checks are not applied consistently - or not at all - users are able to access data or perform actions that they should not be allowed to perform. This can lead to a wide range of problems, including information exposures, denial of service, and arbitrary code execution.

An access control list (ACL) represents who/what has permissions to a given object. Different operating systems implement (ACLs) in different ways. In UNIX, there are three types of permissions: read, write, and execute. Users are divided into three classes for file access: owner, group owner, and all other users where each class has a separate set of rights. In Windows NT, there are four basic types of permissions for files: "No access", "Read access", "Change access", and "Full control". Windows NT extends the concept of three types of users in UNIX to include a list of users and groups along with their associated permissions. A user can create an object (file) and assign specified permissions to that object.

## Observed Examples

CVE-2022-24730: Go-based continuous deployment product does not check that a user has certain privileges to update or create an app, allowing adversaries to read sensitive repository information

CVE-2009-3168: Web application does not restrict access to admin scripts, allowing authenticated users to reset administrative passwords.

CVE-2009-2960: Web application does not restrict access to admin scripts, allowing authenticated users to modify passwords of other users.

CVE-2009-3597: Web application stores database file under the web root with insufficient access control (CWE-219), allowing direct request.

CVE-2009-2282: Terminal server does not check authorization for guest access.

CVE-2009-3230: Database server does not use appropriate privileges for certain sensitive operations.

CVE-2009-2213: Gateway uses default "Allow" configuration for its authorization settings.

CVE-2009-0034: Chain: product does not properly interpret a configuration option for a system group, allowing users to gain privileges.

CVE-2008-6123: Chain: SNMP product does not properly parse a configuration option for which hosts are allowed to connect, allowing unauthorized IP addresses to connect.

CVE-2008-5027: System monitoring software allows users to bypass authorization by creating custom forms.

CVE-2008-7109: Chain: reliance on client-side security (CWE-602) allows attackers to bypass authorization using a custom client.

CVE-2008-3424: Chain: product does not properly handle wildcards in an authorization policy list, allowing unintended access.

CVE-2009-3781: Content management system does not check access permissions for private files, allowing others to view those files.

CVE-2008-4577: ACL-based protection mechanism treats negative access rights as if they are positive, allowing bypass of intended restrictions.

CVE-2008-6548: Product does not check the ACL of a page accessed using an "include" directive, allowing attackers to read unauthorized files.

CVE-2007-2925: Default ACL list for a DNS server does not set certain ACLs, allowing unauthorized DNS queries.

CVE-2006-6679: Product relies on the X-Forwarded-For HTTP header for authorization, allowing unintended access by spoofing the header.

CVE-2005-3623: OS kernel does not check for a certain privilege before setting ACLs for files.

CVE-2005-2801: Chain: file-system code performs an incorrect comparison (CWE-697), preventing default ACLs from being properly applied.

CVE-2001-1155: Chain: product does not properly check the result of a reverse DNS lookup because of operator precedence (CWE-783), allowing bypass of DNS-based access restrictions.

## Top 25 Examples

CVE-2022-30757: Improper authorization in isemtelephony prior to SMR Jul-2022 Release 1 allows attacker to obtain CID without ACCESS_FINE_LOCATION permission.

CVE-2021-28799: An improper authorization vulnerability has been reported to affect QNAP NAS running HBS 3 (Hybrid Backup Sync. ) If exploited, the vulnerability allows remote attackers to log in to a device. This issue affects: QNAP Systems Inc. HBS 3 versions prior to v16.0.0415 on QTS 4.5.2; versions prior to v3.0.210412 on QTS 4.3.6; versions prior to v3.0.210411 on QTS 4.3.4; versions prior to v3.0.210411 on QTS 4.3.3; versions prior to v16.0.0419 on QuTS hero h4.5.1; versions prior to v16.0.0419 on QuTScloud c4.5.1~c4.5.4. This issue does not affect: QNAP Systems Inc. HBS 2 . QNAP Systems Inc. HBS 1.3 .

CVE-2021-1675: Windows Print Spooler Remote Code Execution Vulnerability

CVE-2021-40013: Improper permission control vulnerability in the Bluetooth module.Successful exploitation of this vulnerability will affect integrity.

CVE-2022-20921: A vulnerability in the API implementation of Cisco ACI Multi-Site Orchestrator (MSO) could allow an authenticated, remote attacker to elevate privileges on an affected device. This vulnerability is due to improper authorization on specific APIs. An attacker could exploit this vulnerability by sending crafted HTTP requests. A successful exploit could allow an attacker who is authenticated with non-Administrator privileges to elevate to Administrator privileges on an affected device.

CVE-2022-24083: Password authentication bypass vulnerability for local accounts can be used to bypass local authentication checks.

CVE-2022-26310: Pandora FMS v7.0NG.760 and below allows an improper authorization in User Management where any authenticated user with access to the User Management module could create, modify or delete any user with full admin privilege. The impact could lead to a vertical privilege escalation to access the privileges of a higher-level user or typically an admin user.

CVE-2022-31247: An Improper Authorization vulnerability in SUSE Rancher, allows any user who has permissions to create/edit cluster role template bindings or project role template bindings (such as cluster-owner, manage cluster members, project-owner and manage project members) to gain owner permission in another project in the same cluster or in another project on a different downstream cluster. This issue affects: SUSE Rancher Rancher versions prior to 2.6.7; Rancher versions prior to 2.5.16.

CVE-2022-33732: Improper access control vulnerability in Samsung Dex for PC prior to SMR Aug-2022 Release 1 allows local attackers to scan and connect to PC by unprotected binder call.

CVE-2022-34256: Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Improper Authorization vulnerability that could result in Privilege escalation. An attacker could leverage this vulnerability to access other user's data. Exploitation of this issue does not require user interaction.

CVE-2022-34405: An improper access control vulnerability was identified in the Realtek audio driver. A local authenticated malicious user may potentially exploit this vulnerability by waiting for an administrator to launch the application and attach to the process to elevate privileges on the system. 

CVE-2022-36453: A vulnerability in the MiCollab Client API of Mitel MiCollab 9.1.3 through 9.5.0.101 could allow an authenticated attacker to modify their profile parameters due to improper authorization controls. A successful exploit could allow the authenticated attacker to control another extension number.

CVE-2022-36454: A vulnerability in the MiCollab Client API of Mitel MiCollab through 9.5.0.101 could allow an authenticated attacker to modify their profile parameters due to improper authorization controls. A successful exploit could allow the authenticated attacker to impersonate another user's name.

CVE-2022-38375: An improper authorization vulnerability [CWE-285] in Fortinet FortiNAC version 9.4.0 through 9.4.1 and before 9.2.6 allows an unauthenticated user to perform some administrative operations over the FortiNAC instance via crafted HTTP POST requests.

CVE-2022-39890: Improper Authorization in Samsung Billing prior to version 5.0.56.0 allows attacker to get sensitive information.

CVE-2022-46752:  Dell BIOS contains an Improper Authorization vulnerability. An unauthenticated physical attacker may potentially exploit this vulnerability, leading to denial of service. 

CVE-2022-4701: The Royal Elementor Addons plugin for WordPress is vulnerable to insufficient access control in the 'wpr_activate_required_plugins' AJAX action in versions up to, and including, 1.3.59. This allows any authenticated user, including those with subscriber-level permissions, to activate the 'contact-form-7', 'media-library-assistant', or 'woocommerce' plugins if they are installed on the site.

CVE-2022-4879: A vulnerability was found in Forged Alliance Forever up to 3746. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the component Vote Handler. The manipulation leads to improper authorization. Upgrading to version 3747 is able to address this issue. The patch is named 6880971bd3d73d942384aff62d53058c206ce644. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-217555.

CVE-2022-2393: A flaw was found in pki-core, which could allow a user to get a certificate for another user identity when directory-based authentication is enabled. This flaw allows an authenticated attacker on the adjacent network to impersonate another user within the scope of the domain, but they would not be able to decrypt message content.

CVE-2022-40843: The Tenda AC1200 V-W15Ev2 V15.11.0.10(1576) router is vulnerable to improper authorization / improper session management that allows the router login page to be bypassed. This leads to authenticated attackers having the ability to read the routers syslog.log file which contains the MD5 password of the Administrator's user account.

CVE-2021-30344: Improper authorization of a replayed LTE security mode command can lead to a denial of service in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2022-0027: An improper authorization vulnerability in Palo Alto Network Cortex XSOAR software enables authenticated users in non-Read-Only groups to generate an email report that contains summary information about all incidents in the Cortex XSOAR instance, including incidents to which the user does not have access. This issue impacts: All versions of Cortex XSOAR 6.1; All versions of Cortex XSOAR 6.2; All versions of Cortex XSOAR 6.5; Cortex XSOAR 6.6 versions earlier than Cortex XSOAR 6.6.0 build 6.6.0.2585049.

CVE-2022-2019: A vulnerability classified as critical was found in SourceCodester Prison Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /classes/Users.php?f=save of the component New User Creation. The manipulation leads to improper authorization. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

CVE-2022-22091: Improper authorization of a replayed LTE security mode command can lead to a denial of service in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-22272: Improper authorization in TelephonyManager prior to SMR Jan-2022 Release 1 allows attackers to get IMSI without READ_PRIVILEGED_PHONE_STATE permission

CVE-2022-22288: Improper authorization vulnerability in Galaxy Store prior to 4.5.36.5 allows remote app installation of the allowlist.

CVE-2022-2229: An improper authorization issue in GitLab CE/EE affecting all versions from 13.7 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1 allows an attacker to extract the value of an unprotected variable they know the name of in public projects or private projects they're a member of.

CVE-2022-2244: An improper authorization vulnerability in GitLab EE/CE affecting all versions from 14.8 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1, allows project memebers with reporter role to manage issues in project's error tracking feature.

CVE-2022-24002: Improper Authorization vulnerability in Link Sharing prior to version 12.4.00.3 allows attackers to open protected activity via PreconditionActivity.

CVE-2022-25685: Denial of service in Modem module due to improper authorization while error handling in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-2661: Sequi PortBloque S has an improper authorization vulnerability, which may allow a low-privileged user to perform administrative functions using specifically crafted requests.

CVE-2022-26857: Dell OpenManage Enterprise Versions 3.8.3 and prior contain an improper authorization vulnerability. A remote authenticated malicious user with low privileges may potentially exploit this vulnerability to bypass blocked functionalities and perform unauthorized actions.

CVE-2022-29490: Improper Authorization vulnerability exists in the Workplace X WebUI of the Hitachi Energy MicroSCADA X SYS600 allows an authenticated user to execute any MicroSCADA internal scripts irrespective of the authenticated user's role. This issue affects: Hitachi Energy MicroSCADA X SYS600 version 10 to version 10.3.1. cpe:2.3:a:hitachienergy:microscada_x_sys600:10:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.1.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.2.1:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3:*:*:*:*:*:*:* cpe:2.3:a:hitachienergy:microscada_x_sys600:10.3.1:*:*:*:*:*:*:*

CVE-2022-29538: RESI Gemini-Net Web 4.2 is affected by Improper Access Control in authorization logic. An unauthenticated user is able to access some critical resources.

CVE-2022-30715: Improper access control vulnerability in DofViewer prior to SMR Jun-2022 Release 1 allows attackers to control floating system alert window.

CVE-2022-30730: Improper authorization in Samsung Pass prior to 1.0.00.33 allows physical attackers to acess account list without authentication.

CVE-2022-31589: Due to improper authorization check, business users who are using Israeli File from SHAAM program (/ATL/VQ23 transaction), are granted more than needed authorization to perform certain transaction, which may lead to users getting access to data that would otherwise be restricted.

CVE-2022-33702: Improper authorization vulnerability in Knoxguard prior to SMR Jul-2022 Release 1 allows local attacker to disable keyguard and bypass Knoxguard lock by factory reset.

CVE-2022-35692: Adobe Commerce versions 2.4.3-p2 (and earlier), 2.3.7-p3 (and earlier) and 2.4.4 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An attacker could leverage this vulnerability to leak minor information of another user's account detials. Exploitation of this issue does not require user interaction.

CVE-2022-36848: Improper Authorization vulnerability in setDualDARPolicyCmd prior to SMR Sep-2022 Release 1 allows local attackers to cause local permanent denial of service.

CVE-2022-36852: Improper Authorization vulnerability in Video Editor prior to SMR Sep-2022 Release 1 allows local attacker to access internal application data.

CVE-2022-36857: Improper Authorization vulnerability in Photo Editor prior to SMR Sep-2022 Release 1 allows physical attackers to read internal application data.

CVE-2022-36876: Improper authorization in UPI payment in Samsung Pass prior to version 4.0.04.10 allows physical attackers to access account list without authentication.

CVE-2022-39862: Improper authorization in Dynamic Lockscreen prior to SMR Sep-2022 Release 1 in Android R(11) and 3.3.03.66 in Android S(12) allows unauthorized use of javascript interface api.

CVE-2022-39879: Improper authorization vulnerability in?CallBGProvider prior to SMR Nov-2022 Release 1 allows local attacker to grant permission for accessing information with phone uid.

CVE-2022-39902: Improper authorization in Exynos baseband prior to SMR DEC-2022 Release 1 allows remote attacker to get sensitive information including IMEI via emergency call.

CVE-2022-41326: The web conferencing component of Mitel MiCollab through 9.6.0.13 could allow an unauthenticated attacker to upload arbitrary scripts due to improper authorization controls. A successful exploit could allow remote code execution within the context of the application.

CVE-2022-45874: Huawei Aslan Children's Watch has an improper authorization vulnerability. Successful exploit could allow the attacker to access certain file.

CVE-2022-4613: A vulnerability was found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome and classified as critical. This issue affects some unknown processing of the component Browser Extension Provisioning. The manipulation leads to improper authorization. The attack may be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-216275.

CVE-2022-39873: Improper authorization vulnerability in Samsung Internet prior to version 18.0.4.14 allows physical attackers to add bookmarks in secret mode without user authentication.

CVE-2022-39883: Improper authorization vulnerability in StorageManagerService prior to SMR Nov-2022 Release 1 allows local attacker to call privileged API.

CVE-2022-0373: Improper access control in GitLab CE/EE versions 12.4 to 14.5.4, 14.5 to 14.6.4, and 12.6 to 14.7.1 allows project non-members to retrieve the service desk email address

CVE-2022-0821: Improper Authorization in GitHub repository orchardcms/orchardcore prior to 1.3.0.

CVE-2022-20680: A vulnerability in the web-based management interface of Cisco Prime Service Catalog could allow an authenticated, remote attacker to access sensitive information on an affected device. This vulnerability is due to improper enforcement of Administrator privilege levels for low-value sensitive data. An attacker with read-only Administrator access to the web-based management interface could exploit this vulnerability by sending a malicious HTTP request to the page that contains the sensitive data. A successful exploit could allow the attacker to collect sensitive information about users of the system and orders that have been placed using the application.

CVE-2022-24842: MinIO is a High Performance Object Storage released under GNU Affero General Public License v3.0. A security issue was found where an non-admin user is able to create service accounts for root or other admin users and then is able to assume their access policies via the generated credentials. This in turn allows the user to escalate privilege to that of the root user. This vulnerability has been resolved in pull request #14729 and is included in `RELEASE.2022-04-12T06-55-35Z`. Users unable to upgrade may workaround this issue by explicitly adding a `admin:CreateServiceAccount` deny policy, however, this, in turn, denies the user the ability to create their own service accounts as well.

CVE-2021-39892: In all versions of GitLab CE/EE since version 12.0, a lower privileged user can import users from projects that they don't have a maintainer role on and disclose email addresses of those users.

CVE-2021-44837: An issue was discovered in Delta RM 1.2. It is possible for an unprivileged user to access the same information as an admin user regarding the risk creation information in the /risque/administration/referentiel/json/create/categorie endpoint, using the id_cat1 query parameter to indicate the risk.

CVE-2022-25311: A vulnerability has been identified in SINEC NMS (All versions >= V1.0.3 < V2.0), SINEC NMS (All versions < V1.0.3), SINEMA Server V14 (All versions). The affected software do not properly check privileges between users during the same web browser session, creating an unintended sphere of control. This could allow an authenticated low privileged user to achieve privilege escalation.

CVE-2021-44838: An issue was discovered in Delta RM 1.2. Using the /risque/risque/ajax-details endpoint, with a POST request indicating the risk to access with the id parameter, it is possible for users to access risks of other companies.

CVE-2021-44886: In Zammad 5.0.2, agents can configure "out of office" periods and substitute persons. If the substitute persons didn't have the same permissions as the original agent, they could receive ticket notifications for tickets that they have no access to.

CVE-2022-23331: In DataEase v1.6.1, an authenticated user can gain unauthorized access to all user information and can change the administrator password.

CVE-2022-24331: In JetBrains TeamCity before 2021.1.4, GitLab authentication impersonation was possible.

CVE-2022-2675: Using off-the-shelf commodity hardware, the Unitree Go 1 robotics platform version H0.1.7 and H0.1.9 (using firmware version 0.1.35) can be powered down by an attacker within normal RF range without authentication. Other versions may be affected, such as the A1.

CVE-2022-34446:  PowerPath Management Appliance with versions 3.3 & 3.2* contains Authorization Bypass vulnerability. An authenticated remote user with limited privileges (e.g., of role Monitoring) can exploit this issue and gain access to sensitive information, and modify the configuration. 

CVE-2022-26051: Operation restriction bypass vulnerability in Portal of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to alter the data of Portal.

CVE-2022-26054: Operation restriction bypass vulnerability in Link of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to alter the data of Link.

CVE-2022-26368: Browse restriction bypass and operation restriction bypass vulnerability in Cabinet of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to alter and/or obtain the data of Cabinet.

CVE-2022-32544: Operation restriction bypass vulnerability in Project of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to alter the data of Project via unspecified vectors.

CVE-2022-32583: Operation restriction bypass vulnerability in Scheduler of Cybozu Office 10.0.0 to 10.8.5 allows a remote authenticated attacker to alter the data of Scheduler via unspecified vectors.

CVE-2022-37190: CuppaCMS 1.0 is vulnerable to Remote Code Execution (RCE). An authenticated user can control both parameters (action and function) from "/api/index.php.

CVE-2022-42788: A permissions issue existed. This issue was addressed with improved permission validation. This issue is fixed in macOS Ventura 13. A malicious application may be able to read sensitive location information.

CVE-2022-26703: An authorization issue was addressed with improved state management. This issue is fixed in iOS 15.5 and iPadOS 15.5. A person with physical access to an iOS device may be able to access photos from the lock screen.

CVE-2022-0172: An issue has been discovered in GitLab CE/EE affecting all versions starting with 12.3. Under certain conditions it was possible to bypass the IP restriction for public projects through GraphQL allowing unauthorised users to read titles of issues, merge requests and milestones.

CVE-2022-1545: It was possible to disclose details of confidential notes created via the API in Gitlab CE/EE affecting all versions from 13.2 prior to 14.8.6, 14.9 prior to 14.9.4, and 14.10 prior to 14.10.1 if an unauthorised project member was tagged in the note.

CVE-2022-21899: Windows Extensible Firmware Interface Security Feature Bypass Vulnerability

CVE-2022-2539: An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.6 prior to 15.0.5, 15.1 prior to 15.1.4, and 15.2 prior to 15.2.1, allowed a project member to filter issues by contact and organization.

CVE-2022-27583: A remote unprivileged attacker can interact with the configuration interface of a Flexi-Compact FLX3-CPUC1 or FLX3-CPUC2 running an affected firmware version to potentially impact the availability of the FlexiCompact.

CVE-2022-27661: Operation restriction bypass vulnerability in Workflow of Cybozu Garoon 4.0.0 to 5.5.1 allows a remote authenticated attacker to alter the data of Workflow.

CVE-2022-28718: Operation restriction bypass vulnerability in Bulletin of Cybozu Garoon 4.0.0 to 5.5.1 allow a remote authenticated attacker to alter the data of Bulletin.

CVE-2022-28749: Zooms On-Premise Meeting Connector MMR before version 4.8.113.20220526 fails to properly check the permissions of a Zoom meeting attendee. As a result, a threat actor in the Zooms waiting room can join the meeting without the consent of the host.

CVE-2022-29484: Operation restriction bypass vulnerability in Space of Cybozu Garoon 4.0.0 to 5.9.0 allows a remote authenticated attacker to delete the data of Space.

CVE-2022-31025: Discourse is an open source platform for community discussion. Prior to version 2.8.4 on the `stable` branch and 2.9.0beta5 on the `beta` and `tests-passed` branches, inviting users on sites that use single sign-on could bypass the `must_approve_users` check and invites by staff are always approved automatically. The issue is patched in Discourse version 2.8.4 on the `stable` branch and version `2.9.0.beta5` on the `beta` and `tests-passed` branches. As a workaround, disable invites or increase `min_trust_level_to_allow_invite` to reduce the attack surface to more trusted users.

CVE-2022-31032: Tuleap is a Free & Open Source Suite to improve management of software developments and collaboration. In versions prior to 13.9.99.58 authorizations are not properly verified when creating projects or trackers from projects marked as templates. Users can get access to information in those template projects because the permissions model is not properly enforced. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-3330: It was possible for a guest user to read a todo targeting an inaccessible note in Gitlab CE/EE affecting all versions from 15.0 prior to 15.2.5, 15.3 prior to 15.3.4, and 15.4 prior to 15.4.1.

CVE-2022-39341: OpenFGA is an authorization/permission engine. Versions prior to version 0.2.4 are vulnerable to authorization bypass under certain conditions. Users who have wildcard (`*`) defined on tupleset relations in their authorization model are vulnerable. Version 0.2.4 contains a patch for this issue.

CVE-2022-39342: OpenFGA is an authorization/permission engine. Versions prior to version 0.2.4 are vulnerable to authorization bypass under certain conditions. Users whose model has a relation defined as a tupleset (the right hand side of a ‘from’ statement) that involves anything other than a direct relationship (e.g. ‘as self’) are vulnerable. Version 0.2.4 contains a patch for this issue.

CVE-2022-39352: OpenFGA is a high-performance authorization/permission engine inspired by Google Zanzibar. Versions prior to 0.2.5 are vulnerable to authorization bypass under certain conditions. You are affected by this vulnerability if you added a tuple with a wildcard (*) assigned to a tupleset relation (the right hand side of a ‘from’ statement). This issue has been patched in version v0.2.5. This update is not backward compatible with any authorization model that uses wildcard on a tupleset relation.

CVE-2022-39356: Discourse is a platform for community discussion. Users who receive an invitation link that is not scoped to a single email address can enter any non-admin user's email and gain access to their account when accepting the invitation. All users should upgrade to the latest version. A workaround is temporarily disabling invitations with `SiteSetting.max_invites_per_day = 0` or scope them to individual email addresses.

CVE-2022-40036: An issue was discovered in Rawchen blog-ssm v1.0 allows an attacker to obtain sensitive user information by bypassing permission checks via the /adminGetUserList component.

CVE-2022-48302: The AMS module has a vulnerability of lacking permission verification in APIs.Successful exploitation of this vulnerability may affect data confidentiality.

CVE-2021-41564: Tad Honor viewing book list function is vulnerable to authorization bypass, thus remote attackers can use special parameters to delete articles arbitrarily without logging in.

CVE-2022-1502: Permissions were not properly verified in the API on projects using version control in Git. This allowed projects to be modified by users with only ProjectView permissions.

CVE-2022-21196: MMP: All versions prior to v1.0.3, PTP C-series: Device versions prior to v2.8.6.1, and PTMP C-series and A5x: Device versions prior to v2.5.4.1 does not perform proper authorization and authentication checks on multiple API routes. An attacker may gain access to these API routes and achieve remote code execution, create a denial-of-service condition, and obtain sensitive information.

CVE-2022-30717: Improper caller check in AR Emoji prior to SMR Jun-2022 Release 1 allows untrusted applications to use some camera functions via deeplink.

CVE-2022-31609: NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where it allows the guest VM to allocate resources for which the guest is not authorized. This vulnerability may lead to loss of data integrity and confidentiality, denial of service, or information disclosure.

CVE-2022-33705: Information exposure in Calendar prior to version 12.3.05.10000 allows attacker to access calendar schedule without READ_CALENDAR permission.

CVE-2021-25354: Improper input check in Samsung Internet prior to version 13.2.1.46 allows attackers to launch non-exported activity in Samsung Browser via malicious deeplink.

CVE-2022-0882: A bug exists where an attacker can read the kernel log through exposed Zircon kernel addresses without the required capability ZX_RSRC_KIND_ROOT. It is recommended to upgrade the Fuchsia kernel to 4.1.1 or greater.

CVE-2022-43410: Jenkins Mercurial Plugin 1251.va_b_121f184902 and earlier provides information about which jobs were triggered or scheduled for polling through its webhook endpoint, including jobs the user has no permission to access.

CVE-2022-1783: An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.3 before 14.9.5, all versions starting from 14.10 before 14.10.4, all versions starting from 15.0 before 15.0.1. It may be possible for malicious group maintainers to add new members to a project within their group, through the REST API, even after their group owner enabled a setting to prevent members from being added to projects within that group.

CVE-2022-3994: The Authenticator WordPress plugin before 1.3.1 does not prevent subscribers from updating a site's feed access token, which may deny other users access to the functionality in certain configurations.

# CWE-286 Incorrect User Management

## Description

The product does not properly manage a user within its environment.

Users can be assigned to the wrong group (class) of permissions resulting in unintended access rights to sensitive objects.

## Observed Examples

CVE-2022-36109: Containerization product does not record a user's supplementary group ID, allowing bypass of group restrictions.

CVE-1999-1193: Operating system assigns user to privileged wheel group, allowing the user to gain root privileges.

## Top 25 Examples

CVE-2022-32260: A vulnerability has been identified in SINEMA Remote Connect Server (All versions < V3.2 SP1). The affected application creates temporary user credentials for UMC (User Management Component) users. An attacker could use these temporary credentials for authentication bypass in certain scenarios.

CVE-2022-45857: An incorrect user management vulnerability [CWE-286] in the FortiManager version 6.4.6 and below VDOM creation component may allow an attacker to access a FortiGate without a password via newly created VDOMs after the super_admin account is deleted.

CVE-2021-21553: Dell PowerScale OneFS versions 8.1.0-9.1.0 contain an Incorrect User Management vulnerability.under some specific conditions, this can allow the CompAdmin user to elevate privileges and break out of Compliance mode. This is a critical vulnerability and Dell recommends upgrading at the earliest.

CVE-2022-36109: Moby is an open-source project created by Docker to enable software containerization. A bug was found in Moby (Docker Engine) where supplementary groups are not set up properly. If an attacker has direct access to a container and manipulates their supplementary group access, they may be able to use supplementary group access to bypass primary group restrictions in some cases, potentially gaining access to sensitive information or gaining the ability to execute code in that container. This bug is fixed in Moby (Docker Engine) 20.10.18. Running containers should be stopped and restarted for the permissions to be fixed. For users unable to upgrade, this problem can be worked around by not using the `"USER $USERNAME"` Dockerfile instruction. Instead by calling `ENTRYPOINT ["su", "-", "user"]` the supplementary groups will be set up properly.

# CWE-287 Improper Authentication

## Description

When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Observed Examples

CVE-2022-35248: Chat application skips validation when Central Authentication Service (CAS) is enabled, effectively removing the second factor from two-factor authentication

CVE-2022-36436: Python-based authentication proxy does not enforce password authentication during the initial handshake, allowing the client to bypass authentication by specifying a 'None' authentication type.

CVE-2022-30034: Chain: Web UI for a Python RPC framework does not use regex anchors to validate user login emails (CWE-777), potentially allowing bypass of OAuth (CWE-1390).

CVE-2022-29951: TCP-based protocol in Programmable Logic Controller (PLC) has no authentication.

CVE-2022-29952: Condition Monitor uses a protocol that does not require authentication.

CVE-2022-30313: Safety Instrumented System uses proprietary TCP protocols with no authentication.

CVE-2022-30317: Distributed Control System (DCS) uses a protocol that has no authentication.

CVE-2022-33139: SCADA system only uses client-side authentication, allowing adversaries to impersonate other users.

CVE-2021-3116: Chain: Python-based HTTP Proxy server uses the wrong boolean operators (CWE-480) causing an incorrect comparison (CWE-697) that identifies an authN failure if all three conditions are met instead of only one, allowing bypass of the proxy authentication (CWE-1390)

CVE-2021-21972: Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV.

CVE-2021-37415: IT management product does not perform authentication for some REST API requests, as exploited in the wild per CISA KEV.

CVE-2021-35033: Firmware for a WiFi router uses a hard-coded password for a BusyBox shell, allowing bypass of authentication through the UART port

CVE-2020-10263: Bluetooth speaker does not require authentication for the debug functionality on the UART port, allowing root shell access

CVE-2020-13927: Default setting in workflow management product allows all API requests without authentication, as exploited in the wild per CISA KEV.

CVE-2021-35395: Stack-based buffer overflows in SFK for wifi chipset used for IoT/embedded devices, as exploited in the wild per CISA KEV.

CVE-2021-34523: Mail server does not properly check an access token before executing a Powershell command, as exploited in the wild per CISA KEV.

CVE-2020-12812: Chain: user is not prompted for a second authentication factor (CWE-287) when changing the case of their username (CWE-178), as exploited in the wild per CISA KEV.

CVE-2020-10148: Authentication bypass by appending specific parameters and values to a URI, as exploited in the wild per CISA KEV.

CVE-2020-0688: Mail server does not generate a unique key during installation, as exploited in the wild per CISA KEV.

CVE-2017-14623: LDAP Go package allows authentication bypass using an empty password, causing an unauthenticated LDAP bind

CVE-2009-3421: login script for guestbook allows bypassing authentication by setting a "login_ok" parameter to 1.

CVE-2009-2382: admin script allows authentication bypass by setting a cookie value to "LOGGEDIN".

CVE-2009-1048: VOIP product allows authentication bypass using 127.0.0.1 in the Host header.

CVE-2009-2213: product uses default "Allow" action, instead of default deny, leading to authentication bypass.

CVE-2009-2168: chain: redirect without exit (CWE-698) leads to resultant authentication bypass.

CVE-2009-3107: product does not restrict access to a listening port for a critical service, allowing authentication to be bypassed.

CVE-2009-1596: product does not properly implement a security-related configuration setting, allowing authentication bypass.

CVE-2009-2422: authentication routine returns "nil" instead of "false" in some situations, allowing authentication bypass using an invalid username.

CVE-2009-3232: authentication update script does not properly handle when admin does not select any authentication modules, allowing authentication bypass.

CVE-2009-3231: use of LDAP authentication with anonymous binds causes empty password to result in successful authentication

CVE-2005-3435: product authentication succeeds if user-provided MD5 hash matches the hash in its database; this can be subjected to replay attacks.

CVE-2005-0408: chain: product generates predictable MD5 hashes using a constant value combined with username, allowing authentication bypass.

## Top 25 Examples

CVE-2022-33242: Memory corruption due to improper authentication in Qualcomm IPC while loading unsigned lib in audio PD.

CVE-2022-39267: Bifrost is a heterogeneous middleware that synchronizes MySQL, MariaDB to Redis, MongoDB, ClickHouse, MySQL and other services for production environments. Versions prior to 1.8.8-release are subject to authentication bypass in the admin and monitor user groups by deleting the X-Requested-With: XMLHttpRequest field in the request header. This issue has been patched in 1.8.8-release. There are no known workarounds.

CVE-2022-39219: Bifrost is a middleware package which can synchronize MySQL/MariaDB binlog data to other types of databases. Versions 1.8.6-release and prior are vulnerable to authentication bypass when using HTTP basic authentication. This may allow group members who only have read permissions to write requests when they are normally forbidden from doing so. Version 1.8.7-release contains a patch. There are currently no known workarounds.

CVE-2022-30755: Improper authentication vulnerability in AppLock prior to SMR Jul-2022 Release 1 allows attacker to bypass password confirm activity by hijacking the implicit intent.

CVE-2021-33766: Microsoft Exchange Server Information Disclosure Vulnerability

CVE-2021-34523: Microsoft Exchange Server Elevation of Privilege Vulnerability

CVE-2022-22289: Improper access control vulnerability in S Assistant prior to version 7.5 allows attacker to remotely get senstive information.

CVE-2022-25825: Improper access control vulnerability in Samsung Account prior to version 13.1.0.1 allows attackers to access to the authcode for sign-in.

CVE-2022-28713: Improper authentication vulnerability in Scheduler of Cybozu Garoon 4.10.0 to 5.5.1 allows a remote attacker to obtain some data of Facility Information without logging in to the product.

CVE-2022-30749: Improper access control vulnerability in Smart Things prior to 1.7.85.25 allows local attackers to add arbitrary smart devices by bypassing login activity.

CVE-2022-33720: Improper authentication vulnerability in AppLock prior to SMR Aug-2022 Release 1 allows physical attacker to access Chrome locked by AppLock via new tap shortcut.

CVE-2022-39892: Improper access control in Samsung Pass prior to version 4.0.05.1 allows attackers to unauthenticated access via keep open feature.

CVE-2022-2031: A flaw was found in Samba. The security vulnerability occurs when KDC and the kpasswd service share a single account and set of keys, allowing them to decrypt each other's tickets. A user who has been requested to change their password, can exploit this flaw to obtain and use tickets to other services.

CVE-2022-25652: Cryptographic issues in BSP due to improper hash verification in Snapdragon Wired Infrastructure and Networking

CVE-2022-29838: Improper Authentication vulnerability in the encrypted volumes and auto mount features of Western Digital My Cloud devices allows insecure direct access to the drive information in the case of a device reset. This issue affects: Western Digital My Cloud My Cloud versions prior to 5.25.124 on Linux.

CVE-2022-39901: Improper authentication in Exynos baseband prior to SMR DEC-2022 Release 1 allows remote attacker to disable the network traffic encryption between UE and gNodeB.

CVE-2021-44676: Zoho ManageEngine Access Manager Plus before 4203 allows anyone to view a few data elements (e.g., access control details) and modify a few aspects of the application state.

CVE-2022-30150: Windows Defender Remote Credential Guard Elevation of Privilege Vulnerability

CVE-2021-4230: A vulnerability has been found in Airfield Online and classified as problematic. This vulnerability affects the path /backups/ of the MySQL backup handler. An attacker is able to get access to sensitive data without proper authentication. It is recommended to the change the configuration settings.

CVE-2022-0342: An authentication bypass vulnerability in the CGI program of Zyxel USG/ZyWALL series firmware versions 4.20 through 4.70, USG FLEX series firmware versions 4.50 through 5.20, ATP series firmware versions 4.32 through 5.20, VPN series firmware versions 4.30 through 5.20, and NSG series firmware versions V1.20 through V1.33 Patch 4, which could allow an attacker to bypass the web authentication and obtain administrative access of the device.

CVE-2022-0730: Under certain ldap conditions, Cacti authentication can be bypassed with certain credential types.

CVE-2022-1084: A vulnerability classified as critical was found in SourceCodester One Church Management System 1.0. Affected by this vulnerability is an unknown functionality of the file /one_church/userregister.php. The manipulation leads to authentication bypass. The attack can be launched remotely.

CVE-2022-1101: A vulnerability was found in SourceCodester Royale Event Management System 1.0. It has been rated as critical. This issue affects some unknown processing of the file /royal_event/userregister.php. The manipulation leads to improper authentication. The attack may be initiated remotely. The identifier VDB-195785 was assigned to this vulnerability.

CVE-2022-20798: A vulnerability in the external authentication functionality of Cisco Secure Email and Web Manager, formerly known as Cisco Security Management Appliance (SMA), and Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to bypass authentication and log in to the web management interface of an affected device. This vulnerability is due to improper authentication checks when an affected device uses Lightweight Directory Access Protocol (LDAP) for external authentication. An attacker could exploit this vulnerability by entering a specific input on the login page of the affected device. A successful exploit could allow the attacker to gain unauthorized access to the web-based management interface of the affected device.

CVE-2022-21692: OnionShare is an open source tool that lets you securely and anonymously share files, host websites, and chat with friends using the Tor network. In affected versions anyone with access to the chat environment can write messages disguised as another chat participant.

CVE-2022-21695: OnionShare is an open source tool that lets you securely and anonymously share files, host websites, and chat with friends using the Tor network. In affected versions authenticated users (or unauthenticated in public mode) can send messages without being visible in the list of chat participants. This issue has been resolved in version 2.5.

CVE-2022-21794: Improper authentication in BIOS firmware for some Intel(R) NUC Boards, Intel(R) NUC Business, Intel(R) NUC Enthusiast, Intel(R) NUC Kits before version HN0067 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-21936: On Metasys ADX Server version 12.0 running MVE, an Active Directory user could execute validated actions without providing a valid password when using MVE SMP UI.

CVE-2022-2197: By using a specific credential string, an attacker with network access to the device’s web interface could circumvent the authentication scheme and perform administrative operations.

CVE-2022-22237: An Improper Authentication vulnerability in the kernel of Juniper Networks Junos OS allows an unauthenticated, network-based attacker to cause an impact on confidentiality or integrity. A vulnerability in the processing of TCP-AO will allow a BGP or LDP peer not configured with authentication to establish a session even if the peer is locally configured to use authentication. This could lead to untrusted or unauthorized sessions being established. This issue affects Juniper Networks Junos OS: 21.2 versions prior to 21.2R3-S1; 21.3 versions prior to 21.3R2-S2, 21.3R3; 21.4 versions prior to 21.4R2-S1, 21.4R3; 22.1 versions prior to 22.1R1-S1, 22.1R2. This issue does not affect Juniper Networks Junos OS Evolved.

CVE-2022-22259: There is an improper authentication vulnerability in FLMG-10 10.0.1.0(H100SP22C00). Successful exploitation of this vulnerability may lead to a control of the victim device.

CVE-2022-22284: Improper authentication vulnerability in Samsung Internet prior to 16.0.2.19 allows attackers to bypass secret mode password authentication

CVE-2022-22523: An improper authentication vulnerability exists in the Carlo Gavazzi UWP3.0 in multiple versions and CPY Car Park Server in Version 2.8.3 Web-App which allows an authentication bypass to the context of an unauthorised user if free-access is disabled.

CVE-2022-22656: An authentication issue was addressed with improved state management. This issue is fixed in macOS Big Sur 11.6.5, macOS Monterey 12.3, Security Update 2022-003 Catalina. A local attacker may be able to view the previous logged in user’s desktop from the fast user switching screen.

CVE-2022-22730: Improper authentication in the Intel(R) Edge Insights for Industrial software before version 2.6.1 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

CVE-2022-23156: Wyse Device Agent version 14.6.1.4 and below contain an Improper Authentication vulnerability. A malicious user could potentially exploit this vulnerability by providing invalid input in order to obtain a connection to WMS server.

CVE-2022-23769: Remote code execution vulnerability due to insufficient user privilege verification in reverseWall-MDS. Remote attackers can exploit the vulnerability such as stealing account, through remote code execution.

CVE-2022-23795: An issue was discovered in Joomla! 2.5.0 through 3.10.6 & 4.0.0 through 4.1.0. A user row was not bound to a specific authentication mechanism which could under very special circumstances allow an account takeover.

CVE-2022-23807: An issue was discovered in phpMyAdmin 4.9 before 4.9.8 and 5.1 before 5.1.2. A valid user who is already authenticated to phpMyAdmin can manipulate their account to bypass two-factor authentication for future login instances.

CVE-2022-24422: Dell iDRAC9 versions 5.00.00.00 and later but prior to 5.10.10.00, contain an improper authentication vulnerability. A remote unauthenticated attacker may potentially exploit this vulnerability to gain access to the VNC Console.

CVE-2022-24740: Volto is a ReactJS-based frontend for the Plone Content Management System. Between versions 14.0.0-alpha.5 and 15.0.0-alpha.0, a user could have their authentication cookie replaced with an authentication cookie from another user, effectively giving them control of the other user's account and privileges. This occurs when using an outdated version of the `react-cookie` library and a server is under high load. A proof of concept does not currently exist, but it is possible for this issue to occur in the wild. The patch and fix is present in Volto 15.0.0-alpha.0. As a workaround, one may manually upgrade the `react-cookie` package to 4.1.1 and then override all Volto components that use this library.

CVE-2022-25667: Information disclosure in kernel due to improper handling of ICMP requests in Snapdragon Wired Infrastructure and Networking

CVE-2022-25816: Improper authentication in Samsung Lock and mask apps setting prior to SMR Mar-2022 Release 1 allows attacker to change enable/disable without authentication

CVE-2022-25832: Improper authentication vulnerability in S Secure prior to SMR Apr-2022 Release 1 allows physical attackers to use locked Myfiles app without authentication.

CVE-2022-25833: Improper authentication in ImsService prior to SMR Apr-2022 Release 1 allows attackers to get IMSI without READ_PRIVILEGED_PHONE_STATE permission.

CVE-2022-26034: Improper authentication vulnerability in the communication protocol provided by AD (Automation Design) server of CENTUM VP R6.01.10 to R6.09.00, CENTUM VP Small R6.01.10 to R6.09.00, CENTUM VP Basic R6.01.10 to R6.09.00, and B/M9000 VP R8.01.01 to R8.03.01 allows an attacker to use the functions provided by AD server. This may lead to leakage or tampering of data managed by AD server.

CVE-2022-26508: Improper authentication in the Intel(R) SDP Tool before version 3.0.0 may allow an unauthenticated user to potentially enable information disclosure via network access.

CVE-2022-2662: Sequi PortBloque S has a improper authentication issues which may allow an attacker to bypass the authentication process and gain user-level access to the device.

CVE-2022-2664: A vulnerability classified as critical has been found in Private Cloud Management Platform. Affected is an unknown function of the file /management/api/rcx_management/global_config_query of the component POST Request Handler. The manipulation leads to improper authentication. It is possible to launch the attack remotely. VDB-205614 is the identifier assigned to this vulnerability.

CVE-2022-26724: An authentication issue was addressed with improved state management. This issue is fixed in tvOS 15.5. A local user may be able to enable iCloud Photos without authentication.

CVE-2022-26845: Improper authentication in firmware for Intel(R) AMT before versions 11.8.93, 11.22.93, 11.12.93, 12.0.92, 14.1.67, 15.0.42, 16.1.25 may allow an unauthenticated user to potentially enable escalation of privilege via network access.

CVE-2022-3156: A remote code execution vulnerability exists in Rockwell Automation Studio 5000 Logix Emulate software. Users are granted elevated permissions on certain product services when the software is installed. Due to this misconfiguration, a malicious user could potentially achieve remote code execution on the targeted software. 

CVE-2022-3173: Improper Authentication in GitHub repository snipe/snipe-it prior to 6.0.10.

CVE-2022-32514: A CWE-287: Improper Authentication vulnerability exists that could allow an attacker to gain control of the device when logging into a web page. Affected Products: C-Bus Network Automation Controller - LSS5500NAC (Versions prior to V1.10.0), Wiser for C-Bus Automation Controller - LSS5500SHAC (Versions prior to V1.10.0), Clipsal C-Bus Network Automation Controller - 5500NAC (Versions prior to V1.10.0), Clipsal Wiser for C-Bus Automation Controller - 5500SHAC (Versions prior to V1.10.0), SpaceLogic C-Bus Network Automation Controller - 5500NAC2 (Versions prior to V1.10.0), SpaceLogic C-Bus Application Controller - 5500AC2 (Versions prior to V1.10.0)

CVE-2022-32570: Improper authentication in the Intel(R) Quartus Prime Pro and Standard edition software may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-32971: Improper authentication in the Intel(R) SUR software before version 2.4.8902 may allow a privileged user to potentially enable escalation of privilege via network access.

CVE-2022-33750: CA Automic Automation 12.2 and 12.3 contain an authentication error vulnerability in the Automic agent that could allow a remote attacker to potentially execute arbitrary commands.

CVE-2022-33946: Improper authentication in the Intel(R) SUR software before version 2.4.8902 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-34331: After performing a sequence of Power FW950, FW1010 maintenance operations a SRIOV network adapter can be improperly configured leading to desired VEPA configuration being disabled. IBM X-Force ID: 229695.

CVE-2022-34379: Dell EMC CloudLink 7.1.2 and all prior versions contain an Authentication Bypass Vulnerability. A remote attacker, with the knowledge of the active directory usernames, could potentially exploit this vulnerability to gain unauthorized access to the system.

CVE-2022-35646:  IBM Security Verify Governance, Identity Manager 10.0.1 software component could allow an authenticated user to modify or cancel any other user's access request using man-in-the-middle techniques. IBM X-Force ID: 231096. 

CVE-2022-36370: Improper authentication in BIOS firmware for some Intel(R) NUC Boards and Intel(R) NUC Kits before version MYi30060 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-37345: Improper authentication in BIOS firmware[A1] for some Intel(R) NUC Kits before version RY0386 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-37931: A vulnerability in NetBatch-Plus software allows unauthorized access to the application. HPE has provided a workaround and fix. Please refer to HPE Security Bulletin HPESBNS04388 for details. 

CVE-2022-38119: UPSMON Pro login function has insufficient authentication. An unauthenticated remote attacker can exploit this vulnerability to bypass authentication and get administrator privilege to access, control system or disrupt service.

CVE-2022-38368: An issue was discovered in Aviatrix Gateway before 6.6.5712 and 6.7.x before 6.7.1376. Because Gateway API functions mishandle authentication, an authenticated VPN user can inject arbitrary commands.

CVE-2022-38744:  An unauthenticated attacker with network access to a victim's Rockwell Automation FactoryTalk Alarm and Events service could open a connection, causing the service to fault and become unavailable. The affected port could be used as a server ping port and uses messages structured with XML. 

CVE-2022-39038: Agentflow BPM enterprise management system has improper authentication. A remote attacker with general user privilege can change the name of the user account to acquire arbitrary account privilege, and access, manipulate system or disrupt service.

CVE-2022-39042: aEnrich a+HRD has improper validation for login function. An unauthenticated remote attacker can exploit this vulnerability to bypass authentication and access API function to perform arbitrary system command or disrupt service.

CVE-2022-39801: SAP GRC Access control Emergency Access Management allows an authenticated attacker to access a Firefighter session even after it is closed in Firefighter Logon Pad. This attack can be launched only within the firewall. On successful exploitation the attacker can gain access to admin session and completely compromise the application.

CVE-2022-39899: Improper authentication vulnerability in Samsung WindowManagerService prior to SMR Dec-2022 Release 1 allows attacker to send the input event using S Pen gesture.

CVE-2022-40144: A vulnerability in Trend Micro Apex One and Trend Micro Apex One as a Service could allow an attacker to bypass the product's login authentication by falsifying request parameters on affected installations.

CVE-2022-41579: There is an insufficient authentication vulnerability in some Huawei band products. Successful exploit could allow the attacker to spoof then connect to the band.

CVE-2022-41590: Some smartphones have authentication-related (including session management) vulnerabilities as the setup wizard is bypassed. Successful exploitation of this vulnerability affects the smartphone availability.

CVE-2022-41648: The HEIDENHAIN Controller TNC 640, version 340590 07 SP5, running HEROS 5.08.3 controlling the HARTFORD 5A-65E CNC machine is vulnerable to improper authentication, which may allow an attacker to deny service to the production line, steal sensitive data from the production line, and alter any products created by the production line.

CVE-2022-42463: OpenHarmony-v3.1.2 and prior versions have an authenication bypass vulnerability in a callback handler function of Softbus_server in communication subsystem. Attackers can launch attacks on distributed networks by sending Bluetooth rfcomm packets to any remote device and executing arbitrary commands.

CVE-2021-24881: The Passster WordPress plugin before 3.5.5.9 does not properly check for password, as well as that the post to be viewed is public, allowing unauthenticated users to bypass the protection offered by the plugin, and access arbitrary posts (such as private) content, by sending a specifically crafted request.

CVE-2021-26638: Improper Authentication vulnerability in S&D smarthome(smartcare) application can cause authentication bypass and information exposure. Remote attackers can use this vulerability to take control of the home environment including indoor control.

CVE-2021-33076: Improper authentication in firmware for some Intel(R) SSD DC Products may allow an unauthenticated user to potentially enable escalation of privilege via physical access.

CVE-2021-33159: Improper authentication in subsystem for Intel(R) AMT before versions 11.8.93, 11.22.93, 11.12.93, 12.0.92, 14.1.67, 15.0.42, 16.1.25 may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-43504: Improper authentication vulnerability in WordPress versions prior to 6.0.3 allows a remote unauthenticated attacker to obtain the email address of the user who posted a blog using the WordPress Post by Email Feature. The developer also provides new patched releases for all versions since 3.7.

CVE-2022-43549: Improper authentication in Veeam Backup for Google Cloud v1.0 and v3.0 allows attackers to bypass authentication mechanisms.

CVE-2022-43900:  IBM WebSphere Automation for IBM Cloud Pak for Watson AIOps 1.4.2 could provide a weaker than expected security. A local attacker can create an outbound network connection to another system. IBM X-Force ID: 240827. 

CVE-2022-44574: An improper authentication vulnerability exists in Avalanche version 6.3.x and below allows unauthenticated attacker to modify properties on specific port.

CVE-2022-44620: Improper authentication vulnerability in UDR-JA1604/UDR-JA1608/UDR-JA1616 firmware versions 71x10.1.107112.43A and earlier allows a remote authenticated attacker to execute an arbitrary OS command on the device or alter the device settings.

CVE-2022-46313: The sensor privacy module has an authentication vulnerability. Successful exploitation of this vulnerability may cause unavailability of the smartphone's camera and microphone.

CVE-2022-46773: IBM Robotic Process Automation 21.0.0 - 21.0.7 and 23.0.0 is vulnerable to client-side validation bypass for credential pools. Invalid credential pools may be created as a result. IBM X-Force ID: 242951.

CVE-2022-46829: In JetBrains JetBrains Gateway before 2022.3 a client could connect without a valid token if the host consented.

CVE-2022-48294: The IHwAttestationService interface has a defect in authentication. Successful exploitation of this vulnerability may affect data confidentiality.

CVE-2022-26858: Dell BIOS versions contain an Improper Authentication vulnerability. A locally authenticated malicious user could potentially exploit this vulnerability by sending malicious input to an SMI in order to bypass security controls.

CVE-2022-2752: A vulnerability in the web server of Secomea GateManager allows a local user to impersonate as the previous user under some failed login conditions. This issue affects: Secomea GateManager versions from 9.4 through 9.7. 

CVE-2022-2757:  Due to the lack of adequately implemented access-control rules, all versions Kingspan TMS300 CS are vulnerable to an attacker viewing and modifying the application settings without authenticating by accessing a specific uniform resource locator (URL) on the webserver. 

CVE-2022-27839: Improper authentication vulnerability in SecretMode in Samsung Internet prior to version 16.2.1 allows attackers to access bookmark tab without proper credentials.

CVE-2022-27874: Improper authentication in some Intel(R) XMM(TM) 7560 Modem software before version M2_7560_R_01.2146.00 may allow a privileged user to potentially enable escalation of privilege via physical access.

CVE-2022-28790: Improper authentication in Link to Windows Service prior to version 2.3.04.1 allows attacker to lock the device. The patch adds proper caller signature check logic.

CVE-2022-29083: Prior Dell BIOS versions contain an Improper Authentication vulnerability. An unauthenticated attacker with physical access to the system could potentially exploit this vulnerability by bypassing drive security mechanisms in order to gain access to the system.

CVE-2022-29893: Improper authentication in firmware for Intel(R) AMT before versions 11.8.93, 11.22.93, 11.12.93, 12.0.92, 14.1.67, 15.0.42, 16.1.25 may allow an authenticated user to potentially enable escalation of privilege via network access.

CVE-2022-30238: A CWE-287: Improper Authentication vulnerability exists that could allow an attacker to take over the admin account when an attacker hijacks a session. Affected Products: Wiser Smart, EER21000 & EER21001 (V4.5 and prior)

CVE-2022-31011: TiDB is an open-source NewSQL database that supports Hybrid Transactional and Analytical Processing (HTAP) workloads. Under certain conditions, an attacker can construct malicious authentication requests to bypass the authentication process, resulting in privilege escalation or unauthorized access. Only users using TiDB 5.3.0 are affected by this vulnerability. TiDB version 5.3.1 contains a patch for this issue. Other mitigation strategies include turning off Security Enhanced Mode (SEM), disabling local login for non-root accounts, and ensuring that the same IP cannot be logged in as root and normal user at the same time.

CVE-2022-31125: Roxy-wi is an open source web interface for managing Haproxy, Nginx, Apache and Keepalived servers. A vulnerability in Roxy-wi allows a remote, unauthenticated attacker to bypass authentication and access admin functionality by sending a specially crafted HTTP request. This affects Roxywi versions before 6.1.1.0. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-31164: Tovy is a a staff management system for Roblox groups. A vulnerability in versions prior to 0.7.51 allows users to log in as other users, including privileged users such as the other of the instance. The problem has been patched in version 0.7.51.

# CWE-288 Authentication Bypass Using an Alternate Path or Channel

## Description

A product requires authentication, but the product has an alternate path or channel that does not require authentication.

## Observed Examples

CVE-2000-1179: Router allows remote attackers to read system logs without authentication by directly connecting to the login screen and typing certain control characters.

CVE-1999-1454: Attackers with physical access to the machine may bypass the password prompt by pressing the ESC (Escape) key.

CVE-1999-1077: OS allows local attackers to bypass the password protection of idled sessions via the programmer's switch or CMD-PWR keyboard sequence, which brings up a debugger that the attacker can use to disable the lock.

CVE-2003-0304: Direct request of installation file allows attacker to create administrator accounts.

CVE-2002-0870: Attackers may gain additional privileges by directly requesting the web management URL.

CVE-2002-0066: Bypass authentication via direct request to named pipe.

CVE-2003-1035: User can avoid lockouts by using an API instead of the GUI to conduct brute force password guessing.

## Top 25 Examples

CVE-2022-40684: An authentication bypass using an alternate path or channel [CWE-288] in Fortinet FortiOS version 7.2.0 through 7.2.1 and 7.0.0 through 7.0.6, FortiProxy version 7.2.0 and version 7.0.0 through 7.0.6 and FortiSwitchManager version 7.2.0 and 7.0.0 allows an unauthenticated atttacker to perform operations on the administrative interface via specially crafted HTTP or HTTPS requests.

CVE-2022-42458: Authentication bypass using an alternate path or channel vulnerability in bingo!CMS version1.7.4.1 and earlier allows a remote unauthenticated attacker to upload an arbitrary file. As a result, an arbitrary script may be executed and/or a file may be altered.

CVE-2022-34380: Dell CloudLink 7.1.3 and all earlier versions contain an Authentication Bypass Using an Alternate Path or Channel Vulnerability. A high privileged local attacker may potentially exploit this vulnerability leading to authentication bypass and access the CloudLink system console. This is critical severity vulnerability as it allows attacker to take control of the system.

CVE-2021-44525: Zoho ManageEngine PAM360 before build 5303 allows attackers to modify a few aspects of application state because of a filter bypass in which authentication is not required.

CVE-2021-41995: A misconfiguration of RSA in PingID Mac Login prior to 1.1 is vulnerable to pre-computed dictionary attacks, leading to an offline MFA bypass.

CVE-2022-23722: When a password reset mechanism is configured to use the Authentication API with an Authentication Policy, email One-Time Password, PingID or SMS authentication, an existing user can reset another existing user’s password.

CVE-2022-23723: An MFA bypass vulnerability exists in the PingFederate PingOne MFA Integration Kit when adapter HTML templates are used as part of an authentication flow.

CVE-2022-24813: CreateWiki is Miraheze's MediaWiki extension for requesting & creating wikis. Without the patch for this issue, anonymous comments can be made using Special:RequestWikiQueue when sent directly via POST. A patch for this issue is available in the `master` branch of CreateWiki's GitHub repository.

CVE-2022-24857: django-mfa3 is a library that implements multi factor authentication for the django web framework. It achieves this by modifying the regular login view. Django however has a second login view for its admin area. This second login view was not modified, so the multi factor authentication can be bypassed. Users are affected if they have activated both django-mfa3 (< 0.5.0) and django.contrib.admin and have not taken any other measures to prevent users from accessing the admin login view. The issue has been fixed in django-mfa3 0.5.0. It is possible to work around the issue by overwriting the admin login route, e.g. by adding the following URL definition *before* the admin routes: url('admin/login/', lambda request: redirect(settings.LOGIN_URL)

CVE-2022-33202: Authentication bypass vulnerability in the setup screen of L2Blocker(on-premise) Ver4.8.5 and earlier and L2Blocker(Cloud) Ver4.8.5 and earlier allows an adjacent attacker to perform an unauthorized login and obtain the stored information or cause a malfunction of the device by using alternative paths or channels for Sensor.

CVE-2022-34372: Dell PowerProtect Cyber Recovery versions before 19.11.0.2 contain an authentication bypass vulnerability. A remote unauthenticated attacker may potentially access and interact with the docker registry API leading to an authentication bypass. The attacker may potentially alter the docker images leading to a loss of integrity and confidentiality

CVE-2022-40966: Authentication bypass vulnerability in multiple Buffalo network devices allows a network-adjacent attacker to bypass authentication and access the device. The affected products/versions are as follows: WCR-300 firmware Ver. 1.87 and earlier, WHR-HP-G300N firmware Ver. 2.00 and earlier, WHR-HP-GN firmware Ver. 1.87 and earlier, WPL-05G300 firmware Ver. 1.88 and earlier, WRM-D2133HP firmware Ver. 2.85 and earlier, WRM-D2133HS firmware Ver. 2.96 and earlier, WTR-M2133HP firmware Ver. 2.85 and earlier, WTR-M2133HS firmware Ver. 2.96 and earlier, WXR-1900DHP firmware Ver. 2.50 and earlier, WXR-1900DHP2 firmware Ver. 2.59 and earlier, WXR-1900DHP3 firmware Ver. 2.63 and earlier, WXR-5950AX12 firmware Ver. 3.40 and earlier, WXR-6000AX12B firmware Ver. 3.40 and earlier, WXR-6000AX12S firmware Ver. 3.40 and earlier, WZR-300HP firmware Ver. 2.00 and earlier, WZR-450HP firmware Ver. 2.00 and earlier, WZR-600DHP firmware Ver. 2.00 and earlier, WZR-900DHP firmware Ver. 1.15 and earlier, WZR-1750DHP2 firmware Ver. 2.31 and earlier, WZR-HP-AG300H firmware Ver. 1.76 and earlier, WZR-HP-G302H firmware Ver. 1.86 and earlier, WEM-1266 firmware Ver. 2.85 and earlier, WEM-1266WP firmware Ver. 2.85 and earlier, WLAE-AG300N firmware Ver. 1.86 and earlier, FS-600DHP firmware Ver. 3.40 and earlier, FS-G300N firmware Ver. 3.14 and earlier, FS-HP-G300N firmware Ver. 3.33 and earlier, FS-R600DHP firmware Ver. 3.40 and earlier, BHR-4GRV firmware Ver. 2.00 and earlier, DWR-HP-G300NH firmware Ver. 1.84 and earlier, DWR-PG firmware Ver. 1.83 and earlier, HW-450HP-ZWE firmware Ver. 2.00 and earlier, WER-A54G54 firmware Ver. 1.43 and earlier, WER-AG54 firmware Ver. 1.43 and earlier, WER-AM54G54 firmware Ver. 1.43 and earlier, WER-AMG54 firmware Ver. 1.43 and earlier, WHR-300 firmware Ver. 2.00 and earlier, WHR-300HP firmware Ver. 2.00 and earlier, WHR-AM54G54 firmware Ver. 1.43 and earlier, WHR-AMG54 firmware Ver. 1.43 and earlier, WHR-AMPG firmware Ver. 1.52 and earlier, WHR-G firmware Ver. 1.49 and earlier, WHR-G300N firmware Ver. 1.65 and earlier, WHR-G301N firmware Ver. 1.87 and earlier, WHR-G54S firmware Ver. 1.43 and earlier, WHR-G54S-NI firmware Ver. 1.24 and earlier, WHR-HP-AMPG firmware Ver. 1.43 and earlier, WHR-HP-G firmware Ver. 1.49 and earlier, WHR-HP-G54 firmware Ver. 1.43 and earlier, WLI-H4-D600 firmware Ver. 1.88 and earlier, WS024BF firmware Ver. 1.60 and earlier, WS024BF-NW firmware Ver. 1.60 and earlier, WXR-1750DHP firmware Ver. 2.60 and earlier, WXR-1750DHP2 firmware Ver. 2.60 and earlier, WZR-1166DHP firmware Ver. 2.18 and earlier, WZR-1166DHP2 firmware Ver. 2.18 and earlier, WZR-1750DHP firmware Ver. 2.30 and earlier, WZR2-G300N firmware Ver. 1.55 and earlier, WZR-450HP-CWT firmware Ver. 2.00 and earlier, WZR-450HP-UB firmware Ver. 2.00 and earlier, WZR-600DHP2 firmware Ver. 1.15 and earlier, WZR-600DHP3 firmware Ver. 2.19 and earlier, WZR-900DHP2 firmware Ver. 2.19 and earlier, WZR-AGL300NH firmware Ver. 1.55 and earlier, WZR-AMPG144NH firmware Ver. 1.49 and earlier, WZR-AMPG300NH firmware Ver. 1.51 and earlier, WZR-D1100H firmware Ver. 2.00 and earlier, WZR-G144N firmware Ver. 1.48 and earlier, WZR-G144NH firmware Ver. 1.48 and earlier, WZR-HP-G300NH firmware Ver. 1.84 and earlier, WZR-HP-G301NH firmware Ver. 1.84 and earlier, WZR-HP-G450H firmware Ver. 1.90 and earlier, WZR-S1750DHP firmware Ver. 2.32 and earlier, WZR-S600DHP firmware Ver. 2.19 and earlier, and WZR-S900DHP firmware Ver. 2.19 and earlier.

CVE-2021-35530: A vulnerability in the application authentication and authorization mechanism in Hitachi Energy's TXpert Hub CoreTec 4, that depends on a token validation of the session identifier, allows an unauthorized modified message to be executed in the server enabling an unauthorized actor to change an existing user password, and further gain authorized access into the system via login mechanism. This issue affects: Hitachi Energy TXpert Hub CoreTec 4 version 2.0.0 2.1.0; 2.1.0; 2.1.1; 2.1.2; 2.1.3; 2.2.0; 2.2.1.

CVE-2022-4874: Authentication bypass in Netcomm router models NF20MESH, NF20, and NL1902 allows an unauthenticated user to access content. In order to serve static content, the application performs a check for the existence of specific characters in the URL (.css, .png etc). If it exists, it performs a "fake login" to give the request an active session to load the file and not redirect to the login page.

CVE-2022-26865: Dell Support Assist OS Recovery versions before 5.5.2 contain an Authentication Bypass vulnerability. An unauthenticated attacker with physical access to the system may exploit this vulnerability by bypassing OS Recovery authentication in order to run arbitrary code on the system as Administrator.

CVE-2022-26870: Dell PowerStore versions 2.1.0.x contain an Authentication bypass vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability under specific configuration. An attacker would gain unauthorized access upon successful exploit.

CVE-2022-27510: Unauthorized access to Gateway user capabilities 

CVE-2022-30623: The server checks the user's cookie in a non-standard way, and a value is entered in the cookie value name of the status and its value is set to true to bypass the identification with the system using a username and password.

# CWE-289 Authentication Bypass by Alternate Name

## Description

The product performs authentication based on the name of a resource being accessed, or the name of the actor performing the access, but it does not properly check all possible names for that resource or actor.

## Observed Examples

CVE-2003-0317: Protection mechanism that restricts URL access can be bypassed using URL encoding.

CVE-2004-0847: Bypass of authentication for files using "\" (backslash) or "%5C" (encoded backslash).

## Top 25 Examples

CVE-2022-4722: Authentication Bypass by Primary Weakness in GitHub repository ikus060/rdiffweb prior to 2.5.5.

CVE-2022-23317: CobaltStrike <=4.5 HTTP(S) listener does not determine whether the request URL begins with "/", and attackers can obtain relevant information by specifying the URL.

# CWE-29 Path Traversal: '\..\filename'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '\..\filename' (leading backslash dot dot) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


This is similar to CWE-25, except using "\" instead of "/". Sometimes a program checks for "..\" at the beginning of the input, so a "\..\" can bypass that check. It is also useful for bypassing path traversal protection schemes that only assume that the "/" separator is valid.

## Observed Examples

CVE-2002-1987: Protection mechanism checks for "/.." but doesn't account for Windows-specific "\.." allowing read of arbitrary files.

CVE-2005-2142: Directory traversal vulnerability in FTP server allows remote authenticated attackers to list arbitrary directories via a "\.." sequence in an LS command.

## Top 25 Examples

CVE-2022-2788: Emerson Electric's Proficy Machine Edition Version 9.80 and prior is vulnerable to CWE-29 Path Traversal: '\\..\\Filename', also known as a ZipSlip attack, through an upload procedure which enables attackers to implant a malicious .BLZ file on the PLC. The file can transfer through the engineering station onto Windows in a way that executes the malicious code.

# CWE-290 Authentication Bypass by Spoofing

## Description

This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Observed Examples

CVE-2022-30319: S-bus functionality in a home automation product performs access control using an IP allowlist, which can be bypassed by a forged IP address.

CVE-2009-1048: VOIP product allows authentication bypass using 127.0.0.1 in the Host header.

## Top 25 Examples

CVE-2022-23131: In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

CVE-2022-0030: An authentication bypass vulnerability in the Palo Alto Networks PAN-OS 8.1 web interface allows a network-based attacker with specific knowledge of the target firewall or Panorama appliance to impersonate an existing PAN-OS administrator and perform privileged actions.

CVE-2022-2310: An authentication bypass vulnerability in Skyhigh SWG in main releases 10.x prior to 10.2.12, 9.x prior to 9.2.23, 8.x prior to 8.2.28, and controlled release 11.x prior to 11.2.1 allows a remote attacker to bypass authentication into the administration User Interface. This is possible because of SWG incorrectly whitelisting authentication bypass methods and using a weak crypto password. This can lead to the attacker logging into the SWG admin interface, without valid credentials, as the super user with complete control over the SWG.

CVE-2022-25989: An authentication bypass vulnerability exists in the libxm_av.so getpeermac() functionality of Anker Eufy Homebase 2 2.1.8.5h. A specially-crafted DHCP packet can lead to authentication bypass. An attacker can DHCP poison to trigger this vulnerability.

CVE-2022-32747: A CWE-290: Authentication Bypass by Spoofing vulnerability exists that could cause legitimate users to be locked out of devices or facilitate backdoor account creation by spoofing a device on the local network. Affected Products: EcoStruxure™ Cybersecurity Admin Expert (CAE) (Versions prior to 2.2)

CVE-2022-39227: python-jwt is a module for generating and verifying JSON Web Tokens. Versions prior to 3.3.4 are subject to Authentication Bypass by Spoofing, resulting in identity spoofing, session hijacking or authentication bypass. An attacker who obtains a JWT can arbitrarily forge its contents without knowing the secret key. Depending on the application, this may for example enable the attacker to spoof other user's identities, hijack their sessions, or bypass authentication. Users should upgrade to version 3.3.4. There are no known workarounds.

CVE-2022-40269: Authentication Bypass by Spoofing vulnerability in Mitsubishi Electric Corporation GOT2000 Series GT27 model versions 01.14.000 to 01.47.000, Mitsubishi Electric Corporation GOT2000 Series GT25 model versions 01.14.000 to 01.47.000 and Mitsubishi Electric Corporation GT SoftGOT2000 versions 1.265B to 1.285X allows a remote unauthenticated attacker to disclose sensitive information from users' browsers or spoof legitimate users by abusing inappropriate HTML attributes.

CVE-2022-4098: Multiple Wiesemann&Theis products of the ComServer Series are prone to an authentication bypass through IP spoofing. After a user logged in to the WBM of the Com-Server an unauthenticated attacker in the same subnet can obtain the session ID and through IP spoofing change arbitrary settings by crafting modified HTTP Get requests. This may result in a complete takeover of the device.

CVE-2022-32744: A flaw was found in Samba. The KDC accepts kpasswd requests encrypted with any key known to it. By encrypting forged kpasswd requests with its own key, a user can change other users' passwords, enabling full domain takeover.

CVE-2022-2368: Authentication Bypass by Spoofing in GitHub repository microweber/microweber prior to 1.2.20. 

CVE-2021-40288: A denial-of-service attack in WPA2, and WPA3-SAE authentication methods in TP-Link AX10v1 before V1_211014, allows a remote unauthenticated attacker to disconnect an already connected wireless client via sending with a wireless adapter specific spoofed authentication frames

CVE-2022-35629: Due to a bug in the handling of the communication between the client and server, it was possible for one client, already registered with their own client ID, to send messages to the server claiming to come from another client ID. This issue was resolved in Velociraptor 0.6.5-2.

CVE-2021-34548: An issue was discovered in Tor before 0.4.6.5, aka TROVE-2021-003. An attacker can forge RELAY_END or RELAY_RESOLVED to bypass the intended access control for ending a stream.

CVE-2021-38598: OpenStack Neutron before 16.4.1, 17.x before 17.1.3, and 18.0.0 allows hardware address impersonation when the linuxbridge driver with ebtables-nft is used on a Netfilter-based platform. By sending carefully crafted packets, anyone in control of a server instance connected to the virtual switch can impersonate the hardware addresses of other systems on the network, resulting in denial of service or in some cases possibly interception of traffic intended for other destinations.

CVE-2021-40823: A logic error in the room key sharing functionality of matrix-js-sdk (aka Matrix Javascript SDK) before 12.4.1 allows a malicious Matrix homeserver present in an encrypted room to steal room encryption keys (via crafted Matrix protocol messages) that were originally sent by affected Matrix clients participating in that room. This allows the homeserver to decrypt end-to-end encrypted messages sent by affected clients.

CVE-2021-40824: A logic error in the room key sharing functionality of Element Android before 1.2.2 and matrix-android-sdk2 (aka Matrix SDK for Android) before 1.2.2 allows a malicious Matrix homeserver present in an encrypted room to steal room encryption keys (via crafted Matrix protocol messages) that were originally sent by affected Matrix clients participating in that room. This allows the attacker to decrypt end-to-end encrypted messages sent by affected clients.

# CWE-291 Reliance on IP Address for Authentication

## Description

The product uses an IP address for authentication.

IP addresses can be easily spoofed. Attackers can forge the source IP address of the packets they send, but response packets will return to the forged IP address. To see the response packets, the attacker has to sniff the traffic between the victim machine and the forged IP address. In order to accomplish the required sniffing, attackers typically attempt to locate themselves on the same subnet as the victim machine. Attackers may be able to circumvent this requirement by using source routing, but source routing is disabled across much of the Internet today. In summary, IP address verification can be a useful part of an authentication scheme, but it should not be the single factor required for authentication.

## Observed Examples

CVE-2022-30319: S-bus functionality in a home automation product performs access control using an IP allowlist, which can be bypassed by a forged IP address.

## Top 25 Examples

CVE-2021-40867: Certain NETGEAR smart switches are affected by an authentication hijacking race-condition vulnerability by an unauthenticated attacker who uses the same source IP address as an admin in the process of logging in (e.g., behind the same NAT device, or already in possession of a foothold on an admin's machine). This occurs because the multi-step HTTP authentication process is effectively tied only to the source IP address. This affects GC108P before 1.0.8.2, GC108PP before 1.0.8.2, GS108Tv3 before 7.0.7.2, GS110TPP before 7.0.7.2, GS110TPv3 before 7.0.7.2, GS110TUP before 1.0.5.3, GS308T before 1.0.3.2, GS310TP before 1.0.3.2, GS710TUP before 1.0.5.3, GS716TP before 1.0.4.2, GS716TPP before 1.0.4.2, GS724TPP before 2.0.6.3, GS724TPv2 before 2.0.6.3, GS728TPPv2 before 6.0.8.2, GS728TPv2 before 6.0.8.2, GS750E before 1.0.1.10, GS752TPP before 6.0.8.2, GS752TPv2 before 6.0.8.2, MS510TXM before 1.0.4.2, and MS510TXUP before 1.0.4.2.

CVE-2022-21142: Authentication bypass vulnerability in a-blog cms Ver.2.8.x series versions prior to Ver.2.8.74, Ver.2.9.x series versions prior to Ver.2.9.39, Ver.2.10.x series versions prior to Ver.2.10.43, and Ver.2.11.x series versions prior to Ver.2.11.41 allows a remote unauthenticated attacker to bypass authentication under the specific condition.

CVE-2022-30319: Saia Burgess Controls (SBC) PCD through 2022-05-06 allows Authentication bypass. According to FSCT-2022-0062, there is a Saia Burgess Controls (SBC) PCD S-Bus authentication bypass issue. The affected components are characterized as: S-Bus (5050/UDP) authentication. The potential impact is: Authentication bypass. The Saia Burgess Controls (SBC) PCD controllers utilize the S-Bus protocol (5050/UDP) for a variety of engineering purposes. It is possible to configure a password in order to restrict access to sensitive engineering functionality. Authentication functions on the basis of a MAC/IP whitelist with inactivity timeout to which an authenticated client's MAC/IP is stored. UDP traffic can be spoofed to bypass the whitelist-based access control. Since UDP is stateless, an attacker capable of passively observing traffic can spoof arbitrary messages using the MAC/IP of an authenticated client. This allows the attacker access to sensitive engineering functionality such as uploading/downloading control logic and manipulating controller configuration.

CVE-2022-47648: An Improper Access Control vulnerability allows an attacker to access the control panel of the B420 without requiring any sort of authorization or authentication due to the IP based authorization. If an authorized user has accessed a publicly available B420 product using valid credentials, an insider attacker can gain access to the same panel without requiring any sort of authorization. The B420 module was already obsolete at the time this vulnerability was found (The End of Life announcement was made in 2013).

# CWE-293 Using Referer Field for Authentication

## Description

The referer field in HTTP requests can be easily modified and, as such, is not a valid means of message integrity checking.

The referer field in HTML requests can be simply modified by malicious users, rendering it useless as a means of checking the validity of the request in question.

# CWE-294 Authentication Bypass by Capture-replay

## Description

A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).

Capture-replay attacks are common and can be difficult to defeat without cryptography. They are a subset of network injection attacks that rely on observing previously-sent valid commands, then changing them slightly if necessary and resending the same commands to the server.

## Observed Examples

CVE-2005-3435: product authentication succeeds if user-provided MD5 hash matches the hash in its database; this can be subjected to replay attacks.

CVE-2007-4961: Chain: cleartext transmission of the MD5 hash of password (CWE-319) enables attacks against a server that is susceptible to replay (CWE-294).

## Top 25 Examples

CVE-2022-22806: A CWE-294: Authentication Bypass by Capture-replay vulnerability exists that could cause an unauthenticated connection to the UPS when a malformed connection is sent. Affected Product: SmartConnect Family: SMT Series (SMT Series ID=1015: UPS 04.5 and prior), SMC Series (SMC Series ID=1018: UPS 04.2 and prior), SMTL Series (SMTL Series ID=1026: UPS 02.9 and prior), SCL Series (SCL Series ID=1029: UPS 02.5 and prior / SCL Series ID=1030: UPS 02.5 and prior / SCL Series ID=1036: UPS 02.5 and prior / SCL Series ID=1037: UPS 03.1 and prior), SMX Series (SMX Series ID=1031: UPS 03.1 and prior)

CVE-2022-25159: Authentication Bypass by Capture-replay vulnerability in Mitsubishi Electric MELSEC iQ-F series FX5U(C) CPU all versions, Mitsubishi Electric MELSEC iQ-F series FX5UJ CPU all versions, Mitsubishi Electric MELSEC iQ-R series R00/01/02CPU all versions, Mitsubishi Electric MELSEC iQ-R series R04/08/16/32/120(EN)CPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120SFCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PSFCPU all versions, Mitsubishi Electric MELSEC iQ-R series R16/32/64MTCPU all versions, Mitsubishi Electric MELSEC iQ-R series RJ71C24(-R2/R4) all versions, Mitsubishi Electric MELSEC iQ-R series RJ71EN71 all versions, Mitsubishi Electric MELSEC iQ-R series RJ72GF15-T2 all versions, Mitsubishi Electric MELSEC Q series Q03/04/06/13/26UDVCPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/13/26UDPVCPU all versions, Mitsubishi Electric MELSEC Q series QJ71C24N(-R2/R4) all versions and Mitsubishi Electric MELSEC Q series QJ71E71-100 all versions allows a remote unauthenticated attacker to login to the product by replay attack.

CVE-2022-30466: joyebike Joy ebike Wolf Manufacturing year 2022 is vulnerable to Authentication Bypass by Capture-replay.

CVE-2022-33208: Authentication bypass by capture-replay vulnerability exists in Machine automation controller NJ series all models V 1.48 and earlier, Machine automation controller NX7 series all models V1.28 and earlier, Machine automation controller NX1 series all models V1.48 and earlier, Automation software 'Sysmac Studio' all models V1.49 and earlier, and Programmable Terminal (PT) NA series NA5-15W/NA5-12W/NA5-9W/NA5-7W models Runtime V1.15 and earlier, which may allow a remote attacker who can analyze the communication between the affected controller and automation software 'Sysmac Studio' and/or a Programmable Terminal (PT) to access the controller.

CVE-2022-33971: Authentication bypass by capture-replay vulnerability exists in Machine automation controller NX7 series all models V1.28 and earlier, Machine automation controller NX1 series all models V1.48 and earlier, and Machine automation controller NJ series all models V 1.48 and earlier, which may allow an adjacent attacker who can analyze the communication between the controller and the specific software used by OMRON internally to cause a denial-of-service (DoS) condition or execute a malicious program.

CVE-2022-45789: A CWE-294: Authentication Bypass by Capture-replay vulnerability exists that could cause execution of unauthorized Modbus functions on the controller when hijacking an authenticated Modbus session. Affected Products: EcoStruxure Control Expert (All Versions), EcoStruxure Process Expert (All Versions), Modicon M340 CPU - part numbers BMXP34* (All Versions), Modicon M580 CPU - part numbers BMEP* and BMEH* (All Versions), Modicon M580 CPU Safety - part numbers BMEP58*S and BMEH58*S (All Versions) 

CVE-2021-22640: An attacker can decrypt the Ovarro TBox login password by communication capture and brute force attacks.

CVE-2021-38296: Apache Spark supports end-to-end encryption of RPC connections via "spark.authenticate" and "spark.network.crypto.enabled". In versions 3.1.2 and earlier, it uses a bespoke mutual authentication protocol that allows for full encryption key recovery. After an initial interactive attack, this would allow someone to decrypt plaintext traffic offline. Note that this does not affect security mechanisms controlled by "spark.authenticate.enableSaslEncryption", "spark.io.encryption.enabled", "spark.ssl", "spark.ui.strictTransportSecurity". Update to Apache Spark 3.1.3 or later

CVE-2022-22936: An issue was discovered in SaltStack Salt in versions before 3002.8, 3003.4, 3004.1. Job publishes and file server replies are susceptible to replay attacks, which can result in an attacker replaying job publishes causing minions to run old jobs. File server replies can also be re-played. A sufficient craft attacker could gain root access on minion under certain scenarios.

CVE-2022-29878: A vulnerability has been identified in SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00). Affected devices use a limited range for challenges that are sent during the unencrypted challenge-response communication. An unauthenticated attacker could capture a valid challenge-response pair generated by a legitimate user, and request the webpage repeatedly to wait for the same challenge to reappear for which the correct response is known. This could allow the attacker to access the management interface of the device.

CVE-2022-40621: Because the WAVLINK Quantum D4G (WN531G3) running firmware version M31G3.V5030.200325 and earlier communicates over HTTP and not HTTPS, and because the hashing mechanism does not rely on a server-supplied key, it is possible for an attacker with sufficient network access to capture the hashed password of a logged on user and use it in a classic Pass-the-Hash style attack.

CVE-2022-41541: TP-Link AX10v1 V1_211117 allows attackers to execute a replay attack by using a previously transmitted encrypted authentication message and valid authentication token. Attackers are able to login to the web application as an admin user.

CVE-2022-29334: An issue in H v1.0 allows attackers to bypass authentication via a session replay attack.

CVE-2022-31158: LTI 1.3 Tool Library is a library used for building IMS-certified LTI 1.3 tool providers in PHP. Prior to version 5.0, the Nonce Claim Value was not being validated against the nonce value sent in the Authentication Request. Users should upgrade to version 5.0 to receive a patch. There are currently no known workarounds.

# CWE-295 Improper Certificate Validation

## Description

The product does not validate, or incorrectly validates, a certificate.

When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client. The product might connect to a malicious host while believing it is a trusted host, or the product might be deceived into accepting spoofed data that appears to originate from a trusted host.

A certificate is a token that associates an identity (principal) to a cryptographic key. Certificates can be used to check if a public key belongs to the assumed owner.

## Observed Examples

CVE-2019-12496: A Go framework for robotics, drones, and IoT devices skips verification of root CA certificates by default.

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversary-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

CVE-2021-22909: Chain: router's firmware update procedure uses curl with "-k" (insecure) option that disables certificate validation (CWE-295), allowing adversary-in-the-middle (AITM) compromise with a malicious firmware image (CWE-494).

CVE-2008-4989: Verification function trusts certificate chains in which the last certificate is self-signed.

CVE-2012-5821: Web browser uses a TLS-related function incorrectly, preventing it from verifying that a server's certificate is signed by a trusted certification authority (CA)

CVE-2009-3046: Web browser does not check if any intermediate certificates are revoked.

CVE-2011-0199: Operating system does not check Certificate Revocation List (CRL) in some cases, allowing spoofing using a revoked certificate.

CVE-2012-5810: Mobile banking application does not verify hostname, leading to financial loss.

CVE-2012-3446: Cloud-support library written in Python uses incorrect regular expression when matching hostname.

CVE-2009-2408: Web browser does not correctly handle '\0' character (NUL) in Common Name, allowing spoofing of https sites.

CVE-2012-2993: Smartphone device does not verify hostname, allowing spoofing of mail services.

CVE-2012-5822: Application uses third-party library that does not validate hostname.

CVE-2012-5819: Cloud storage management application does not validate hostname.

CVE-2012-5817: Java library uses JSSE SSLSocket and SSLEngine classes, which do not verify the hostname.

CVE-2010-1378: chain: incorrect calculation allows attackers to bypass certificate checks.

CVE-2005-3170: LDAP client accepts certificates even if they are not from a trusted CA.

CVE-2009-0265: chain: DNS server does not correctly check return value from the OpenSSL EVP_VerifyFinal function allows bypass of validation of the certificate chain.

CVE-2003-1229: chain: product checks if client is trusted when it intended to check if the server is trusted, allowing validation of signed code.

CVE-2002-0862: Cryptographic API, as used in web browsers, mail clients, and other software, does not properly validate Basic Constraints.

CVE-2009-1358: chain: OS package manager does not check properly check the return value, allowing bypass using a revoked certificate.

## Top 25 Examples

CVE-2021-3935: When PgBouncer is configured to use "cert" authentication, a man-in-the-middle attacker can inject arbitrary SQL queries when a connection is first established, despite the use of TLS certificate verification and encryption. This flaw affects PgBouncer versions prior to 1.16.1.

CVE-2022-20703: Multiple vulnerabilities in Cisco Small Business RV160, RV260, RV340, and RV345 Series Routers could allow an attacker to do any of the following: Execute arbitrary code Elevate privileges Execute arbitrary commands Bypass authentication and authorization protections Fetch and run unsigned software Cause denial of service (DoS) For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-26923: Active Directory Domain Services Elevation of Privilege Vulnerability

CVE-2022-1632: An Improper Certificate Validation attack was found in Openshift. A re-encrypt Route with destinationCACertificate explicitly set to the default serviceCA skips internal Service TLS certificate validation. This flaw allows an attacker to exploit an invalid certificate, resulting in a loss of confidentiality.

CVE-2022-29482: 'Mobaoku-Auction&Flea Market' App for iOS versions prior to 5.5.16 improperly verifies server certificates, which may allow an attacker to eavesdrop on an encrypted communication via a man-in-the-middle attack.

CVE-2022-34156: 'Hulu / ????' App for iOS versions prior to 3.0.81 improperly verifies server certificates, which may allow an attacker to eavesdrop on an encrypted communication via a man-in-the-middle attack.

CVE-2022-45597: ComponentSpace.Saml2 4.4.0 Missing SSL Certificate Validation. NOTE: the vendor does not consider this a vulnerability because the report is only about use of certificates at the application layer (not the transport layer) and "Certificates are exchanged in a controlled fashion between entities within a trust relationship. This is why self-signed certificates may be used and why validating certificates isn’t as important as doing so for the transport layer certificates."

CVE-2022-29908: The folioupdate service in Fabasoft Cloud Enterprise Client 22.4.0043 allows Local Privilege Escalation.

CVE-2021-45035: Velneo vClient on its 28.1.3 version, does not correctly check the certificate of authenticity by default. This could allow an attacker that has access to the network to perform a MITM attack in order to obtain the user´s credentials.

CVE-2022-25640: In wolfSSL before 5.2.0, a TLS 1.3 server cannot properly enforce a requirement for mutual authentication. A client can simply omit the certificate_verify message from the handshake, and never present a certificate.

CVE-2022-31083: Parse Server is an open source backend that can be deployed to any infrastructure that can run Node.js. Prior to versions 4.10.11 and 5.2.2, the certificate in the Parse Server Apple Game Center auth adapter not validated. As a result, authentication could potentially be bypassed by making a fake certificate accessible via certain Apple domains and providing the URL to that certificate in an authData object. Versions 4.0.11 and 5.2.2 prevent this by introducing a new `rootCertificateUrl` property to the Parse Server Apple Game Center auth adapter which takes the URL to the root certificate of Apple's Game Center authentication certificate. If no value is set, the `rootCertificateUrl` property defaults to the URL of the current root certificate as of May 27, 2022. Keep in mind that the root certificate can change at any time and that it is the developer's responsibility to keep the root certificate URL up-to-date when using the Parse Server Apple Game Center auth adapter. There are no known workarounds for this issue.

# CWE-296 Improper Following of a Certificate's Chain of Trust

## Description

The product does not follow, or incorrectly follows, the chain of trust for a certificate back to a trusted root certificate, resulting in incorrect trust of any resource that is associated with that certificate.

If a system does not follow the chain of trust of a certificate to a root server, the certificate loses all usefulness as a metric of trust. Essentially, the trust gained from a certificate is derived from a chain of trust -- with a reputable trusted entity at the end of that list. The end user must trust that reputable source, and this reputable source must vouch for the resource in question through the medium of the certificate.


In some cases, this trust traverses several entities who vouch for one another. The entity trusted by the end user is at one end of this trust chain, while the certificate-wielding resource is at the other end of the chain. If the user receives a certificate at the end of one of these trust chains and then proceeds to check only that the first link in the chain, no real trust has been derived, since the entire chain must be traversed back to a trusted source to verify the certificate.


There are several ways in which the chain of trust might be broken, including but not limited to:


  - Any certificate in the chain is self-signed, unless it the root.

  - Not every intermediate certificate is checked, starting from the original certificate all the way up to the root certificate.

  - An intermediate, CA-signed certificate does not have the expected Basic Constraints or other important extensions.

  - The root certificate has been compromised or authorized to the wrong party.

## Observed Examples

CVE-2016-2402: Server allows bypass of certificate pinning by sending a chain of trust that includes a trusted CA that is not pinned.

CVE-2008-4989: Verification function trusts certificate chains in which the last certificate is self-signed.

CVE-2012-5821: Chain: Web browser uses a TLS-related function incorrectly, preventing it from verifying that a server's certificate is signed by a trusted certification authority (CA).

CVE-2009-3046: Web browser does not check if any intermediate certificates are revoked.

CVE-2009-0265: chain: DNS server does not correctly check return value from the OpenSSL EVP_VerifyFinal function allows bypass of validation of the certificate chain.

CVE-2009-0124: chain: incorrect check of return value from the OpenSSL EVP_VerifyFinal function allows bypass of validation of the certificate chain.

CVE-2002-0970: File-transfer software does not validate Basic Constraints of an intermediate CA-signed certificate.

CVE-2002-0862: Cryptographic API, as used in web browsers, mail clients, and other software, does not properly validate Basic Constraints.

# CWE-297 Improper Validation of Certificate with Host Mismatch

## Description

The product communicates with a host that provides a certificate, but the product does not properly ensure that the certificate is actually associated with that host.

Even if a certificate is well-formed, signed, and follows the chain of trust, it may simply be a valid certificate for a different site than the site that the product is interacting with. If the certificate's host-specific data is not properly checked - such as the Common Name (CN) in the Subject or the Subject Alternative Name (SAN) extension of an X.509 certificate - it may be possible for a redirection or spoofing attack to allow a malicious host with a valid certificate to provide data, impersonating a trusted host. In order to ensure data integrity, the certificate must be valid and it must pertain to the site that is being accessed.


Even if the product attempts to check the hostname, it is still possible to incorrectly check the hostname. For example, attackers could create a certificate with a name that begins with a trusted name followed by a NUL byte, which could cause some string-based comparisons to only examine the portion that contains the trusted name.


This weakness can occur even when the product uses Certificate Pinning, if the product does not verify the hostname at the time a certificate is pinned.

## Observed Examples

CVE-2012-5810: Mobile banking application does not verify hostname, leading to financial loss.

CVE-2012-5811: Mobile application for printing documents does not verify hostname, allowing attackers to read sensitive documents.

CVE-2012-5807: Software for electronic checking does not verify hostname, leading to financial loss.

CVE-2012-3446: Cloud-support library written in Python uses incorrect regular expression when matching hostname.

CVE-2009-2408: Web browser does not correctly handle '\0' character (NUL) in Common Name, allowing spoofing of https sites.

CVE-2012-0867: Database program truncates the Common Name during hostname verification, allowing spoofing.

CVE-2010-2074: Incorrect handling of '\0' character (NUL) in hostname verification allows spoofing.

CVE-2009-4565: Mail server's incorrect handling of '\0' character (NUL) in hostname verification allows spoofing.

CVE-2009-3767: LDAP server's incorrect handling of '\0' character (NUL) in hostname verification allows spoofing.

CVE-2012-5806: Payment processing module does not verify hostname when connecting to PayPal using PHP fsockopen function.

CVE-2012-2993: Smartphone device does not verify hostname, allowing spoofing of mail services.

CVE-2012-5804: E-commerce module does not verify hostname when connecting to payment site.

CVE-2012-5824: Chat application does not validate hostname, leading to loss of privacy.

CVE-2012-5822: Application uses third-party library that does not validate hostname.

CVE-2012-5819: Cloud storage management application does not validate hostname.

CVE-2012-5817: Java library uses JSSE SSLSocket and SSLEngine classes, which do not verify the hostname.

CVE-2012-5784: SOAP platform does not verify the hostname.

CVE-2012-5782: PHP library for payments does not verify the hostname.

CVE-2012-5780: Merchant SDK for payments does not verify the hostname.

CVE-2003-0355: Web browser does not validate Common Name, allowing spoofing of https sites.

## Top 25 Examples

CVE-2021-22131: A improper validation of certificate with host mismatch in Fortinet FortiTokenAndroid version 5.0.3 and below, Fortinet FortiTokeniOS version 5.2.0 and below, Fortinet FortiTokenWinApp version 4.0.3 and below allows attacker to retrieve information disclosed via man-in-the-middle attacks.

CVE-2022-29082: Dell EMC NetWorker versions 19.1.x, 19.1.0.x, 19.1.1.x, 19.2.x, 19.2.0.x, 19.2.1.x 19.3.x, 19.3.0.x, 19.4.x, 19.4.0.x, 19.5.x,19.5.0.x, 19.6 and 19.6.0.1 and 19.6.0.2 contain an Improper Validation of Certificate with Host Mismatch vulnerability in Rabbitmq port 5671 which could allow remote attackers to spoof certificates.

CVE-2022-48306: Improper Validation of Certificate with Host Mismatch vulnerability in Gotham Chat IRC helper of Palantir Gotham allows A malicious attacker in a privileged network position could abuse this to perform a man-in-the-middle attack. A successful man-in-the-middle attack would allow them to intercept, read, or modify network communications to and from the affected service. This issue affects: Palantir Palantir Gotham Chat IRC helper versions prior to 30221005.210011.9242.

# CWE-298 Improper Validation of Certificate Expiration

## Description

A certificate expiration is not validated or is incorrectly validated, so trust may be assigned to certificates that have been abandoned due to age.

When the expiration of a certificate is not taken into account, no trust has necessarily been conveyed through it. Therefore, the validity of the certificate cannot be verified and all benefit of the certificate is lost.

# CWE-299 Improper Check for Certificate Revocation

## Description

The product does not check or incorrectly checks the revocation status of a certificate, which may cause it to use a certificate that has been compromised.

An improper check for certificate revocation is a far more serious flaw than related certificate failures. This is because the use of any revoked certificate is almost certainly malicious. The most common reason for certificate revocation is compromise of the system in question, with the result that no legitimate servers will be using a revoked certificate, unless they are sorely out of sync.

## Observed Examples

CVE-2011-2014: LDAP-over-SSL implementation does not check Certificate Revocation List (CRL), allowing spoofing using a revoked certificate.

CVE-2011-0199: Operating system does not check Certificate Revocation List (CRL) in some cases, allowing spoofing using a revoked certificate.

CVE-2010-5185: Antivirus product does not check whether certificates from signed executables have been revoked.

CVE-2009-3046: Web browser does not check if any intermediate certificates are revoked.

CVE-2009-0161: chain: Ruby module for OCSP misinterprets a response, preventing detection of a revoked certificate.

CVE-2011-2701: chain: incorrect parsing of replies from OCSP responders allows bypass using a revoked certificate.

CVE-2011-0935: Router can permanently cache certain public keys, which would allow bypass if the certificate is later revoked.

CVE-2009-1358: chain: OS package manager does not properly check the return value, allowing bypass using a revoked certificate.

CVE-2009-0642: chain: language interpreter does not properly check the return value from an OSCP function, allowing bypass using a revoked certificate.

CVE-2008-4679: chain: web service component does not call the expected method, which prevents a check for revoked certificates.

CVE-2006-4410: Certificate revocation list not searched for certain certificates.

CVE-2006-4409: Product cannot access certificate revocation list when an HTTP proxy is being used.

## Top 25 Examples

CVE-2022-21170: Improper check for certificate revocation in i-FILTER Ver.10.45R01 and earlier, i-FILTER Ver.9.50R10 and earlier, i-FILTER Browser & Cloud MultiAgent for Windows Ver.4.93R04 and earlier, and D-SPA (Ver.3 / Ver.4) using i-FILTER allows a remote unauthenticated attacker to conduct a man-in-the-middle attack and eavesdrop on an encrypted communication.

