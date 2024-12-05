# CWE-30 Path Traversal: '\dir\..\filename'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '\dir\..\filename' (leading backslash dot dot) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


This is similar to CWE-26, except using "\" instead of "/". The '\dir\..\filename' manipulation is useful for bypassing some path traversal protection schemes. Sometimes a program only checks for "..\" at the beginning of the input, so a "\..\" can bypass that check.

## Observed Examples

CVE-2002-1987: Protection mechanism checks for "/.." but doesn't account for Windows-specific "\.." allowing read of arbitrary files.

# CWE-300 Channel Accessible by Non-Endpoint

## Description

The product does not adequately verify the identity of actors at both ends of a communication channel, or does not adequately ensure the integrity of the channel, in a way that allows the channel to be accessed or influenced by an actor that is not an endpoint.

In order to establish secure communication between two parties, it is often important to adequately verify the identity of entities at each end of the communication channel. Inadequate or inconsistent verification may result in insufficient or incorrect identification of either communicating entity. This can have negative consequences such as misplaced trust in the entity at the other end of the channel. An attacker can leverage this by interposing between the communicating entities and masquerading as the original entity. In the absence of sufficient verification of identity, such an attacker can eavesdrop and potentially modify the communication between the original entities.

## Observed Examples

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversry-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

## Top 25 Examples

CVE-2021-3716: A flaw was found in nbdkit due to to improperly caching plaintext state across the STARTTLS encryption boundary. A MitM attacker could use this flaw to inject a plaintext NBD_OPT_STRUCTURED_REPLY before proxying everything else a client sends to the server, potentially leading the client to terminate the NBD session. The highest threat from this vulnerability is to system availability.

# CWE-301 Reflection Attack in an Authentication Protocol

## Description

Simple authentication protocols are subject to reflection attacks if a malicious user can use the target machine to impersonate a trusted user.

A mutual authentication protocol requires each party to respond to a random challenge by the other party by encrypting it with a pre-shared key. Often, however, such protocols employ the same pre-shared key for communication with a number of different entities. A malicious user or an attacker can easily compromise this protocol without possessing the correct key by employing a reflection attack on the protocol.


Reflection attacks capitalize on mutual authentication schemes in order to trick the target into revealing the secret shared between it and another valid user. In a basic mutual-authentication scheme, a secret is known to both the valid user and the server; this allows them to authenticate. In order that they may verify this shared secret without sending it plainly over the wire, they utilize a Diffie-Hellman-style scheme in which they each pick a value, then request the hash of that value as keyed by the shared secret. In a reflection attack, the attacker claims to be a valid user and requests the hash of a random value from the server. When the server returns this value and requests its own value to be hashed, the attacker opens another connection to the server. This time, the hash requested by the attacker is the value which the server requested in the first connection. When the server returns this hashed value, it is used in the first connection, authenticating the attacker successfully as the impersonated valid user.

## Observed Examples

CVE-2005-3435: product authentication succeeds if user-provided MD5 hash matches the hash in its database; this can be subjected to replay attacks.

# CWE-302 Authentication Bypass by Assumed-Immutable Data

## Description

The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.

## Observed Examples

CVE-2002-0367: DebPloit

CVE-2004-0261: Web auth

CVE-2002-1730: Authentication bypass by setting certain cookies to "true".

CVE-2002-1734: Authentication bypass by setting certain cookies to "true".

CVE-2002-2064: Admin access by setting a cookie.

CVE-2002-2054: Gain privileges by setting cookie.

CVE-2004-1611: Product trusts authentication information in cookie.

CVE-2005-1708: Authentication bypass by setting admin-testing variable to true.

CVE-2005-1787: Bypass auth and gain privileges by setting a variable.

## Top 25 Examples

CVE-2022-35843: An authentication bypass by assumed-immutable data vulnerability [CWE-302] in the FortiOS SSH login component 7.2.0, 7.0.0 through 7.0.7, 6.4.0 through 6.4.9, 6.2 all versions, 6.0 all versions and FortiProxy SSH login component 7.0.0 through 7.0.5, 2.0.0 through 2.0.10, 1.2.0 all versions may allow a remote and unauthenticated attacker to login into the device via sending specially crafted Access-Challenge response from the Radius server.

CVE-2022-40703: CWE-302 Authentication Bypass by Assumed-Immutable Data in AliveCor Kardia App version 5.17.1-754993421 and prior on Android allows an unauthenticated attacker with physical access to the Android device containing the app to bypass application authentication and alter information in the app.

CVE-2022-2133: The OAuth Single Sign On WordPress plugin before 6.22.6 doesn't validate that OAuth access token requests are legitimate, which allows attackers to log onto the site with the only knowledge of a user's email address.

CVE-2022-22729: CAMS for HIS Server contained in the following Yokogawa Electric products improperly authenticate the receiving packets. The authentication may be bypassed via some crafted packets: CENTUM CS 3000 versions from R3.08.10 to R3.09.00, CENTUM VP versions from R4.01.00 to R4.03.00, from R5.01.00 to R5.04.20, and from R6.01.00 to R6.08.00, and Exaopc versions from R3.72.00 to R3.79.00.

# CWE-303 Incorrect Implementation of Authentication Algorithm

## Description

The requirements for the product dictate the use of an established authentication algorithm, but the implementation of the algorithm is incorrect.

This incorrect implementation may allow authentication to be bypassed.

## Observed Examples

CVE-2003-0750: Conditional should have been an 'or' not an 'and'.

## Top 25 Examples

CVE-2022-20695: A vulnerability in the authentication functionality of Cisco Wireless LAN Controller (WLC) Software could allow an unauthenticated, remote attacker to bypass authentication controls and log in to the device through the management interface This vulnerability is due to the improper implementation of the password validation algorithm. An attacker could exploit this vulnerability by logging in to an affected device with crafted credentials. A successful exploit could allow the attacker to bypass authentication and log in to the device as an administrator. The attacker could obtain privileges that are the same level as an administrative user but it depends on the crafted credentials. Note: This vulnerability exists because of a non-default device configuration that must be present for it to be exploitable. For details about the vulnerable configuration, see the Vulnerable Products section of this advisory.

CVE-2022-20923: A vulnerability in the IPSec VPN Server authentication functionality of Cisco Small Business RV110W, RV130, RV130W, and RV215W Routers could allow an unauthenticated, remote attacker to bypass authentication controls and access the IPSec VPN network. This vulnerability is due to the improper implementation of the password validation algorithm. An attacker could exploit this vulnerability by logging in to the VPN from an affected device with crafted credentials. A successful exploit could allow the attacker to bypass authentication and access the IPSec VPN network. The attacker may obtain privileges that are the same level as an administrative user, depending on the crafted credentials that are used. Cisco has not released software updates that address this vulnerability.

CVE-2022-33736: A vulnerability has been identified in Opcenter Quality V13.1 (All versions < V13.1.20220624), Opcenter Quality V13.2 (All versions < V13.2.20220624). The affected applications do not properly validate login information during authentication. This could lead to denial of service condition for existing users or allow unauthenticated remote attackers to successfully login without credentials.

CVE-2022-4861: Incorrect implementation in authentication protocol in M-Files Client before 22.5.11356.0 allows high privileged user to get other users tokens to another resource.

CVE-2022-29865: OPC UA .NET Standard Stack allows a remote attacker to bypass the application authentication check via crafted fake credentials.

# CWE-304 Missing Critical Step in Authentication

## Description

The product implements an authentication technique, but it skips a step that weakens the technique.

Authentication techniques should follow the algorithms that define them exactly, otherwise authentication can be bypassed or more easily subjected to brute force attacks.

## Observed Examples

CVE-2004-2163: Shared secret not verified in a RADIUS response packet, allowing authentication bypass by spoofing server replies.

CVE-2005-3327: Chain: Authentication bypass by skipping the first startup step as required by the protocol.

## Top 25 Examples

CVE-2022-48195: An issue was discovered in Mellium mellium.im/sasl before 0.3.1. When performing SCRAM-based SASL authentication, if the remote end advertises support for channel binding, no random nonce is generated (instead, the nonce is empty). This causes authentication to fail in the best case, but (if paired with a remote end that does not validate the length of the nonce) could lead to insufficient randomness being used during authentication.

CVE-2022-2302: Multiple Lenze products of the cabinet series skip the password verification upon second login. After a user has been logged on to the device once, a remote attacker can get full access without knowledge of the password.

# CWE-305 Authentication Bypass by Primary Weakness

## Description

The authentication algorithm is sound, but the implemented mechanism can be bypassed as the result of a separate weakness that is primary to the authentication error.

## Observed Examples

CVE-2002-1374: The provided password is only compared against the first character of the real password.

CVE-2000-0979: The password is not properly checked, which allows remote attackers to bypass access controls by sending a 1-byte password that matches the first character of the real password.

CVE-2001-0088: Chain: Forum software does not properly initialize an array, which inadvertently sets the password to a single character, allowing remote attackers to easily guess the password and gain administrative privileges.

## Top 25 Examples

CVE-2022-0547: OpenVPN 2.1 until v2.4.12 and v2.5.6 may enable authentication bypass in external authentication plug-ins when more than one of them makes use of deferred authentication replies, which allows an external user to be granted access with only partially correct credentials.

CVE-2022-23729: When the device is in factory state, it can be access the shell without adb authentication process. The LG ID is LVE-SMP-210010.

CVE-2022-38064: OpenHarmony-v3.1.2 and prior versions have a permission bypass vulnerability. Local attackers can bypass permission control and get sensitive information.

CVE-2022-38081: OpenHarmony-v3.1.2 and prior versions have a permission bypass vulnerability. LAN attackers can bypass the distributed permission control.To take advantage of this weakness, attackers need another vulnerability to obtain system.

CVE-2022-38700: OpenHarmony-v3.1.1 and prior versions have a permission bypass vulnerability. LAN attackers can bypass permission control and get control of camera service.

# CWE-306 Missing Authentication for Critical Function

## Description

The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

## Observed Examples

CVE-2022-31260: Chain: a digital asset management program has an undisclosed backdoor in the legacy version of a PHP script (CWE-912) that could allow an unauthenticated user to export metadata (CWE-306)

CVE-2022-29951: TCP-based protocol in Programmable Logic Controller (PLC) has no authentication.

CVE-2022-29952: Condition Monitor firmware uses a protocol that does not require authentication.

CVE-2022-30276: SCADA-based protocol for bridging WAN and LAN traffic has no authentication.

CVE-2022-30313: Safety Instrumented System uses proprietary TCP protocols with no authentication.

CVE-2022-30317: Distributed Control System (DCS) uses a protocol that has no authentication.

CVE-2021-21972: Chain: Cloud computing virtualization platform does not require authentication for upload of a tar format file (CWE-306), then uses .. path traversal sequences (CWE-23) in the file to access unexpected files, as exploited in the wild per CISA KEV.

CVE-2020-10263: Bluetooth speaker does not require authentication for the debug functionality on the UART port, allowing root shell access

CVE-2021-23147: WiFi router does not require authentication for its UART port, allowing adversaries with physical access to execute commands as root

CVE-2021-37415: IT management product does not perform authentication for some REST API requests, as exploited in the wild per CISA KEV.

CVE-2020-13927: Default setting in workflow management product allows all API requests without authentication, as exploited in the wild per CISA KEV.

CVE-2002-1810: MFV. Access TFTP server without authentication and obtain configuration file with sensitive plaintext information.

CVE-2008-6827: Agent software running at privileges does not authenticate incoming requests over an unprotected channel, allowing a Shatter" attack.

CVE-2004-0213: Product enforces restrictions through a GUI but not through privileged APIs.

CVE-2020-15483: monitor device allows access to physical UART debug port without authentication

CVE-2019-9201: Programmable Logic Controller (PLC) does not have an authentication feature on its communication protocols.

## Top 25 Examples

CVE-2022-20857: Multiple vulnerabilities in Cisco Nexus Dashboard could allow an unauthenticated, remote attacker to execute arbitrary commands, read or upload container image files, or perform a cross-site request forgery attack. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-40202:  The database backup function in Delta Electronics InfraSuite Device Master Versions 00.00.01a and prior lacks proper authentication. An attacker could provide malicious serialized objects which, when deserialized, could activate an opcode for a backup scheduling function without authentication. This function allows the user to designate all function arguments and the file to be executed. This could allow the attacker to start any new process and achieve remote code execution. 

CVE-2022-20858: Multiple vulnerabilities in Cisco Nexus Dashboard could allow an unauthenticated, remote attacker to execute arbitrary commands, read or upload container image files, or perform a cross-site request forgery attack. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2021-21472: SAP Software Provisioning Manager 1.0 (SAP NetWeaver Master Data Management Server 7.1) does not have an option to set password during its installation, this allows an authenticated attacker to perform various security attacks like Directory Traversal, Password Brute force Attack, SMB Relay attack, Security Downgrade.

CVE-2022-26143: The TP-240 (aka tp240dvr) component in Mitel MiCollab before 9.4 SP1 FP1 and MiVoice Business Express through 8.1 allows remote attackers to obtain sensitive information and cause a denial of service (performance degradation and excessive outbound traffic). This was exploited in the wild in February and March 2022 for the TP240PhoneHome DDoS attack.

CVE-2022-26501: Veeam Backup & Replication 10.x and 11.x has Incorrect Access Control (issue 1 of 2).

CVE-2021-37415: Zoho ManageEngine ServiceDesk Plus before 11302 is vulnerable to authentication bypass that allows a few REST-API URLs without authentication.

CVE-2021-39144: XStream is a simple library to serialize objects to XML and back again. In affected versions this vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by manipulating the processed input stream. No user is affected, who followed the recommendation to setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a blacklist by default, since it cannot be secured for general purpose.

CVE-2021-44077: Zoho ManageEngine ServiceDesk Plus before 11306, ServiceDesk Plus MSP before 10530, and SupportCenter Plus before 11014 are vulnerable to unauthenticated remote code execution. This is related to /RestAPI URLs in a servlet, and ImportTechnicians in the Struts configuration.

CVE-2022-21587: Vulnerability in the Oracle Web Applications Desktop Integrator product of Oracle E-Business Suite (component: Upload). Supported versions that are affected are 12.2.3-12.2.11. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Web Applications Desktop Integrator. Successful attacks of this vulnerability can result in takeover of Oracle Web Applications Desktop Integrator. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

CVE-2022-24990: TerraMaster NAS 4.2.29 and earlier allows remote attackers to discover the administrative password by sending "User-Agent: TNAS" to module/api.php?mobile/webNasIPS and then reading the PWD field in the response.

CVE-2022-26925: Windows LSA Spoofing Vulnerability

CVE-2021-41418: AriaNg v0.1.0~v1.2.2 is affected by an incorrect access control vulnerability through not authenticating visitors' access rights.

CVE-2021-43447: ONLYOFFICE all versions as of 2021-11-08 is affected by Incorrect Access Control. An authentication bypass in the document editor allows attackers to edit documents without authentication.

CVE-2022-1598: The WPQA Builder WordPress plugin before 5.5 which is a companion to the Discy and Himer , lacks authentication in a REST API endpoint, allowing unauthenticated users to discover private questions sent between users on the site.

CVE-2022-2242: The KUKA SystemSoftware V/KSS in versions prior to 8.6.5 is prone to improper access control as an unauthorized attacker can directly read and write robot configurations when access control is not available or not enabled (default).

CVE-2022-23345: BigAnt Software BigAnt Server v5.6.06 was discovered to contain incorrect access control.

CVE-2022-26833: An improper authentication vulnerability exists in the REST API functionality of Open Automation Software OAS Platform V16.00.0121. A specially-crafted series of HTTP requests can lead to unauthenticated use of the REST API. An attacker can send a series of HTTP requests to trigger this vulnerability.

CVE-2022-28771: Due to missing authentication check, SAP Business one License service API - version 10.0 allows an unauthenticated attacker to send malicious http requests over the network. On successful exploitation, an attacker can break the whole application making it inaccessible. 

CVE-2022-31701: VMware Workspace ONE Access and Identity Manager contain a broken authentication vulnerability. VMware has evaluated the severity of this issue to be in the Moderate severity range with a maximum CVSSv3 base score of 5.3.

CVE-2022-36521: Insecure permissions in cskefu v7.0.1 allows unauthenticated attackers to arbitrarily add administrator accounts.

CVE-2022-37680: An improper authentication for critical function issue in Hitachi Kokusai Electric Network products for monitoring system (Camera, Decoder and Encoder) and bellow allows attckers to remotely reboot the device via a crafted POST request to the endpoint /ptipupgrade.cgi. Security information ID hitachi-sec-2022-001 contains fixes for the issue.

CVE-2022-38817: Dapr Dashboard v0.1.0 through v0.10.0 is vulnerable to Incorrect Access Control that allows attackers to obtain sensitive data.

CVE-2022-41263: Due to a missing authentication check, SAP Business Objects Business Intelligence Platform (Web Intelligence) - versions 420, 430, allows an authenticated non-administrator attacker to modify the data source information for a document that is otherwise restricted. On successful exploitation, the attacker can modify information causing a limited impact on the integrity of the application.

CVE-2022-42785: Multiple W&T products of the ComServer Series are prone to an authentication bypass. An unathenticated remote attacker, can log in without knowledge of the password by crafting a modified HTTP GET Request.

CVE-2022-3738: The vulnerability allows a remote unauthenticated attacker to download a backup file, if one exists. That backup file might contain sensitive information like credentials and cryptographic material. A valid user has to create a backup after the last reboot for this attack to be successfull. 

CVE-2022-45423: Some Dahua software products have a vulnerability of unauthenticated request of MQTT credentials. An attacker can obtain encrypted MQTT credentials by sending a specific crafted packet to the vulnerable interface (the credentials cannot be directly exploited).

CVE-2022-45424: Some Dahua software products have a vulnerability of unauthenticated request of AES crypto key. An attacker can obtain the AES crypto key by sending a specific crafted packet to the vulnerable interface.

CVE-2022-20060: In preloader (usb), there is a possible permission bypass due to a missing proper image authentication. This could lead to local escalation of privilege, for an attacker who has physical access to the device, with no additional execution privileges needed. User interaction is needed for exploitation. Patch ID: ALPS06160806; Issue ID: ALPS06137462.

CVE-2021-28809: An improper access control vulnerability has been reported to affect certain legacy versions of HBS 3. If exploited, this vulnerability allows attackers to compromise the security of the operating system.QNAP have already fixed this vulnerability in the following versions of HBS 3: QTS 4.3.6: HBS 3 v3.0.210507 and later QTS 4.3.4: HBS 3 v3.0.210506 and later QTS 4.3.3: HBS 3 v3.0.210506 and later

CVE-2022-4229: A vulnerability classified as critical was found in SourceCodester Book Store Management System 1.0. This vulnerability affects unknown code of the file /bsms_ci/index.php. The manipulation leads to improper access controls. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-214588.

CVE-2021-31814: In Stormshield 1.1.0, and 2.1.0 through 2.9.0, an attacker can block a client from accessing the VPN and can obtain sensitive information through the SN VPN SSL Client.

CVE-2022-26267: Piwigo v12.2.0 was discovered to contain an information leak via the action parameter in /admin/maintenance_actions.php.

CVE-2022-27332: An access control issue in Zammad v5.0.3 allows attackers to write entries to the CTI caller log without authentication. This vulnerability can allow attackers to execute phishing attacks or cause a Denial of Service (DoS).

CVE-2022-36780: Avdor CIS - crystal quality Credentials Management Errors. The product is phone call recorder, you can hear all the recorded calls without authenticate to the system. Attacker sends crafted URL to the system: ip:port//V=2;ChannellD=number;Ext=number;Command=startLM;Client=number;Request=number;R=number number - id of the recorded number.

CVE-2022-22652: The GSMA authentication panel could be presented on the lock screen. The issue was resolved by requiring device unlock to interact with the GSMA authentication panel. This issue is fixed in iOS 15.4 and iPadOS 15.4. A person with physical access may be able to view and modify the carrier account information and settings from the lock screen.

CVE-2022-47703: TIANJIE CPE906-3 is vulnerable to password disclosure. This is present on Software Version WEB5.0_LCD_20200513, Firmware Version MV8.003, and Hardware Version CPF906-V5.0_LCD_20200513.

CVE-2022-0992: The SiteGround Security plugin for WordPress is vulnerable to authentication bypass that allows unauthenticated users to log in as administrative users due to missing identity verification on initial 2FA set-up that allows unauthenticated and unauthorized users to configure 2FA for pending accounts. Upon successful configuration, the attacker is logged in as that user without access to a username/password pair which is the expected first form of authentication. This affects versions up to, and including, 1.2.5.

CVE-2022-0993: The SiteGround Security plugin for WordPress is vulnerable to authentication bypass that allows unauthenticated users to log in as administrative users due to missing identity verification on the 2FA back-up code implementation that logs users in upon success. This affects versions up to, and including, 1.2.5.

CVE-2022-1248: A vulnerability was found in SAP Information System 1.0 which has been rated as critical. Affected by this issue is the file /SAP_Information_System/controllers/add_admin.php. An unauthenticated attacker is able to create a new admin account for the web application with a simple POST request. Exploit details were disclosed.

CVE-2022-2141: SMS-based GPS commands can be executed by MiCODUS MV720 GPS tracker without authentication.

CVE-2022-22576: An improper authentication vulnerability exists in curl 7.33.0 to and including 7.82.0 which might allow reuse OAUTH2-authenticated connections without properly making sure that the connection was authenticated with the same credentials as set for this transfer. This affects SASL-enabled protocols: SMPTP(S), IMAP(S), POP3(S) and LDAP(S) (openldap only).

CVE-2022-23220: USBView 2.1 before 2.2 allows some local users (e.g., ones logged in via SSH) to execute arbitrary code as root because certain Polkit settings (e.g., allow_any=yes) for pkexec disable the authentication requirement. Code execution can, for example, use the --gtk-module option. This affects Ubuntu, Debian, and Gentoo.

CVE-2022-23719: PingID Windows Login prior to 2.8 does not authenticate communication with a local Java service used to capture security key requests. An attacker with the ability to execute code on the target machine maybe able to exploit and spoof the local Java service using multiple attack vectors. A successful attack can lead to code executed as SYSTEM by the PingID Windows Login application, or even a denial of service for offline security key authentication.

CVE-2022-24047: This vulnerability allows remote attackers to bypass authentication on affected installations of BMC Track-It! 20.21.01.102. Authentication is not required to exploit this vulnerability. The specific flaw exists within the authorization of HTTP requests. The issue results from the lack of authentication prior to allowing access to functionality. An attacker can leverage this vulnerability to bypass authentication on the system. Was ZDI-CAN-14618.

CVE-2022-24562: In IOBit IOTransfer 4.3.1.1561, an unauthenticated attacker can send GET and POST requests to Airserv and gain arbitrary read/write access to the entire file-system (with admin privileges) on the victim's endpoint, which can result in data theft and remote code execution.

CVE-2022-25359: On ICL ScadaFlex II SCADA Controller SC-1 and SC-2 1.03.07 devices, unauthenticated remote attackers can overwrite, delete, or create files.

CVE-2022-2552: The Duplicator WordPress plugin before 1.4.7 does not authenticate or authorize visitors before displaying information about the system such as server software, php version and full file system path to the site.

CVE-2022-34767: Web page which "wizardpwd.asp" ALLNET Router model WR0500AC is prone to Authorization bypass vulnerability – the password, located at "admin" allows changing the http[s]://wizardpwd.asp/cgi-bin. Does not validate the user's identity and can be accessed publicly.

CVE-2022-34858: Authentication Bypass vulnerability in miniOrange OAuth 2.0 client for SSO plugin <= 1.11.3 at WordPress. 

CVE-2022-35122: An access control issue in Ecowitt GW1100 Series Weather Stations <=GW1100B_v2.1.5 allows unauthenticated attackers to access sensitive information including device and local WiFi passwords.

CVE-2021-20238: It was found in OpenShift Container Platform 4 that ignition config, served by the Machine Config Server, can be accessed externally from clusters without authentication. The MCS endpoint (port 22623) provides ignition configuration used for bootstrapping Nodes and can include some sensitive data, e.g. registry pull secrets. There are two scenarios where this data can be accessed. The first is on Baremetal, OpenStack, Ovirt, Vsphere and KubeVirt deployments which do not have a separate internal API endpoint and allow access from outside the cluster to port 22623 from the standard OpenShift API Virtual IP address. The second is on cloud deployments when using unsupported network plugins, which do not create iptables rules that prevent to port 22623. In this scenario, the ignition config is exposed to all pods within the cluster and cannot be accessed externally.

CVE-2021-26637: There is no account authentication and permission check logic in the firmware and existing apps of SiHAS's SGW-300, ACM-300, GCM-300, so unauthorized users can remotely control the device.

CVE-2022-44013: An issue was discovered in Simmeth Lieferantenmanager before 5.6. An attacker can make various API calls without authentication because the password in a Credential Object is not checked.

CVE-2022-45378: In the default configuration of Apache SOAP, an RPCRouterServlet is available without authentication. This gives an attacker the possibility to invoke methods on the classpath that meet certain criteria. Depending on what classes are available on the classpath this might even lead to arbitrary remote code execution. NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

CVE-2022-45933: KubeView through 0.1.31 allows attackers to obtain control of a Kubernetes cluster because api/scrape/kube-system does not require authentication, and retrieves certificate files that can be used for authentication as kube-admin. NOTE: the vendor's position is that KubeView was a "fun side project and a learning exercise," and not "very secure."

CVE-2022-46145: authentik is an open-source identity provider. Versions prior to 2022.11.2 and 2022.10.2 are vulnerable to unauthorized user creation and potential account takeover. With the default flows, unauthenticated users can create new accounts in authentik. If a flow exists that allows for email-verified password recovery, this can be used to overwrite the email address of admin accounts and take over their accounts. authentik 2022.11.2 and 2022.10.2 fix this issue. As a workaround, a policy can be created and bound to the `default-user-settings-flow flow` with the contents `return request.user.is_authenticated`.

CVE-2022-26971: Barco Control Room Management Suite web application, which is part of TransForm N before 3.14, is exposing a license file upload mechanism. This upload can be executed without authentication.

CVE-2022-2765: A vulnerability was found in SourceCodester Company Website CMS 1.0. It has been declared as critical. Affected by this vulnerability is an unknown functionality of the file /dashboard/settings. The manipulation leads to improper authentication. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-206161 was assigned to this vulnerability.

CVE-2022-29883: A vulnerability has been identified in SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P850 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00), SICAM P855 (All versions < V3.00). Affected devices do not restrict unauthenticated access to certain pages of the web interface. This could allow an attacker to delete log files without authentication.

CVE-2022-29934: USU Oracle Optimization before 5.17.5 lacks Polkit authentication, which allows smartcollector users to achieve root access via pkexec. NOTE: this is not an Oracle Corporation product.

CVE-2022-30229: A vulnerability has been identified in SICAM GridEdge Essential ARM (All versions < V2.6.6), SICAM GridEdge Essential Intel (All versions < V2.6.6), SICAM GridEdge Essential with GDS ARM (All versions < V2.6.6), SICAM GridEdge Essential with GDS Intel (All versions < V2.6.6). The affected software does not require authenticated access for privileged functions. This could allow an unauthenticated attacker to change data of an user, such as credentials, in case that user's id is known.

CVE-2022-3119: The OAuth client Single Sign On WordPress plugin before 3.0.4 does not have authorisation and CSRF when updating its settings, which could allow unauthenticated attackers to update them and change the OAuth endpoints to ones they controls, allowing them to then be authenticated as admin if they know the correct email address

CVE-2022-31461: Owl Labs Meeting Owl 5.2.0.15 allows attackers to deactivate the passcode protection mechanism via a certain c 11 message.

CVE-2022-44216: Gnuboard 5.5.4 and 5.5.5 is vulnerable to Insecure Permissions. An attacker can change password of all users without knowing victim's original password.

CVE-2022-0188: The CMP WordPress plugin before 4.0.19 allows any user, even not logged in, to arbitrarily change the coming soon page layout.

CVE-2022-1521: LRM does not implement authentication or authorization by default. A malicious actor can inject, replay, modify, and/or intercept sensitive data.

CVE-2022-32557: An issue was discovered in Couchbase Server before 7.0.4. The Index Service does not enforce authentication for TCP/TLS servers.

CVE-2022-35136: Boodskap IoT Platform v4.4.9-02 allows attackers to make unauthenticated API requests.

CVE-2022-3675: Fedora CoreOS supports setting a GRUB bootloader password using a Butane config. When this feature is enabled, GRUB requires a password to access the GRUB command-line, modify kernel command-line arguments, or boot non-default OSTree deployments. Recent Fedora CoreOS releases have a misconfiguration which allows booting non-default OSTree deployments without entering a password. This allows someone with access to the GRUB menu to boot into an older version of Fedora CoreOS, reverting any security fixes that have recently been applied to the machine. A password is still required to modify kernel command-line arguments and to access the GRUB command line. 

CVE-2022-29270: In Nagios XI through 5.8.5, it is possible for a user without password verification to change his e-mail address.

CVE-2022-36129: HashiCorp Vault Enterprise 1.7.0 through 1.9.7, 1.10.4, and 1.11.0 clusters using Integrated Storage expose an unauthenticated API endpoint that could be abused to override the voter status of a node within a Vault HA cluster, introducing potential for future data loss or catastrophic failure. Fixed in Vault Enterprise 1.9.8, 1.10.5, and 1.11.1.

CVE-2022-45190: An issue was discovered on Microchip RN4870 1.43 devices. An attacker within BLE radio range can bypass passkey entry in the legacy pairing of the device.

CVE-2021-37234: Incorrect Access Control vulnerability in Modern Honey Network commit 0abf0db9cd893c6d5c727d036e1f817c02de4c7b allows remote attackers to view sensitive information via crafted PUT request to Web API.

CVE-2022-24935: Lexmark products through 2022-02-10 have Incorrect Access Control.

CVE-2022-3124: The Frontend File Manager Plugin WordPress plugin before 21.3 allows any unauthenticated user to rename uploaded files from users. Furthermore, due to the lack of validation in the destination filename, this could allow allow them to change the content of arbitrary files on the web server

CVE-2022-27897: Palantir Gotham versions prior to 3.22.11.2 included an unauthenticated endpoint that would load portions of maliciously crafted zip files to memory. An attacker could repeatedly upload a malicious zip file, which would allow them to exhaust memory resources on the dispatch server.

CVE-2022-3312: Insufficient validation of untrusted input in VPN in Google Chrome on ChromeOS prior to 106.0.5249.62 allowed a local attacker to bypass managed device restrictions via physical access to the device. (Chromium security severity: Medium)

CVE-2021-42889: In TOTOLINK EX1200T V4.1.2cu.5215, an attacker can obtain sensitive information (wifikey, wifiname, etc.) without authorization.

CVE-2021-42891: In TOTOLINK EX1200T V4.1.2cu.5215, an attacker can obtain sensitive information (wifikey, etc.) without authorization.

CVE-2021-42893: In TOTOLINK EX1200T V4.1.2cu.5215, an attacker can obtain sensitive information (wifikey, etc.) without authorization through getSysStatusCfg.

CVE-2022-0140: The Visual Form Builder WordPress plugin before 3.0.6 does not perform access control on entry form export, allowing unauthenticated users to see the form entries or export it as a CSV File using the vfb-export endpoint.

CVE-2022-24820: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. A guest user without the right to view pages of the wiki can still list documents by rendering some velocity documents. The problem has been patched in XWiki versions 12.10.11, 13.4.4, and 13.9-rc-1. There is no known workaround for this problem.

CVE-2022-25245: Zoho ManageEngine ServiceDesk Plus before 13001 allows anyone to know the organisation's default currency name.

CVE-2022-27891: Palantir Gotham included an unauthenticated endpoint that listed all active usernames on the stack with an active session. The affected services have been patched and automatically deployed to all Apollo-managed Gotham instances. It is highly recommended that customers upgrade all affected services to the latest version. This issue affects: Palantir Gotham versions prior to 103.30221005.0.

CVE-2022-31176: Grafana Image Renderer is a Grafana backend plugin that handles rendering of panels & dashboards to PNGs using a headless browser (Chromium/Chrome). An internal security review identified an unauthorized file disclosure vulnerability. It is possible for a malicious user to retrieve unauthorized files under some network conditions or via a fake datasource (if user has admin permissions in Grafana). All Grafana installations should be upgraded to version 3.6.1 as soon as possible. As a workaround it is possible to [disable HTTP remote rendering](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#plugingrafana-image-renderer).

CVE-2022-35572: On Linksys E5350 WiFi Router with firmware version 1.0.00.037 and lower, (and potentially other vendors/devices due to code reuse), the /SysInfo.htm URI does not require a session ID. This web page calls a show_sysinfo function which retrieves WPA passwords, SSIDs, MAC Addresses, serial numbers, WPS Pins, and hardware/firmware versions, and prints this information into the web page. This web page is visible when remote management is enabled. A user who has access to the web interface of the device can extract these secrets. If the device has remote management enabled and is connected directly to the internet, this vulnerability is exploitable over the internet without interaction.

CVE-2022-36884: The webhook endpoint in Jenkins Git Plugin 4.11.3 and earlier provide unauthenticated attackers information about the existence of jobs configured to use an attacker-specified Git repository.

CVE-2022-4228: A vulnerability classified as problematic has been found in SourceCodester Book Store Management System 1.0. This affects an unknown part of the file /bsms_ci/index.php/user/edit_user/. The manipulation of the argument password leads to information disclosure. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-214587.

CVE-2022-25508: An access control issue in the component /ManageRoute/postRoute of FreeTAKServer v1.9.8 allows unauthenticated attackers to cause a Denial of Service (DoS) via an unusually large amount of created routes, or create unsafe or false routes for legitimate users.

CVE-2021-21816: An information disclosure vulnerability exists in the Syslog functionality of D-LINK DIR-3040 1.13B03. A specially crafted network request can lead to the disclosure of sensitive information. An attacker can send an HTTP request to trigger this vulnerability.

# CWE-307 Improper Restriction of Excessive Authentication Attempts

## Description

The product does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks.

## Observed Examples

CVE-2019-0039: the REST API for a network OS has a high limit for number of connections, allowing brute force password guessing

CVE-1999-1152: Product does not disconnect or timeout after multiple failed logins.

CVE-2001-1291: Product does not disconnect or timeout after multiple failed logins.

CVE-2001-0395: Product does not disconnect or timeout after multiple failed logins.

CVE-2001-1339: Product does not disconnect or timeout after multiple failed logins.

CVE-2002-0628: Product does not disconnect or timeout after multiple failed logins.

CVE-1999-1324: User accounts not disabled when they exceed a threshold; possibly a resultant problem.

## Top 25 Examples

CVE-2022-3993: Improper Restriction of Excessive Authentication Attempts in GitHub repository kareadita/kavita prior to 0.6.0.3. 

CVE-2022-22485: In some cases, an unsuccessful attempt to log into IBM Spectrum Protect Operations Center 8.1.0.000 through 8.1.14.000 does not cause the administrator's invalid sign-on count to be incremented on the IBM Spectrum Protect Server. An attacker could exploit this vulnerability using brute force techniques to gain unauthorized administrative access to the IBM Spectrum Protect Server. IBM X-Force ID: 226325.

CVE-2022-22487: An IBM Spectrum Protect storage agent could allow a remote attacker to perform a brute force attack by allowing unlimited attempts to login to the storage agent without locking the administrative ID. A remote attacker could exploit this vulnerability using brute force techniques to gain unauthorized administrative access to both the IBM Spectrum Protect storage agent and the IBM Spectrum Protect Server 8.1.0.000 through 8.1.14 with which it communicates. IBM X-Force ID: 226326.

CVE-2022-35925: BookWyrm is a social network for tracking reading. Versions prior to 0.4.5 were found to lack rate limiting on authentication views which allows brute-force attacks. This issue has been patched in version 0.4.5. Admins with existing instances will need to update their `nginx.conf` file that was created when the instance was set up. Users are advised advised to upgrade. Users unable to upgrade may update their nginx.conf files with the changes manually.

# CWE-308 Use of Single-factor Authentication

## Description

The use of single-factor authentication can lead to unnecessary risk of compromise when compared with the benefits of a dual-factor authentication scheme.

While the use of multiple authentication schemes is simply piling on more complexity on top of authentication, it is inestimably valuable to have such measures of redundancy. The use of weak, reused, and common passwords is rampant on the internet. Without the added protection of multiple authentication schemes, a single mistake can result in the compromise of an account. For this reason, if multiple schemes are possible and also easy to use, they should be implemented and required.

## Observed Examples

CVE-2022-35248: Chat application skips validation when Central Authentication Service (CAS) is enabled, effectively removing the second factor from two-factor authentication

## Top 25 Examples

CVE-2022-35248: A improper authentication vulnerability exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 that allowed two factor authentication can be bypassed when telling the server to use CAS during login.

# CWE-309 Use of Password System for Primary Authentication

## Description

The use of password systems as the primary means of authentication may be subject to several flaws or shortcomings, each reducing the effectiveness of the mechanism.

Password systems are the simplest and most ubiquitous authentication mechanisms. However, they are subject to such well known attacks,and such frequent compromise that their use in the most simple implementation is not practical.

# CWE-31 Path Traversal: 'dir\..\..\filename'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize 'dir\..\..\filename' (multiple internal backslash dot dot) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The 'dir\..\..\filename' manipulation is useful for bypassing some path traversal protection schemes. Sometimes a program only removes one "..\" sequence, so multiple "..\" can bypass that check. Alternately, this manipulation could be used to bypass a check for "..\" at the beginning of the pathname, moving up more than one directory level.

## Observed Examples

CVE-2002-0160: The administration function in Access Control Server allows remote attackers to read HTML, Java class, and image files outside the web root via a "..\.." sequence in the URL to port 2002.

# CWE-311 Missing Encryption of Sensitive Data

## Description

The product does not encrypt sensitive or critical information before storage or transmission.

The lack of proper data encryption passes up the guarantees of confidentiality, integrity, and accountability that properly implemented encryption conveys.

## Observed Examples

CVE-2009-2272: password and username stored in cleartext in a cookie

CVE-2009-1466: password stored in cleartext in a file with insecure permissions

CVE-2009-0152: chat program disables SSL in some circumstances even when the user says to use SSL.

CVE-2009-1603: Chain: product uses an incorrect public exponent when generating an RSA key, which effectively disables the encryption

CVE-2009-0964: storage of unencrypted passwords in a database

CVE-2008-6157: storage of unencrypted passwords in a database

CVE-2008-6828: product stores a password in cleartext in memory

CVE-2008-1567: storage of a secret key in cleartext in a temporary file

CVE-2008-0174: SCADA product uses HTTP Basic Authentication, which is not encrypted

CVE-2007-5778: login credentials stored unencrypted in a registry key

CVE-2002-1949: Passwords transmitted in cleartext.

CVE-2008-4122: Chain: Use of HTTPS cookie without "secure" flag causes it to be transmitted across unencrypted HTTP.

CVE-2008-3289: Product sends password hash in cleartext in violation of intended policy.

CVE-2008-4390: Remote management feature sends sensitive information including passwords in cleartext.

CVE-2007-5626: Backup routine sends password in cleartext in email.

CVE-2004-1852: Product transmits Blowfish encryption key in cleartext.

CVE-2008-0374: Printer sends configuration information, including administrative password, in cleartext.

CVE-2007-4961: Chain: cleartext transmission of the MD5 hash of password enables attacks against a server that is susceptible to replay (CWE-294).

CVE-2007-4786: Product sends passwords in cleartext to a log server.

CVE-2005-3140: Product sends file with cleartext passwords in e-mail message intended for diagnostic purposes.

## Top 25 Examples

CVE-2021-37050: There is a Missing sensitive data encryption vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may affect service confidentiality.

CVE-2022-0183: Missing encryption of sensitive data vulnerability in 'MIRUPASS' PW10 firmware all versions and 'MIRUPASS' PW20 firmware all versions allows an attacker who can physically access the device to obtain the stored passwords.

CVE-2022-35860: Missing AES encryption in Corsair K63 Wireless 3.1.3 allows physically proximate attackers to inject and sniff keystrokes via 2.4 GHz radio transmissions.

CVE-2022-38658: BigFix deployments that have installed the Notification Service on Windows are susceptible to disclosing SMTP BigFix operator's sensitive data in clear text. Operators who use Notification Service related content from BES Support are at risk of leaving their SMTP sensitive data exposed. 

CVE-2021-27779: VersionVault Express exposes sensitive information that an attacker can use to impersonate the server or eavesdrop on communications with the server.

CVE-2021-27783: User generated PPKG file for Bulk Enroll may have unencrypted sensitive information exposed.

CVE-2022-30237: A CWE-311: Missing Encryption of Sensitive Data vulnerability exists that could allow authentication credentials to be recovered when an attacker breaks the encoding. Affected Products: Wiser Smart, EER21000 & EER21001 (V4.5 and prior)

CVE-2022-39014: Under certain conditions SAP BusinessObjects Business Intelligence Platform Central Management Console (CMC) - version 430, allows an attacker to access certain unencrypted sensitive parameters which would otherwise be restricted.

# CWE-312 Cleartext Storage of Sensitive Information

## Description

The product stores sensitive information in cleartext within a resource that might be accessible to another control sphere.

Because the information is stored in cleartext (i.e., unencrypted), attackers could potentially read it. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.


When organizations adopt cloud services, it can be easier for attackers to access the data from anywhere on the Internet.


In some systems/environments such as cloud, the use of "double encryption" (at both the software and hardware layer) might be required, and the developer might be solely responsible for both layers, instead of shared responsibility with the administrator of the broader system/environment.

## Observed Examples

CVE-2022-30275: Remote Terminal Unit (RTU) uses a driver that relies on a password stored in plaintext.

CVE-2009-2272: password and username stored in cleartext in a cookie

CVE-2009-1466: password stored in cleartext in a file with insecure permissions

CVE-2009-0152: chat program disables SSL in some circumstances even when the user says to use SSL.

CVE-2009-1603: Chain: product uses an incorrect public exponent when generating an RSA key, which effectively disables the encryption

CVE-2009-0964: storage of unencrypted passwords in a database

CVE-2008-6157: storage of unencrypted passwords in a database

CVE-2008-6828: product stores a password in cleartext in memory

CVE-2008-1567: storage of a secret key in cleartext in a temporary file

CVE-2008-0174: SCADA product uses HTTP Basic Authentication, which is not encrypted

CVE-2007-5778: login credentials stored unencrypted in a registry key

CVE-2001-1481: Plaintext credentials in world-readable file.

CVE-2005-1828: Password in cleartext in config file.

CVE-2005-2209: Password in cleartext in config file.

CVE-2002-1696: Decrypted copy of a message written to disk given a combination of options and when user replies to an encrypted message.

CVE-2004-2397: Plaintext storage of private key and passphrase in log file when user imports the key.

CVE-2002-1800: Admin password in plaintext in a cookie.

CVE-2001-1537: Default configuration has cleartext usernames/passwords in cookie.

CVE-2001-1536: Usernames/passwords in cleartext in cookies.

CVE-2005-2160: Authentication information stored in cleartext in a cookie.

## Top 25 Examples

CVE-2022-26390: The Baxter Spectrum Wireless Battery Module (WBM) stores network credentials and PHI (only applicable to Spectrum IQ pumps using auto programming) in unencrypted form. An attacker with physical access to a device that hasn't had all data and settings erased may be able to extract sensitive information.

CVE-2022-22069: Devices with keyprotect off may store unencrypted keybox in RPMB and cause cryptographic issue in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-27549: HCL Launch may store certain data for recurring activities in a plain text format.

CVE-2022-20219: In multiple functions of StorageManagerService.java and UserManagerService.java, there is a possible way to leave user's directories unencrypted due to a logic error in the code. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-224585613

CVE-2022-29959: Emerson OpenBSI through 2022-04-29 mishandles credential storage. It is an engineering environment for the ControlWave and Bristol Babcock line of RTUs. This environment provides access control functionality through user authentication and privilege management. The credentials for various users are stored insecurely in the SecUsers.ini file by using a simple string transformation rather than a cryptographic mechanism.

# CWE-313 Cleartext Storage in a File or on Disk

## Description

The product stores sensitive information in cleartext in a file, or on disk.

The sensitive information could be read by attackers with access to the file, or with physical or administrator access to the raw disk. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

## Observed Examples

CVE-2001-1481: Cleartext credentials in world-readable file.

CVE-2005-1828: Password in cleartext in config file.

CVE-2005-2209: Password in cleartext in config file.

CVE-2002-1696: Decrypted copy of a message written to disk given a combination of options and when user replies to an encrypted message.

CVE-2004-2397: Cleartext storage of private key and passphrase in log file when user imports the key.

## Top 25 Examples

CVE-2022-42931: Logins saved by Firefox should be managed by the Password Manager component which uses encryption to save files on-disk. Instead, the username (not password) was saved by the Form Manager to an unencrypted file on disk. This vulnerability affects Firefox < 106.

# CWE-314 Cleartext Storage in the Registry

## Description

The product stores sensitive information in cleartext in the registry.

Attackers can read the information by accessing the registry key. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

## Observed Examples

CVE-2005-2227: Cleartext passwords in registry key.

## Top 25 Examples

CVE-2022-22031: Windows Credential Guard Domain-joined Public Key Elevation of Privilege Vulnerability

# CWE-315 Cleartext Storage of Sensitive Information in a Cookie

## Description

The product stores sensitive information in cleartext in a cookie.

Attackers can use widely-available tools to view the cookie and read the sensitive information. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

## Observed Examples

CVE-2002-1800: Admin password in cleartext in a cookie.

CVE-2001-1537: Default configuration has cleartext usernames/passwords in cookie.

CVE-2001-1536: Usernames/passwords in cleartext in cookies.

CVE-2005-2160: Authentication information stored in cleartext in a cookie.

## Top 25 Examples

CVE-2021-45025: ASG technologies ( A Rocket Software Company) ASG-Zena Cross Platform Server Enterprise Edition 4.2.1 is vulnerable to Cleartext Storage of Sensitive Information in a Cookie.

# CWE-316 Cleartext Storage of Sensitive Information in Memory

## Description

The product stores sensitive information in cleartext in memory.

The sensitive memory might be saved to disk, stored in a core dump, or remain uncleared if the product crashes, or if the programmer does not properly clear the memory before freeing it.


It could be argued that such problems are usually only exploitable by those with administrator privileges. However, swapping could cause the memory to be written to disk and leave it accessible to physical attack afterwards. Core dump files might have insecure permissions or be stored in archive files that are accessible to untrusted people. Or, uncleared sensitive memory might be inadvertently exposed to attackers due to another weakness.

## Observed Examples

CVE-2001-1517: Sensitive authentication information in cleartext in memory.

CVE-2001-0984: Password protector leaves passwords in memory when window is minimized, even when "clear password when minimized" is set.

CVE-2003-0291: SSH client does not clear credentials from memory.

## Top 25 Examples

CVE-2022-29832: Cleartext Storage of Sensitive Information in Memory vulnerability in Mitsubishi Electric Corporation GX Works3 versions 1.015R and later, GX Works2 all versions and GX Developer versions 8.40S and later allows a remote unauthenticated attacker to disclose sensitive information. As a result, unauthenticated users could obtain information about the project file for MELSEC safety CPU modules or project file for MELSEC Q/FX/L series with security setting.

CVE-2022-31205: In Omron CS series, CJ series, and CP series PLCs through 2022-05-18, the password for access to the Web UI is stored in memory area D1449...D1452 and can be read out using the Omron FINS protocol without any further authentication.

# CWE-317 Cleartext Storage of Sensitive Information in GUI

## Description

The product stores sensitive information in cleartext within the GUI.

An attacker can often obtain data from a GUI, even if hidden, by using an API to directly access GUI objects such as windows and menus. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

## Observed Examples

CVE-2002-1848: Unencrypted passwords stored in GUI dialog may allow local users to access the passwords.

# CWE-318 Cleartext Storage of Sensitive Information in Executable

## Description

The product stores sensitive information in cleartext in an executable.

Attackers can reverse engineer binary code to obtain secret data. This is especially easy when the cleartext is plain ASCII. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

## Observed Examples

CVE-2005-1794: Product stores RSA private key in a DLL and uses it to sign a certificate, allowing spoofing of servers and Adversary-in-the-Middle (AITM) attacks.

CVE-2001-1527: administration passwords in cleartext in executable

# CWE-319 Cleartext Transmission of Sensitive Information

## Description

The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.

Many communication channels can be "sniffed" (monitored) by adversaries during data transmission. For example, in networking, packets can traverse many intermediary nodes from the source to the destination, whether across the internet, an internal network, the cloud, etc. Some actors might have privileged access to a network interface or any link along the channel, such as a router, but they might not be authorized to collect the underlying data. As a result, network traffic could be sniffed by adversaries, spilling security-critical data.


Applicable communication channels are not limited to software products. Applicable channels include hardware-specific technologies such as internal hardware networks and external debug channels, supporting remote JTAG debugging. When mitigations are not applied to combat adversaries within the product's threat model, this weakness significantly lowers the difficulty of exploitation by such adversaries.


When full communications are recorded or logged, such as with a packet dump, an adversary could attempt to obtain the dump long after the transmission has occurred and try to "sniff" the cleartext from the recorded communications in the dump itself. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode the information.

## Observed Examples

CVE-2022-29519: Programmable Logic Controller (PLC) sends sensitive information in plaintext, including passwords and session tokens.

CVE-2022-30312: Building Controller uses a protocol that transmits authentication credentials in plaintext.

CVE-2022-31204: Programmable Logic Controller (PLC) sends password in plaintext.

CVE-2002-1949: Passwords transmitted in cleartext.

CVE-2008-4122: Chain: Use of HTTPS cookie without "secure" flag causes it to be transmitted across unencrypted HTTP.

CVE-2008-3289: Product sends password hash in cleartext in violation of intended policy.

CVE-2008-4390: Remote management feature sends sensitive information including passwords in cleartext.

CVE-2007-5626: Backup routine sends password in cleartext in email.

CVE-2004-1852: Product transmits Blowfish encryption key in cleartext.

CVE-2008-0374: Printer sends configuration information, including administrative password, in cleartext.

CVE-2007-4961: Chain: cleartext transmission of the MD5 hash of password enables attacks against a server that is susceptible to replay (CWE-294).

CVE-2007-4786: Product sends passwords in cleartext to a log server.

CVE-2005-3140: Product sends file with cleartext passwords in e-mail message intended for diagnostic purposes.

## Top 25 Examples

CVE-2022-23509: Weave GitOps is a simple open source developer platform for people who want cloud native applications, without needing Kubernetes expertise. GitOps run has a local S3 bucket which it uses for synchronizing files that are later applied against a Kubernetes cluster. The communication between GitOps Run and the local S3 bucket is not encrypted. This allows privileged users or process to tap the local traffic to gain information permitting access to the s3 bucket. From that point, it would be possible to alter the bucket content, resulting in changes in the Kubernetes cluster's resources. There are no known workaround(s) for this vulnerability. This vulnerability has been fixed by commits ce2bbff and babd915. Users should upgrade to Weave GitOps version >= v0.12.0 released on 08/12/2022. 

CVE-2022-39287: tiny-csrf is a Node.js cross site request forgery (CSRF) protection middleware. In versions prior to 1.1.0 cookies were not encrypted and thus CSRF tokens were transmitted in the clear. This issue has been addressed in commit `8eead6d` and the patch with be included in version 1.1.0. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2021-1896: Weak configuration in WLAN could cause forwarding of unencrypted packets from one client to another in Snapdragon Compute, Snapdragon Connectivity

CVE-2021-35246: The application fails to prevent users from connecting to it over unencrypted connections. An attacker able to modify a legitimate user's network traffic could bypass the application's use of SSL/TLS encryption and use the application as a platform for attacks against its users.

CVE-2021-40148: In Modem EMM, there is a possible information disclosure due to a missing data encryption. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: MOLY00716585; Issue ID: ALPS05886933.

CVE-2021-4161: The affected products contain vulnerable firmware, which could allow an attacker to sniff the traffic and decrypt login credential details. This could give an attacker admin rights through the HTTP web server.

CVE-2021-41849: An issue was discovered in Luna Simo PPR1.180610.011/202001031830. It sends the following Personally Identifiable Information (PII) in plaintext using HTTP to servers located in China: user's list of installed apps and device International Mobile Equipment Identity (IMEI). This PII is transmitted to log.skyroam.com.cn using HTTP, independent of whether the user uses the Simo software.

CVE-2021-43270: Datalust Seq.App.EmailPlus (aka seq-app-htmlemail) 3.1.0-dev-00148, 3.1.0-dev-00170, and 3.1.0-dev-00176 can use cleartext SMTP on port 25 in some cases where encryption on port 465 was intended.

CVE-2022-1524: LRM version 2.4 and lower does not implement TLS encryption. A malicious actor can MITM attack sensitive data in-transit, including credentials.

CVE-2022-21951: A Cleartext Transmission of Sensitive Information vulnerability in SUSE Rancher, Rancher allows attackers on the network to read and change network data due to missing encryption of data transmitted via the network when a cluster is created from an RKE template with the CNI value overridden This issue affects: SUSE Rancher Rancher versions prior to 2.5.14; Rancher versions prior to 2.6.5. 

CVE-2022-2338: Softing Secure Integration Server V1.22 is vulnerable to authentication bypass via a machine-in-the-middle attack. The default the administration interface is accessible via plaintext HTTP protocol, facilitating the attack. The HTTP request may contain the session cookie in the request, which may be captured for use in authenticating to the server.

CVE-2022-32227: A cleartext transmission of sensitive information exists in Rocket.Chat <v5, <v4.8.2 and <v4.7.5 relating to Oauth tokens by having the permission "view-full-other-user-info", this could cause an oauth token leak in the product.

CVE-2022-41627:  The physical IoT device of the AliveCor's KardiaMobile, a smartphone-based personal electrocardiogram (EKG) has no encryption for its data-over-sound protocols. Exploiting this vulnerability could allow an attacker to read patient EKG results or create a denial-of-service condition by emitting sounds at similar frequencies as the device, disrupting the smartphone microphone’s ability to accurately read the data. To carry out this attack, the attacker must be close (less than 5 feet) to pick up and emit sound waves. 

CVE-2022-41983: On specific hardware platforms, on BIG-IP versions 16.1.x before 16.1.3.1, 15.1.x before 15.1.7, 14.1.x before 14.1.5.1, and all versions of 13.1.x, while Intel QAT (QuickAssist Technology) and the AES-GCM/CCM cipher is in use, undisclosed conditions can cause BIG-IP to send data unencrypted even with an SSL Profile applied.

CVE-2022-45877: OpenHarmony-v3.1.4 and prior versions had an vulnerability. PIN code is transmitted to the peer device in plain text during cross-device authentication, which reduces the difficulty of man-in-the-middle attacks.

CVE-2022-0005: Sensitive information accessible by physical probing of JTAG interface for some Intel(R) Processors with SGX may allow an unprivileged user to potentially enable information disclosure via physical access.

CVE-2021-22923: When curl is instructed to get content using the metalink feature, and a user name and password are used to download the metalink XML file, those same credentials are then subsequently passed on to each of the servers from which curl will download or try to download the contents from. Often contrary to the user's expectations and intentions and without telling the user it happened.

CVE-2022-23223: On Apache ShenYu versions 2.4.0 and 2.4.1, and endpoint existed that disclosed the passwords of all users. Users are recommended to upgrade to version 2.4.2 or later.

CVE-2022-24978: Zoho ManageEngine ADAudit Plus before 7055 allows authenticated Privilege Escalation on Integrated products. This occurs because a password field is present in a JSON response.

CVE-2022-25180: Jenkins Pipeline: Groovy Plugin 2648.va9433432b33c and earlier includes password parameters from the original build in replayed builds, allowing attackers with Run/Replay permission to obtain the values of password parameters passed to previous builds of a Pipeline.

CVE-2022-47714: Last Yard 22.09.8-1 does not enforce HSTS headers

CVE-2022-0553: There is no check to see if slot 0 is being uploaded from the device to the host. When using encrypted images this means the unencrypted firmware can be retrieved easily.

CVE-2022-29945: DJI drone devices sold in 2017 through 2022 broadcast unencrypted information about the drone operator's physical location via the AeroScope protocol.

CVE-2021-31898: In JetBrains WebStorm before 2021.1, HTTP requests were used instead of HTTPS.

CVE-2022-2083: The Simple Single Sign On WordPress plugin through 4.1.0 leaks its OAuth client_secret, which could be used by attackers to gain unauthorized access to the site.

CVE-2021-45081: An issue was discovered in Cobbler through 3.3.1. Routines in several files use the HTTP protocol instead of the more secure HTTPS.

# CWE-32 Path Traversal: '...' (Triple Dot)

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '...' (triple dot) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The '...' manipulation is useful for bypassing some path traversal protection schemes. On some Windows systems, it is equivalent to "..\.." and might bypass checks that assume only two dots are valid. Incomplete filtering, such as removal of "./" sequences, can ultimately produce valid ".." sequences due to a collapse into unsafe value (CWE-182).

## Observed Examples

CVE-2001-0467: "\..." in web server

CVE-2001-0615: "..." or "...." in chat server

CVE-2001-0963: "..." in cd command in FTP server

CVE-2001-1193: "..." in cd command in FTP server

CVE-2001-1131: "..." in cd command in FTP server

CVE-2001-0480: read of arbitrary files and directories using GET or CD with "..." in Windows-based FTP server.

CVE-2002-0288: read files using "." and Unicode-encoded "/" or "\" characters in the URL.

CVE-2003-0313: Directory listing of web server using "..."

CVE-2005-1658: Triple dot

# CWE-321 Use of Hard-coded Cryptographic Key

## Description

The use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered.

## Observed Examples

CVE-2022-29960: Engineering Workstation uses hard-coded cryptographic keys that could allow for unathorized filesystem access and privilege escalation

CVE-2022-30271: Remote Terminal Unit (RTU) uses a hard-coded SSH private key that is likely to be used by default.

CVE-2020-10884: WiFi router service has a hard-coded encryption key, allowing root access

CVE-2014-2198: Communications / collaboration product has a hardcoded SSH private key, allowing access to root account

## Top 25 Examples

CVE-2022-35857: kvf-admin through 2022-02-12 allows remote attackers to execute arbitrary code because deserialization is mishandled. The rememberMe parameter is encrypted with a hardcoded key from the com.kalvin.kvf.common.shiro.ShiroConfig file.

CVE-2021-41028: A combination of a use of hard-coded cryptographic key vulnerability [CWE-321] in FortiClientEMS 7.0.1 and below, 6.4.6 and below and an improper certificate validation vulnerability [CWE-297] in FortiClientWindows, FortiClientLinux and FortiClientMac 7.0.1 and below, 6.4.6 and below may allow an unauthenticated and network adjacent attacker to perform a man-in-the-middle attack between the EMS and the FCT via the telemetry protocol.

CVE-2021-22644: Ovarro TBox TWinSoft uses the custom hardcoded user “TWinSoft” with a hardcoded key.

CVE-2022-1400: Use of Hard-coded Cryptographic Key vulnerability in the WebReportsApi.dll of Exago Web Reports, as used in the Device42 Asset Management Appliance, allows an attacker to leak session IDs and elevate privileges. This issue affects: Device42 CMDB versions prior to 18.01.00.

CVE-2022-1701: SonicWall SMA1000 series firmware 12.4.0, 12.4.1-02965 and earlier versions uses a shared and hard-coded encryption key to store data.

CVE-2022-23440: A use of hard-coded cryptographic key vulnerability [CWE-321] in the registration mechanism of FortiEDR collectors versions 5.0.2, 5.0.1, 5.0.0, 4.0.0 may allow a local attacker to disable and uninstall the collectors from the end-points within the same deployment.

CVE-2022-23441: A use of hard-coded cryptographic key vulnerability [CWE-321] in FortiEDR versions 5.0.2, 5.0.1, 5.0.0, 4.0.0 may allow an unauthenticated attacker on the network to disguise as and forge messages from other collectors.

CVE-2022-23650: Netmaker is a platform for creating and managing virtual overlay networks using WireGuard. Prior to versions 0.8.5, 0.9.4, and 010.0, there is a hard-coded cryptographic key in the code base which can be exploited to run admin commands on a remote server if the exploiter know the address and username of the admin. This effects the server (netmaker) component, and not clients. This has been patched in Netmaker v0.8.5, v0.9.4, and v0.10.0. There are currently no known workarounds.

CVE-2022-23724: Use of static encryption key material allows forging an authentication token to other users within a tenant organization. MFA may be bypassed by redirecting an authentication flow to a target user. To exploit the vulnerability, must have compromised user credentials.

CVE-2022-24860: Databasir is a team-oriented relational database model document management platform. Databasir 1.01 has Use of Hard-coded Cryptographic Key vulnerability. An attacker can use hard coding to generate login credentials of any user and log in to the service background located at different IP addresses.

CVE-2022-25217: Use of a hard-coded cryptographic key pair by the telnetd_startup service allows an attacker on the local area network to obtain a root shell on the device over telnet. The builds of telnetd_startup included in the version 22.5.9.163 of the K2 firmware, and version 32.1.15.93 of the K3C firmware (possibly amongst many other releases) included both the private and public RSA keys. The remaining versions cited here redacted the private key, but left the public key unchanged. An attacker in possession of the leaked private key may, through a scripted exchange of UDP packets, instruct telnetd_startup to spawn an unauthenticated telnet shell as root, by means of which they can then obtain complete control of the device. A consequence of the limited availablility of firmware images for testing is that models and versions not listed here may share this vulnerability.

CVE-2022-2660: Delta Industrial Automation DIALink versions 1.4.0.0 and prior are vulnerable to the use of a hard-coded cryptographic key which could allow an attacker to decrypt sensitive data and compromise the machine. 

CVE-2022-29060: A use of hard-coded cryptographic key vulnerability [CWE-321] in FortiDDoS API 5.5.0 through 5.5.1, 5.4.0 through 5.4.2, 5.3.0 through 5.3.1, 5.2.0, 5.1.0 may allow an attacker who managed to retrieve the key from one device to sign JWT tokens for any device.

CVE-2022-29827: Use of Hard-coded Cryptographic Key vulnerability in Mitsubishi Electric GX Works3 versions from 1.000A and later allows a remote unauthenticated attacker to disclose sensitive information. As a result, unauthenticated attackers may view programs and project files or execute programs illegally.

CVE-2022-29828: Use of Hard-coded Cryptographic Key vulnerability in Mitsubishi Electric GX Works3 versions from 1.000A and later allows a remote unauthenticated attacker to disclose sensitive information. As a result, unauthenticated attackers may view programs and project file or execute programs illegally.

CVE-2022-29829: Use of Hard-coded Cryptographic Key vulnerability in Mitsubishi Electric GX Works3 versions from 1.000A to 1.090U, GT Designer3 Version1 (GOT2000) versions from 1.122C to 1.290C and Motion Control Setting(GX Works3 related software) versions from 1.035M to 1.042U allows a remote unauthenticated attacker to disclose sensitive information. As a result, unauthenticated users may view programs and project files or execute programs illegally.

CVE-2022-29830: Use of Hard-coded Cryptographic Key vulnerability in Mitsubishi Electric GX Works3 versions from 1.000A to 1.095Z and Motion Control Setting(GX Works3 related software) versions from 1.000A and later allows a remote unauthenticated attacker to disclose or tamper with sensitive information. As a result, unauthenticated attackers may obtain information about project files illegally.

CVE-2022-29856: A hardcoded cryptographic key in Automation360 22 allows an attacker to decrypt exported RPA packages.

CVE-2022-30271: The Motorola ACE1000 RTU through 2022-05-02 ships with a hardcoded SSH private key and initialization scripts (such as /etc/init.d/sshd_service) only generate a new key if no private-key file exists. Thus, this hardcoded key is likely to be used by default.

CVE-2022-30274: The Motorola ACE1000 RTU through 2022-05-02 uses ECB encryption unsafely. It can communicate with an XRT LAN-to-radio gateway by means of an embedded client. Credentials for accessing this gateway are stored after being encrypted with the Tiny Encryption Algorithm (TEA) in ECB mode using a hardcoded key. Similarly, the ACE1000 RTU can route MDLC traffic over Extended Command and Management Protocol (XCMP) and Network Layer (XNL) networks via the MDLC driver. Authentication to the XNL port is protected by TEA in ECB mode using a hardcoded key.

CVE-2022-34440: Dell EMC SCG Policy Manager, versions from 5.10 to 5.12, contain(s) a contain a Hard-coded Cryptographic Key vulnerability. An attacker with the knowledge of the hard-coded sensitive information, could potentially exploit this vulnerability to login to the system to gain admin privileges. 

CVE-2022-34441:  Dell EMC SCG Policy Manager, versions from 5.10 to 5.12, contain(s) a contain a Hard-coded Cryptographic Key vulnerability. An attacker with the knowledge of the hard-coded sensitive information, could potentially exploit this vulnerability to login to the system to gain admin privileges. 

CVE-2022-34442:  Dell EMC SCG Policy Manager, versions from 5.10 to 5.12, contain(s) a contain a Hard-coded Cryptographic Key vulnerability. An attacker with the knowledge of the hard-coded sensitive information, could potentially exploit this vulnerability to login to the system to gain LDAP user privileges. 

CVE-2022-34449:  PowerPath Management Appliance with versions 3.3 & 3.2* contains a Hardcoded Cryptographic Keys vulnerability. Authenticated admin users can exploit the issue that leads to view and modifying sensitive information stored in the application. 

CVE-2022-34906: A hard-coded cryptographic key is used in FileWave before 14.6.3 and 14.7.x before 14.7.2. Exploitation could allow an unauthenticated actor to decrypt sensitive information saved in FileWave, and even send crafted requests.

CVE-2022-41540: The web app client of TP-Link AX10v1 V1_211117 uses hard-coded cryptographic keys when communicating with the router. Attackers who are able to intercept the communications between the web client and router through a man-in-the-middle attack can then obtain the sequence key via a brute-force attack, and access sensitive information.

CVE-2021-23842: Communication to the AMC2 uses a state-of-the-art cryptographic algorithm for symmetric encryption called Blowfish. An attacker could retrieve the key from the firmware to decrypt network traffic between the AMC2 and the host system. Thus, an attacker can exploit this vulnerability to decrypt and modify network traffic, decrypt and further investigate the device\\'s firmware file, and change the device configuration. The attacker needs to have access to the local network, typically even the same subnet.

CVE-2021-45458: Apache Kylin provides encryption classes PasswordPlaceholderConfigurer to help users encrypt their passwords. In the encryption algorithm used by this encryption class, the cipher is initialized with a hardcoded key and IV. If users use class PasswordPlaceholderConfigurer to encrypt their password and configure it into kylin's configuration file, there is a risk that the password may be decrypted. This issue affects Apache Kylin 2 version 2.6.6 and prior versions; Apache Kylin 3 version 3.1.2 and prior versions; Apache Kylin 4 version 4.0.0 and prior versions.

CVE-2022-23942: Apache Doris, prior to 1.0.0, used a hardcoded key and IV to initialize the cipher used for ldap password, which may lead to information disclosure.

CVE-2022-25806: An issue was discovered in the IGEL Universal Management Suite (UMS) 6.07.100. A hardcoded DES key in the PrefDBCredentials class allows an attacker, who has discovered encrypted superuser credentials, to decrypt those credentials using a static 8-byte DES key.

CVE-2022-25807: An issue was discovered in the IGEL Universal Management Suite (UMS) 6.07.100. A hardcoded DES key in the LDAPDesPWEncrypter class allows an attacker, who has discovered encrypted LDAP bind credentials, to decrypt those credentials using a static 8-byte DES key.

CVE-2022-26660: RunAsSpc 4.0 uses a universal and recoverable encryption key. In possession of a file encrypted by RunAsSpc, an attacker can recover the credentials that were used.

CVE-2022-34045: Wavlink WN530HG4 M30HG4.V5030.191116 was discovered to contain a hardcoded encryption/decryption key for its configuration files at /etc_ro/lighttpd/www/cgi-bin/ExportAllSettings.sh.

CVE-2022-34386:  Dell SupportAssist for Home PCs (version 3.11.4 and prior) and SupportAssist for Business PCs (version 3.2.0 and prior) contain cryptographic weakness vulnerability. An authenticated non-admin user could potentially exploit the issue and obtain sensitive information. 

CVE-2022-34425: Dell Enterprise SONiC OS, 4.0.0, 4.0.1, contain a cryptographic key vulnerability in SSH. An unauthenticated remote attacker could potentially exploit this vulnerability, leading to unauthorized access to communication.

CVE-2022-37710: Patterson Dental Eaglesoft 21 has AES-256 encryption but there are two ways to obtain a keyfile: (1) keybackup.data > License > Encryption Key or (2) Eaglesoft.Server.Configuration.data > DbEncryptKeyPrimary > Encryption Key. Applicable files are encrypted with keys and salt that are hardcoded into a DLL or EXE file.

CVE-2022-38117: Juiker app hard-coded its AES key in the source code. A physical attacker, after getting the Android root privilege, can use the AES key to decrypt users’ ciphertext and tamper with it.

CVE-2022-45425: Some Dahua software products have a vulnerability of using of hard-coded cryptographic key. An attacker can obtain the AES crypto key by exploiting this vulnerability.

CVE-2021-40903: A vulnerability in Antminer Monitor 0.50.0 exists because of backdoor or misconfiguration inside a settings file in flask server. Settings file has a predefined secret string, which would be randomly generated, however it is static.

CVE-2022-26020: An information disclosure vulnerability exists in the router configuration export functionality of InHand Networks InRouter302 V3.5.4. A specially-crafted network request can lead to increased privileges. An attacker can send an HTTP request to trigger this vulnerability.

# CWE-322 Key Exchange without Entity Authentication

## Description

The product performs a key exchange with an actor without verifying the identity of that actor.

Performing a key exchange will preserve the integrity of the information sent between two entities, but this will not guarantee that the entities are who they claim they are. This may enable an attacker to impersonate an actor by modifying traffic between the two entities. Typically, this involves a victim client that contacts a malicious server that is impersonating a trusted server. If the client skips authentication or ignores an authentication failure, the malicious server may request authentication information from the user. The malicious server can then use this authentication information to log in to the trusted server using the victim's credentials, sniff traffic between the victim and trusted server, etc.

## Top 25 Examples

CVE-2021-0133: Key exchange without entity authentication in the Intel(R) Security Library before version 3.3 may allow an authenticated user to potentially enable escalation of privilege via network access.

CVE-2021-38878: IBM QRadar 7.3, 7.4, and 7.5 could allow a malicious actor to impersonate an actor due to key exchange without entity authentication. IBM X-Force ID: 208756.

CVE-2022-39254: matrix-nio is a Python Matrix client library, designed according to sans I/O principles. Prior to version 0.20, when a users requests a room key from their devices, the software correctly remember the request. Once they receive a forwarded room key, they accept it without checking who the room key came from. This allows homeservers to try to insert room keys of questionable validity, potentially mounting an impersonation attack. Version 0.20 fixes the issue.

# CWE-323 Reusing a Nonce, Key Pair in Encryption

## Description

Nonces should be used for the present occasion and only once.

Nonces are often bundled with a key in a communication exchange to produce a new session key for each exchange.

# CWE-324 Use of a Key Past its Expiration Date

## Description

The product uses a cryptographic key or password past its expiration date, which diminishes its safety significantly by increasing the timing window for cracking attacks against that key.

While the expiration of keys does not necessarily ensure that they are compromised, it is a significant concern that keys which remain in use for prolonged periods of time have a decreasing probability of integrity. For this reason, it is important to replace keys within a period of time proportional to their strength.

## Observed Examples

CVE-2021-33020: Picture Archiving and Communication System (PACS) system for hospitals uses a cryptographic key or password past its expiration date

## Top 25 Examples

CVE-2021-33020: Philips Vue PACS versions 12.2.x.x and prior uses a cryptographic key or password past its expiration date, which diminishes its safety significantly by increasing the timing window for cracking attacks against that key.

# CWE-325 Missing Cryptographic Step

## Description

The product does not implement a required step in a cryptographic algorithm, resulting in weaker encryption than advertised by the algorithm.

## Observed Examples

CVE-2001-1585: Missing challenge-response step allows authentication bypass using public key.

## Top 25 Examples

CVE-2022-1279: A vulnerability in the encryption implementation of EBICS messages in the open source librairy ebics-java/ebics-java-client allows an attacker sniffing network traffic to decrypt EBICS payloads. This issue affects: ebics-java/ebics-java-client versions prior to 1.2.

CVE-2022-22934: An issue was discovered in SaltStack Salt in versions before 3002.8, 3003.4, 3004.1. Salt Masters do not sign pillar data with the minion’s public key, which can result in attackers substituting arbitrary pillar data.

CVE-2022-29053: A missing cryptographic steps vulnerability [CWE-325] in the functions that encrypt the keytab files in FortiOS version 7.2.0, 7.0.0 through 7.0.5 and below 7.0.0 may allow an attacker in possession of the encrypted file to decipher it.

CVE-2022-29054: A missing cryptographic steps vulnerability [CWE-325] in the functions that encrypt the DHCP and DNS keys in Fortinet FortiOS version 7.2.0, 7.0.0 through 7.0.5, 6.4.0 through 6.4.9, 6.2.x and 6.0.x may allow an attacker in possession of the encrypted key to decipher it.

CVE-2022-29229: CaSS is a Competency and Skills System. CaSS Library, (npm:cassproject) has a missing cryptographic step when storing cryptographic keys that can allow a server administrator access to an account’s cryptographic keys. This affects CaSS servers using standalone username/password authentication, which uses a method that expects e2e cryptographic security of authorization credentials. The issue has been patched in 1.5.8, however, the vulnerable accounts are only resecured when the user next logs in using standalone authentication, as the data required to resecure the account is not available to the server. The issue may be mitigated by using SSO or client side certificates to log in. Please note that SSO and client side certificate authentication does not have this expectation of no-knowledge credential access, and cryptographic keys are available to the server administrator.

CVE-2021-26099: Missing cryptographic steps in the Identity-Based Encryption service of FortiMail before 7.0.0 may allow an attacker who comes in possession of the encrypted master keys to compromise their confidentiality by observing a few invariant properties of the ciphertext.

CVE-2021-32591: A missing cryptographic steps vulnerability in the function that encrypts users' LDAP and RADIUS credentials in FortiSandbox before 4.0.1, FortiWeb before 6.3.12, FortiADC before 6.2.1, FortiMail 7.0.1 and earlier may allow an attacker in possession of the password store to compromise the confidentiality of the encrypted secrets.

CVE-2021-3798: A flaw was found in openCryptoki. The openCryptoki Soft token does not check if an EC key is valid when an EC key is created via C_CreateObject, nor when C_DeriveKey is used with ECDH public data. This may allow a malicious user to extract the private key by performing an invalid curve attack.

# CWE-326 Inadequate Encryption Strength

## Description

The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.

A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Observed Examples

CVE-2001-1546: Weak encryption

CVE-2004-2172: Weak encryption (chosen plaintext attack)

CVE-2002-1682: Weak encryption

CVE-2002-1697: Weak encryption produces same ciphertext from the same plaintext blocks.

CVE-2002-1739: Weak encryption

CVE-2005-2281: Weak encryption scheme

CVE-2002-1872: Weak encryption (XOR)

CVE-2002-1910: Weak encryption (reversible algorithm).

CVE-2002-1946: Weak encryption (one-to-one mapping).

CVE-2002-1975: Encryption error uses fixed salt, simplifying brute force / dictionary attacks (overlaps randomness).

## Top 25 Examples

CVE-2021-40341: DES cipher, which has inadequate encryption strength, is used Hitachi Energy FOXMAN-UN to encrypt user credentials used to access the Network Elements. Successful exploitation allows sensitive information to be decrypted easily. This issue affects * FOXMAN-UN product: FOXMAN-UN R16A, FOXMAN-UN R15B, FOXMAN-UN R15A, FOXMAN-UN R14B, FOXMAN-UN R14A, FOXMAN-UN R11B, FOXMAN-UN R11A, FOXMAN-UN R10C, FOXMAN-UN R9C; * UNEM product: UNEM R16A, UNEM R15B, UNEM R15A, UNEM R14B, UNEM R14A, UNEM R11B, UNEM R11A, UNEM R10C, UNEM R9C. List of CPEs: * cpe:2.3:a:hitachienergy:foxman-un:R16A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:foxman-un:R9C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R16A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R15A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R14A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11B:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R11A:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R10C:*:*:*:*:*:*:* * cpe:2.3:a:hitachienergy:unem:R9C:*:*:*:*:*:*:* 

CVE-2021-27761: Weak web transport security (Weak TLS): An attacker may be able to decrypt the data using attacks

CVE-2021-32010: Inadequate Encryption Strength vulnerability in TLS stack of Secomea SiteManager, LinkManager, GateManager may facilitate man in the middle attacks. This issue affects: Secomea SiteManager All versions prior to 9.7. Secomea LinkManager versions prior to 9.7. Secomea GateManager versions prior to 9.7.

CVE-2021-32945: An attacker could decipher the encryption and gain access to MDT AutoSave versions prior to v6.02.06.

CVE-2021-38947: IBM Spectrum Copy Data Management 2.2.13 and earlier uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 211242.

CVE-2022-21139: Inadequate encryption strength for some Intel(R) PROSet/Wireless WiFi products may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2022-22368: IBM Spectrum Scale 5.1.0 through 5.1.3.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 221012.

CVE-2022-22453: IBM Security Verify Identity Manager 10.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 224919.

CVE-2022-22464: IBM Security Access Manager Appliance 10.0.0.0, 10.0.1.0, 10.0.2.0, and 10.0.3.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 225081.

CVE-2022-24116: Certain General Electric Renewable Energy products have inadequate encryption strength. This affects iNET and iNET II before 8.3.0.

CVE-2022-24318: A CWE-326: Inadequate Encryption Strength vulnerability exists that could cause non-encrypted communication with the server when outdated versions of the ViewX client are used. Affected Product: ClearSCADA (All Versions), EcoStruxure Geo SCADA Expert 2019 (All Versions), EcoStruxure Geo SCADA Expert 2020 (All Versions)

CVE-2022-2640: The Config-files of Horner Automation’s RCC 972 with firmware version 15.40 are encrypted with weak XOR encryption vulnerable to reverse engineering. This could allow an attacker to obtain credentials to run services such as File Transfer Protocol (FTP) and Hypertext Transfer Protocol (HTTP).

CVE-2022-2758: Passwords are not adequately encrypted during the communication process between all versions of LS Industrial Systems (LSIS) Co. Ltd LS Electric XG5000 software prior to V4.0 and LS Electric PLCs: all versions of XGK-CPUU/H/A/S/E prior to V3.50, all versions of XGI-CPUU/UD/H/S/E prior to V3.20, all versions of XGR-CPUH prior to V1.80, all versions of XGB-XBMS prior to V3.00, all versions of XGB-XBCH prior to V1.90, and all versions of XGB-XECH prior to V1.30. This would allow an attacker to identify and decrypt the password of the affected PLCs by sniffing the PLC’s communication traffic.

CVE-2022-34385:  SupportAssist for Home PCs (version 3.11.4 and prior) and SupportAssist for Business PCs (version 3.2.0 and prior) contain cryptographic weakness vulnerability. An authenticated non-admin user could potentially exploit the issue and obtain sensitive information. 

CVE-2022-41209: SAP Customer Data Cloud (Gigya mobile app for Android) - version 7.4, uses encryption method which lacks proper diffusion and does not hide the patterns well. This can lead to information disclosure. In certain scenarios, application might also be susceptible to replay attacks. 

CVE-2021-27450: SSH server configuration file does not implement some best practices. This could lead to a weakening of the SSH protocol strength, which could lead to additional misconfiguration or be leveraged as part of a larger attack on the MU320E (all firmware versions prior to v04A00.1).

CVE-2021-37209: A vulnerability has been identified in RUGGEDCOM i800 (All versions < V4.3.8), RUGGEDCOM i801 (All versions < V4.3.8), RUGGEDCOM i802 (All versions < V4.3.8), RUGGEDCOM i803 (All versions < V4.3.8), RUGGEDCOM M2100 (All versions < V4.3.8), RUGGEDCOM M2200 (All versions < V4.3.8), RUGGEDCOM M969 (All versions < V4.3.8), RUGGEDCOM RMC30 (All versions < V4.3.8), RUGGEDCOM RMC8388 V4.X (All versions < V4.3.8), RUGGEDCOM RMC8388 V5.X (All versions < V5.7.0), RUGGEDCOM RP110 (All versions < V4.3.8), RUGGEDCOM RS1600 (All versions < V4.3.8), RUGGEDCOM RS1600F (All versions < V4.3.8), RUGGEDCOM RS1600T (All versions < V4.3.8), RUGGEDCOM RS400 (All versions < V4.3.8), RUGGEDCOM RS401 (All versions < V4.3.8), RUGGEDCOM RS416 (All versions < V4.3.8), RUGGEDCOM RS416P (All versions < V4.3.8), RUGGEDCOM RS416Pv2 V4.X (All versions < V4.3.8), RUGGEDCOM RS416Pv2 V5.X (All versions < V5.7.0), RUGGEDCOM RS416v2 V4.X (All versions < V4.3.8), RUGGEDCOM RS416v2 V5.X (All versions < V5.7.0), RUGGEDCOM RS8000 (All versions < V4.3.8), RUGGEDCOM RS8000A (All versions < V4.3.8), RUGGEDCOM RS8000H (All versions < V4.3.8), RUGGEDCOM RS8000T (All versions < V4.3.8), RUGGEDCOM RS900 (All versions < V4.3.8), RUGGEDCOM RS900 (32M) V4.X (All versions < V4.3.8), RUGGEDCOM RS900 (32M) V5.X (All versions < V5.7.0), RUGGEDCOM RS900G (All versions < V4.3.8), RUGGEDCOM RS900G (32M) V4.X (All versions < V4.3.8), RUGGEDCOM RS900G (32M) V5.X (All versions < V5.7.0), RUGGEDCOM RS900GP (All versions < V4.3.8), RUGGEDCOM RS900L (All versions < V4.3.8), RUGGEDCOM RS900M-GETS-C01 (All versions < V4.3.8), RUGGEDCOM RS900M-GETS-XX (All versions < V4.3.8), RUGGEDCOM RS900M-STND-C01 (All versions < V4.3.8), RUGGEDCOM RS900M-STND-XX (All versions < V4.3.8), RUGGEDCOM RS900W (All versions < V4.3.8), RUGGEDCOM RS910 (All versions < V4.3.8), RUGGEDCOM RS910L (All versions < V4.3.8), RUGGEDCOM RS910W (All versions < V4.3.8), RUGGEDCOM RS920L (All versions < V4.3.8), RUGGEDCOM RS920W (All versions < V4.3.8), RUGGEDCOM RS930L (All versions < V4.3.8), RUGGEDCOM RS930W (All versions < V4.3.8), RUGGEDCOM RS940G (All versions < V4.3.8), RUGGEDCOM RS969 (All versions < V4.3.8), RUGGEDCOM RSG2100 (All versions < V4.3.8), RUGGEDCOM RSG2100 (32M) V4.X (All versions < V4.3.8), RUGGEDCOM RSG2100 (32M) V5.X (All versions < V5.7.0), RUGGEDCOM RSG2100P (All versions < V4.3.8), RUGGEDCOM RSG2200 (All versions < V4.3.8), RUGGEDCOM RSG2288 V4.X (All versions < V4.3.8), RUGGEDCOM RSG2288 V5.X (All versions < V5.7.0), RUGGEDCOM RSG2300 V4.X (All versions < V4.3.8), RUGGEDCOM RSG2300 V5.X (All versions < V5.7.0), RUGGEDCOM RSG2300P V4.X (All versions < V4.3.8), RUGGEDCOM RSG2300P V5.X (All versions < V5.7.0), RUGGEDCOM RSG2488 V4.X (All versions < V4.3.8), RUGGEDCOM RSG2488 V5.X (All versions < V5.7.0), RUGGEDCOM RSG907R (All versions < V5.7.0), RUGGEDCOM RSG908C (All versions < V5.7.0), RUGGEDCOM RSG909R (All versions < V5.7.0), RUGGEDCOM RSG910C (All versions < V5.7.0), RUGGEDCOM RSG920P V4.X (All versions < V4.3.8), RUGGEDCOM RSG920P V5.X (All versions < V5.7.0), RUGGEDCOM RSL910 (All versions < V5.7.0), RUGGEDCOM RST2228 (All versions < V5.7.0), RUGGEDCOM RST2228P (All versions < V5.7.0), RUGGEDCOM RST916C (All versions < V5.7.0), RUGGEDCOM RST916P (All versions < V5.7.0). The SSH server on affected devices is configured to offer weak ciphers by default. This could allow an unauthorized attacker in a man-in-the-middle position to read and modify any data passed over the connection between legitimate clients and the affected device.

# CWE-327 Use of a Broken or Risky Cryptographic Algorithm

## Description

The product uses a broken or risky cryptographic algorithm or protocol.

Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors. Insecure cryptography can be exploited to expose sensitive information, modify data in unexpected ways, spoof identities of other users or devices, or other impacts.


It is very difficult to produce a secure algorithm, and even high-profile algorithms by accomplished cryptographic experts have been broken. Well-known techniques exist to break or weaken various kinds of cryptography. Accordingly, there are a small number of well-understood and heavily studied algorithms that should be used by most products. Using a non-standard or known-insecure algorithm is dangerous because a determined adversary may be able to break the algorithm and compromise whatever data has been protected.


Since the state of cryptography advances so rapidly, it is common for an algorithm to be considered "unsafe" even if it was once thought to be strong. This can happen when new attacks are discovered, or if computing power increases so much that the cryptographic algorithm no longer provides the amount of protection that was originally thought.


For a number of reasons, this weakness is even more challenging to manage with hardware deployment of cryptographic algorithms as opposed to software implementation. First, if a flaw is discovered with hardware-implemented cryptography, the flaw cannot be fixed in most cases without a recall of the product, because hardware is not easily replaceable like software. Second, because the hardware product is expected to work for years, the adversary's computing power will only increase over time.

## Observed Examples

CVE-2022-30273: SCADA-based protocol supports a legacy encryption mode that uses Tiny Encryption Algorithm (TEA) in ECB mode, which leaks patterns in messages and cannot protect integrity

CVE-2022-30320: Programmable Logic Controller (PLC) uses a protocol with a cryptographically insecure hashing algorithm for passwords.

CVE-2008-3775: Product uses "ROT-25" to obfuscate the password in the registry.

CVE-2007-4150: product only uses "XOR" to obfuscate sensitive data

CVE-2007-5460: product only uses "XOR" and a fixed key to obfuscate sensitive data

CVE-2005-4860: Product substitutes characters with other characters in a fixed way, and also leaves certain input characters unchanged.

CVE-2002-2058: Attackers can infer private IP addresses by dividing each octet by the MD5 hash of '20'.

CVE-2008-3188: Product uses DES when MD5 has been specified in the configuration, resulting in weaker-than-expected password hashes.

CVE-2005-2946: Default configuration of product uses MD5 instead of stronger algorithms that are available, simplifying forgery of certificates.

CVE-2007-6013: Product uses the hash of a hash for authentication, allowing attackers to gain privileges if they can obtain the original hash.

## Top 25 Examples

CVE-2021-31562: The SSL/TLS configuration of Fresenius Kabi Agilia Link + version 3.0 has serious deficiencies that may allow an attacker to compromise SSL/TLS sessions in different ways. An attacker may be able to eavesdrop on transferred data, manipulate data allegedly secured by SSL/TLS, and impersonate an entity to gain access to sensitive information.

CVE-2021-2351: Vulnerability in the Advanced Networking Option component of Oracle Database Server. Supported versions that are affected are 12.1.0.2, 12.2.0.1 and 19c. Difficult to exploit vulnerability allows unauthenticated attacker with network access via Oracle Net to compromise Advanced Networking Option. Successful attacks require human interaction from a person other than the attacker and while the vulnerability is in Advanced Networking Option, attacks may significantly impact additional products. Successful attacks of this vulnerability can result in takeover of Advanced Networking Option. Note: The July 2021 Critical Patch Update introduces a number of Native Network Encryption changes to deal with vulnerability CVE-2021-2351 and prevent the use of weaker ciphers. Customers should review: "Changes in Native Network Encryption with the July 2021 Critical Patch Update" (Doc ID 2791571.1). CVSS 3.1 Base Score 8.3 (Confidentiality, Integrity and Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).

CVE-2021-37588: In Charm 0.43, any two users can collude to achieve the ability to decrypt YCT14 data.

CVE-2021-43774: A risky-algorithm issue was discovered on Fujifilm DocuCentre-VI C4471 1.8 devices. An attacker that obtained access to the administrative web interface of a printer (e.g., by using the default credentials) can download the address book file, which contains the list of users (domain users, FTP users, etc.) stored on the printer, together with their encrypted passwords. The passwords are protected by a weak cipher, such as ROT13, which requires minimal effort to instantly retrieve the original password, giving the attacker a list of valid domain or FTP usernames and passwords.

CVE-2021-43989: mySCADA myPRO Versions 8.20.0 and prior stores passwords using MD5, which may allow an attacker to crack the previously retrieved password hashes.

CVE-2021-45512: Certain NETGEAR devices are affected by weak cryptography. This affects D7000v2 before 1.0.0.62, D8500 before 1.0.3.50, EX3700 before 1.0.0.84, EX3800 before 1.0.0.84, EX6120 before 1.0.0.54, EX6130 before 1.0.0.36, EX7000 before 1.0.1.90, R6250 before 1.0.4.42, R6400v2 before 1.0.4.98, R6700v3 before 1.0.4.98, R6900P before 1.3.2.124, R7000 before 1.0.11.106, R7000P before 1.3.2.124, R7100LG before 1.0.0.56, R7900 before 1.0.4.26, R8000 before 1.0.4.58, R8300 before 1.0.2.134, R8500 before 1.0.2.134, RS400 before 1.5.0.48, WNR3500Lv2 before 1.2.0.62, and XR300 before 1.0.3.50.

CVE-2021-45696: An issue was discovered in the sha2 crate 0.9.7 before 0.9.8 for Rust. Hashes of long messages may be incorrect when the AVX2-accelerated backend is used.

CVE-2022-0377: Users of the LearnPress WordPress plugin before 4.1.5 can upload an image as a profile avatar after the registration. After this process the user crops and saves the image. Then a "POST" request that contains user supplied name of the image is sent to the server for renaming and cropping of the image. As a result of this request, the name of the user-supplied image is changed with a MD5 value. This process can be conducted only when type of the image is JPG or PNG. An attacker can use this vulnerability in order to rename an arbitrary image file. By doing this, they could destroy the design of the web site.

CVE-2022-1252: Use of a Broken or Risky Cryptographic Algorithm in GitHub repository gnuboard/gnuboard5 prior to and including 5.5.5. A vulnerability in gnuboard v5.5.5 and below uses weak encryption algorithms leading to sensitive information exposure. This allows an attacker to derive the email address of any user, including when the 'Let others see my information.' box is ticked off. Or to send emails to any email address, with full control of its contents 

CVE-2022-1434: The OpenSSL 3.0 implementation of the RC4-MD5 ciphersuite incorrectly uses the AAD data as the MAC key. This makes the MAC key trivially predictable. An attacker could exploit this issue by performing a man-in-the-middle attack to modify data being sent from one endpoint to an OpenSSL 3.0 recipient such that the modified data would still pass the MAC integrity check. Note that data sent from an OpenSSL 3.0 endpoint to a non-OpenSSL 3.0 endpoint will always be rejected by the recipient and the connection will fail at that point. Many application protocols require data to be sent from the client to the server first. Therefore, in such a case, only an OpenSSL 3.0 server would be impacted when talking to a non-OpenSSL 3.0 client. If both endpoints are OpenSSL 3.0 then the attacker could modify data being sent in both directions. In this case both clients and servers could be affected, regardless of the application protocol. Note that in the absence of an attacker this bug means that an OpenSSL 3.0 endpoint communicating with a non-OpenSSL 3.0 endpoint will fail to complete the handshake when using this ciphersuite. The confidentiality of data is not impacted by this issue, i.e. an attacker cannot decrypt data that has been encrypted using this ciphersuite - they can only modify it. In order for this attack to work both endpoints must legitimately negotiate the RC4-MD5 ciphersuite. This ciphersuite is not compiled by default in OpenSSL 3.0, and is not available within the default provider or the default ciphersuite list. This ciphersuite will never be used if TLSv1.3 has been negotiated. In order for an OpenSSL 3.0 endpoint to use this ciphersuite the following must have occurred: 1) OpenSSL must have been compiled with the (non-default) compile time option enable-weak-ssl-ciphers 2) OpenSSL must have had the legacy provider explicitly loaded (either through application code or via configuration) 3) The ciphersuite must have been explicitly added to the ciphersuite list 4) The libssl security level must have been set to 0 (default is 1) 5) A version of SSL/TLS below TLSv1.3 must have been negotiated 6) Both endpoints must negotiate the RC4-MD5 ciphersuite in preference to any others that both endpoints have in common Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2).

CVE-2022-20805: A vulnerability in the automatic decryption process in Cisco Umbrella Secure Web Gateway (SWG) could allow an authenticated, adjacent attacker to bypass the SSL decryption and content filtering policies on an affected system. This vulnerability is due to how the decryption function uses the TLS Sever Name Indication (SNI) extension of an HTTP request to discover the destination domain and determine if the request needs to be decrypted. An attacker could exploit this vulnerability by sending a crafted request over TLS from a client to an unknown or controlled URL. A successful exploit could allow an attacker to bypass the decryption process of Cisco Umbrella SWG and allow malicious content to be downloaded to a host on a protected network. There are workarounds that address this vulnerability.

CVE-2022-2097: AES OCB mode for 32-bit x86 platforms using the AES-NI assembly optimised implementation will not encrypt the entirety of the data under some circumstances. This could reveal sixteen bytes of data that was preexisting in the memory that wasn't written. In the special case of "in place" encryption, sixteen bytes of the plaintext would be revealed. Since OpenSSL does not support OCB based cipher suites for TLS and DTLS, they are both unaffected. Fixed in OpenSSL 3.0.5 (Affected 3.0.0-3.0.4). Fixed in OpenSSL 1.1.1q (Affected 1.1.1-1.1.1p).

CVE-2022-2781: In affected versions of Octopus Server it was identified that the same encryption process was used for both encrypting session cookies and variables.

CVE-2022-28164: Brocade SANnav before SANnav 2.2.0 application uses the Blowfish symmetric encryption algorithm for the storage of passwords. This could allow an authenticated attacker to decrypt stored account passwords.

CVE-2022-28382: An issue was discovered in certain Verbatim drives through 2022-03-31. Due to the use of an insecure encryption AES mode (Electronic Codebook, aka ECB), an attacker may be able to extract information even from encrypted data, for example by observing repeating byte patterns. The firmware of the USB-to-SATA bridge controller INIC-3637EN uses AES-256 with the ECB mode. This operation mode of block ciphers (e.g., AES) always encrypts identical plaintext data, in this case blocks of 16 bytes, to identical ciphertext data. For some data, for instance bitmap images, the lack of the cryptographic property called diffusion, within ECB, can leak sensitive information even in encrypted data. Thus, the use of the ECB operation mode can put the confidentiality of specific information at risk, even in an encrypted form. This affects Keypad Secure USB 3.2 Gen 1 Drive Part Number #49428, Store 'n' Go Secure Portable HDD GD25LK01-3637-C VER4.0, Executive Fingerprint Secure SSD GDMSFE01-INI3637-C VER1.1, and Fingerprint Secure Portable Hard Drive Part Number #53650.

CVE-2022-29960: Emerson OpenBSI through 2022-04-29 uses weak cryptography. It is an engineering environment for the ControlWave and Bristol Babcock line of RTUs. DES with hardcoded cryptographic keys is used for protection of certain system credentials, engineering files, and sensitive utilities.

CVE-2022-30320: Saia Burgess Controls (SBC) PCD through 2022-05-06 uses a Broken or Risky Cryptographic Algorithm. According to FSCT-2022-0063, there is a Saia Burgess Controls (SBC) PCD S-Bus weak credential hashing scheme issue. The affected components are characterized as: S-Bus (5050/UDP) authentication. The potential impact is: Authentication bypass. The Saia Burgess Controls (SBC) PCD controllers utilize the S-Bus protocol (5050/UDP) for a variety of engineering purposes. It is possible to configure a password in order to restrict access to sensitive engineering functionality. Authentication is done by using the S-Bus 'write byte' message to a specific address and supplying a hashed version of the password. The hashing algorithm used is based on CRC-16 and as such not cryptographically secure. An insecure hashing algorithm is used. An attacker capable of passively observing traffic can intercept the hashed credentials and trivially find collisions allowing for authentication without having to bruteforce a keyspace defined by the actual strength of the password. This allows the attacker access to sensitive engineering functionality such as uploading/downloading control logic and manipulating controller configuration.

CVE-2022-35513: The Blink1Control2 application <= 2.2.7 uses weak password encryption and an insecure method of storage.

CVE-2022-38493: Rhonabwy 0.9.99 through 1.1.x before 1.1.7 doesn't check the RSA private key length before RSA-OAEP decryption. This allows attackers to cause a Denial of Service via a crafted JWE (JSON Web Encryption) token.

CVE-2022-39237: syslabs/sif is the Singularity Image Format (SIF) reference implementation. In versions prior to 2.8.1the `github.com/sylabs/sif/v2/pkg/integrity` package did not verify that the hash algorithm(s) used are cryptographically secure when verifying digital signatures. A patch is available in version >= v2.8.1 of the module. Users are encouraged to upgrade. Users unable to upgrade may independently validate that the hash algorithm(s) used for metadata digest(s) and signature hash are cryptographically secure.

CVE-2022-28166: In Brocade SANnav version before SANN2.2.0.2 and Brocade SANNav before 2.1.1.8, the implementation of TLS/SSL Server Supports the Use of Static Key Ciphers (ssl-static-key-ciphers) on ports 443 & 18082.

CVE-2022-30187: Azure Storage Library Information Disclosure Vulnerability

CVE-2021-23839: OpenSSL 1.0.2 supports SSLv2. If a client attempts to negotiate SSLv2 with a server that is configured to support both SSLv2 and more recent SSL and TLS versions then a check is made for a version rollback attack when unpadding an RSA signature. Clients that support SSL or TLS versions greater than SSLv2 are supposed to use a special form of padding. A server that supports greater than SSLv2 is supposed to reject connection attempts from a client where this special form of padding is present, because this indicates that a version rollback has occurred (i.e. both client and server support greater than SSLv2, and yet this is the version that is being requested). The implementation of this padding check inverted the logic so that the connection attempt is accepted if the padding is present, and rejected if it is absent. This means that such as server will accept a connection if a version rollback attack has occurred. Further the server will erroneously reject a connection if a normal SSLv2 connection attempt is made. Only OpenSSL 1.0.2 servers from version 1.0.2s to 1.0.2x are affected by this issue. In order to be vulnerable a 1.0.2 server must: 1) have configured SSLv2 support at compile time (this is off by default), 2) have configured SSLv2 support at runtime (this is off by default), 3) have configured SSLv2 ciphersuites (these are not in the default ciphersuite list) OpenSSL 1.1.1 does not have SSLv2 support and therefore is not vulnerable to this issue. The underlying error is in the implementation of the RSA_padding_check_SSLv23() function. This also affects the RSA_SSLV23_PADDING padding mode used by various other functions. Although 1.1.1 does not support SSLv2 the RSA_padding_check_SSLv23() function still exists, as does the RSA_SSLV23_PADDING padding mode. Applications that directly call that function or use that padding mode will encounter this issue. However since there is no support for the SSLv2 protocol in 1.1.1 this is considered a bug and not a security issue in that version. OpenSSL 1.0.2 is out of support and no longer receiving public updates. Premium support customers of OpenSSL 1.0.2 should upgrade to 1.0.2y. Other users should upgrade to 1.1.1j. Fixed in OpenSSL 1.0.2y (Affected 1.0.2s-1.0.2x).

CVE-2021-20379: IBM Guardium Data Encryption (GDE) 3.0.0.3 and 4.0.0.4 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 195711.

CVE-2021-20406: IBM Security Verify Information Queue 1.0.6 and 1.0.7 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 196184. 

CVE-2021-20419: IBM Security Guardium 11.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 196280.

CVE-2021-20441: IBM Security Verify Bridge uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 196617.

CVE-2021-20479: IBM Cloud Pak System 2.3.0 through 2.3.3.3 Interim Fix 1 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 197498.

CVE-2021-20497: IBM Security Verify Access Docker 10.0.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 197969

CVE-2021-20566: IBM Resilient SOAR V38.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 199238.

CVE-2021-22212: ntpkeygen can generate keys that ntpd fails to parse. NTPsec 1.2.0 allows ntpkeygen to generate keys with '#' characters. ntpd then either pads, shortens the key, or fails to load these keys entirely, depending on the key type and the placement of the '#'. This results in the administrator not being able to use the keys as expected or the keys are shorter than expected and easier to brute-force, possibly resulting in MITM attacks between ntp clients and ntp servers. For short AES128 keys, ntpd generates a warning that it is padding them.

CVE-2021-22356: There is a weak secure algorithm vulnerability in Huawei products. A weak secure algorithm is used in a module. Attackers can exploit this vulnerability by capturing and analyzing the messages between devices to obtain information. This can lead to information leak.Affected product versions include: IPS Module V500R005C00SPC100, V500R005C00SPC200; NGFW Module V500R005C00SPC100, V500R005C00SPC200; Secospace USG6300 V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C00SPC100, V500R005C00SPC200; Secospace USG6500 V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C00SPC100, V500R005C00SPC200; Secospace USG6600 V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C00SPC100, V500R005C00SPC200; USG9500 V500R001C30SPC200, V500R001C30SPC600, V500R001C60SPC500, V500R005C00SPC100, V500R005C00SPC200.

CVE-2021-22738: Use of a Broken or Risky Cryptographic Algorithm vulnerability exists in homeLYnk (Wiser For KNX) and spaceLYnk V2.60 and prior that could cause unauthorized access when credentials are discovered after a brute force attack.

CVE-2021-25763: In JetBrains Ktor before 1.4.2, weak cipher suites were enabled by default.

CVE-2021-27756: "TLS-RSA cipher suites are not disabled in BigFix Compliance up to v2.0.5. If TLS 2.0 and secure ciphers are not enabled then an attacker can passively record traffic and later decrypt it."

CVE-2021-29704: IBM Security SOAR uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information.

CVE-2021-29722: IBM Sterling Secure Proxy 6.0.1, 6.0.2, 2.4.3.2, and 3.4.3.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 201095.

CVE-2021-29723: IBM Sterling Secure Proxy 6.0.1, 6.0.2, 2.4.3.2, and 3.4.3.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-ForceID: 201100.

CVE-2021-29750: IBM QRadar SIEM 7.3 and 7.4 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 201778.

CVE-2021-29894: IBM Cloud Pak for Security (CP4S) 1.7.0.0, 1.7.1.0, 1.7.2.0, and 1.8.0.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 207320.

CVE-2021-32593: A use of a broken or risky cryptographic algorithm vulnerability [CWE-327] in the Dynamic Tunnel Protocol of FortiWAN before 4.5.9 may allow an unauthenticated remote attacker to decrypt and forge protocol communication messages.

CVE-2021-33018: The use of a broken or risky cryptographic algorithm in Philips Vue PACS versions 12.2.x.x and prior is an unnecessary risk that may result in the exposure of sensitive information.

CVE-2021-33846: Fresenius Kabi Vigilant Software Suite (Mastermed Dashboard) version 2.0.1.3 issues authentication tokens to authenticated users that are signed with a symmetric encryption key. An attacker in possession of the key can issue valid JWTs and impersonate arbitrary users.

CVE-2021-36647: Use of a Broken or Risky Cryptographic Algorithm in the function mbedtls_mpi_exp_mod() in lignum.c in Mbed TLS Mbed TLS all versions before 3.0.0, 2.27.0 or 2.16.11 allows attackers with access to precise enough timing and memory access information (typically an untrusted operating system attacking a secure enclave such as SGX or the TrustZone secure world) to recover the private keys used in RSA.

CVE-2021-38921: IBM Security Verify 10.0.0, 10.0.1.0, and 10.0.2.0 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 210067.

CVE-2021-39002: IBM DB2 for Linux, UNIX and Windows (includes DB2 Connect Server) 9.7, 10.1, 10.5, 11.1, and 11.5 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information.

CVE-2021-39058: IBM Spectrum Copy Data Management 2.2.13 and earlier uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 214617.

CVE-2021-39076: IBM Security Guardium 10.5 and 11.3 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt sensitive information. IBM X-Force ID: 215585.

CVE-2021-39082: IBM UrbanCode Deploy (UCD) 7.1.1.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information.

CVE-2021-41096: Rucky is a USB HID Rubber Ducky Launch Pad for Android. Versions 2.2 and earlier for release builds and versions 425 and earlier for nightly builds suffer from use of a weak cryptographic algorithm (RSA/ECB/PKCS1Padding). The issue will be patched in v2.3 for release builds and 426 onwards for nightly builds. As a workaround, one may disable an advance security feature if not required.

CVE-2021-41278: Functions SDK for EdgeX is meant to provide all the plumbing necessary for developers to get started in processing/transforming/exporting data out of the EdgeX IoT platform. In affected versions broken encryption in app-functions-sdk “AES” transform in EdgeX Foundry releases prior to Jakarta allows attackers to decrypt messages via unspecified vectors. The app-functions-sdk exports an “aes” transform that user scripts can optionally call to encrypt data in the processing pipeline. No decrypt function is provided. Encryption is not enabled by default, but if used, the level of protection may be less than the user may expects due to a broken implementation. Version v2.1.0 (EdgeX Foundry Jakarta release and later) of app-functions-sdk-go/v2 deprecates the “aes” transform and provides an improved “aes256” transform in its place. The broken implementation will remain in a deprecated state until it is removed in the next EdgeX major release to avoid breakage of existing software that depends on the broken implementation. As the broken transform is a library function that is not invoked by default, users who do not use the AES transform in their processing pipelines are unaffected. Those that are affected are urged to upgrade to the Jakarta EdgeX release and modify processing pipelines to use the new "aes256" transform.

CVE-2021-42583: A Broken or Risky Cryptographic Algorithm exists in Max Mazurov Maddy before 0.5.2, which is an unnecessary risk that may result in the exposure of sensitive information.

CVE-2021-43550: The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information, which affects the communications between Patient Information Center iX (PIC iX) Versions C.02 and C.03 and Efficia CM Series Revisions A.01 to C.0x and 4.0.

CVE-2022-20117: In (TBD) of (TBD), there is a possible way to decrypt local data encrypted by the GSC due to improperly used crypto. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-217475903References: N/A

CVE-2022-22327: IBM UrbanCode Deploy (UCD) 7.0.5, 7.1.0, 7.1.1, and 7.1.2 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 218859.

CVE-2022-22461:  IBM Security Verify Governance, Identity Manager 10.0.1 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 225007. 

CVE-2022-22462:  IBM Security Verify Governance, Identity Manager virtual appliance component 10.0.1 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 225078. 

CVE-2022-22559: Dell PowerScale OneFS, version 9.3.0, contains a use of a broken or risky cryptographic algorithm. An unprivileged network attacker could exploit this vulnerability, leading to the potential for information disclosure.

CVE-2022-22564: Dell EMC Unity versions before 5.2.0.0.5.173 , use(es) broken cryptographic algorithm. A remote unauthenticated attacker could potentially exploit this vulnerability by performing MitM attacks and let attackers obtain sensitive information. 

CVE-2022-24296: Use of a Broken or Risky Cryptographic Algorithm vulnerability in Air Conditioning System G-150AD Ver. 3.21 and prior, Air Conditioning System AG-150A-A Ver. 3.21 and prior, Air Conditioning System AG-150A-J Ver. 3.21 and prior, Air Conditioning System GB-50AD Ver. 3.21 and prior, Air Conditioning System GB-50ADA-A Ver. 3.21 and prior, Air Conditioning System GB-50ADA-J Ver. 3.21 and prior, Air Conditioning System EB-50GU-A Ver. 7.10 and prior, Air Conditioning System EB-50GU-J Ver. 7.10 and prior, Air Conditioning System AE-200J Ver. 7.97 and prior, Air Conditioning System AE-200A Ver. 7.97 and prior, Air Conditioning System AE-200E Ver. 7.97 and prior, Air Conditioning System AE-50J Ver. 7.97 and prior, Air Conditioning System AE-50A Ver. 7.97 and prior, Air Conditioning System AE-50E Ver. 7.97 and prior, Air Conditioning System EW-50J Ver. 7.97 and prior, Air Conditioning System EW-50A Ver. 7.97 and prior, Air Conditioning System EW-50E Ver. 7.97 and prior, Air Conditioning System TE-200A Ver. 7.97 and prior, Air Conditioning System TE-50A Ver. 7.97 and prior and Air Conditioning System TW-50A Ver. 7.97 and prior allows a remote unauthenticated attacker to cause a disclosure of encrypted message of the air conditioning systems by sniffing encrypted communications.

CVE-2022-26854: Dell PowerScale OneFS, versions 8.2.x-9.2.x, contain risky cryptographic algorithms. A remote unprivileged malicious attacker could potentially exploit this vulnerability, leading to full system access

CVE-2022-27581: Use of a Broken or Risky Cryptographic Algorithm in SICK RFU61x firmware version <v2.25 allows a low-privileged remote attacker to decrypt the encrypted data if the user requested weak cipher suites to be used for encryption via the SSH interface. The patch and installation procedure for the firmware update is available from the responsible SICK customer contact person.

CVE-2022-28622: A potential security vulnerability has been identified in HPE StoreOnce Software. The SSH server supports weak key exchange algorithms which could lead to remote unauthorized access. HPE has made the following software update to resolve the vulnerability in HPE StoreOnce Software 4.3.2.

CVE-2022-29217: PyJWT is a Python implementation of RFC 7519. PyJWT supports multiple different JWT signing algorithms. With JWT, an attacker submitting the JWT token can choose the used signing algorithm. The PyJWT library requires that the application chooses what algorithms are supported. The application can specify `jwt.algorithms.get_default_algorithms()` to get support for all algorithms, or specify a single algorithm. The issue is not that big as `algorithms=jwt.algorithms.get_default_algorithms()` has to be used. Users should upgrade to v2.4.0 to receive a patch for this issue. As a workaround, always be explicit with the algorithms that are accepted and expected when decoding.

CVE-2022-29249: JavaEZ is a library that adds new functions to make Java easier. A weakness in JavaEZ 1.6 allows force decryption of locked text by unauthorized actors. The issue is NOT critical for non-secure applications, however may be critical in a situation where the highest levels of security are required. This issue ONLY affects v1.6 and does not affect anything pre-1.6. The vulnerability has been patched in release 1.7. Currently, there is no way to fix the issue without upgrading.

CVE-2022-30111: Due to the use of an insecure algorithm for rolling codes in MCK Smartlock 1.0, allows attackers to unlock the mechanism via replay attacks.

CVE-2022-30273: The Motorola MDLC protocol through 2022-05-02 mishandles message integrity. It supports three security modes: Plain, Legacy Encryption, and New Encryption. In Legacy Encryption mode, traffic is encrypted via the Tiny Encryption Algorithm (TEA) block-cipher in ECB mode. This mode of operation does not offer message integrity and offers reduced confidentiality above the block level, as demonstrated by an ECB Penguin attack against any block ciphers.

CVE-2022-31230: Dell PowerScale OneFS, versions 8.2.x-9.2.x, contain broken or risky cryptographic algorithm. A remote unprivileged malicious attacker could potentially exploit this vulnerability, leading to full system access.

CVE-2022-34319: IBM CICS TX 11.7 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 229463.

CVE-2022-34320:  IBM CICS TX 11.1 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 229464. 

CVE-2022-34361:  IBM Sterling Secure Proxy 6.0.3 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 230522. 

CVE-2022-34444:  Dell PowerScale OneFS, versions 9.2.0.x through 9.4.0.x contain an information vulnerability. A remote unauthenticated attacker may potentially exploit this vulnerability to cause data leak. 

CVE-2022-34632: Rocket-Chip commit 4f8114374d8824dfdec03f576a8cd68bebce4e56 was discovered to contain insufficient cryptography via the component /rocket/RocketCore.scala.

CVE-2022-34757: A CWE-327: Use of a Broken or Risky Cryptographic Algorithm vulnerability exists where weak cipher suites can be used for the SSH connection between Easergy Pro software and the device, which may allow an attacker to observe protected communication details. Affected Products: Easergy P5 (V01.401.102 and prior)

CVE-2022-35720: IBM Sterling External Authentication Server 6.1.0 and IBM Sterling Secure Proxy 6.0.3 uses weaker than expected cryptographic algorithms during installation that could allow a local attacker to decrypt sensitive information. IBM X-Force ID: 231373.

CVE-2022-38391:  IBM Spectrum Control 5.4 uses weaker than expected cryptographic algorithms that could allow an attacker to decrypt highly sensitive information. IBM X-Force ID: 233982. 

CVE-2022-4610: A vulnerability, which was classified as problematic, has been found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome. Affected by this issue is some unknown functionality. The manipulation leads to risky cryptographic algorithm. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-216272.

CVE-2022-46140: Affected devices use a weak encryption scheme to encrypt the debug zip file. This could allow an authenticated attacker to decrypt the contents of the file and retrieve debug information about the system.

CVE-2022-46832: Use of a Broken or Risky Cryptographic Algorithm in SICK RFU62x firmware version < 2.21 allows a low-privileged remote attacker to decrypt the encrypted data if the user requested weak cipher suites to be used for encryption via the SSH interface. The patch and installation procedure for the firmware update is available from the responsible SICK customer contact person.

CVE-2022-46833: Use of a Broken or Risky Cryptographic Algorithm in SICK RFU63x firmware version < v2.21 allows a low-privileged remote attacker to decrypt the encrypted data if the user requested weak cipher suites to be used for encryption via the SSH interface. The patch and installation procedure for the firmware update is available from the responsible SICK customer contact person.

CVE-2022-46834: Use of a Broken or Risky Cryptographic Algorithm in SICK RFU65x firmware version < v2.21 allows a low-privileged remote attacker to decrypt the encrypted data if the user requested weak cipher suites to be used for encryption via the SSH interface. The patch and installation procedure for the firmware update is available from the responsible SICK customer contact person.

# CWE-328 Use of Weak Hash

## Description

The product uses an algorithm that produces a digest (output value) that does not meet security expectations for a hash function that allows an adversary to reasonably determine the original input (preimage attack), find another input that can produce the same hash (2nd preimage attack), or find multiple inputs that evaluate to the same hash (birthday attack).

A hash function is defined as an algorithm that maps arbitrarily sized data into a fixed-sized digest (output) such that the following properties hold:


  1. The algorithm is not invertible (also called "one-way" or "not reversible")

  1. The algorithm is deterministic; the same input produces the same digest every time

 Building on this definition, a cryptographic hash function must also ensure that a malicious actor cannot leverage the hash function to have a reasonable chance of success at determining any of the following:

  1. the original input (preimage attack), given only the digest

  1. another input that can produce the same digest (2nd preimage attack), given the original input

  1. a set of two or more inputs that evaluate to the same digest (birthday attack), given the actor can arbitrarily choose the inputs to be hashed and can do so a reasonable amount of times

What is regarded as "reasonable" varies by context and threat model, but in general, "reasonable" could cover any attack that is more efficient than brute force (i.e., on average, attempting half of all possible combinations). Note that some attacks might be more efficient than brute force but are still not regarded as achievable in the real world.

Any algorithm that does not meet the above conditions will generally be considered weak for general use in hashing.


In addition to algorithmic weaknesses, a hash function can be made weak by using the hash in a security context that breaks its security guarantees. For example, using a hash function without a salt for storing passwords (that are sufficiently short) could enable an adversary to create a "rainbow table" [REF-637] to recover the password under certain conditions; this attack works against such hash functions as MD5, SHA-1, and SHA-2.

## Observed Examples

CVE-2022-30320: Programmable Logic Controller (PLC) uses a protocol with a cryptographically insecure hashing algorithm for passwords.

CVE-2005-4900: SHA-1 algorithm is not collision-resistant.

CVE-2020-25685: DNS product uses a weak hash (CRC32 or SHA-1) of the query name, allowing attacker to forge responses by computing domain names with the same hash.

CVE-2012-6707: blogging product uses MD5-based algorithm for passwords.

CVE-2019-14855: forging of certificate signatures using SHA-1 collisions.

CVE-2017-15999: mobile app for backup sends SHA-1 hash of password in cleartext.

CVE-2006-4068: Hard-coded hashed values for username and password contained in client-side script, allowing brute-force offline attacks.

## Top 25 Examples

CVE-2022-3433: The aeson library is not safe to use to consume untrusted JSON input. A remote user could abuse this flaw to produce a hash collision in the underlying unordered-containers library by sending specially crafted JSON data, resulting in a denial of service.

CVE-2022-21653: Jawn is an open source JSON parser. Extenders of the `org.typelevel.jawn.SimpleFacade` and `org.typelevel.jawn.MutableFacade` who don't override `objectContext()` are vulnerable to a hash collision attack which may result in a denial of service. Most applications do not implement these traits directly, but inherit from a library. `jawn-parser-1.3.1` fixes this issue and users are advised to upgrade. For users unable to upgrade override `objectContext()` to use a collision-safe collection.

CVE-2022-22321: IBM MQ Appliance 9.2 CD and 9.2 LTS local messaging users stored with a password hash that provides insufficient protection. IBM X-Force ID: 218368.

CVE-2022-25156: Use of Weak Hash vulnerability in Mitsubishi Electric MELSEC iQ-F series FX5U(C) CPU all versions, Mitsubishi Electric MELSEC iQ-F series FX5UJ CPU all versions, Mitsubishi Electric MELSEC iQ-R series R00/01/02CPU all versions, Mitsubishi Electric MELSEC iQ-R series R04/08/16/32/120(EN)CPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120SFCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PCPU all versions, Mitsubishi Electric MELSEC iQ-R series R08/16/32/120PSFCPU all versions, Mitsubishi Electric MELSEC iQ-R series RJ71C24(-R2/R4) all versions, Mitsubishi Electric MELSEC iQ-R series RJ71EN71 all versions, Mitsubishi Electric MELSEC iQ-R series RJ72GF15-T2 all versions, Mitsubishi Electric MELSEC Q series Q03UDECPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/10/13/20/26/50/100UDEHCPU all versions, Mitsubishi Electric MELSEC Q series Q03/04/06/13/26UDVCPU all versions, Mitsubishi Electric MELSEC Q series Q04/06/13/26UDPVCPU all versions, Mitsubishi Electric MELSEC Q series QJ71C24N(-R2/R4) all versions, Mitsubishi Electric MELSEC Q series QJ71E71-100 all versions, Mitsubishi Electric MELSEC Q series QJ72BR15 all versions, Mitsubishi Electric MELSEC Q series QJ72LP25(-25/G/GE) all versions, Mitsubishi Electric MELSEC L series L02/06/26CPU(-P) all versions, Mitsubishi Electric MELSEC L series L26CPU-(P)BT all versions, Mitsubishi Electric MELSEC L series LJ71C24(-R2) all versions, Mitsubishi Electric MELSEC L series LJ71E71-100 all versions and Mitsubishi Electric MELSEC L series LJ72GF15-T2 all versions allows a remote unauthenticated attacker to login to the product by using a password reversed from a previously eavesdropped password hash.

CVE-2022-30285: In Quest KACE Systems Management Appliance (SMA) through 12.0, a hash collision is possible during authentication. This may allow authentication with invalid credentials.

CVE-2022-31459: Owl Labs Meeting Owl 5.2.0.15 allows attackers to retrieve the passcode hash via a certain c 10 value over Bluetooth.

CVE-2022-36555: Hytec Inter HWL-2511-SS v1.05 and below implements a SHA512crypt hash for the root account which can be easily cracked via a brute-force attack.

CVE-2022-4036: The Appointment Hour Booking plugin for WordPress is vulnerable to CAPTCHA bypass in versions up to, and including, 1.3.72. This is due to the use of insufficiently strong hashing algorithm on the CAPTCHA secret that is also displayed to the user via a cookie.

CVE-2022-43922: IBM App Connect Enterprise Certified Container 4.1, 4.2, 5.0, 5.1, 5.2, 6.0, 6.1, and 6.2 could disclose sensitive information to an attacker due to a weak hash of an API Key in the configuration. IBM X-Force ID: 241583.

CVE-2022-45379: Jenkins Script Security Plugin 1189.vb_a_b_7c8fd5fde and earlier stores whole-script approvals as the SHA-1 hash of the script, making it vulnerable to collision attacks.

CVE-2021-25761: In JetBrains Ktor before 1.5.0, a birthday attack on SessionStorage key was possible.

CVE-2021-37606: Meow hash 0.5/calico does not sufficiently thwart key recovery by an attacker who can query whether there's a collision in the bottom bits of the hashes of two messages, as demonstrated by an attack against a long-running web service that allows the attacker to infer collisions by measuring timing differences.

CVE-2021-39182: EnroCrypt is a Python module for encryption and hashing. Prior to version 1.1.4, EnroCrypt used the MD5 hashing algorithm in the hashing file. Beginners who are unfamiliar with hashes can face problems as MD5 is considered an insecure hashing algorithm. The vulnerability is patched in v1.1.4 of the product. As a workaround, users can remove the `MD5` hashing function from the file `hashing.py`.

CVE-2021-42216: A Broken or Risky Cryptographic Algorithm exists in AnonAddy 0.8.5 via VerificationController.php.

CVE-2021-44150: The client in tusdotnet through 2.5.0 relies on SHA-1 to prevent spoofing of file content.

CVE-2022-21800: MMP: All versions prior to v1.0.3, PTP C-series: Device versions prior to v2.8.6.1, and PTMP C-series and A5x: Device versions prior to v2.5.4.1 uses the MD5 algorithm to hash the passwords before storing them but does not salt the hash. As a result, attackers may be able to crack the hashed passwords.

CVE-2022-29161: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. The XWiki Crypto API will generate X509 certificates signed by default using SHA1 with RSA, which is not considered safe anymore for use in certificate signatures, due to the risk of collisions with SHA1. The problem has been patched in XWiki version 13.10.6, 14.3.1 and 14.4-rc-1. Since then, the Crypto API will generate X509 certificates signed by default using SHA256 with RSA. Administrators are advised to upgrade their XWiki installation to one of the patched versions. If the upgrade is not possible, it is possible to patch the module xwiki-platform-crypto in a local installation by applying the change exposed in 26728f3 and re-compiling the module.

CVE-2022-29566: The Bulletproofs 2017/1066 paper mishandles Fiat-Shamir generation because the hash computation fails to include all of the public values from the Zero Knowledge proof statement as well as all of the public values computed in the proof, aka the Frozen Heart issue.

CVE-2022-29835: WD Discovery software executable files were signed with an unsafe SHA-1 hashing algorithm. An attacker could use this weakness to create forged certificate signatures due to the use of a hashing algorithm that is not collision-free. This could thereby impact the confidentiality of user content. This issue affects: Western Digital WD Discovery WD Discovery Desktop App versions prior to 4.4.396 on Mac; WD Discovery Desktop App versions prior to 4.4.396 on Windows.

CVE-2022-45141: Since the Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability was disclosed by Microsoft on Nov 8 2022 and per RFC8429 it is assumed that rc4-hmac is weak, Vulnerable Samba Active Directory DCs will issue rc4-hmac encrypted tickets despite the target server supporting better encryption (eg aes256-cts-hmac-sha1-96).

CVE-2022-47931: IO FinNet tss-lib before 2.0.0 allows a collision of hash values.

# CWE-329 Generation of Predictable IV with CBC Mode

## Description

The product generates and uses a predictable initialization Vector (IV) with Cipher Block Chaining (CBC) Mode, which causes algorithms to be susceptible to dictionary attacks when they are encrypted under the same key.

CBC mode eliminates a weakness of Electronic Code Book (ECB) mode by allowing identical plaintext blocks to be encrypted to different ciphertext blocks. This is possible by the XOR-ing of an IV with the initial plaintext block so that every plaintext block in the chain is XOR'd with a different value before encryption. If IVs are reused, then identical plaintexts would be encrypted to identical ciphertexts. However, even if IVs are not identical but are predictable, then they still break the security of CBC mode against Chosen Plaintext Attacks (CPA).



CBC mode is a commonly used mode of operation for a block cipher. It works by XOR-ing an IV with the initial block of a plaintext prior to encryption and then XOR-ing each successive block of plaintext with the previous block of ciphertext before encryption.

```
	 C_0 = IV
	 C_i = E_k{M_i XOR C_{i-1}} 
```
 When used properly, CBC mode provides security against chosen plaintext attacks. Having an unpredictable IV is a crucial underpinning of this. See [REF-1171].

## Observed Examples

CVE-2020-5408: encryption functionality in an authentication framework uses a fixed null IV with CBC mode, allowing attackers to decrypt traffic in applications that use this functionality

CVE-2017-17704: messages for a door-unlocking product use a fixed IV in CBC mode, which is the same after each restart

CVE-2017-11133: application uses AES in CBC mode, but the pseudo-random secret and IV are generated using math.random, which is not cryptographically strong.

CVE-2007-3528: Blowfish-CBC implementation constructs an IV where each byte is calculated modulo 8 instead of modulo 256, resulting in less than 12 bits for the effective IV length, and less than 4096 possible IV values.

CVE-2011-3389: BEAST attack in SSL 3.0 / TLS 1.0. In CBC mode, chained initialization vectors are non-random, allowing decryption of HTTPS traffic using a chosen plaintext attack.

# CWE-33 Path Traversal: '....' (Multiple Dot)

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '....' (multiple dot) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The '....' manipulation is useful for bypassing some path traversal protection schemes. On some Windows systems, it is equivalent to "..\..\.." and might bypass checks that assume only two dots are valid. Incomplete filtering, such as removal of "./" sequences, can ultimately produce valid ".." sequences due to a collapse into unsafe value (CWE-182).

## Observed Examples

CVE-2000-0240: read files via "/........../" in URL

CVE-2000-0773: read files via "...." in web server

CVE-1999-1082: read files via "......" in web server (doubled triple dot?)

CVE-2004-2121: read files via "......" in web server (doubled triple dot?)

CVE-2001-0491: multiple attacks using "..", "...", and "...." in different commands

CVE-2001-0615: "..." or "...." in chat server

# CWE-330 Use of Insufficiently Random Values

## Description

The product uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.

When product generates predictable values in a context requiring unpredictability, it may be possible for an attacker to guess the next value that will be generated, and use this guess to impersonate another user or access sensitive information.

Computers are deterministic machines, and as such are unable to produce true randomness. Pseudo-Random Number Generators (PRNGs) approximate randomness algorithmically, starting with a seed from which subsequent values are calculated. There are two types of PRNGs: statistical and cryptographic. Statistical PRNGs provide useful statistical properties, but their output is highly predictable and forms an easy to reproduce numeric stream that is unsuitable for use in cases where security depends on generated values being unpredictable. Cryptographic PRNGs address this problem by generating output that is more difficult to predict. For a value to be cryptographically secure, it must be impossible or highly improbable for an attacker to distinguish between it and a truly random value.

## Observed Examples

CVE-2021-3692: PHP framework uses mt_rand() function (Marsenne Twister) when generating tokens

CVE-2020-7010: Cloud application on Kubernetes generates passwords using a weak random number generator based on deployment time.

CVE-2009-3278: Crypto product uses rand() library function to generate a recovery key, making it easier to conduct brute force attacks.

CVE-2009-3238: Random number generator can repeatedly generate the same value.

CVE-2009-2367: Web application generates predictable session IDs, allowing session hijacking.

CVE-2009-2158: Password recovery utility generates a relatively small number of random passwords, simplifying brute force attacks.

CVE-2009-0255: Cryptographic key created with a seed based on the system time.

CVE-2008-5162: Kernel function does not have a good entropy source just after boot.

CVE-2008-4905: Blogging software uses a hard-coded salt when calculating a password hash.

CVE-2008-4929: Bulletin board application uses insufficiently random names for uploaded files, allowing other users to access private files.

CVE-2008-3612: Handheld device uses predictable TCP sequence numbers, allowing spoofing or hijacking of TCP connections.

CVE-2008-2433: Web management console generates session IDs based on the login time, making it easier to conduct session hijacking.

CVE-2008-0166: SSL library uses a weak random number generator that only generates 65,536 unique keys.

CVE-2008-2108: Chain: insufficient precision causes extra zero bits to be assigned, reducing entropy for an API function that generates random numbers.

CVE-2008-2108: Chain: insufficient precision (CWE-1339) in random-number generator causes some zero bits to be reliably generated, reducing the amount of entropy (CWE-331)

CVE-2008-2020: CAPTCHA implementation does not produce enough different images, allowing bypass using a database of all possible checksums.

CVE-2008-0087: DNS client uses predictable DNS transaction IDs, allowing DNS spoofing.

CVE-2008-0141: Application generates passwords that are based on the time of day.

## Top 25 Examples

CVE-2021-24998: The Simple JWT Login WordPress plugin before 3.3.0 can be used to create new WordPress user accounts with a randomly generated password. The password is generated using the str_shuffle PHP function that "does not generate cryptographically secure values, and should not be used for cryptographic purposes" according to PHP's documentation.

CVE-2021-28099: In Netflix OSS Hollow, since the Files.exists(parent) is run before creating the directories, an attacker can pre-create these directories with wide permissions. Additionally, since an insecure source of randomness is used, the file names to be created can be deterministically calculated.

CVE-2022-22922: TP-Link TL-WA850RE Wi-Fi Range Extender before v6_200923 was discovered to use highly predictable and easily detectable session keys, allowing attackers to gain administrative privileges.

CVE-2022-23138: ZTE's MF297D product has cryptographic issues vulnerability. Due to the use of weak random values, the security of the device is reduced, and it may face the risk of attack.

CVE-2022-24406: OX App Suite through 7.10.6 allows SSRF because multipart/form-data boundaries are predictable, and this can lead to injection into internal Documentconverter API calls.

CVE-2022-30295: uClibc-ng through 1.0.40 and uClibc through 0.9.33.2 use predictable DNS transaction IDs that may lead to DNS cache poisoning. This is related to a reset of a value to 0x2.

CVE-2022-31157: LTI 1.3 Tool Library is a library used for building IMS-certified LTI 1.3 tool providers in PHP. Prior to version 5.0, the function used to generate random nonces was not sufficiently cryptographically complex. Users should upgrade to version 5.0 to receive a patch. There are currently no known workarounds.

CVE-2022-32296: The Linux kernel before 5.17.9 allows TCP servers to identify clients by observing what source ports are used. This occurs because of use of Algorithm 4 ("Double-Hash Port Selection Algorithm") of RFC 6056.

CVE-2022-40299: In Singular before 4.3.1, a predictable /tmp pathname is used (e.g., by sdb.cc), which allows local users to gain the privileges of other users via a procedure in a file under /tmp. NOTE: this CVE Record is about sdb.cc and similar files in the Singular interface that have predictable /tmp pathnames; this CVE Record is not about the lack of a safe temporary-file creation capability in the Singular language.

CVE-2021-26726: A remote code execution vulnerability affecting a Valmet DNA service listening on TCP port 1517, allows an attacker to execute commands with SYSTEM privileges This issue affects: Valmet DNA versions from Collection 2012 until Collection 2021.

CVE-2021-45487: In NetBSD through 9.2, the IPv4 ID generation algorithm does not use appropriate cryptographic measures.

CVE-2021-45488: In NetBSD through 9.2, there is an information leak in the TCP ISN (ISS) generation algorithm.

# CWE-331 Insufficient Entropy

## Description

The product uses an algorithm or scheme that produces insufficient entropy, leaving patterns or clusters of values that are more likely to occur than others.

## Observed Examples

CVE-2001-0950: Insufficiently random data used to generate session tokens using C rand(). Also, for certificate/key generation, uses a source that does not block when entropy is low.

CVE-2008-2108: Chain: insufficient precision (CWE-1339) in random-number generator causes some zero bits to be reliably generated, reducing the amount of entropy (CWE-331)

## Top 25 Examples

CVE-2021-22799: A CWE-331: Insufficient Entropy vulnerability exists that could cause unintended connection from an internal network to an external network when an attacker manages to decrypt the SESU proxy password from the registry. Affected Product: Schneider Electric Software Update, V2.3.0 through V2.5.1

CVE-2021-42138: A user of a machine protected by SafeNet Agent for Windows Logon may leverage weak entropy to access the encrypted credentials of any or all the users on that machine.

CVE-2022-34294: totd 1.5.3 uses a fixed UDP source port in upstream queries sent to DNS resolvers. This allows DNS cache poisoning because there is not enough entropy to prevent traffic injection attacks.

CVE-2022-37401: Apache OpenOffice supports the storage of passwords for web connections in the user's configuration database. The stored passwords are encrypted with a single master key provided by the user. A flaw in OpenOffice existed where master key was poorly encoded resulting in weakening its entropy from 128 to 43 bits making the stored passwords vulnerable to a brute force attack if an attacker has access to the users stored config. This issue affects: Apache OpenOffice versions prior to 4.1.13. Reference: CVE-2022-26307 - LibreOffice

CVE-2021-31797: The user identification mechanism used by CyberArk Credential Provider prior to 12.1 is susceptible to a local host race condition, leading to password disclosure.

# CWE-332 Insufficient Entropy in PRNG

## Description

The lack of entropy available for, or used by, a Pseudo-Random Number Generator (PRNG) can be a stability and security threat.

## Observed Examples

[REF-1374]: Chain: JavaScript-based cryptocurrency library can fall back to the insecure Math.random() function instead of reporting a failure (CWE-392), thus reducing the entropy (CWE-332) and leading to generation of non-unique cryptographic keys for Bitcoin wallets (CWE-1391)

CVE-2019-1715: security product has insufficient entropy in the DRBG, allowing collisions and private key discovery

# CWE-333 Improper Handling of Insufficient Entropy in TRNG

## Description

True random number generators (TRNG) generally have a limited source of entropy and therefore can fail or block.

The rate at which true random numbers can be generated is limited. It is important that one uses them only when they are needed for security.

# CWE-334 Small Space of Random Values

## Description

The number of possible random values is smaller than needed by the product, making it more susceptible to brute force attacks.

## Observed Examples

CVE-2002-0583: Product uses 5 alphanumeric characters for filenames of expense claim reports, stored under web root.

CVE-2002-0903: Product uses small number of random numbers for a code to approve an action, and also uses predictable new user IDs, allowing attackers to hijack new accounts.

CVE-2003-1230: SYN cookies implementation only uses 32-bit keys, making it easier to brute force ISN.

CVE-2004-0230: Complex predictability / randomness (reduced space).

## Top 25 Examples

CVE-2021-44151: An issue was discovered in Reprise RLM 14.2. As the session cookies are small, an attacker can hijack any existing sessions by bruteforcing the 4 hex-character session cookie on the Windows version (the Linux version appears to have 8 characters). An attacker can obtain the static part of the cookie (cookie name) by first making a request to any page on the application (e.g., /goforms/menu) and saving the name of the cookie sent with the response. The attacker can then use the name of the cookie and try to request that same page, setting a random value for the cookie. If any user has an active session, the page should return with the authorized content, when a valid cookie value is hit.

CVE-2022-3959: A vulnerability, which was classified as problematic, has been found in drogon up to 1.8.1. Affected by this issue is some unknown functionality of the component Session Hash Handler. The manipulation leads to small space of random values. The attack may be launched remotely. Upgrading to version 1.8.2 is able to address this issue. The name of the patch is c0d48da99f66aaada17bcd28b07741cac8697647. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-213464.

# CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator (PRNG)

## Description

The product uses a Pseudo-Random Number Generator (PRNG) but does not correctly manage seeds.

PRNGs are deterministic and, while their output appears random, they cannot actually create entropy. They rely on cryptographically secure and unique seeds for entropy so proper seeding is critical to the secure operation of the PRNG.


 Management of seeds could be broken down into two main areas: 


  -  (1) protecting seeds as cryptographic material (such as a cryptographic key); 

  -  (2) whenever possible, using a uniquely generated seed from a cryptographically secure source 

 PRNGs require a seed as input to generate a stream of numbers that are functionally indistinguishable from random numbers. While the output is, in many cases, sufficient for cryptographic uses, the output of any PRNG is directly determined by the seed provided as input. If the seed can be ascertained by a third party, the entire output of the PRNG can be made known to them. As such, the seed should be kept secret and should ideally not be able to be guessed. For example, the current time may be a poor seed. Knowing the approximate time the PRNG was seeded greatly reduces the possible key space. 

 Seeds do not necessarily need to be unique, but reusing seeds may open up attacks if the seed is discovered.

## Observed Examples

CVE-2020-7010: Cloud application on Kubernetes generates passwords using a weak random number generator based on deployment time.

CVE-2019-11495: server uses erlang:now() to seed the PRNG, which results in a small search space for potential random seeds

CVE-2018-12520: Product's PRNG is not seeded for the generation of session IDs

CVE-2016-10180: Router's PIN generation is based on rand(time(0)) seeding.

## Top 25 Examples

CVE-2021-34600: Telenot CompasX versions prior to 32.0 use a weak seed for random number generation leading to predictable AES keys used in the NFC tags used for local authorization of users. This may lead to total loss of trustworthiness of the installation. 

CVE-2021-41117: keypair is a a RSA PEM key generator written in javascript. keypair implements a lot of cryptographic primitives on its own or by borrowing from other libraries where possible, including node-forge. An issue was discovered where this library was generating identical RSA keys used in SSH. This would mean that the library is generating identical P, Q (and thus N) values which, in practical terms, is impossible with RSA-2048 keys. Generating identical values, repeatedly, usually indicates an issue with poor random number generation, or, poor handling of CSPRNG output. Issue 1: Poor random number generation (`GHSL-2021-1012`). The library does not rely entirely on a platform provided CSPRNG, rather, it uses it's own counter-based CMAC approach. Where things go wrong is seeding the CMAC implementation with "true" random data in the function `defaultSeedFile`. In order to seed the AES-CMAC generator, the library will take two different approaches depending on the JavaScript execution environment. In a browser, the library will use [`window.crypto.getRandomValues()`](https://github.com/juliangruber/keypair/blob/87c62f255baa12c1ec4f98a91600f82af80be6db/index.js#L971). However, in a nodeJS execution environment, the `window` object is not defined, so it goes down a much less secure solution, also of which has a bug in it. It does look like the library tries to use node's CSPRNG when possible unfortunately, it looks like the `crypto` object is null because a variable was declared with the same name, and set to `null`. So the node CSPRNG path is never taken. However, when `window.crypto.getRandomValues()` is not available, a Lehmer LCG random number generator is used to seed the CMAC counter, and the LCG is seeded with `Math.random`. While this is poor and would likely qualify in a security bug in itself, it does not explain the extreme frequency in which duplicate keys occur. The main flaw: The output from the Lehmer LCG is encoded incorrectly. The specific [line][https://github.com/juliangruber/keypair/blob/87c62f255baa12c1ec4f98a91600f82af80be6db/index.js#L1008] with the flaw is: `b.putByte(String.fromCharCode(next & 0xFF))` The [definition](https://github.com/juliangruber/keypair/blob/87c62f255baa12c1ec4f98a91600f82af80be6db/index.js#L350-L352) of `putByte` is `util.ByteBuffer.prototype.putByte = function(b) {this.data += String.fromCharCode(b);};`. Simplified, this is `String.fromCharCode(String.fromCharCode(next & 0xFF))`. The double `String.fromCharCode` is almost certainly unintentional and the source of weak seeding. Unfortunately, this does not result in an error. Rather, it results most of the buffer containing zeros. Since we are masking with 0xFF, we can determine that 97% of the output from the LCG are converted to zeros. The only outputs that result in meaningful values are outputs 48 through 57, inclusive. The impact is that each byte in the RNG seed has a 97% chance of being 0 due to incorrect conversion. When it is not, the bytes are 0 through 9. In summary, there are three immediate concerns: 1. The library has an insecure random number fallback path. Ideally the library would require a strong CSPRNG instead of attempting to use a LCG and `Math.random`. 2. The library does not correctly use a strong random number generator when run in NodeJS, even though a strong CSPRNG is available. 3. The fallback path has an issue in the implementation where a majority of the seed data is going to effectively be zero. Due to the poor random number generation, keypair generates RSA keys that are relatively easy to guess. This could enable an attacker to decrypt confidential messages or gain authorized access to an account belonging to the victim.

# CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)

## Description

A Pseudo-Random Number Generator (PRNG) uses the same seed each time the product is initialized.

Given the deterministic nature of PRNGs, using the same seed for each initialization will lead to the same output in the same order. If an attacker can guess (or knows) the seed, then the attacker may be able to determine the random numbers that will be produced from the PRNG.

## Observed Examples

CVE-2022-39218: SDK for JavaScript app builder for serverless code uses the same fixed seed for a PRNG, allowing cryptography bypass

## Top 25 Examples

CVE-2022-39218: The JS Compute Runtime for Fastly's Compute@Edge platform provides the environment JavaScript is executed in when using the Compute@Edge JavaScript SDK. In versions prior to 0.5.3, the `Math.random` and `crypto.getRandomValues` methods fail to use sufficiently random values. The initial value to seed the PRNG (pseudorandom number generator) is baked-in to the final WebAssembly module, making the sequence of random values for that specific WebAssembly module predictable. An attacker can use the fixed seed to predict random numbers generated by these functions and bypass cryptographic security controls, for example to disclose sensitive data encrypted by functions that use these generators. The problem has been patched in version 0.5.3. No known workarounds exist.

# CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)

## Description

A Pseudo-Random Number Generator (PRNG) is initialized from a predictable seed, such as the process ID or system time.

The use of predictable seeds significantly reduces the number of possible seeds that an attacker would need to test in order to predict which random numbers will be generated by the PRNG.

## Observed Examples

CVE-2020-7010: Cloud application on Kubernetes generates passwords using a weak random number generator based on deployment time.

CVE-2019-11495: server uses erlang:now() to seed the PRNG, which results in a small search space for potential random seeds

CVE-2008-0166: The removal of a couple lines of code caused Debian's OpenSSL Package to only use the current process ID for seeding a PRNG

CVE-2016-10180: Router's PIN generation is based on rand(time(0)) seeding.

CVE-2018-9057: cloud provider product uses a non-cryptographically secure PRNG and seeds it with the current time

## Top 25 Examples

CVE-2022-29965: The Emerson DeltaV Distributed Control System (DCS) controllers and IO cards through 2022-04-29 misuse passwords. Access to privileged operations on the maintenance port TELNET interface (23/TCP) on M-series and SIS (CSLS/LSNB/LSNG) nodes is controlled by means of utility passwords. These passwords are generated using a deterministic, insecure algorithm using a single seed value composed of a day/hour/minute timestamp with less than 16 bits of entropy. The seed value is fed through a lookup table and a series of permutation operations resulting in three different four-character passwords corresponding to different privilege levels. An attacker can easily reconstruct these passwords and thus gain access to privileged maintenance operations. NOTE: this is different from CVE-2014-2350.

CVE-2022-31008: RabbitMQ is a multi-protocol messaging and streaming broker. In affected versions the shovel and federation plugins perform URI obfuscation in their worker (link) state. The encryption key used to encrypt the URI was seeded with a predictable secret. This means that in case of certain exceptions related to Shovel and Federation plugins, reasonably easily deobfuscatable data could appear in the node log. Patched versions correctly use a cluster-wide secret for that purpose. This issue has been addressed and Patched versions: `3.10.2`, `3.9.18`, `3.8.32` are available. Users unable to upgrade should disable the Shovel and Federation plugins.

CVE-2022-31034: Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. All versions of Argo CD starting with v0.11.0 are vulnerable to a variety of attacks when an SSO login is initiated from the Argo CD CLI or UI. The vulnerabilities are due to the use of insufficiently random values in parameters in Oauth2/OIDC login flows. In each case, using a relatively-predictable (time-based) seed in a non-cryptographically-secure pseudo-random number generator made the parameter less random than required by the relevant spec or by general best practices. In some cases, using too short a value made the entropy even less sufficient. The attacks on login flows which are meant to be mitigated by these parameters are difficult to accomplish but can have a high impact potentially granting an attacker admin access to Argo CD. Patches for this vulnerability has been released in the following Argo CD versions: v2.4.1, v2.3.5, v2.2.10 and v2.1.16. There are no known workarounds for this vulnerability.

CVE-2022-42159: D-Link COVR 1200,1202,1203 v1.08 was discovered to have a predictable seed in a Pseudo-Random Number Generator.

CVE-2022-40267: Predictable Seed in Pseudo-Random Number Generator (PRNG) vulnerability in Mitsubishi Electric Corporation MELSEC iQ-F Series FX5U-xMy/z (x=32,64,80, y=T,R, z=ES,DS,ESS,DSS) with serial number 17X**** or later, and versions 1.280 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5U-xMy/z (x=32,64,80, y=T,R, z=ES,DS,ESS,DSS) with serial number 179**** and prior, and versions 1.074 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UC-xMy/z (x=32,64,96, y=T, z=D,DSS)) with serial number 17X**** or later, and versions 1.280 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UC-xMy/z (x=32,64,96, y=T, z=D,DSS)) with serial number 179**** and prior, and versions 1.074 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UC-32MT/DS-TS versions 1.280 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UC-32MT/DSS-TS versions 1.280 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UJ-xMy/z (x=24,40,60, y=T,R, z=ES,ESS) versions 1.042 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UJ-xMy/ES-A (x=24,40,60, y=T,R) versions 1.043 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5S-xMy/z (x=30,40,60,80, y=T,R, z=ES,ESS) versions 1.003 and prior, Mitsubishi Electric Corporation MELSEC iQ-F Series FX5UC-32MR/DS-TS versions 1.280 and prior, Mitsubishi Electric Corporation MELSEC iQ-R Series R00/01/02CPU versions 33 and prior, Mitsubishi Electric Corporation MELSEC iQ-R Series R04/08/16/32/120(EN)CPU versions 66 and prior allows a remote unauthenticated attacker to access the Web server function by guessing the random numbers used for authentication from several used random numbers.

# CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

## Description

The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG's algorithm is not cryptographically strong.

When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.


Often a pseudo-random number generator (PRNG) is not designed for cryptography. Sometimes a mediocre source of randomness is sufficient or preferable for algorithms that use random numbers. Weak generators generally take less processing power and/or do not use the precious, finite, entropy sources on a system. While such PRNGs might have very useful features, these same features could be used to break the cryptography.

## Observed Examples

CVE-2021-3692: PHP framework uses mt_rand() function (Marsenne Twister) when generating tokens

CVE-2009-3278: Crypto product uses rand() library function to generate a recovery key, making it easier to conduct brute force attacks.

CVE-2009-3238: Random number generator can repeatedly generate the same value.

CVE-2009-2367: Web application generates predictable session IDs, allowing session hijacking.

CVE-2008-0166: SSL library uses a weak random number generator that only generates 65,536 unique keys.

## Top 25 Examples

CVE-2021-43799: Zulip is an open-source team collaboration tool. Zulip Server installs RabbitMQ for internal message passing. In versions of Zulip Server prior to 4.9, the initial installation (until first reboot, or restart of RabbitMQ) does not successfully limit the default ports which RabbitMQ opens; this includes port 25672, the RabbitMQ distribution port, which is used as a management port. RabbitMQ's default "cookie" which protects this port is generated using a weak PRNG, which limits the entropy of the password to at most 36 bits; in practicality, the seed for the randomizer is biased, resulting in approximately 20 bits of entropy. If other firewalls (at the OS or network level) do not protect port 25672, a remote attacker can brute-force the 20 bits of entropy in the "cookie" and leverage it for arbitrary execution of code as the rabbitmq user. They can also read all data which is sent through RabbitMQ, which includes all message traffic sent by users. Version 4.9 contains a patch for this vulnerability. As a workaround, ensure that firewalls prevent access to ports 5672 and 25672 from outside the Zulip server.

CVE-2021-45484: In NetBSD through 9.2, the IPv6 fragment ID generation algorithm employs a weak cryptographic PRNG.

CVE-2021-45489: In NetBSD through 9.2, the IPv6 Flow Label generation algorithm employs a weak cryptographic PRNG.

CVE-2022-29245: SSH.NET is a Secure Shell (SSH) library for .NET. In versions 2020.0.0 and 2020.0.1, during an `X25519` key exchange, the client’s private key is generated with `System.Random`. `System.Random` is not a cryptographically secure random number generator, it must therefore not be used for cryptographic purposes. When establishing an SSH connection to a remote host, during the X25519 key exchange, the private key is generated with a weak random number generator whose seed can be brute forced. This allows an attacker who is able to eavesdrop on the communications to decrypt them. Version 2020.0.2 contains a patch for this issue. As a workaround, one may disable support for `curve25519-sha256` and `curve25519-sha256@libssh.org` key exchange algorithms.

CVE-2022-45782: An issue was discovered in dotCMS core 5.3.8.5 through 5.3.8.15 and 21.03 through 22.10.1. A cryptographically insecure random generation algorithm for password-reset token generation leads to account takeover.

CVE-2021-23126: An issue was discovered in Joomla! 3.2.0 through 3.9.24. Usage of the insecure rand() function within the process of generating the 2FA secret.

CVE-2022-0828: The Download Manager WordPress plugin before 3.2.34 uses the uniqid php function to generate the master key for a download, allowing an attacker to brute force the key with reasonable resources giving direct download access regardless of role based restrictions or password protections set for the download.

CVE-2021-22948: Vulnerability in the generation of session IDs in revive-adserver < 5.3.0, based on the cryptographically insecure uniqid() PHP function. Under some circumstances, an attacker could theoretically be able to brute force session IDs in order to take over a specific account.

# CWE-339 Small Seed Space in PRNG

## Description

A Pseudo-Random Number Generator (PRNG) uses a relatively small seed space, which makes it more susceptible to brute force attacks.

PRNGs are entirely deterministic once seeded, so it should be extremely difficult to guess the seed. If an attacker can collect the outputs of a PRNG and then brute force the seed by trying every possibility to see which seed matches the observed output, then the attacker will know the output of any subsequent calls to the PRNG. A small seed space implies that the attacker will have far fewer possible values to try to exhaust all possibilities.

## Observed Examples

CVE-2019-10908: product generates passwords via org.apache.commons.lang.RandomStringUtils, which uses java.util.Random internally. This PRNG has only a 48-bit seed.

# CWE-34 Path Traversal: '....//'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '....//' (doubled dot dot slash) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The '....//' manipulation is useful for bypassing some path traversal protection schemes. If "../" is filtered in a sequential fashion, as done by some regular expression engines, then "....//" can collapse into the "../" unsafe value (CWE-182). It could also be useful when ".." is removed, if the operating system treats "//" and "/" as equivalent.

## Observed Examples

CVE-2004-1670: Mail server allows remote attackers to create arbitrary directories via a ".." or rename arbitrary files via a "....//" in user supplied parameters.

# CWE-340 Generation of Predictable Numbers or Identifiers

## Description

The product uses a scheme that generates numbers or identifiers that are more predictable than required.

## Observed Examples

CVE-2022-29330: Product for administering PBX systems uses predictable identifiers and timestamps for filenames (CWE-340) which allows attackers to access files via direct request (CWE-425).

CVE-2001-1141: PRNG allows attackers to use the output of small PRNG requests to determine the internal state information, which could be used by attackers to predict future pseudo-random numbers.

CVE-1999-0074: Listening TCP ports are sequentially allocated, allowing spoofing attacks.

## Top 25 Examples

CVE-2022-26317: A vulnerability has been identified in Mendix Applications using Mendix 7 (All versions < V7.23.29). When returning the result of a completed Microflow execution call the affected framework does not correctly verify, if the request was initially made by the user requesting the result. Together with predictable identifiers for Microflow execution calls, this could allow a malicious attacker to retrieve information about arbitrary Microflow execution calls made by users within the affected system.

CVE-2022-29330: Missing access control in the backup system of Telesoft VitalPBX before 3.2.1 allows attackers to access the PJSIP and SIP extension credentials, cryptographic keys and voicemails files via unspecified vectors.

CVE-2022-38970: ieGeek IG20 hipcam RealServer V1.0 is vulnerable to Incorrect Access Control. The algorithm used to generate device IDs (UIDs) for devices that utilize Shenzhen Yunni Technology iLnkP2P suffers from a predictability flaw that allows remote attackers to establish direct connections to arbitrary devices.

# CWE-341 Predictable from Observable State

## Description

A number or object is predictable based on observations that the attacker can make about the state of the system or network, such as time, process ID, etc.

## Observed Examples

CVE-2002-0389: Mail server stores private mail messages with predictable filenames in a world-executable directory, which allows local users to read private mailing list archives.

CVE-2001-1141: PRNG allows attackers to use the output of small PRNG requests to determine the internal state information, which could be used by attackers to predict future pseudo-random numbers.

CVE-2000-0335: DNS resolver library uses predictable IDs, which allows a local attacker to spoof DNS query results.

CVE-2005-1636: MFV. predictable filename and insecure permissions allows file modification to execute SQL queries.

## Top 25 Examples

CVE-2021-41694: An Incorrect Access Control vulnerability exists in Premiumdatingscript 4.2.7.7 via the password change procedure in requests\\user.php.

CVE-2021-4277: A vulnerability, which was classified as problematic, has been found in fredsmith utils. This issue affects some unknown processing of the file screenshot_sync of the component Filename Handler. The manipulation leads to predictable from observable state. The name of the patch is dbab1b66955eeb3d76b34612b358307f5c4e3944. It is recommended to apply a patch to fix this issue. The identifier VDB-216749 was assigned to this vulnerability.

CVE-2022-36536: An issue in the component post_applogin.php of Super Flexible Software GmbH & Co. KG Syncovery 9 for Linux v9.47x and below allows attackers to escalate privileges via creating crafted session tokens.

# CWE-342 Predictable Exact Value from Previous Values

## Description

An exact value or random number can be precisely predicted by observing previous values.

## Observed Examples

CVE-2002-1463: Firewall generates easily predictable initial sequence numbers (ISN), which allows remote attackers to spoof connections.

CVE-1999-0074: Listening TCP ports are sequentially allocated, allowing spoofing attacks.

CVE-1999-0077: Predictable TCP sequence numbers allow spoofing.

CVE-2000-0335: DNS resolver uses predictable IDs, allowing a local user to spoof DNS query results.

# CWE-343 Predictable Value Range from Previous Values

## Description

The product's random number generator produces a series of values which, when observed, can be used to infer a relatively small range of possibilities for the next value that could be generated.

The output of a random number generator should not be predictable based on observations of previous values. In some cases, an attacker cannot predict the exact value that will be produced next, but can narrow down the possibilities significantly. This reduces the amount of effort to perform a brute force attack. For example, suppose the product generates random numbers between 1 and 100, but it always produces a larger value until it reaches 100. If the generator produces an 80, then the attacker knows that the next value will be somewhere between 81 and 100. Instead of 100 possibilities, the attacker only needs to consider 20.

# CWE-344 Use of Invariant Value in Dynamically Changing Context

## Description

The product uses a constant value, name, or reference, but this value can (or should) vary across different environments.

## Observed Examples

CVE-2002-0980: Component for web browser writes an error message to a known location, which can then be referenced by attackers to process HTML/script in a less restrictive context

# CWE-345 Insufficient Verification of Data Authenticity

## Description

The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Observed Examples

CVE-2022-30260: Distributed Control System (DCS) does not sign firmware images and only relies on insecure checksums for integrity checks

CVE-2022-30267: Distributed Control System (DCS) does not sign firmware images and only relies on insecure checksums for integrity checks

CVE-2022-30272: Remote Terminal Unit (RTU) does not use signatures for firmware images and relies on insecure checksums

## Top 25 Examples

CVE-2022-26871: An arbitrary file upload vulnerability in Trend Micro Apex Central could allow an unauthenticated remote attacker to upload an arbitrary file which could lead to remote code execution.

CVE-2021-44850: On Xilinx Zynq-7000 SoC devices, physical modification of an SD boot image allows for a buffer overflow attack in the ROM. Because the Zynq-7000's boot image header is unencrypted and unauthenticated before use, an attacker can modify the boot header stored on an SD card so that a secure image appears to be unencrypted, and they will be able to modify the full range of register initialization values. Normally, these registers will be restricted when booting securely. Of importance to this attack are two registers that control the SD card's transfer type and transfer size. These registers could be modified a way that causes a buffer overflow in the ROM.

CVE-2022-28385: An issue was discovered in certain Verbatim drives through 2022-03-31. Due to missing integrity checks, an attacker can manipulate the content of the emulated CD-ROM drive (containing the Windows and macOS client software). The content of this emulated CD-ROM drive is stored as an ISO-9660 image in the hidden sectors of the USB drive, that can only be accessed using special IOCTL commands, or when installing the drive in an external disk enclosure. By manipulating this ISO-9660 image or replacing it with another one, an attacker is able to store malicious software on the emulated CD-ROM drive. This software may get executed by an unsuspecting victim when using the device. For example, an attacker with temporary physical access during the supply chain could program a modified ISO-9660 image on a device that always accepts an attacker-controlled password for unlocking the device. If the attacker later on gains access to the used USB drive, he can simply decrypt all contained user data. Storing arbitrary other malicious software is also possible. This affects Executive Fingerprint Secure SSD GDMSFE01-INI3637-C VER1.1 and Fingerprint Secure Portable Hard Drive Part Number #53650.

CVE-2022-36360: A vulnerability has been identified in LOGO! 8 BM (incl. SIPLUS variants) (All versions < V8.3). Affected devices load firmware updates without checking the authenticity. Furthermore the integrity of the unencrypted firmware is only verified by a non-cryptographic method. This could allow an attacker to manipulate a firmware update and flash it to the device.

CVE-2022-39199: immudb is a database with built-in cryptographic proof and verification. immudb client SDKs use server's UUID to distinguish between different server instance so that the client can connect to different immudb instances and keep the state for multiple servers. SDK does not validate this uuid and can accept any value reported by the server. A malicious server can change the reported UUID tricking the client to treat it as a different server thus accepting a state completely irrelevant to the one previously retrieved from the server. This issue has been patched in version 1.4.1. As a workaround, when initializing an immudb client object a custom state handler can be used to store the state. Providing custom implementation that ignores the server UUID can be used to ensure that even if the server changes the UUID, client will still consider it to be the same server.

CVE-2022-39909: Insufficient verification of data authenticity vulnerability in Samsung Gear IconX PC Manager prior to version 2.1.221019.51 allows local attackers to create arbitrary file using symbolic link.

CVE-2022-23491: Certifi is a curated collection of Root Certificates for validating the trustworthiness of SSL certificates while verifying the identity of TLS hosts. Certifi 2022.12.07 removes root certificates from "TrustCor" from the root store. These are in the process of being removed from Mozilla's trust store. TrustCor's root certificates are being removed pursuant to an investigation prompted by media reporting that TrustCor's ownership also operated a business that produced spyware. Conclusions of Mozilla's investigation can be found in the linked google group discussion.

CVE-2022-30315: Honeywell Experion PKS Safety Manager (SM and FSC) through 2022-05-06 has Insufficient Verification of Data Authenticity. According to FSCT-2022-0053, there is a Honeywell Experion PKS Safety Manager insufficient logic security controls issue. The affected components are characterized as: Honeywell FSC runtime (FSC-CPU, QPP), Honeywell Safety Builder. The potential impact is: Remote Code Execution, Denial of Service. The Honeywell Experion PKS Safety Manager family of safety controllers utilize the unauthenticated Safety Builder protocol (FSCT-2022-0051) for engineering purposes, including downloading projects and control logic to the controller. Control logic is downloaded to the controller on a block-by-block basis. The logic that is downloaded consists of FLD code compiled to native machine code for the CPU module (which applies to both the Safety Manager and FSC families). Since this logic does not seem to be cryptographically authenticated, it allows an attacker capable of triggering a logic download to execute arbitrary machine code on the controller's CPU module in the context of the runtime. While the researchers could not verify this in detail, the researchers believe that the microprocessor underpinning the FSC and Safety Manager CPU modules is incapable of offering memory protection or privilege separation capabilities which would give an attacker full control of the CPU module. There is no authentication on control logic downloaded to the controller. Memory protection and privilege separation capabilities for the runtime are possibly lacking. The researchers confirmed the issues in question on Safety Manager R145.1 and R152.2 but suspect the issue affects all FSC and SM controllers and associated Safety Builder versions regardless of software or firmware revision. An attacker who can communicate with a Safety Manager controller via the Safety Builder protocol can execute arbitrary code without restrictions on the CPU module, allowing for covert manipulation of control operations and implanting capabilities similar to the TRITON malware (MITRE ATT&CK software ID S1009). A mitigating factor with regards to some, but not all, of the above functionality is that these require the Safety Manager physical keyswitch to be in the right position.

CVE-2022-0715: A CWE-287: Improper Authentication vulnerability exists that could cause an attacker to arbitrarily change the behavior of the UPS when a key is leaked and used to upload malicious firmware. Affected Product: APC Smart-UPS Family: SMT Series (SMT Series ID=18: UPS 09.8 and prior / SMT Series ID=1040: UPS 01.2 and prior / SMT Series ID=1031: UPS 03.1 and prior), SMC Series (SMC Series ID=1005: UPS 14.1 and prior / SMC Series ID=1007: UPS 11.0 and prior / SMC Series ID=1041: UPS 01.1 and prior), SCL Series (SCL Series ID=1030: UPS 02.5 and prior / SCL Series ID=1036: UPS 02.5 and prior), SMX Series (SMX Series ID=20: UPS 10.2 and prior / SMX Series ID=23: UPS 07.0 and prior), SRT Series (SRT Series ID=1010/1019/1025: UPS 08.3 and prior / SRT Series ID=1024: UPS 01.0 and prior / SRT Series ID=1020: UPS 10.4 and prior / SRT Series ID=1021: UPS 12.2 and prior / SRT Series ID=1001/1013: UPS 05.1 and prior / SRT Series ID=1002/1014: UPSa05.2 and prior), APC SmartConnect Family: SMT Series (SMT Series ID=1015: UPS 04.5 and prior), SMC Series (SMC Series ID=1018: UPS 04.2 and prior), SMTL Series (SMTL Series ID=1026: UPS 02.9 and prior), SCL Series (SCL Series ID=1029: UPS 02.5 and prior / SCL Series ID=1030: UPS 02.5 and prior / SCL Series ID=1036: UPS 02.5 and prior / SCL Series ID=1037: UPS 03.1 and prior), SMX Series (SMX Series ID=1031: UPS 03.1 and prior)

CVE-2022-25262: In JetBrains Hub before 2022.1.14434, SAML request takeover was possible.

CVE-2022-20396: In SettingsActivity.java, there is a possible way to make a device discoverable over Bluetooth, without permission or user interaction, due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12L Android-13Android ID: A-234440688

CVE-2021-46559: The firmware on Moxa TN-5900 devices through 3.1 has a weak algorithm that allows an attacker to defeat an inspection mechanism for integrity protection.

CVE-2022-28370: On Verizon 5G Home LVSKIHP OutDoorUnit (ODU) 3.33.101.0 devices, the RPC endpoint crtc_fw_upgrade provides a means of provisioning a firmware update for the device. /lib/functions/wnc_jsonsh/wnc_crtc_fw.sh has no cryptographic validation of the image, thus allowing an attacker to modify the installed firmware.

CVE-2021-45419: Certain Starcharge products are affected by Improper Input Validation. The affected products include: Nova 360 Cabinet <= 1.3.0.0.7b102 - Fixed: Beta1.3.0.1.0 and Titan 180 Premium <= 1.3.0.0.6 - Fixed: 1.3.0.0.9.

# CWE-346 Origin Validation Error

## Description

The product does not properly verify that the source of data or communication is valid.

## Observed Examples

CVE-2000-1218: DNS server can accept DNS updates from hosts that it did not query, leading to cache poisoning

CVE-2005-0877: DNS server can accept DNS updates from hosts that it did not query, leading to cache poisoning

CVE-2001-1452: DNS server caches glue records received from non-delegated name servers

CVE-2005-2188: user ID obtained from untrusted source (URL)

CVE-2003-0174: LDAP service does not verify if a particular attribute was set by the LDAP server

CVE-1999-1549: product does not sufficiently distinguish external HTML from internal, potentially dangerous HTML, allowing bypass using special strings in the page title. Overlaps special elements.

CVE-2003-0981: product records the reverse DNS name of a visitor in the logs, allowing spoofing and resultant XSS.

## Top 25 Examples

CVE-2022-25146: The Remote App module in Liferay Portal Liferay Portal v7.4.3.4 through v7.4.3.8 and Liferay DXP 7.4 before update 5 does not check if the origin of event messages it receives matches the origin of the Remote App, allowing attackers to exfiltrate the CSRF token via a crafted event message.

CVE-2022-41924: A vulnerability identified in the Tailscale Windows client allows a malicious website to reconfigure the Tailscale daemon `tailscaled`, which can then be used to remotely execute code. In the Tailscale Windows client, the local API was bound to a local TCP socket, and communicated with the Windows client GUI in cleartext with no Host header verification. This allowed an attacker-controlled website visited by the node to rebind DNS to an attacker-controlled DNS server, and then make local API requests in the client, including changing the coordination server to an attacker-controlled coordination server. An attacker-controlled coordination server can send malicious URL responses to the client, including pushing executables or installing an SMB share. These allow the attacker to remotely execute code on the node. All Windows clients prior to version v.1.32.3 are affected. If you are running Tailscale on Windows, upgrade to v1.32.3 or later to remediate the issue.

CVE-2021-38507: The Opportunistic Encryption feature of HTTP2 (RFC 8164) allows a connection to be transparently upgraded to TLS while retaining the visual properties of an HTTP connection, including being same-origin with unencrypted connections on port 80. However, if a second encrypted port on the same IP address (e.g. port 8443) did not opt-in to opportunistic encryption; a network attacker could forward a connection from the browser to port 443 to port 8443, causing the browser to treat the content of port 8443 as same-origin with HTTP. This was resolved by disabling the Opportunistic Encryption feature, which had low usage. This vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3.

CVE-2022-24762: sysend.js is a library that allows a user to send messages between pages that are open in the same browser. Users that use cross-origin communication may have their communications intercepted. Impact is limited by the communication occurring in the same browser. This issue has been patched in sysend.js version 1.10.0. The only currently known workaround is to avoid sending communications that a user does not want to have intercepted via sysend messages.

CVE-2021-33959: Plex media server 1.21 and before is vulnerable to ddos reflection attack via plex service.

# CWE-347 Improper Verification of Cryptographic Signature

## Description

The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Observed Examples

CVE-2002-1796: Does not properly verify signatures for "trusted" entities.

CVE-2005-2181: Insufficient verification allows spoofing.

CVE-2005-2182: Insufficient verification allows spoofing.

CVE-2002-1706: Accepts a configuration file without a Message Integrity Check (MIC) signature.

## Top 25 Examples

CVE-2021-32977: AVEVA System Platform versions 2017 through 2020 R2 P01 does not verify, or incorrectly verifies, the cryptographic signature for data.

CVE-2021-35097: Possible authentication bypass due to improper order of signature verification and hashing in the signature verification call in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-35113: Possible authentication bypass due to improper order of signature verification and hashing in the signature verification call in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2021-36277: Dell Command | Update, Dell Update, and Alienware Update versions before 4.3 contains an Improper Verification of Cryptographic Signature Vulnerability. A local authenticated malicious user may exploit this vulnerability by executing arbitrary code on the system.

CVE-2021-43074: An improper verification of cryptographic signature vulnerability [CWE-347] in FortiWeb 6.4 all versions, 6.3.16 and below, 6.2 all versions, 6.1 all versions, 6.0 all versions; FortiOS 7.0.3 and below, 6.4.8 and below, 6.2 all versions, 6.0 all versions; FortiSwitch 7.0.3 and below, 6.4.10 and below, 6.2 all versions, 6.0 all versions; FortiProxy 7.0.1 and below, 2.0.7 and below, 1.2 all versions, 1.1 all versions, 1.0 all versions may allow an attacker to decrypt portions of the administrative session management cookie if able to intercept the latter.

CVE-2022-1739: The tested version of Dominion Voting Systems ImageCast X does not validate application signatures to a trusted root certificate. Use of a trusted root certificate ensures software installed on a device is traceable to, or verifiable against, a cryptographic key provided by the manufacturer to detect tampering. An attacker could leverage this vulnerability to install malicious code, which could also be spread to other vulnerable ImageCast X devices via removable media.

CVE-2022-20929: A vulnerability in the upgrade signature verification of Cisco Enterprise NFV Infrastructure Software (NFVIS) could allow an unauthenticated, local attacker to provide an unauthentic upgrade file for upload. This vulnerability is due to insufficient cryptographic signature verification of upgrade files. An attacker could exploit this vulnerability by providing an administrator with an unauthentic upgrade file. A successful exploit could allow the attacker to fully compromise the Cisco NFVIS system.

CVE-2022-23507: Tendermint is a high-performance blockchain consensus engine for Byzantine fault tolerant applications. Versions prior to 0.28.0 contain a potential attack via Improper Verification of Cryptographic Signature, affecting anyone using the tendermint-light-client and related packages to perform light client verification (e.g. IBC-rs, Hermes). The light client does not check that the chain IDs of the trusted and untrusted headers match, resulting in a possible attack vector where someone who finds a header from an untrusted chain that satisfies all other verification conditions (e.g. enough overlapping validator signatures) could fool a light client. The attack vector is currently theoretical, and no proof-of-concept exists yet to exploit it on live networks. This issue is patched in version 0.28.0. There are no workarounds.

CVE-2022-24759: `@chainsafe/libp2p-noise` contains TypeScript implementation of noise protocol, an encryption protocol used in libp2p. `@chainsafe/libp2p-noise` before 4.1.2 and 5.0.3 does not correctly validate signatures during the handshake process. This may allow a man-in-the-middle to pose as other peers and get those peers banned. Users should upgrade to version 4.1.2 or 5.0.3 to receive a patch. There are currently no known workarounds.

CVE-2022-25898: The package jsrsasign before 10.5.25 are vulnerable to Improper Verification of Cryptographic Signature when JWS or JWT signature with non Base64URL encoding special characters or number escaped characters may be validated as valid by mistake. Workaround: Validate JWS or JWT signature if it has Base64URL and dot safe string before executing JWS.verify() or JWS.verifyJWT() method.

CVE-2022-2790: Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulenrable to CWE-347 Improper Verification of Cryptographic Signature, and does not properly verify compiled logic (PDT files) and data blocks data (BLD/BLK files).

CVE-2022-31156: Gradle is a build tool. Dependency verification is a security feature in Gradle Build Tool that was introduced to allow validation of external dependencies either through their checksum or cryptographic signatures. In versions 6.2 through 7.4.2, there are some cases in which Gradle may skip that verification and accept a dependency that would otherwise fail the build as an untrusted external artifact. This can occur in two ways. When signature verification is disabled but the verification metadata contains entries for dependencies that only have a `gpg` element but no `checksum` element. When signature verification is enabled, the verification metadata contains entries for dependencies with a `gpg` element but there is no signature file on the remote repository. In both cases, the verification will accept the dependency, skipping signature verification and not complaining that the dependency has no checksum entry. For builds that are vulnerable, there are two risks. Gradle could download a malicious binary from a repository outside your organization due to name squatting. For those still using HTTP only and not HTTPS for downloading dependencies, the build could download a malicious library instead of the expected one. Gradle 7.5 patches this issue by making sure to run checksum verification if signature verification cannot be completed, whatever the reason. Two workarounds are available: Remove all `gpg` elements from dependency verification metadata if you disable signature validation and/or avoid adding `gpg` entries for dependencies that do not have signature files.

CVE-2022-31206: The Omron SYSMAC Nx product family PLCs (NJ series, NY series, NX series, and PMAC series) through 2022-005-18 lack cryptographic authentication. These PLCs are programmed using the SYMAC Studio engineering software (which compiles IEC 61131-3 conformant POU code to native machine code for execution by the PLC's runtime). The resulting machine code is executed by a runtime, typically controlled by a real-time operating system. The logic that is downloaded to the PLC does not seem to be cryptographically authenticated, allowing an attacker to manipulate transmitted object code to the PLC and execute arbitrary machine code on the processor of the PLC's CPU module in the context of the runtime. In the case of at least the NJ series, an RTOS and hardware combination is used that would potentially allow for memory protection and privilege separation and thus limit the impact of code execution. However, it was not confirmed whether these sufficiently segment the runtime from the rest of the RTOS.

CVE-2022-31207: The Omron SYSMAC Cx product family PLCs (CS series, CJ series, and CP series) through 2022-05-18 lack cryptographic authentication. They utilize the Omron FINS (9600/TCP) protocol for engineering purposes, including downloading projects and control logic to the PLC. This protocol has authentication flaws as reported in FSCT-2022-0057. Control logic is downloaded to PLC volatile memory using the FINS Program Area Read and Program Area Write commands or to non-volatile memory using other commands from where it can be loaded into volatile memory for execution. The logic that is loaded into and executed from the user program area exists in compiled object code form. Upon execution, these object codes are first passed to a dedicated ASIC that determines whether the object code is to be executed by the ASIC or the microprocessor. In the former case, the object code is interpreted by the ASIC whereas in the latter case the object code is passed to the microprocessor for object code interpretation by a ROM interpreter. In the abnormal case where the object code cannot be handled by either, an abnormal condition is triggered and the PLC is halted. The logic that is downloaded to the PLC does not seem to be cryptographically authenticated, thus allowing an attacker to manipulate transmitted object code to the PLC and either execute arbitrary object code commands on the ASIC or on the microprocessor interpreter.

CVE-2022-34459:  Dell Command | Update, Dell Update, and Alienware Update versions prior to 4.7 contain a improper verification of cryptographic signature in get applicable driver component. A local malicious user could potentially exploit this vulnerability leading to malicious payload execution. 

CVE-2022-39366: DataHub is an open-source metadata platform. Prior to version 0.8.45, the `StatelessTokenService` of the DataHub metadata service (GMS) does not verify the signature of JWT tokens. This allows an attacker to connect to DataHub instances as any user if Metadata Service authentication is enabled. This vulnerability occurs because the `StatelessTokenService` of the Metadata service uses the `parse` method of `io.jsonwebtoken.JwtParser`, which does not perform a verification of the cryptographic token signature. This means that JWTs are accepted regardless of the used algorithm. This issue may lead to an authentication bypass. Version 0.8.45 contains a patch for the issue. There are no known workarounds.

CVE-2022-41666: A CWE-347: Improper Verification of Cryptographic Signature vulnerability exists that allows adversaries with local user privileges to load a malicious DLL which could lead to execution of malicious code. Affected Products: EcoStruxure Operator Terminal Expert(V3.3 Hotfix 1 or prior), Pro-face BLUE(V3.3 Hotfix1 or prior).

CVE-2022-41669: A CWE-347: Improper Verification of Cryptographic Signature vulnerability exists in the SGIUtility component that allows adversaries with local user privileges to load a malicious DLL which could result in execution of malicious code. Affected Products: EcoStruxure Operator Terminal Expert(V3.3 Hotfix 1 or prior), Pro-face BLUE(V3.3 Hotfix1 or prior).

CVE-2021-23993: An attacker may perform a DoS attack to prevent a user from sending encrypted email to a correspondent. If an attacker creates a crafted OpenPGP key with a subkey that has an invalid self signature, and the Thunderbird user imports the crafted key, then Thunderbird may try to use the invalid subkey, but the RNP library rejects it from being used, causing encryption to fail. This vulnerability affects Thunderbird < 78.9.1.

CVE-2022-23540: In versions `<=8.5.1` of `jsonwebtoken` library, lack of algorithm definition in the `jwt.verify()` function can lead to signature validation bypass due to defaulting to the `none` algorithm for signature verification. Users are affected if you do not specify algorithms in the `jwt.verify()` function. This issue has been fixed, please update to version 9.0.0 which removes the default support for the none algorithm in the `jwt.verify()` method. There will be no impact, if you update to version 9.0.0 and you don’t need to allow for the `none` algorithm. If you need 'none' algorithm, you have to explicitly specify that in `jwt.verify()` options. 

CVE-2022-42793: An issue in code signature validation was addressed with improved checks. This issue is fixed in macOS Big Sur 11.7, macOS Ventura 13, iOS 16, iOS 15.7 and iPadOS 15.7, macOS Monterey 12.6. An app may be able to bypass code signing checks.

# CWE-348 Use of Less Trusted Source

## Description

The product has two different sources of the same data or information, but it uses the source that has less support for verification, is less trusted, or is less resistant to attack.

## Observed Examples

CVE-2001-0860: Product uses IP address provided by a client, instead of obtaining it from the packet headers, allowing easier spoofing.

CVE-2004-1950: Web product uses the IP address in the X-Forwarded-For HTTP header instead of a server variable that uses the connecting IP address, allowing filter bypass.

CVE-2001-0908: Product logs IP address specified by the client instead of obtaining it from the packet headers, allowing information hiding.

CVE-2006-1126: PHP application uses IP address from X-Forwarded-For HTTP header, instead of REMOTE_ADDR.

# CWE-349 Acceptance of Extraneous Untrusted Data With Trusted Data

## Description

The product, when processing trusted data, accepts any untrusted data that is also included with the trusted data, treating the untrusted data as if it were trusted.

## Observed Examples

CVE-2002-0018: Does not verify that trusted entity is authoritative for all entities in its response.

CVE-2006-5462: use of extra data in a signature allows certificate signature forging

# CWE-35 Path Traversal: '.../...//'

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '.../...//' (doubled triple dot slash) sequences that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.


The '.../...//' manipulation is useful for bypassing some path traversal protection schemes. If "../" is filtered in a sequential fashion, as done by some regular expression engines, then ".../...//" can collapse into the "../" unsafe value (CWE-182). Removing the first "../" yields "....//"; the second removal yields "../". Depending on the algorithm, the product could be susceptible to CWE-34 but not CWE-35, or vice versa.

## Observed Examples

CVE-2005-2169: chain: ".../...//" bypasses protection mechanism using regexp's that remove "../" resulting in collapse into an unsafe value "../" (CWE-182) and resultant path traversal.

CVE-2005-0202: ".../....///" bypasses regexp's that remove "./" and "../"

# CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action

## Description

The product performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision, but it does not properly ensure that the IP address is truly associated with the hostname.

Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authentication mechanism.


When the product performs a reverse DNS resolution for an IP address, if an attacker controls the DNS server for that IP address, then the attacker can cause the server to return an arbitrary hostname. As a result, the attacker may be able to bypass authentication, cause the wrong hostname to be recorded in log files to hide activities, or perform other attacks.


Attackers can spoof DNS names by either (1) compromising a DNS server and modifying its records (sometimes called DNS cache poisoning), or (2) having legitimate control over a DNS server associated with their IP address.

## Observed Examples

CVE-2001-1488: Does not do double-reverse lookup to prevent DNS spoofing.

CVE-2001-1500: Does not verify reverse-resolved hostnames in DNS.

CVE-2000-1221: Authentication bypass using spoofed reverse-resolved DNS hostnames.

CVE-2002-0804: Authentication bypass using spoofed reverse-resolved DNS hostnames.

CVE-2001-1155: Filter does not properly check the result of a reverse DNS lookup, which could allow remote attackers to bypass intended access restrictions via DNS spoofing.

CVE-2004-0892: Reverse DNS lookup used to spoof trusted content in intermediary.

CVE-2003-0981: Product records the reverse DNS name of a visitor in the logs, allowing spoofing and resultant XSS.

# CWE-351 Insufficient Type Distinction

## Description

The product does not properly distinguish between different types of elements in a way that leads to insecure behavior.

## Observed Examples

CVE-2005-2260: Browser user interface does not distinguish between user-initiated and synthetic events.

CVE-2005-2801: Product does not compare all required data in two separate elements, causing it to think they are the same, leading to loss of ACLs. Similar to Same Name error.

# CWE-352 Cross-Site Request Forgery (CSRF)

## Description

The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user who submitted the request.

When a web server is designed to receive a request from a client without any mechanism for verifying that it was intentionally sent, then it might be possible for an attacker to trick a client into making an unintentional request to the web server which will be treated as an authentic request. This can be done via a URL, image load, XMLHttpRequest, etc. and can result in exposure of data or unintended code execution.

## Observed Examples

CVE-2004-1703: Add user accounts via a URL in an img tag

CVE-2004-1995: Add user accounts via a URL in an img tag

CVE-2004-1967: Arbitrary code execution by specifying the code in a crafted img tag or URL

CVE-2004-1842: Gain administrative privileges via a URL in an img tag

CVE-2005-1947: Delete a victim's information via a URL or an img tag

CVE-2005-2059: Change another user's settings via a URL or an img tag

CVE-2005-1674: Perform actions as administrator via a URL or an img tag

CVE-2009-3520: modify password for the administrator

CVE-2009-3022: CMS allows modification of configuration via CSRF attack against the administrator

CVE-2009-3759: web interface allows password changes or stopping a virtual machine via CSRF

## Top 25 Examples

CVE-2021-24410: The ?????? ?????? ??????? WordPress plugin through 1.0 is lacking any CSRF check when saving its settings and verses, and do not sanitise or escape them when outputting them back in the page. This could allow attackers to make a logged in admin change the settings, as well as add malicious verses containing JavaScript code in them, leading to Stored XSS issues

CVE-2021-25326: Skyworth Digital Technology RN510 V.3.1.0.4 is affected by an incorrect access control vulnerability in/cgi-bin/test_version.asp. If Wi-Fi is connected but an unauthenticated user visits a URL, the SSID password and web UI password may be disclosed.

CVE-2022-0642: The JivoChat Live Chat WordPress plugin before 1.3.5.4 does not properly check CSRF tokens on POST requests to the plugins admin page, and does not sanitise some parameters, leading to a stored Cross-Site Scripting vulnerability where an attacker can trick a logged in administrator to inject arbitrary javascript.

CVE-2022-0780: The SearchIQ WordPress plugin before 3.9 contains a flag to disable the verification of CSRF nonces, granting unauthenticated attackers access to the siq_ajax AJAX action and allowing them to perform Cross-Site Scripting attacks due to the lack of sanitisation and escaping in the customCss parameter

CVE-2022-0830: The FormBuilder WordPress plugin through 1.08 does not have CSRF checks in place when creating/updating and deleting forms, and does not sanitise as well as escape its form field values. As a result, attackers could make logged in admin update and delete arbitrary forms via a CSRF attack, and put Cross-Site Scripting payloads in them.

CVE-2022-0875: The Google Authenticator WordPress plugin before 1.0.5 does not have CSRF check when saving its settings, and does not sanitise as well as escape them, allowing attackers to make a logged in admin change them and perform Cross-Site Scripting attacks

CVE-2022-1578: The My wpdb WordPress plugin before 2.5 is missing CSRF check when running SQL queries, which could allow attacker to make a logged in admin run arbitrary SQL query via a CSRF attack

CVE-2022-1593: The Site Offline or Coming Soon WordPress plugin through 1.6.6 does not have CSRF check in place when updating its settings, and it also lacking sanitisation as well as escaping in some of them. As a result, attackers could make a logged in admin change them and put Cross-Site Scripting payloads in them via a CSRF attack

CVE-2022-1626: The Sharebar WordPress plugin through 1.4.1 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and also lead to Stored Cross-Site Scripting issue due to the lack of sanitisation and escaping in some of them

CVE-2022-1758: The Genki Pre-Publish Reminder WordPress plugin through 1.4.1 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored XSS as well as RCE when custom code is added via the plugin settings.

CVE-2022-1763: Due to missing checks the Static Page eXtended WordPress plugin through 2.1 is vulnerable to CSRF attacks which allows changing the plugin settings, including required user levels for specific features. This could also lead to Stored Cross-Site Scripting due to the lack of escaping in some of the settings

CVE-2022-1764: The WP-chgFontSize WordPress plugin through 1.8 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1780: The LaTeX for WordPress plugin through 3.4.10 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack which could also lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1781: The postTabs WordPress plugin through 2.10.6 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack, which also lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1787: The Sideblog WordPress plugin through 6.0 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1792: The Quick Subscribe WordPress plugin through 1.7.1 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and leading to Stored XSS due to the lack of sanitisation and escaping in some of them

CVE-2022-1818: The Multi-page Toolkit WordPress plugin through 2.6 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping as well

CVE-2022-1829: The Inline Google Maps WordPress plugin through 5.11 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack, and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1830: The Amazon Einzeltitellinks WordPress plugin through 1.3.3 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1842: The OpenBook Book Data WordPress plugin through 3.5.2 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping as well

CVE-2022-1844: The WP Sentry WordPress plugin through 1.0 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping as well

CVE-2022-1913: The Add Post URL WordPress plugin through 2.1.0 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored Cross-Site Scripting due to the lack of sanitisation and escaping

CVE-2022-1914: The Clean-Contact WordPress plugin through 1.6 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack and lead to Stored XSS due to the lack of sanitisation and escaping as well

CVE-2022-2071: The Name Directory WordPress plugin before 1.25.4 does not have CSRF check when importing names, and is also lacking sanitisation as well as escaping in some of the imported data, which could allow attackers to make a logged in admin import arbitrary names with XSS payloads in them.

CVE-2022-2146: The Import CSV Files WordPress plugin through 1.0 does not sanitise and escaped imported data before outputting them back in a page, and is lacking CSRF check when performing such action as well, resulting in a Reflected Cross-Site Scripting

CVE-2022-2171: The Progressive License WordPress plugin through 1.1.0 is lacking any CSRF check when saving its settings, which could allow attackers to make a logged in admin change them. Furthermore, as the plugin allows arbitrary HTML to be inserted in one of the settings, this could lead to Stored XSS issue which will be triggered in the frontend as well.

CVE-2022-2312: The Student Result or Employee Database WordPress plugin before 1.7.5 does not have CSRF in its AJAX actions, allowing attackers to make logged in user with a role as low as contributor to add/edit and delete students via CSRF attacks. Furthermore, due to the lack of sanitisation and escaping, it could also lead to Stored Cross-Site scripting

CVE-2022-2353: Prior to microweber/microweber v1.2.20, due to improper neutralization of input, an attacker can steal tokens to perform cross-site request forgery, fetch contents from same-site and redirect a user.

CVE-2022-2540: The Link Optimizer Lite plugin for WordPress is vulnerable to Cross-Site Request Forgery to Cross-Site Scripting in versions up to, and including 1.4.5. This is due to missing nonce validation on the admin_page function found in the ~/admin.php file. This makes it possible for unauthenticated attackers to modify the plugin's settings and inject malicious web scripts via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

CVE-2022-2541: The uContext for Amazon plugin for WordPress is vulnerable to Cross-Site Request Forgery to Cross-Site Scripting in versions up to, and including 3.9.1. This is due to missing nonce validation in the ~/app/sites/ajax/actions/keyword_save.php file that is called via the doAjax() function. This makes it possible for unauthenticated attackers to modify the plugin's settings and inject malicious web scripts via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

CVE-2022-2542: The uContext for Clickbank plugin for WordPress is vulnerable to Cross-Site Request Forgery to Cross-Site Scripting in versions up to, and including 3.9.1. This is due to missing nonce validation in the ~/app/sites/ajax/actions/keyword_save.php file that is called via the doAjax() function. This makes it possible for unauthenticated attackers to modify the plugin's settings and inject malicious web scripts via a forged request granted they can trick a site administrator into performing an action such as clicking on a link.

CVE-2022-3568: The ImageMagick Engine plugin for WordPress is vulnerable to deserialization of untrusted input via the 'cli_path' parameter in versions up to, and including 1.7.5. This makes it possible for unauthenticated users to call files using a PHAR wrapper, granted they can trick a site administrator into performing an action such as clicking on a link, that will deserialize and call arbitrary PHP Objects that can be used to perform a variety of malicious actions granted a POP chain is also present. It also requires that the attacker is successful in uploading a file with the serialized payload.

CVE-2022-35943: Shield is an authentication and authorization framework for CodeIgniter 4. This vulnerability may allow [SameSite Attackers](https://canitakeyoursubdomain.name/) to bypass the [CodeIgniter4 CSRF protection](https://codeigniter4.github.io/userguide/libraries/security.html) mechanism with CodeIgniter Shield. For this attack to succeed, the attacker must have direct (or indirect, e.g., XSS) control over a subdomain site (e.g., `https://a.example.com/`) of the target site (e.g., `http://example.com/`). Upgrade to **CodeIgniter v4.2.3 or later** and **Shield v1.0.0-beta.2 or later**. As a workaround: set `Config\\Security::$csrfProtection` to `'session,'`remove old session data right after login (immediately after ID and password match) and regenerate CSRF token right after login (immediately after ID and password match)

CVE-2022-38075: Cross-Site Request Forgery (CSRF) vulnerability leading to Stored Cross-Site Scripting (XSS) in Mantenimiento web plugin <= 0.13 on WordPress.

CVE-2022-40695: Multiple Cross-Site Scripting (CSRF) vulnerabilities in SEO Redirection Plugin plugin <= 8.9 on WordPress.

CVE-2022-41136: Cross-Site Request Forgery (CSRF) vulnerability leading to Stored Cross-Site Scripting (XSS) in Vladimir Anokhin's Shortcodes Ultimate plugin <= 5.12.0 on WordPress.

CVE-2022-44741: Cross-Site Request Forgery (CSRF) vulnerability leading to Cross-Site Scripting (XSS) in David Anderson Testimonial Slider plugin <= 1.3.1 on WordPress.

CVE-2022-3853: Cross-site Scripting (XSS) is a client-side code injection attack. The attacker aims to execute malicious scripts in a web browser of the victim by including malicious code in a legitimate web page or web application.

CVE-2022-1759: The RB Internal Links WordPress plugin through 2.0.16 does not have CSRF check in place when updating its settings, which could allow attackers to make a logged in admin change them via a CSRF attack, as well as perform Stored Cross-Site Scripting attacks due to the lack of sanitisation and escaping

CVE-2022-1967: The WP Championship WordPress plugin before 9.3 is lacking CSRF checks in various places, allowing attackers to make a logged in admin perform unwanted actions, such as create and delete arbitrary teams as well as update the plugin's settings. Due to the lack of sanitisation and escaping, it could also lead to Stored Cross-Site Scripting issues

CVE-2022-0164: The Coming soon and Maintenance mode WordPress plugin before 3.5.3 does not have authorisation and CSRF checks in its coming_soon_send_mail AJAX action, allowing any authenticated users, with a role as low as subscriber to send arbitrary emails to all subscribed users

CVE-2022-0229: The miniOrange's Google Authenticator WordPress plugin before 5.5 does not have proper authorisation and CSRF checks when handling the reconfigureMethod, and does not validate the parameters passed to it properly. As a result, unauthenticated users could delete arbitrary options from the blog, making it unusable.

CVE-2022-0345: The Customize WordPress Emails and Alerts WordPress plugin before 1.8.7 does not have authorisation and CSRF check in its bnfw_search_users AJAX action, allowing any authenticated users to call it and query for user e-mail prefixes (finding the first letter, then the second one, then the third one etc.).

CVE-2022-0363: The myCred WordPress plugin before 2.4.3.1 does not have any authorisation and CSRF checks in the mycred-tools-import-export AJAX action, allowing any authenticated users, such as subscribers, to call it and import mycred setup, thus creating badges, managing points or creating arbitrary posts.

CVE-2022-0398: The ThirstyAffiliates Affiliate Link Manager WordPress plugin before 3.10.5 does not have authorisation and CSRF checks when creating affiliate links, which could allow any authenticated user, such as subscriber to create arbitrary affiliate links, which could then be used to redirect users to an arbitrary website

CVE-2022-0403: The Library File Manager WordPress plugin before 5.2.3 is using an outdated version of the elFinder library, which is know to be affected by security issues (CVE-2021-32682), and does not have any authorisation as well as CSRF checks in its connector AJAX action, allowing any authenticated users, such as subscriber to call it. Furthermore, as the options passed to the elFinder library does not restrict any file type, users with a role as low as subscriber can Create/Upload/Delete Arbitrary files and folders.

CVE-2022-0444: The Backup, Restore and Migrate WordPress Sites With the XCloner Plugin WordPress plugin before 4.3.6 does not have authorisation and CSRF checks when resetting its settings, allowing unauthenticated attackers to reset them, including generating a new backup encryption key.

CVE-2022-23601: Symfony is a PHP framework for web and console applications and a set of reusable PHP components. The Symfony form component provides a CSRF protection mechanism by using a random token injected in the form and using the session to store and control the token submitted by the user. When using the FrameworkBundle, this protection can be enabled or disabled with the configuration. If the configuration is not specified, by default, the mechanism is enabled as long as the session is enabled. In a recent change in the way the configuration is loaded, the default behavior has been dropped and, as a result, the CSRF protection is not enabled in form when not explicitly enabled, which makes the application sensible to CSRF attacks. This issue has been resolved in the patch versions listed and users are advised to update. There are no known workarounds for this issue.

CVE-2022-23765: This vulnerability occured by sending a malicious POST request to a specific page while logged in random user from some family of IPTIME NAS. Remote attackers can steal root privileges by changing the password of the root through a POST request.

CVE-2022-27226: A CSRF issue in /api/crontab on iRZ Mobile Routers through 2022-03-16 allows a threat actor to create a crontab entry in the router administration panel. The cronjob will consequently execute the entry on the threat actor's defined interval, leading to remote code execution, allowing the threat actor to gain filesystem access. In addition, if the router's default credentials aren't rotated or a threat actor discovers valid credentials, remote code execution can be achieved without user interaction.

CVE-2022-2783: In affected versions of Octopus Server it was identified that a session cookie could be used as the CSRF token

CVE-2021-25116: The Enqueue Anything WordPress plugin through 1.0.1 does not have authorisation and CSRF checks in the remove_asset AJAX action, and does not ensure that the item to be deleted is actually an asset. As a result, low privilege users such as subscriber could delete arbitrary assets, as well as put arbitrary posts in the trash.

CVE-2022-4148: The WP OAuth Server (OAuth Authentication) WordPress plugin before 4.3.0 has a flawed CSRF and authorisation check when deleting a client, which could allow any authenticated users, such as subscriber to delete arbitrary client.

CVE-2021-24890: The Scripts Organizer WordPress plugin before 3.0 does not have capability and CSRF checks in the saveScript AJAX action, available to both unauthenticated and authenticated users, and does not validate user input in any way, which could allow unauthenticated users to put arbitrary PHP code in a file

CVE-2022-1020: The Product Table for WooCommerce (wooproducttable) WordPress plugin before 3.1.2 does not have authorisation and CSRF checks in the wpt_admin_update_notice_option AJAX action (available to both unauthenticated and authenticated users), as well as does not validate the callback parameter, allowing unauthenticated attackers to call arbitrary functions with either none or one user controlled argument

CVE-2022-2657: The Multivendor Marketplace Solution for WooCommerce WordPress plugin before 3.8.12 is lacking authorisation and CSRF in multiple AJAX actions, which could allow any authenticated users, such as subscriber to call them and suspend vendors (reporter by the submitter) or update arbitrary order status (identified by WPScan when verifying the issue) for example. Other unauthenticated attacks are also possible, either directly or via CSRF

CVE-2022-3489: The WP Hide WordPress plugin through 0.0.2 does not have authorisation and CSRF checks in place when updating the custom_wpadmin_slug settings, allowing unauthenticated attackers to update it with a crafted request

CVE-2022-3538: The Webmaster Tools Verification WordPress plugin through 1.2 does not have authorisation and CSRF checks when disabling plugins, allowing unauthenticated users to disable arbitrary plugins

CVE-2022-3585: A vulnerability classified as problematic has been found in SourceCodester Simple Cold Storage Management System 1.0. Affected is an unknown function of the file /csms/?page=contact_us of the component Contact Us. The manipulation leads to cross-site request forgery. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-211194 is the identifier assigned to this vulnerability.

CVE-2022-3582: A vulnerability has been found in SourceCodester Simple Cold Storage Management System 1.0 and classified as problematic. Affected by this vulnerability is an unknown functionality. The manipulation of the argument change password leads to cross-site request forgery. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-211189 was assigned to this vulnerability.

CVE-2022-36404: Missing Authorization, Cross-Site Request Forgery (CSRF) vulnerability in David Cole Simple SEO (WordPress plugin) plugin <= 1.8.12 versions.

CVE-2022-4349: A vulnerability classified as problematic has been found in CTF-hacker pwn. This affects an unknown part of the file delete.html. The manipulation leads to cross-site request forgery. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used. The identifier VDB-215109 was assigned to this vulnerability.

CVE-2022-4014: A vulnerability, which was classified as problematic, has been found in FeehiCMS. Affected by this issue is some unknown functionality of the component Post My Comment Tab. The manipulation leads to cross-site request forgery. The attack may be launched remotely. The identifier of this vulnerability is VDB-213788.

CVE-2022-3451: The Product Stock Manager WordPress plugin before 1.0.5 does not have authorisation and proper CSRF checks in multiple AJAX actions, allowing users with a role as low as subscriber to call them. One action in particular could allow to update arbitrary options

CVE-2021-27885: usersettings.php in e107 through 2.3.0 lacks a certain e_TOKEN protection mechanism.

# CWE-353 Missing Support for Integrity Check

## Description

The product uses a transmission protocol that does not include a mechanism for verifying the integrity of the data during transmission, such as a checksum.

If integrity check values or "checksums" are omitted from a protocol, there is no way of determining if data has been corrupted in transmission. The lack of checksum functionality in a protocol removes the first application-level check of data that can be used. The end-to-end philosophy of checks states that integrity checks should be performed at the lowest level that they can be completely implemented. Excluding further sanity checks and input validation performed by applications, the protocol's checksum is the most important level of checksum, since it can be performed more completely than at any previous level and takes into account entire messages, as opposed to single packets.

## Top 25 Examples

CVE-2022-2793: Emerson Electric's Proficy Machine Edition Version 9.00 and prior is vulenrable to CWE-353 Missing Support for Integrity Check, and has no authentication or authorization of data packets after establishing a connection for the SRTP protocol.

# CWE-354 Improper Validation of Integrity Check Value

## Description

The product does not validate or incorrectly validates the integrity check values or "checksums" of a message. This may prevent it from detecting if the data has been modified or corrupted in transmission.

Improper validation of checksums before use results in an unnecessary risk that can easily be mitigated. The protocol specification describes the algorithm used for calculating the checksum. It is then a simple matter of implementing the calculation and verifying that the calculated checksum and the received checksum match. Improper verification of the calculated checksum and the received checksum can lead to far greater consequences.

# CWE-356 Product UI does not Warn User of Unsafe Actions

## Description

The product's user interface does not warn the user before undertaking an unsafe action on behalf of that user. This makes it easier for attackers to trick users into inflicting damage to their system.

Product systems should warn users that a potentially dangerous action may occur if the user proceeds. For example, if the user downloads a file from an unknown source and attempts to execute the file on their machine, then the application's GUI can indicate that the file is unsafe.

## Observed Examples

CVE-1999-1055: Product does not warn user when document contains certain dangerous functions or macros.

CVE-1999-0794: Product does not warn user when document contains certain dangerous functions or macros.

CVE-2000-0277: Product does not warn user when document contains certain dangerous functions or macros.

CVE-2000-0517: Product does not warn user about a certificate if it has already been accepted for a different site. Possibly resultant.

CVE-2005-0602: File extractor does not warn user if setuid/setgid files could be extracted. Overlaps privileges/permissions.

CVE-2000-0342: E-mail client allows bypass of warning for dangerous attachments via a Windows .LNK file that refers to the attachment.

## Top 25 Examples

CVE-2021-44714: Acrobat Reader DC version 21.007.20099 (and earlier), 20.004.30017 (and earlier) and 17.011.30204 (and earlier) are affected by a Violation of Secure Design Principles that could lead to a Security feature bypass. Acrobat Reader DC displays a warning message when a user clicks on a PDF file, which could be used by an attacker to mislead the user. In affected versions, this warning message does not include custom protocols when used by the sender. User interaction is required to abuse this vulnerability as they would need to click 'allow' on the warning message of a malicious file.

CVE-2022-0803: Inappropriate implementation in Permissions in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to tamper with the contents of the Omnibox (URL bar) via a crafted HTML page.

CVE-2022-2622: Insufficient validation of untrusted input in Safe Browsing in Google Chrome on Windows prior to 104.0.5112.79 allowed a remote attacker to bypass download restrictions via a crafted file.

CVE-2022-3316: Insufficient validation of untrusted input in Safe Browsing in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to bypass security feature via a crafted HTML page. (Chromium security severity: Low)

CVE-2022-3317: Insufficient validation of untrusted input in Intents in Google Chrome on Android prior to 106.0.5249.62 allowed a remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Low)

# CWE-357 Insufficient UI Warning of Dangerous Operations

## Description

The user interface provides a warning to a user regarding dangerous or sensitive operations, but the warning is not noticeable enough to warrant attention.

## Observed Examples

CVE-2007-1099: User not sufficiently warned if host key mismatch occurs

## Top 25 Examples

CVE-2021-42292: Microsoft Excel Security Feature Bypass Vulnerability

CVE-2022-41904: Element iOS is an iOS Matrix client provided by Element. It is based on MatrixSDK. Prior to version 1.9.7, events encrypted using Megolm for which trust could not be established did not get decorated accordingly (with warning shields). Therefore a malicious homeserver could inject messages into the room without the user being alerted that the messages were not sent by a verified group member, even if the user has previously verified all group members. This issue has been patched in Element iOS 1.9.7. There are currently no known workarounds.

CVE-2022-3443: Insufficient data validation in File System API in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to bypass File System restrictions via a crafted HTML page. (Chromium security severity: Low)

# CWE-358 Improperly Implemented Security Check for Standard

## Description

The product does not implement or incorrectly implements one or more security-relevant checks as specified by the design of a standardized algorithm, protocol, or technique.

## Observed Examples

CVE-2002-0862: Browser does not verify Basic Constraints of a certificate, even though it is required, allowing spoofing of trusted certificates.

CVE-2002-0970: Browser does not verify Basic Constraints of a certificate, even though it is required, allowing spoofing of trusted certificates.

CVE-2002-1407: Browser does not verify Basic Constraints of a certificate, even though it is required, allowing spoofing of trusted certificates.

CVE-2005-0198: Logic error prevents some required conditions from being enforced during Challenge-Response Authentication Mechanism with MD5 (CRAM-MD5).

CVE-2004-2163: Shared secret not verified in a RADIUS response packet, allowing authentication bypass by spoofing server replies.

CVE-2005-2181: Insufficient verification in VoIP implementation, in violation of standard, allows spoofed messages.

CVE-2005-2182: Insufficient verification in VoIP implementation, in violation of standard, allows spoofed messages.

CVE-2005-2298: Security check not applied to all components, allowing bypass.

## Top 25 Examples

CVE-2022-3056: Insufficient policy enforcement in Content Security Policy in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to bypass content security policy via a crafted HTML page.

# CWE-359 Exposure of Private Personal Information to an Unauthorized Actor

## Description

The product does not properly prevent a person's private, personal information from being accessed by actors who either (1) are not explicitly authorized to access the information or (2) do not have the implicit consent of the person about whom the information is collected.

There are many types of sensitive information that products must protect from attackers, including system data, communications, configuration, business secrets, intellectual property, and an individual's personal (private) information. Private personal information may include a password, phone number, geographic location, personal messages, credit card number, etc. Private information is important to consider whether the person is a user of the product, or part of a data set that is processed by the product. An exposure of private information does not necessarily prevent the product from working properly, and in fact the exposure might be intended by the developer, e.g. as part of data sharing with other organizations. However, the exposure of personal private information can still be undesirable or explicitly prohibited by law or regulation.


Some types of private information include:


  - Government identifiers, such as Social Security Numbers

  - Contact information, such as home addresses and telephone numbers

  - Geographic location - where the user is (or was)

  - Employment history

  - Financial data - such as credit card numbers, salary, bank accounts, and debts

  - Pictures, video, or audio

  - Behavioral patterns - such as web surfing history, when certain activities are performed, etc.

  - Relationships (and types of relationships) with others - family, friends, contacts, etc.

  - Communications - e-mail addresses, private messages, text messages, chat logs, etc.

  - Health - medical conditions, insurance status, prescription records

  - Account passwords and other credentials

Some of this information may be characterized as PII (Personally Identifiable Information), Protected Health Information (PHI), etc. Categories of private information may overlap or vary based on the intended usage or the policies and practices of a particular industry.

Sometimes data that is not labeled as private can have a privacy implication in a different context. For example, student identification numbers are usually not considered private because there is no explicit and publicly-available mapping to an individual student's personal information. However, if a school generates identification numbers based on student social security numbers, then the identification numbers should be considered private.

## Top 25 Examples

CVE-2022-1365: Exposure of Private Personal Information to an Unauthorized Actor in GitHub repository lquixada/cross-fetch prior to 3.1.5.

CVE-2022-46081: In Garmin Connect 4.61, terminating a LiveTrack session wouldn't prevent the LiveTrack API from continued exposure of private personal information. NOTE: this is disputed by the vendor because the LiveTrack API service is not a customer-controlled product.

CVE-2021-46687: JFrog Artifactory prior to version 7.31.10 and 6.23.38 is vulnerable to Sensitive Data Exposure through the Project Administrator REST API. This issue affects: JFrog JFrog Artifactory JFrog Artifactory versions before 7.31.10 versions prior to 7.x; JFrog Artifactory versions before 6.23.38 versions prior to 6.x.

CVE-2022-24866: Discourse Assign is a plugin for assigning users to a topic in Discourse, an open-source messaging platform. Prior to version 1.0.1, the UserBookmarkSerializer serialized the whole User / Group object, which leaked some private information. The data was only being serialized to people who could view assignment info, which is limited to staff by default. For the vast majority of sites, this data was only leaked to trusted staff member, but for sites with assign features enabled publicly, the data was accessible to more people than just staff. Version 1.0.1 contains a patch. There are currently no known workarounds.

CVE-2022-31185: mprweb is a hosting platform for the makedeb Package Repository. Email addresses were found to not have been hidden, even if a user had clicked the `Hide Email Address` checkbox on their account page, or during signup. This could lead to an account's email being leaked, which may be problematic if your email needs to remain private for any reason. Users hosting their own mprweb instance will need to upgrade to the latest commit to get this fixed. Users on the official instance will already have this issue fixed.

# CWE-36 Absolute Path Traversal

## Description

The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as "/abs/path" that can resolve to a location that is outside of that directory.

This allows attackers to traverse the file system to access files or directories that are outside of the restricted directory.

## Observed Examples

CVE-2022-31503: Python package constructs filenames using an unsafe os.path.join call on untrusted input, allowing absolute path traversal because os.path.join resets the pathname to an absolute path that is specified as part of the input.

CVE-2002-1345: Multiple FTP clients write arbitrary files via absolute paths in server responses

CVE-2001-1269: ZIP file extractor allows full path

CVE-2002-1818: Path traversal using absolute pathname

CVE-2002-1913: Path traversal using absolute pathname

CVE-2005-2147: Path traversal using absolute pathname

CVE-2000-0614: Arbitrary files may be overwritten via compressed attachments that specify absolute path names for the decompressed output.

CVE-1999-1263: Mail client allows remote attackers to overwrite arbitrary files via an e-mail message containing a uuencoded attachment that specifies the full pathname for the file to be modified.

CVE-2003-0753: Remote attackers can read arbitrary files via a full pathname to the target file in config parameter.

CVE-2002-1525: Remote attackers can read arbitrary files via an absolute pathname.

CVE-2001-0038: Remote attackers can read arbitrary files by specifying the drive letter in the requested URL.

CVE-2001-0255: FTP server allows remote attackers to list arbitrary directories by using the "ls" command and including the drive letter name (e.g. C:) in the requested pathname.

CVE-2001-0933: FTP server allows remote attackers to list the contents of arbitrary drives via a ls command that includes the drive letter as an argument.

CVE-2002-0466: Server allows remote attackers to browse arbitrary directories via a full pathname in the arguments to certain dynamic pages.

CVE-2002-1483: Remote attackers can read arbitrary files via an HTTP request whose argument is a filename of the form "C:" (Drive letter), "//absolute/path", or ".." .

CVE-2004-2488: FTP server read/access arbitrary files using "C:\" filenames

CVE-2001-0687: FTP server allows a remote attacker to retrieve privileged web server system information by specifying arbitrary paths in the UNC format (\\computername\sharename).

## Top 25 Examples

CVE-2021-32506: Absolute Path Traversal vulnerability in GetImage in QSAN Storage Manager allows remote authenticated attackers download arbitrary files via the Url path parameter. The referred vulnerability has been solved with the updated version of QSAN Storage Manager v3.3.3 .

CVE-2022-25216: An absolute path traversal vulnerability allows a remote attacker to download any file on the Windows file system for which the user account running DVDFab 12 Player (recently renamed PlayerFab) has read-access, by means of an HTTP GET request to http://<IP_ADDRESS>:32080/download/<URL_ENCODED_PATH>.

CVE-2022-31501: The ChaoticOnyx/OnyxForum repository before 2022-05-04 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31502: The operatorequals/wormnest repository through 0.4.7 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31503: The orchest/orchest repository before 2022.05.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31504: The ChangeWeDer/BaiduWenkuSpider_flaskWeb repository before 2021-11-29 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31505: The cheo0/MercadoEnLineaBack repository through 2022-05-04 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31506: The cmusatyalab/opendiamond repository through 10.1.1 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31507: The ganga-devs/ganga repository before 8.5.10 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31508: The idayrus/evoting repository before 2022-05-08 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31509: The iedadata/usap-dc-website repository through 1.0.1 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31510: The sergeKashkin/Simple-RAT repository before 2022-05-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31511: The AFDudley/equanimity repository through 2014-04-23 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31512: The Atom02/flask-mvc repository through 2020-09-14 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31513: The BolunHan/Krypton repository through 2021-06-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31514: The Caoyongqi912/Fan_Platform repository through 2021-04-20 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31515: The Delor4/CarceresBE repository through 1.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31516: The Harveyzyh/Python repository through 2022-05-04 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31517: The HolgerGraef/MSM repository through 2021-04-20 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31518: The JustAnotherSoftwareDeveloper/Python-Recipe-Database repository through 2021-03-31 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31519: The Lukasavicus/WindMill repository through 1.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31520: The Luxas98/logstash-management-api repository through 2020-05-04 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31521: The Niyaz-Mohamed/mosaic repository through 1.0.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31522: The NotVinay/karaokey repository through 2019-12-11 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31523: The PaddlePaddle/Anakin repository through 0.1.1 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31524: The PureStorage-OpenConnect/swagger repository through 1.1.5 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31525: The SummaLabs/DLS repository through 0.1.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31526: The ThundeRatz/ThunderDocs repository through 2020-05-01 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31527: The Wildog/flask-file-server repository through 2020-02-20 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31528: The bonn-activity-maps/bam_annotation_tool repository through 2021-08-31 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31529: The cinemaproject/monorepo repository through 2021-03-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31530: The csm-aut/csm repository through 3.5 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31531: The dainst/cilantro repository through 0.0.4 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31532: The dankolbman/travel_blahg repository through 2016-01-16 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31533: The decentraminds/umbral repository through 2020-01-15 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31534: The echoleegroup/PythonWeb repository through 2018-10-31 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31535: The freefood89/Fishtank repository through 2015-06-24 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31536: The jaygarza1982/ytdl-sync repository through 2021-01-02 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31537: The jmcginty15/Solar-system-simulator repository through 2021-07-26 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31538: The joaopedro-fg/mp-m08-interface repository through 2020-12-10 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31539: The kotekan/kotekan repository through 2021.11 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31540: The kumardeepak/hin-eng-preprocessing repository through 2019-07-16 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31541: The lyubolp/Barry-Voice-Assistant repository through 2021-01-18 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31542: The mandoku/mdweb repository through 2015-05-07 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31543: The maxtortime/SetupBox repository through 1.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31544: The meerstein/rbtm repository through 1.5 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31545: The ml-inory/ModelConverter repository through 2021-04-26 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31546: The nlpweb/glance repository through 2014-06-27 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31547: The noamezekiel/sphere repository through 2020-05-31 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31548: The nrlakin/homepage repository through 2017-03-06 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31549: The olmax99/helm-flask-celery repository before 2022-05-25 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31550: The olmax99/pyathenastack repository through 2019-11-08 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31551: The pleomax00/flask-mongo-skel repository through 2012-11-01 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31552: The project-anuvaad/anuvaad-corpus repository through 2020-11-23 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31553: The rainsoupah/sleep-learner repository through 2021-02-21 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31554: The rohitnayak/movie-review-sentiment-analysis repository through 2017-05-07 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31555: The romain20100/nursequest repository through 2018-02-22 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31556: The rusyasoft/TrainEnergyServer repository through 2017-08-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31557: The seveas/golem repository through 2016-05-17 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31558: The tooxie/shiva-server repository through 0.10.0 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31559: The tsileo/flask-yeoman repository through 2013-09-13 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31560: The uncleYiba/photo_tag repository through 2020-08-31 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31561: The varijkapil13/Sphere_ImageBackend repository through 2019-10-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31562: The waveyan/internshipsystem repository through 2018-05-22 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31563: The whmacmac/vprj repository through 2022-04-06 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31564: The woduq1414/munhak-moa repository before 2022-05-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31565: The yogson/syrabond repository through 2020-05-25 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31566: The DSAB-local/DSAB repository through 2019-02-18 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31567: The DSABenchmark/DSAB repository through 2.1 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31568: The Rexians/rex-web repository through 2022-06-05 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31570: The adriankoczuruek/ceneo-web-scrapper repository through 2021-03-15 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31571: The akashtalole/python-flask-restful-api repository through 2019-09-16 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31572: The ceee-vip/cockybook repository through 2015-04-16 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31573: The chainer/chainerrl-visualizer repository through 0.1.1 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31574: The deepaliupadhyay/RealEstate repository through 2018-11-30 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31575: The duducosmos/livro_python repository through 2018-06-06 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31576: The heidi-luong1109/shackerpanel repository through 2021-05-25 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31577: The longmaoteamtf/audio_aligner_app repository through 2020-01-10 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31578: The piaoyunsoft/bt_lnmp repository through 2019-10-10 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31579: The ralphjzhang/iasset repository through 2022-05-04 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31580: The sanojtharindu/caretakerr-api repository through 2021-05-17 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31581: The scorelab/OpenMF repository before 2022-05-03 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31583: The sravaniboinepelli/AutomatedQuizEval repository through 2020-04-27 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31584: The stonethree/s3label repository through 2019-08-14 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31585: The umeshpatil-dev/Home__internet repository through 2020-08-28 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31586: The unizar-30226-2019-06/ChangePop-Back repository through 2019-06-04 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31587: The yuriyouzhou/KG-fashion-chatbot repository through 2018-05-22 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-31588: The zippies/testplatform repository through 2016-07-19 on GitHub allows absolute path traversal because the Flask send_file function is used unsafely.

CVE-2022-39812: Italtel NetMatch-S CI 5.2.0-20211008 allows Absolute Path Traversal under NMSCI-WebGui/SaveFileUploader. An unauthenticated user can upload files to an arbitrary path. An attacker can change the uploadDir parameter in a POST request (not possible using the GUI) to an arbitrary directory. Because the application does not check in which directory a file will be uploaded, an attacker can perform a variety of attacks that can result in unauthorized access to the server.

CVE-2022-39838: Systematic FIX Adapter (ALFAFX) 2.4.0.25 13/09/2017 allows remote file inclusion via a UNC share pathname, and also allows absolute path traversal to local pathnames.

CVE-2022-40443: An absolute path traversal vulnerability in ZZCMS 2022 allows attackers to obtain sensitive information via a crafted GET request sent to /one/siteinfo.php.

CVE-2022-40715: An issue was discovered in NOKIA 1350OMS R14.2. An Absolute Path Traversal vulnerability exists for a specific endpoint via the logfile parameter, allowing a remote authenticated attacker to read files on the filesystem arbitrarily.

CVE-2022-4123: A flaw was found in Buildah. The local path and the lowest subdirectory may be disclosed due to incorrect absolute path traversal, resulting in an impact to confidentiality.

CVE-2022-2943: The WordPress Infinite Scroll – Ajax Load More plugin for Wordpress is vulnerable to arbitrary file reading in versions up to, and including, 5.5.3 due to insufficient file path validation on the alm_repeaters_export() function. This makes it possible for authenticated attackers, with administrative privileges, to download arbitrary files hosted on the server that may contain sensitive content, such as the wp-config.php file.

# CWE-360 Trust of System Event Data

## Description

Security based on event locations are insecure and can be spoofed.

Events are a messaging system which may provide control data to programs listening for events. Events often do not have any type of authentication framework to allow them to be verified from a trusted source. Any application, in Windows, on a given desktop can send a message to any window on the same desktop. There is no authentication framework for these messages. Therefore, any message can be used to manipulate any process on the desktop if the process does not check the validity and safeness of those messages.

## Observed Examples

CVE-2004-0213: Attacker uses Shatter attack to bypass GUI-enforced protection for CVE-2003-0908.

# CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')

## Description

The product contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource, but a timing window exists in which the shared resource can be modified by another code sequence that is operating concurrently.

This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that should not be influenced by an outsider.


A race condition occurs within concurrent environments, and is effectively a property of a code sequence. Depending on the context, a code sequence may be in the form of a function call, a small number of instructions, a series of program invocations, etc.


A race condition violates these properties, which are closely related:


  - Exclusivity - the code sequence is given exclusive access to the shared resource, i.e., no other code sequence can modify properties of the shared resource before the original sequence has completed execution.

  - Atomicity - the code sequence is behaviorally atomic, i.e., no other thread or process can concurrently execute the same sequence of instructions (or a subset) against the same resource.

A race condition exists when an "interfering code sequence" can still access the shared resource, violating exclusivity. Programmers may assume that certain code sequences execute too quickly to be affected by an interfering code sequence; when they are not, this violates atomicity. For example, the single "x++" statement may appear atomic at the code layer, but it is actually non-atomic at the instruction layer, since it involves a read (the original value of x), followed by a computation (x+1), followed by a write (save the result to x).

The interfering code sequence could be "trusted" or "untrusted." A trusted interfering code sequence occurs within the product; it cannot be modified by the attacker, and it can only be invoked indirectly. An untrusted interfering code sequence can be authored directly by the attacker, and typically it is external to the vulnerable product.

## Observed Examples

CVE-2022-29527: Go application for cloud management creates a world-writable sudoers file that allows local attackers to inject sudo rules and escalate privileges to root by winning a race condition.

CVE-2021-1782: Chain: improper locking (CWE-667) leads to race condition (CWE-362), as exploited in the wild per CISA KEV.

CVE-2021-0920: Chain: mobile platform race condition (CWE-362) leading to use-after-free (CWE-416), as exploited in the wild per CISA KEV.

CVE-2020-6819: Chain: race condition (CWE-362) leads to use-after-free (CWE-416), as exploited in the wild per CISA KEV.

CVE-2019-18827: chain: JTAG interface is not disabled (CWE-1191) during ROM code execution, introducing a race condition (CWE-362) to extract encryption keys

CVE-2019-1161: Chain: race condition (CWE-362) in anti-malware product allows deletion of files by creating a junction (CWE-1386) and using hard links during the time window in which a temporary file is created and deleted.

CVE-2015-1743: TOCTOU in sandbox process allows installation of untrusted browser add-ons by replacing a file after it has been verified, but before it is executed

CVE-2014-8273: Chain: chipset has a race condition (CWE-362) between when an interrupt handler detects an attempt to write-enable the BIOS (in violation of the lock bit), and when the handler resets the write-enable bit back to 0, allowing attackers to issue BIOS writes during the timing window [REF-1237].

CVE-2008-5044: Race condition leading to a crash by calling a hook removal procedure while other activities are occurring at the same time.

CVE-2008-2958: chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.

CVE-2008-1570: chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.

CVE-2008-0058: Unsynchronized caching operation enables a race condition that causes messages to be sent to a deallocated object.

CVE-2008-0379: Race condition during initialization triggers a buffer overflow.

CVE-2007-6599: Daemon crash by quickly performing operations and undoing them, which eventually leads to an operation that does not acquire a lock.

CVE-2007-6180: chain: race condition triggers NULL pointer dereference

CVE-2007-5794: Race condition in library function could cause data to be sent to the wrong process.

CVE-2007-3970: Race condition in file parser leads to heap corruption.

CVE-2008-5021: chain: race condition allows attacker to access an object while it is still being initialized, causing software to access uninitialized memory.

CVE-2009-4895: chain: race condition for an argument value, possibly resulting in NULL dereference

CVE-2009-3547: chain: race condition might allow resource to be released before operating on it, leading to NULL dereference

CVE-2006-5051: Chain: Signal handler contains too much functionality (CWE-828), introducing a race condition (CWE-362) that leads to a double free (CWE-415).

## Top 25 Examples

CVE-2021-0955: In pf_write_buf of FuseDaemon.cpp, there is possible memory corruption due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-11Android ID: A-192085766

CVE-2021-30982: A race condition was addressed with improved locking. This issue is fixed in macOS Monterey 12.1, Security Update 2021-008 Catalina, macOS Big Sur 11.6.2. A remote attacker may be able to cause unexpected application termination or heap corruption.

CVE-2021-3609: .A flaw was found in the CAN BCM networking protocol in the Linux kernel, where a local attacker can abuse a flaw in the CAN subsystem to corrupt memory, crash the system or escalate privileges. This race condition in net/can/bcm.c in the Linux kernel allows for local privilege escalation to root.

CVE-2021-3752: A use-after-free flaw was found in the Linux kernel’s Bluetooth subsystem in the way user calls connect to the socket and disconnect simultaneously due to a race condition. This flaw allows a user to crash the system or escalate their privileges. The highest threat from this vulnerability is to confidentiality, integrity, as well as system availability.

CVE-2021-39642: In synchronous_process_io_entries of lwis_ioctl.c, there is a possible out of bounds write due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-195731663References: N/A

CVE-2021-39712: In TBD of TBD, there is a possible user after free vulnerability due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-176918884References: N/A

CVE-2021-39735: In gasket_alloc_coherent_memory of gasket_page_table.c, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-151455484References: N/A

CVE-2021-4083: A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race condition. This flaw allows a local user to crash the system or escalate their privileges on the system. This flaw affects Linux kernel versions prior to 5.16-rc4.

CVE-2021-4207: A flaw was found in the QXL display device emulation in QEMU. A double fetch of guest controlled values `cursor->header.width` and `cursor->header.height` can lead to the allocation of a small cursor object followed by a subsequent heap-based buffer overflow. A malicious privileged guest user could use this flaw to crash the QEMU process on the host or potentially execute arbitrary code within the context of the QEMU process.

CVE-2021-45710: An issue was discovered in the tokio crate before 1.8.4, and 1.9.x through 1.13.x before 1.13.1, for Rust. In certain circumstances involving a closed oneshot channel, there is a data race and memory corruption.

CVE-2022-1462: An out-of-bounds read flaw was found in the Linux kernel’s TeleTYpe subsystem. The issue occurs in how a user triggers a race condition using ioctls TIOCSPTLCK and TIOCGPTPEER and TIOCSTI and TCXONC with leakage of memory in the flush_to_ldisc function. This flaw allows a local user to crash the system or read unauthorized random data from memory.

CVE-2022-20032: In vow driver, there is a possible memory corruption due to a race condition. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05852822; Issue ID: ALPS05852822.

CVE-2022-20077: In vow, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is no needed for exploitation. Patch ID: ALPS05837742; Issue ID: ALPS05852812.

CVE-2022-20078: In vow, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is no needed for exploitation. Patch ID: ALPS05852819; Issue ID: ALPS05852819.

CVE-2022-20080: In SUB2AF, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is no needed for exploitation. Patch ID: ALPS05881290; Issue ID: ALPS05881290.

CVE-2022-20082: In GPU, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07044730; Issue ID: ALPS07044730.

CVE-2022-20154: In lock_sock_nested of sock.c, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174846563References: Upstream kernel

CVE-2022-20155: In ipu_core_jqs_msg_transport_kernel_write_sync of ipu-core-jqs-msg-transport.c, there is a possible use-after-free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-176754369References: N/A

CVE-2022-20256: In the Audio HAL, there is a possible out of bounds write due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-222572821

CVE-2022-20373: In st21nfc_loc_set_polaritymode of fc/st21nfc.c, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-208269510References: N/A

CVE-2022-20567: In pppol2tp_create of l2tp_ppp.c, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-186777253References: Upstream kernel

CVE-2022-21771: In GED driver, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06641585; Issue ID: ALPS06641585.

CVE-2022-21773: In TEEI driver, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06641388; Issue ID: ALPS06641388.

CVE-2022-21774: In TEEI driver, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06641447; Issue ID: ALPS06641447.

CVE-2022-21776: In MDP, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06545450; Issue ID: ALPS06545450.

CVE-2022-21789: In audio ipi, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06478101; Issue ID: ALPS06478101.

CVE-2022-22057: Use after free in graphics fence due to a race condition while closing fence file descriptor and destroy graphics timeline simultaneously in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-22208: A Use After Free vulnerability in the Routing Protocol Daemon (rdp) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated network-based attacker to cause Denial of Service (DoS). When a BGP session flap happens, a Use After Free of a memory location that was assigned to another object can occur, which will lead to an rpd crash. This is a race condition that is outside of the attacker's control and cannot be deterministically exploited. Continued flapping of BGP sessions can create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS: All versions prior to 18.4R2-S9, 18.4R3-S11; 19.1 versions prior to 19.1R3-S8; 19.2 version 19.2R1 and later versions; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to 19.4R2-S6, 19.4R3-S6; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions prior to 20.4R3-S1; 21.1 versions prior to 21.1R3-S3; 21.2 versions prior to 21.2R2-S1, 21.2R3. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S4-EVO; 21.1-EVO versions prior to 21.1R3-S2-EVO; 21.2-EVO versions prior to 21.2R3-EVO; 21.3-EVO versions prior to 21.3R2-EVO.

CVE-2022-22737: Constructing audio sinks could have lead to a race condition when playing audio files and closing windows. This could have lead to a use-after-free causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 91.5, Firefox < 96, and Thunderbird < 91.5.

CVE-2022-24949: A privilege escalation to root exists in Eternal Terminal prior to version 6.2.0. This is due to the combination of a race condition, buffer overflow, and logic bug all in PipeSocketHandler::listen().

CVE-2022-2623: Use after free in Offline in Google Chrome on Android prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-26428: In video codec, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06521260; Issue ID: ALPS06521260.

CVE-2022-26450: In apusys, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07177801; Issue ID: ALPS07177801.

CVE-2022-28796: jbd2_journal_wait_updates in fs/jbd2/transaction.c in the Linux kernel before 5.17.1 has a use-after-free caused by a transaction_t race condition.

CVE-2022-29582: In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due to a race condition in io_uring timeouts. This can be triggered by a local user who has no access to any user namespace; however, the race condition perhaps can only be exploited infrequently.

CVE-2022-2961: A use-after-free flaw was found in the Linux kernel’s PLP Rose functionality in the way a user triggers a race condition by calling bind while simultaneously triggering the rose_bind() function. This flaw allows a local user to crash or potentially escalate their privileges on the system.

CVE-2022-3028: A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem) when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read and copying it into a socket.

CVE-2022-3042: Use after free in PhoneHub in Google Chrome on Chrome OS prior to 105.0.5195.52 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3307: Use after free in media in Google Chrome prior to 106.0.5249.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-37035: An issue was discovered in bgpd in FRRouting (FRR) 8.3. In bgp_notify_send_with_data() and bgp_process_packet() in bgp_packet.c, there is a possible use-after-free due to a race condition. This could lead to Remote Code Execution or Information Disclosure by sending crafted BGP packets. User interaction is not needed for exploitation.

CVE-2022-39134: In audio driver, there is a use after free due to a race condition. This could lead to local denial of service in kernel.

CVE-2022-40307: An issue was discovered in the Linux kernel through 5.19.8. drivers/firmware/efi/capsule-loader.c has a race condition with a resultant use-after-free.

CVE-2022-44032: An issue was discovered in the Linux kernel through 6.0.6. drivers/char/pcmcia/cm4000_cs.c has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling open(), aka a race condition between cmm_open() and cm4000_detach().

CVE-2022-44033: An issue was discovered in the Linux kernel through 6.0.6. drivers/char/pcmcia/cm4040_cs.c has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling open(), aka a race condition between cm4040_open() and reader_detach().

CVE-2022-44034: An issue was discovered in the Linux kernel through 6.0.6. drivers/char/pcmcia/scr24x_cs.c has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling open(), aka a race condition between scr24x_open() and scr24x_remove().

CVE-2022-45869: A race condition in the x86 KVM subsystem in the Linux kernel through 6.1-rc6 allows guest OS users to cause a denial of service (host OS crash or host OS memory corruption) when nested virtualisation and the TDP MMU are enabled.

CVE-2022-32612: In vcu, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07203500; Issue ID: ALPS07203500.

CVE-2022-32613: In vcu, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07206340; Issue ID: ALPS07206340.

CVE-2022-20724: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-27626: A vulnerability regarding concurrent execution using shared resource with improper synchronization ('Race Condition') is found in the session processing functionality of Out-of-Band (OOB) Management. This allows remote attackers to execute arbitrary commands via unspecified vectors. The following models with Synology DiskStation Manager (DSM) versions before 7.1.1-42962-2 may be affected: DS3622xs+, FS3410, and HD6500.

CVE-2022-32645: In vow, there is a possible information disclosure due to a race condition. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494477; Issue ID: ALPS07494477.

CVE-2022-23036: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2022-23037: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2022-23038: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2022-23039: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2022-23040: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2022-23041: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2022-23042: Linux PV device frontends vulnerable to attacks by backends T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Several Linux PV device frontends are using the grant table interfaces for removing access rights of the backends in ways being subject to race conditions, resulting in potential data leaks, data corruption by malicious backends, and denial of service triggered by malicious backends: blkfront, netfront, scsifront and the gntalloc driver are testing whether a grant reference is still in use. If this is not the case, they assume that a following removal of the granted access will always succeed, which is not true in case the backend has mapped the granted page between those two operations. As a result the backend can keep access to the memory page of the guest no matter how the page will be used after the frontend I/O has finished. The xenbus driver has a similar problem, as it doesn't check the success of removing the granted access of a shared ring buffer. blkfront: CVE-2022-23036 netfront: CVE-2022-23037 scsifront: CVE-2022-23038 gntalloc: CVE-2022-23039 xenbus: CVE-2022-23040 blkfront, netfront, scsifront, usbfront, dmabuf, xenbus, 9p, kbdfront, and pvcalls are using a functionality to delay freeing a grant reference until it is no longer in use, but the freeing of the related data page is not synchronized with dropping the granted access. As a result the backend can keep access to the memory page even after it has been freed and then re-used for a different purpose. CVE-2022-23041 netfront will fail a BUG_ON() assertion if it fails to revoke access in the rx path. This will result in a Denial of Service (DoS) situation of the guest which can be triggered by the backend. CVE-2022-23042

CVE-2021-0920: In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References: Upstream kernel

CVE-2021-21166: Data race in audio in Google Chrome prior to 89.0.4389.72 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-22600: A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755

CVE-2022-26904: Windows User Profile Service Elevation of Privilege Vulnerability

CVE-2022-25090: Printix Secure Cloud Print Management through 1.3.1106.0 creates a temporary temp.ini file in a directory with insecure permissions, leading to privilege escalation because of a race condition.

CVE-2022-29527: Amazon AWS amazon-ssm-agent before 3.1.1208.0 creates a world-writable sudoers file, which allows local attackers to inject Sudo rules and escalate privileges to root. This occurs in certain situations involving a race condition.

CVE-2022-0207: A race condition was found in vdsm. Functionality to obfuscate sensitive values in log files that may lead to values being stored in clear text.

CVE-2022-21772: In TEEI driver, there is a possible type confusion due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06493842; Issue ID: ALPS06493842.

CVE-2022-22220: A Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Routing Protocol Daemon (rpd) of Juniper Networks Junos OS, Junos OS Evolved allows a network-based unauthenticated attacker to cause a Denial of Service (DoS). When a BGP flow route with redirect IP extended community is received, and the reachability to the next-hop of the corresponding redirect IP is flapping, the rpd process might crash. Whether the crash occurs depends on the timing of the internally processing of these two events and is outside the attackers control. Please note that this issue also affects Route-Reflectors unless 'routing-options flow firewall-install-disable' is configured. This issue affects: Juniper Networks Junos OS: 18.4 versions prior to 18.4R2-S10, 18.4R3-S10; 19.1 versions prior to 19.1R3-S7; 19.2 versions prior to 19.2R1-S8, 19.2R3-S4; 19.4 versions prior to 19.4R3-S8; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions prior to 20.4R3; 21.1 versions prior to 21.1R2. Juniper Networks Junos OS Evolved: All versions prior to 20.4R2-EVO; 21.1-EVO versions prior to 21.1R2-EVO. This issue does not affect Juniper Networks Junos OS versions prior to 18.4R1.

CVE-2022-22225: A Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in the Routing Protocol Daemon (rpd) of Juniper Networks Junos OS and Junos OS Evolved allows an unauthenticated attacker with an established BGP session to cause a Denial of Service (DoS). In a BGP multipath scenario, when one of the contributing routes is flapping often and rapidly, rpd may crash. As this crash depends on whether a route is a contributing route, and on the internal timing of the events triggered by the flap this vulnerability is outside the direct control of a potential attacker. This issue affects: Juniper Networks Junos OS 19.2 versions prior to 19.2R3-S6; 20.2 versions prior to 20.2R3-S4; 20.3 versions prior to 20.3R3-S3; 20.4 versions prior to 20.4R3-S4; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R2; 21.3 versions prior to 21.3R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S4-EVO; 21.1-EVO version 21.1R1-EVO and later versions; 21.2-EVO versions prior to 21.2R2-EVO; 21.3-EVO versions prior to 21.3R2-EVO. This issue does not affect: Juniper Networks Junos OS versions 19.2 versions prior to 19.2R2, 19.3R1 and above prior to 20.2R1. Juniper Networks Junos OS Evolved versions prior to 20.2R1-EVO.

CVE-2022-32844: A race condition was addressed with improved state handling. This issue is fixed in tvOS 15.6, watchOS 8.7, iOS 15.6 and iPadOS 15.6. An app with arbitrary kernel read and write capability may be able to bypass Pointer Authentication.

CVE-2021-24000: A race condition with requestPointerLock() and setTimeout() could have resulted in a user interacting with one tab when they believed they were on a separate tab. In conjunction with certain elements (such as &lt;input type="file"&gt;) this could have led to an attack where a user was confused about the origin of the webpage and potentially disclosed information they did not intend to. This vulnerability affects Firefox < 88.

CVE-2022-2160: Insufficient policy enforcement in DevTools in Google Chrome on Windows prior to 103.0.5060.53 allowed an attacker who convinced a user to install a malicious extension to obtain potentially sensitive information from a user's local files via a crafted HTML page.

CVE-2022-21881: Windows Kernel Elevation of Privilege Vulnerability

CVE-2022-21896: Windows DWM Core Library Elevation of Privilege Vulnerability

CVE-2022-24986: KDE KCron through 21.12.2 uses a temporary file in /tmp when saving, but reuses the filename during an editing session. Thus, someone watching it be created the first time could potentially intercept the file the following time, enabling that person to run unauthorized commands.

CVE-2022-3564: A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211087.

CVE-2022-3635: A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the identifier assigned to this vulnerability.

# CWE-363 Race Condition Enabling Link Following

## Description

The product checks the status of a file or directory before accessing it, which produces a race condition in which the file can be replaced with a link before the access is performed, causing the product to access the wrong file.

While developers might expect that there is a very narrow time window between the time of check and time of use, there is still a race condition. An attacker could cause the product to slow down (e.g. with memory consumption), causing the time window to become larger. Alternately, in some situations, the attacker could win the race by performing a large number of attacks.

# CWE-364 Signal Handler Race Condition

## Description

The product uses a signal handler that introduces a race condition.

Race conditions frequently occur in signal handlers, since signal handlers support asynchronous actions. These race conditions have a variety of root causes and symptoms. Attackers may be able to exploit a signal handler race condition to cause the product state to be corrupted, possibly leading to a denial of service or even code execution.


These issues occur when non-reentrant functions, or state-sensitive actions occur in the signal handler, where they may be called at any time. These behaviors can violate assumptions being made by the "regular" code that is interrupted, or by other signal handlers that may also be invoked. If these functions are called at an inopportune moment - such as while a non-reentrant function is already running - memory corruption could occur that may be exploitable for code execution. Another signal race condition commonly found occurs when free is called within a signal handler, resulting in a double free and therefore a write-what-where condition. Even if a given pointer is set to NULL after it has been freed, a race condition still exists between the time the memory was freed and the pointer was set to NULL. This is especially problematic if the same signal handler has been set for more than one signal -- since it means that the signal handler itself may be reentered.


There are several known behaviors related to signal handlers that have received the label of "signal handler race condition":


  - Shared state (e.g. global data or static variables) that are accessible to both a signal handler and "regular" code

  - Shared state between a signal handler and other signal handlers

  - Use of non-reentrant functionality within a signal handler - which generally implies that shared state is being used. For example, malloc() and free() are non-reentrant because they may use global or static data structures for managing memory, and they are indirectly used by innocent-seeming functions such as syslog(); these functions could be exploited for memory corruption and, possibly, code execution.

  - Association of the same signal handler function with multiple signals - which might imply shared state, since the same code and resources are accessed. For example, this can be a source of double-free and use-after-free weaknesses.

  - Use of setjmp and longjmp, or other mechanisms that prevent a signal handler from returning control back to the original functionality

  - While not technically a race condition, some signal handlers are designed to be called at most once, and being called more than once can introduce security problems, even when there are not any concurrent calls to the signal handler. This can be a source of double-free and use-after-free weaknesses.

Signal handler vulnerabilities are often classified based on the absence of a specific protection mechanism, although this style of classification is discouraged in CWE because programmers often have a choice of several different mechanisms for addressing the weakness. Such protection mechanisms may preserve exclusivity of access to the shared resource, and behavioral atomicity for the relevant code:

  - Avoiding shared state

  - Using synchronization in the signal handler

  - Using synchronization in the regular code

  - Disabling or masking other signals, which provides atomicity (which effectively ensures exclusivity)

## Observed Examples

CVE-1999-0035: Signal handler does not disable other signal handlers, allowing it to be interrupted, causing other functionality to access files/etc. with raised privileges

CVE-2001-0905: Attacker can send a signal while another signal handler is already running, leading to crash or execution with root privileges

CVE-2001-1349: unsafe calls to library functions from signal handler

CVE-2004-0794: SIGURG can be used to remotely interrupt signal handler; other variants exist

CVE-2004-2259: SIGCHLD signal to FTP server can cause crash under heavy load while executing non-reentrant functions like malloc/free.

# CWE-366 Race Condition within a Thread

## Description

If two threads of execution use a resource simultaneously, there exists the possibility that resources may be used while invalid, in turn making the state of execution undefined.

## Observed Examples

CVE-2022-2621: Chain: two threads in a web browser use the same resource (CWE-366), but one of those threads can destroy the resource before the other has completed (CWE-416).

## Top 25 Examples

CVE-2021-44733: A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11. This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory object.

CVE-2022-20148: In TBD of TBD, there is a possible use-after-free due to a race condition. This could lead to local escalation of privilege in the kernel with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-219513976References: Upstream kernel

CVE-2022-2607: Use after free in Tab Strip in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2608: Use after free in Overview Mode in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2609: Use after free in Nearby Share in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2617: Use after free in Extensions API in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2621: Use after free in Extensions in Google Chrome prior to 104.0.5112.79 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2857: Use after free in Blink in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2742: Use after free in Exosphere in Google Chrome on Chrome OS and Lacros prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted UI interactions. (Chrome security severity: High)

CVE-2022-2854: Use after free in SwiftShader in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3049: Use after free in SplitScreen in Google Chrome on Chrome OS, Lacros prior to 105.0.5195.52 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3071: Use after free in Tab Strip in Google Chrome on Chrome OS, Lacros prior to 105.0.5195.52 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted UI interaction.

# CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition

## Description

The product checks the state of a resource before using that resource, but the resource's state can change between the check and the use in a way that invalidates the results of the check. This can cause the product to perform invalid actions when the resource is in an unexpected state.

This weakness can be security-relevant when an attacker can influence the state of the resource between check and use. This can happen with shared resources such as files, memory, or even variables in multithreaded programs.

## Observed Examples

CVE-2015-1743: TOCTOU in sandbox process allows installation of untrusted browser add-ons by replacing a file after it has been verified, but before it is executed

CVE-2003-0813: A multi-threaded race condition allows remote attackers to cause a denial of service (crash or reboot) by causing two threads to process the same RPC request, which causes one thread to use memory after it has been freed.

CVE-2004-0594: PHP flaw allows remote attackers to execute arbitrary code by aborting execution before the initialization of key data structures is complete.

CVE-2008-2958: chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.

CVE-2008-1570: chain: time-of-check time-of-use (TOCTOU) race condition in program allows bypass of protection mechanism that was designed to prevent symlink attacks.

## Top 25 Examples

CVE-2021-35090: Possible hypervisor memory corruption due to TOC TOU race condition when updating address mappings in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2022-1974: A use-after-free flaw was found in the Linux kernel's NFC core functionality due to a race condition between kobject creation and delete. This vulnerability allows a local attacker with CAP_NET_ADMIN privilege to leak kernel information.

CVE-2022-20013: In vow driver, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05837742; Issue ID: ALPS05837742.

CVE-2022-20110: In ion, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06399915; Issue ID: ALPS06399901.

CVE-2022-22093: Memory corruption or temporary denial of service due to improper handling of concurrent hypervisor operations to attach or detach IRQs from virtual interrupt sources in Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2022-22094: memory corruption in Kernel due to race condition while getting mapping reference in Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2022-25696: Memory corruption in display due to time-of-check time-of-use race condition during map or unmap in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-25716: Memory corruption in Multimedia Framework due to unsafe access to the data members

CVE-2022-32608: In jpeg, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07388753; Issue ID: ALPS07388753.

CVE-2022-32638: In isp, there is a possible out of bounds write due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494449; Issue ID: ALPS07494449.

CVE-2022-33214: Memory corruption in display due to time-of-check time-of-use of metadata reserved size in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

CVE-2022-33257: Memory corruption in Core due to time-of-check time-of-use race condition during dump collection in trust zone.

CVE-2022-39908: TOCTOU vulnerability in Samsung decoding library for video thumbnails prior to SMR Dec-2022 Release 1 allows local attacker to perform Out-Of-Bounds Write.

CVE-2022-33909: DMA transactions which are targeted at input buffers used for the HddPassword software SMI handler could cause SMRAM corruption through a TOCTOU attack. DMA transactions which are targeted at input buffers used for the software SMI handler used by the HddPassword driver could cause SMRAM corruption through a TOCTOU attack..This issue was discovered by Insyde engineering based on the general description provided by Intel's iSTARE group. Fixed in kernel Kernel 5.2: 05.27.23, Kernel 5.3: 05.36.23, Kernel 5.4: 05.44.23, Kernel 5.5: 05.52.23 https://www.insyde.com/security-pledge/SA-2022051

CVE-2021-26350: A TOCTOU race condition in SMU may allow for the caller to obtain and manipulate the address of a message port register which may result in a potential denial of service.

CVE-2021-30342: Improper integrity check can lead to race condition between tasks PDCP and RRC? after a valid RRC Command packet has been received in Snapdragon Auto, Snapdragon Compute, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-30343: Improper integrity check can lead to race condition between tasks PDCP and RRC? after a valid RRC Command packet has been received in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2021-30347: Improper integrity check can lead to race condition between tasks PDCP and RRC? right after a valid RRC Command packet has been received in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2021-35082: Improper integrity check can lead to race condition between tasks PDCP and RRC? right after a valid RRC security mode command packet has been received in Snapdragon Industrial IOT

CVE-2021-35111: Improper validation of tag id while RRC sending tag id to MAC can lead to TOCTOU race condition in Snapdragon Connectivity, Snapdragon Mobile

CVE-2021-35937: A race condition vulnerability was found in rpm. A local unprivileged user could use this flaw to bypass the checks that were introduced in response to CVE-2017-7500 and CVE-2017-7501, potentially gaining root privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

CVE-2022-0280: A race condition vulnerability exists in the QuickClean feature of McAfee Total Protection for Windows prior to 16.0.43 that allows a local user to gain privilege elevation and perform an arbitrary file delete. This could lead to sensitive files being deleted and potentially cause denial of service. This attack exploits the way symlinks are created and how the product works with them.

CVE-2022-0915: There is a Time-of-check Time-of-use (TOCTOU) Race Condition Vulnerability in Logitech Sync for Windows prior to 2.4.574. Successful exploitation of these vulnerabilities may escalate the permission to the system user.

CVE-2022-21198: Time-of-check time-of-use race condition in the BIOS firmware for some Intel(R) Processors may allow a privileged user to potentially enable escalation of privilege via local access.

CVE-2022-23651: b2-sdk-python is a python library to access cloud storage provided by backblaze. Linux and Mac releases of the SDK version 1.14.0 and below contain a key disclosure vulnerability that, in certain conditions, can be exploited by local attackers through a time-of-check-time-of-use (TOCTOU) race condition. SDK users of the SqliteAccountInfo format are vulnerable while users of the InMemoryAccountInfo format are safe. The SqliteAccountInfo saves API keys (and bucket name-to-id mapping) in a local database file ($XDG_CONFIG_HOME/b2/account_info, ~/.b2_account_info or a user-defined path). When first created, the file is world readable and is (typically a few milliseconds) later altered to be private to the user. If the directory containing the file is readable by a local attacker then during the brief period between file creation and permission modification, a local attacker can race to open the file and maintain a handle to it. This allows the local attacker to read the contents after the file after the sensitive information has been saved to it. Consumers of this SDK who rely on it to save data using SqliteAccountInfo class should upgrade to the latest version of the SDK. Those who believe a local user might have opened a handle using this race condition, should remove the affected database files and regenerate all application keys. Users should upgrade to b2-sdk-python 1.14.1 or later.

CVE-2022-23653: B2 Command Line Tool is the official command line tool for the backblaze cloud storage service. Linux and Mac releases of the B2 command-line tool version 3.2.0 and below contain a key disclosure vulnerability that, in certain conditions, can be exploited by local attackers through a time-of-check-time-of-use (TOCTOU) race condition. The command line tool saves API keys (and bucket name-to-id mapping) in a local database file (`$XDG_CONFIG_HOME/b2/account_info`, `~/.b2_account_info` or a user-defined path) when `b2 authorize-account` is first run. This happens regardless of whether a valid key is provided or not. When first created, the file is world readable and is (typically a few milliseconds) later altered to be private to the user. If the directory is readable by a local attacker and the user did not yet run `b2 authorize-account` then during the brief period between file creation and permission modification, a local attacker can race to open the file and maintain a handle to it. This allows the local attacker to read the contents after the file after the sensitive information has been saved to it. Users that have not yet run `b2 authorize-account` should upgrade to B2 Command-Line Tool v3.2.1 before running it. Users that have run `b2 authorize-account` are safe if at the time of the file creation no other local users had read access to the local configuration file. Users that have run `b2 authorize-account` where the designated path could be opened by another local user should upgrade to B2 Command-Line Tool v3.2.1 and remove the database and regenerate all application keys. Note that `b2 clear-account` does not remove the database file and it should not be used to ensure that all open handles to the file are invalidated. If B2 Command-Line Tool cannot be upgraded to v3.2.1 due to a dependency conflict, a binary release can be used instead. Alternatively a new version could be installed within a virtualenv, or the permissions can be changed to prevent local users from opening the database file.

CVE-2022-25165: An issue was discovered in Amazon AWS VPN Client 2.0.0. A TOCTOU race condition exists during the validation of VPN configuration files. This allows parameters outside of the AWS VPN Client allow list to be injected into the configuration file prior to the AWS VPN Client service (running as SYSTEM) processing the file. Dangerous arguments can be injected by a low-level user such as log, which allows an arbitrary destination to be specified for writing log files. This leads to an arbitrary file write as SYSTEM with partial control over the files content. This can be abused to cause an elevation of privilege or denial of service.

CVE-2022-26859: Dell BIOS contains a race condition vulnerability. A local attacker could exploit this vulnerability by sending malicious input via SMI in order to bypass security checks during SMM.

CVE-2022-28743: Time-of-check Time-of-use (TOCTOU) Race Condition vulerability in Foscam R2C IP camera running System FW <= 1.13.1.6, and Application FW <= 2.91.2.66, allows an authenticated remote attacker with administrator permissions to execute arbitrary remote code via a malicious firmware patch. The impact of this vulnerability is that the remote attacker could gain full remote access to the IP camera and the underlying Linux system with root permissions. With root access to the camera's Linux OS, an attacker could effectively change the code that is running, add backdoor access, or invade the privacy of the user by accessing the live camera stream.

CVE-2022-29800: A time-of-check-time-of-use (TOCTOU) race condition vulnerability was found in networkd-dispatcher. This flaw exists because there is a certain time between the scripts being discovered and them being run. An attacker can abuse this vulnerability to replace scripts that networkd-dispatcher believes to be owned by root with ones that are not.

CVE-2022-31466: Time of Check - Time of Use (TOCTOU) vulnerability in Quick Heal Total Security prior to 12.1.1.27 allows a local attacker to achieve privilege escalation, potentially leading to deletion of system files. This is achieved through exploiting the time between detecting a file as malicious and when the action of quarantining or cleaning is performed, and using the time to replace the malicious file by a symlink.

CVE-2022-33691: A possible race condition vulnerability in score driver prior to SMR Jul-2022 Release 1 can allow local attackers to interleave malicious operations.

CVE-2022-34830: An Arm product family through 2022-06-29 has a TOCTOU Race Condition that allows non-privileged user to make improper GPU processing operations to gain access to already freed memory.

CVE-2022-34899: This vulnerability allows local attackers to escalate privileges on affected installations of Parallels Access 6.5.4 (39316) Agent. An attacker must first obtain the ability to execute low-privileged code on the target host system in order to exploit this vulnerability. The specific flaw exists within the Parallels service. By creating a symbolic link, an attacker can abuse the service to execute a file. An attacker can leverage this vulnerability to escalate privileges and execute arbitrary code in the context of root. Was ZDI-CAN-16134.

CVE-2022-3590: WordPress is affected by an unauthenticated blind SSRF in the pingback feature. Because of a TOCTOU race condition between the validation checks and the HTTP request, attackers can reach internal hosts that are explicitly forbidden.

CVE-2022-45842: Unauth. Race Condition vulnerability in WP ULike Plugin <= 4.6.4 on WordPress allows attackers to increase/decrease rating scores. 

CVE-2022-1537: file.copy operations in GruntJS are vulnerable to a TOCTOU race condition leading to arbitrary file write in GitHub repository gruntjs/grunt prior to 1.5.3. This vulnerability is capable of arbitrary file writes which can lead to local privilege escalation to the GruntJS user if a lower-privileged user has write access to both source and destination directories as the lower-privileged user can create a symlink to the GruntJS user's .bashrc file or replace /etc/shadow file if the GruntJS user is root.

CVE-2022-21658: Rust is a multi-paradigm, general-purpose programming language designed for performance and safety, especially safe concurrency. The Rust Security Response WG was notified that the `std::fs::remove_dir_all` standard library function is vulnerable a race condition enabling symlink following (CWE-363). An attacker could use this security issue to trick a privileged program into deleting files and directories the attacker couldn't otherwise access or delete. Rust 1.0.0 through Rust 1.58.0 is affected by this vulnerability with 1.58.1 containing a patch. Note that the following build targets don't have usable APIs to properly mitigate the attack, and are thus still vulnerable even with a patched toolchain: macOS before version 10.10 (Yosemite) and REDOX. We recommend everyone to update to Rust 1.58.1 as soon as possible, especially people developing programs expected to run in privileged contexts (including system daemons and setuid binaries), as those have the highest risk of being affected by this. Note that adding checks in your codebase before calling remove_dir_all will not mitigate the vulnerability, as they would also be vulnerable to race conditions like remove_dir_all itself. The existing mitigation is working as intended outside of race conditions.

CVE-2022-23563: Tensorflow is an Open Source Machine Learning Framework. In multiple places, TensorFlow uses `tempfile.mktemp` to create temporary files. While this is acceptable in testing, in utilities and libraries it is dangerous as a different process can create the file between the check for the filename in `mktemp` and the actual creation of the file by a subsequent operation (a TOC/TOU type of weakness). In several instances, TensorFlow was supposed to actually create a temporary directory instead of a file. This logic bug is hidden away by the `mktemp` function usage. We have patched the issue in several commits, replacing `mktemp` with the safer `mkstemp`/`mkdtemp` functions, according to the usage pattern. Users are advised to upgrade as soon as possible.

CVE-2021-4098: Insufficient data validation in Mojo in Google Chrome prior to 96.0.4664.110 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

# CWE-368 Context Switching Race Condition

## Description

A product performs a series of non-atomic actions to switch between contexts that cross privilege or other security boundaries, but a race condition allows an attacker to modify or misrepresent the product's behavior during the switch.

This is commonly seen in web browser vulnerabilities in which the attacker can perform certain actions while the browser is transitioning from a trusted to an untrusted domain, or vice versa, and the browser performs the actions on one domain using the trust level and resources of the other domain.

## Observed Examples

CVE-2009-1837: Chain: race condition (CWE-362) from improper handling of a page transition in web client while an applet is loading (CWE-368) leads to use after free (CWE-416)

CVE-2004-2260: Browser updates address bar as soon as user clicks on a link instead of when the page has loaded, allowing spoofing by redirecting to another page using onUnload method. ** this is one example of the role of "hooks" and context switches, and should be captured somehow - also a race condition of sorts **

CVE-2004-0191: XSS when web browser executes Javascript events in the context of a new page while it's being loaded, allowing interaction with previous page in different domain.

CVE-2004-2491: Web browser fills in address bar of clicked-on link before page has been loaded, and doesn't update afterward.

# CWE-369 Divide By Zero

## Description

The product divides a value by zero.

This weakness typically occurs when an unexpected value is provided to the product, or if an error occurs that is not properly detected. It frequently occurs in calculations involving physical dimensions such as size, length, width, and height.

## Observed Examples

CVE-2007-3268: Invalid size value leads to divide by zero.

CVE-2007-2723: "Empty" content triggers divide by zero.

CVE-2007-2237: Height value of 0 triggers divide by zero.

# CWE-37 Path Traversal: '/absolute/pathname/here'

## Description

The product accepts input in the form of a slash absolute path ('/absolute/pathname/here') without appropriate validation, which can allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2002-1345: Multiple FTP clients write arbitrary files via absolute paths in server responses

CVE-2001-1269: ZIP file extractor allows full path

CVE-2002-1818: Path traversal using absolute pathname

CVE-2002-1913: Path traversal using absolute pathname

CVE-2005-2147: Path traversal using absolute pathname

CVE-2000-0614: Arbitrary files may be overwritten via compressed attachments that specify absolute path names for the decompressed output.

# CWE-370 Missing Check for Certificate Revocation after Initial Check

## Description

The product does not check the revocation status of a certificate after its initial revocation check, which can cause the product to perform privileged actions even after the certificate is revoked at a later time.

If the revocation status of a certificate is not checked before each action that requires privileges, the system may be subject to a race condition. If a certificate is revoked after the initial check, all subsequent actions taken with the owner of the revoked certificate will lose all benefits guaranteed by the certificate. In fact, it is almost certain that the use of a revoked certificate indicates malicious activity.

# CWE-372 Incomplete Internal State Distinction

## Description

The product does not properly determine which state it is in, causing it to assume it is in state X when in fact it is in state Y, causing it to perform incorrect operations in a security-relevant manner.

## Top 25 Examples

CVE-2021-25735: A security issue was discovered in kube-apiserver that could allow node updates to bypass a Validating Admission Webhook. Clusters are only affected by this vulnerability if they run a Validating Admission Webhook for Nodes that denies admission based at least partially on the old state of the Node object. Validating Admission Webhook does not observe some previous fields.

# CWE-374 Passing Mutable Objects to an Untrusted Method

## Description

The product sends non-cloned mutable data as an argument to a method or function.

The function or method that has been called can alter or delete the mutable data. This could violate assumptions that the calling function has made about its state. In situations where unknown code is called with references to mutable data, this external code could make changes to the data sent. If this data was not previously cloned, the modified data might not be valid in the context of execution.

## Top 25 Examples

CVE-2022-1488: Inappropriate implementation in Extensions API in Google Chrome prior to 101.0.4951.41 allowed an attacker who convinced a user to install a malicious extension to leak cross-origin data via a crafted Chrome Extension.

# CWE-375 Returning a Mutable Object to an Untrusted Caller

## Description

Sending non-cloned mutable data as a return value may result in that data being altered or deleted by the calling function.

In situations where functions return references to mutable data, it is possible that the external code which called the function may make changes to the data sent. If this data was not previously cloned, the class will then be using modified data which may violate assumptions about its internal state.

# CWE-377 Insecure Temporary File

## Description

Creating and using insecure temporary files can leave application and system data vulnerable to attack.

## Observed Examples

CVE-2022-41954: A library uses the Java File.createTempFile() method which creates a file with "-rw-r--r--" default permissions on Unix-like operating systems

## Top 25 Examples

CVE-2022-0315: Insecure Temporary File in GitHub repository horovod/horovod prior to 0.24.0.

CVE-2022-24913: Versions of the package com.fasterxml.util:java-merge-sort before 1.1.0 are vulnerable to Insecure Temporary File in the StdTempFileProvider() function in StdTempFileProvider.java, which uses the permissive File.createTempFile() function, exposing temporary file contents.

CVE-2022-27772: spring-boot versions prior to version v2.2.11.RELEASE was vulnerable to temporary directory hijacking. This vulnerability impacted the org.springframework.boot.web.server.AbstractConfigurableWebServerFactory.createTempDir method. NOTE: This vulnerability only affects products and/or versions that are no longer supported by the maintainer

CVE-2022-34387:  Dell SupportAssist for Home PCs (version 3.11.4 and prior) and SupportAssist for Business PCs (version 3.2.0 and prior) contain a privilege escalation vulnerability. A local authenticated malicious user could potentially exploit this vulnerability to elevate privileges and gain total control of the system. 

CVE-2022-41954: MPXJ is an open source library to read and write project plans from a variety of file formats and databases. On Unix-like operating systems (not Windows or macos), MPXJ's use of `File.createTempFile(..)` results in temporary files being created with the permissions `-rw-r--r--`. This means that any other user on the system can read the contents of this file. When MPXJ is reading a schedule file which requires the creation of a temporary file or directory, a knowledgeable local user could locate these transient files while they are in use and would then be able to read the schedule being processed by MPXJ. The problem has been patched, MPXJ version 10.14.1 and later includes the necessary changes. Users unable to upgrade may set `java.io.tmpdir` to a directory to which only the user running the application has access will prevent other users from accessing these temporary files.

# CWE-378 Creation of Temporary File With Insecure Permissions

## Description

Opening temporary files without appropriate measures or controls can leave the file, its contents and any function that it impacts vulnerable to attack.

## Observed Examples

CVE-2022-24823: A network application framework uses the Java function createTempFile(), which will create a file that is readable by other local users of the system

## Top 25 Examples

CVE-2021-21290: Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers & clients. In Netty before version 4.1.59.Final there is a vulnerability on Unix-like systems involving an insecure temp file. When netty's multipart decoders are used local information disclosure can occur via the local system temporary directory if temporary storing uploads on the disk is enabled. On unix-like systems, the temporary directory is shared between all user. As such, writing to this directory using APIs that do not explicitly set the file/directory permissions can lead to information disclosure. Of note, this does not impact modern MacOS Operating Systems. The method "File.createTempFile" on unix-like systems creates a random file, but, by default will create this file with the permissions "-rw-r--r--". Thus, if sensitive information is written to this file, other local users can read this information. This is the case in netty's "AbstractDiskHttpData" is vulnerable. This has been fixed in version 4.1.59.Final. As a workaround, one may specify your own "java.io.tmpdir" when you start the JVM or use "DefaultHttpDataFactory.setBaseDir(...)" to set the directory to something that is only readable by the current user.

CVE-2022-45935: Usage of temporary files with insecure permissions by the Apache James server allows an attacker with local access to access private user data in transit. Vulnerable components includes the SMTP stack and IMAP APPEND command. This issue affects Apache James server version 3.7.2 and prior versions.

CVE-2022-4817: A vulnerability was found in centic9 jgit-cookbook. It has been declared as problematic. This vulnerability affects unknown code. The manipulation leads to insecure temporary file. The attack can be initiated remotely. The name of the patch is b8cb29b43dc704708d598c60ac1881db7cf8e9c3. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216988.

CVE-2021-22572: On unix-like systems, the system temporary directory is shared between all users on that system. The root cause is File.createTempFile creates files in the the system temporary directory with world readable permissions. Any sensitive information written to theses files is visible to all other local users on unix-like systems. We recommend upgrading past commit https://github.com/google/data-transfer-project/pull/969

CVE-2022-24823: Netty is an open-source, asynchronous event-driven network application framework. The package `io.netty:netty-codec-http` prior to version 4.1.77.Final contains an insufficient fix for CVE-2021-21290. When Netty's multipart decoders are used local information disclosure can occur via the local system temporary directory if temporary storing uploads on the disk is enabled. This only impacts applications running on Java version 6 and lower. Additionally, this vulnerability impacts code running on Unix-like systems, and very old versions of Mac OSX and Windows as they all share the system temporary directory between all users. Version 4.1.77.Final contains a patch for this vulnerability. As a workaround, specify one's own `java.io.tmpdir` when starting the JVM or use DefaultHttpDataFactory.setBaseDir(...) to set the directory to something that is only readable by the current user.

CVE-2022-24411: Dell PowerScale OneFS 8.2.2 and above contain an elevation of privilege vulnerability. A local attacker with ISI_PRIV_LOGIN_SSH and/or ISI_PRIV_LOGIN_CONSOLE could potentially exploit this vulnerability, leading to elevation of privilege. This could potentially allow users to circumvent PowerScale Compliance Mode guarantees.

# CWE-379 Creation of Temporary File in Directory with Insecure Permissions

## Description

The product creates a temporary file in a directory whose permissions allow unintended actors to determine the file's existence or otherwise access that file.

On some operating systems, the fact that the temporary file exists may be apparent to any user with sufficient privileges to access that directory. Since the file is visible, the application that is using the temporary file could be known. If one has access to list the processes on the system, the attacker has gained information about what the user is doing at that time. By correlating this with the applications the user is running, an attacker could potentially discover what a user's actions are. From this, higher levels of security could be breached.

## Observed Examples

CVE-2022-27818: A hotkey daemon written in Rust creates a domain socket file underneath /tmp, which is accessible by any user.

CVE-2021-21290: A Java-based application for a rapid-development framework uses File.createTempFile() to create a random temporary file with insecure default permissions.

## Top 25 Examples

CVE-2021-41988: Qlik NPrinting Designer through 21.14.3.0 creates a Temporary File in a Directory with Insecure Permissions.

CVE-2021-41989: Qlik QlikView through 12.60.20100.0 creates a Temporary File in a Directory with Insecure Permissions.

CVE-2021-42713: Splashtop Remote Client (Personal Edition) through 3.4.6.1 creates a Temporary File in a Directory with Insecure Permissions.

CVE-2021-42714: Splashtop Remote Client (Business Edition) through 3.4.8.3 creates a Temporary File in a Directory with Insecure Permissions.

CVE-2022-21126: The package com.github.samtools:htsjdk before 3.0.1 are vulnerable to Creation of Temporary File in Directory with Insecure Permissions due to the createTempDir() function in util/IOUtil.java not checking for the existence of the temporary directory before attempting to create it.

CVE-2022-3952: A vulnerability has been found in ManyDesigns Portofino 5.3.2 and classified as problematic. Affected by this vulnerability is the function createTempDir of the file WarFileLauncher.java. The manipulation leads to creation of temporary file in directory with insecure permissions. Upgrading to version 5.3.3 is able to address this issue. The name of the patch is 94653cb357806c9cf24d8d294e6afea33f8f0775. It is recommended to upgrade the affected component. The identifier VDB-213457 was assigned to this vulnerability.

CVE-2021-28633: Adobe Creative Cloud Desktop Application (installer) version 2.4 (and earlier) is affected by an Insecure temporary file creation vulnerability. An attacker could leverage this vulnerability to cause arbitrary file overwriting in the context of the current user. Exploitation of this issue requires physical interaction to the system.

CVE-2021-21428: Openapi generator is a java tool which allows generation of API client libraries (SDK generation), server stubs, documentation and configuration automatically given an OpenAPI Spec. openapi-generator-online creates insecure temporary folders with File.createTempFile during the code generation process. The insecure temporary folders store the auto-generated files which can be read and appended to by any users on the system. The issue has been patched with `Files.createTempFile` and released in the v5.1.0 stable version.

CVE-2022-27818: SWHKD 1.1.5 unsafely uses the /tmp/swhkd.sock pathname. There can be an information leak or denial of service.

CVE-2022-23950: In Keylime before 6.3.0, Revocation Notifier uses a fixed /tmp path for UNIX domain socket which can allow unprivileged users a method to prohibit keylime operations.

CVE-2022-23163: Dell PowerScale OneFS, 8.2,x, 9.1.0.x, 9.2.1.x, and 9.3.0.x contain a denial of service vulnerability. A local malicious user could potentially exploit this vulnerability, leading to denial of service/data unavailability.

CVE-2022-26850: When creating or updating credentials for single-user access, Apache NiFi wrote a copy of the Login Identity Providers configuration to the operating system temporary directory. On most platforms, the operating system temporary directory has global read permissions. NiFi immediately moved the temporary file to the final configuration directory, which significantly limited the window of opportunity for access. NiFi 1.16.0 includes updates to replace the Login Identity Providers configuration without writing a file to the operating system temporary directory.

CVE-2022-28226: Local privilege vulnerability in Yandex Browser for Windows prior to 22.3.3.801 allows a local, low privileged, attacker to execute arbitary code with the SYSTEM privileges through manipulating temporary files in directory with insecure permissions during Yandex Browser update process.

CVE-2022-41946: pgjdbc is an open source postgresql JDBC Driver. In affected versions a prepared statement using either `PreparedStatement.setText(int, InputStream)` or `PreparedStatemet.setBytea(int, InputStream)` will create a temporary file if the InputStream is larger than 2k. This will create a temporary file which is readable by other users on Unix like systems, but not MacOS. On Unix like systems, the system's temporary directory is shared between all users on that system. Because of this, when files and directories are written into this directory they are, by default, readable by other users on that same system. This vulnerability does not allow other users to overwrite the contents of these directories or files. This is purely an information disclosure vulnerability. Because certain JDK file system APIs were only added in JDK 1.7, this this fix is dependent upon the version of the JDK you are using. Java 1.7 and higher users: this vulnerability is fixed in 4.5.0. Java 1.6 and lower users: no patch is available. If you are unable to patch, or are stuck running on Java 1.6, specifying the java.io.tmpdir system environment variable to a directory that is exclusively owned by the executing user will mitigate this vulnerability.

# CWE-38 Path Traversal: '\absolute\pathname\here'

## Description

The product accepts input in the form of a backslash absolute path ('\absolute\pathname\here') without appropriate validation, which can allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-1999-1263: Mail client allows remote attackers to overwrite arbitrary files via an e-mail message containing a uuencoded attachment that specifies the full pathname for the file to be modified.

CVE-2003-0753: Remote attackers can read arbitrary files via a full pathname to the target file in config parameter.

CVE-2002-1525: Remote attackers can read arbitrary files via an absolute pathname.

# CWE-382 J2EE Bad Practices: Use of System.exit()

## Description

A J2EE application uses System.exit(), which also shuts down its container.

It is never a good idea for a web application to attempt to shut down the application container. Access to a function that can shut down the application is an avenue for Denial of Service (DoS) attacks.

# CWE-383 J2EE Bad Practices: Direct Use of Threads

## Description

Thread management in a Web application is forbidden in some circumstances and is always highly error prone.

Thread management in a web application is forbidden by the J2EE standard in some circumstances and is always highly error prone. Managing threads is difficult and is likely to interfere in unpredictable ways with the behavior of the application container. Even without interfering with the container, thread management usually leads to bugs that are hard to detect and diagnose like deadlock, race conditions, and other synchronization errors.

# CWE-384 Session Fixation

## Description

Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.

Such a scenario is commonly observed when:


  - A web application authenticates a user without first invalidating the existing session, thereby continuing to use the session already associated with the user.

  - An attacker is able to force a known session identifier on a user so that, once the user authenticates, the attacker has access to the authenticated session.

  - The application or container uses predictable session identifiers.

In the generic exploit of session fixation vulnerabilities, an attacker creates a new session on a web application and records the associated session identifier. The attacker then causes the victim to associate, and possibly authenticate, against the server using that session identifier, giving the attacker access to the user's account through the active session.

## Observed Examples

CVE-2022-2820: Website software for game servers does not proprerly terminate user sessions, allowing for possible session fixation

## Top 25 Examples

CVE-2022-2820: Session Fixation in GitHub repository namelessmc/nameless prior to v2.0.2. 

CVE-2022-31798: Nortek Linear eMerge E3-Series 0.32-07p devices are vulnerable to /card_scan.php?CardFormatNo= XSS with session fixation (via PHPSESSID) when they are chained together. This would allow an attacker to take over an admin account or a user account.

CVE-2022-26591: FANTEC GmbH MWiD25-DS Firmware v2.000.030 allows unauthenticated attackers to access and download arbitrary files via a crafted GET request.

# CWE-385 Covert Timing Channel

## Description

Covert timing channels convey information by modulating some aspect of system behavior over time, so that the program receiving the information can observe system behavior and infer protected information.

In some instances, knowing when data is transmitted between parties can provide a malicious user with privileged information. Also, externally monitoring the timing of operations can potentially reveal sensitive data. For example, a cryptographic operation can expose its internal state if the time it takes to perform the operation varies, based on the state.


Covert channels are frequently classified as either storage or timing channels. Some examples of covert timing channels are the system's paging rate, the time a certain transaction requires to execute, and the time it takes to gain access to a shared bus.

## Top 25 Examples

CVE-2022-24409: Dell BSAFE SSL-J contains remediation for a covert timing channel vulnerability that may be exploited by malicious users to compromise the affected system. Only customers with active BSAFE maintenance contracts can receive details about this vulnerability. Public disclosure of the vulnerability details will be shared at a later date.

# CWE-386 Symbolic Name not Mapping to Correct Object

## Description

A constant symbolic reference to an object is used, even though the reference can resolve to a different object over time.

# CWE-39 Path Traversal: 'C:dirname'

## Description

The product accepts input that contains a drive letter or Windows volume letter ('C:dirname') that potentially redirects access to an unintended location or arbitrary file.

## Observed Examples

CVE-2001-0038: Remote attackers can read arbitrary files by specifying the drive letter in the requested URL.

CVE-2001-0255: FTP server allows remote attackers to list arbitrary directories by using the "ls" command and including the drive letter name (e.g. C:) in the requested pathname.

CVE-2001-0687: FTP server allows a remote attacker to retrieve privileged system information by specifying arbitrary paths.

CVE-2001-0933: FTP server allows remote attackers to list the contents of arbitrary drives via a ls command that includes the drive letter as an argument.

CVE-2002-0466: Server allows remote attackers to browse arbitrary directories via a full pathname in the arguments to certain dynamic pages.

CVE-2002-1483: Remote attackers can read arbitrary files via an HTTP request whose argument is a filename of the form "C:" (Drive letter), "//absolute/path", or ".." .

CVE-2004-2488: FTP server read/access arbitrary files using "C:\" filenames

## Top 25 Examples

CVE-2021-27065: Microsoft Exchange Server Remote Code Execution Vulnerability

CVE-2022-32328: Fast Food Ordering System v1.0 is vulnerable to Delete any file. via /ffos/classes/Master.php?f=delete_img.

CVE-2022-36687: Ingredients Stock Management System v1.0 was discovered to contain an arbitrary file deletion vulnerability via the component /classes/Master.php?f=delete_img.

CVE-2022-44280: Automotive Shop Management System v1.0 is vulnerable to Delete any file via /asms/classes/Master.php?f=delete_img.

# CWE-390 Detection of Error Condition Without Action

## Description

The product detects a specific error, but takes no actions to handle the error.

## Observed Examples

CVE-2022-21820: A GPU data center manager detects an error due to a malformed request but does not act on it, leading to memory corruption.

## Top 25 Examples

CVE-2022-20057: In btif, there is a possible memory corruption due to incorrect error handling. This could lead to local escalation of privilege with System execution privileges needed. User interaction is needed for exploitation. Patch ID: ALPS06271186; Issue ID: ALPS06271186.

CVE-2021-1906: Improper handling of address deregistration on failure can lead to new GPU address allocation failure. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2022-21820: NVIDIA DCGM contains a vulnerability in nvhostengine, where a network user can cause detection of error conditions without action, which may lead to limited code execution, some denial of service, escalation of privileges, and limited impacts to both data confidentiality and integrity.

# CWE-392 Missing Report of Error Condition

## Description

The product encounters an error but does not provide a status code or return value to indicate that an error has occurred.

## Observed Examples

[REF-1374]: Chain: JavaScript-based cryptocurrency library can fall back to the insecure Math.random() function instead of reporting a failure (CWE-392), thus reducing the entropy (CWE-332) and leading to generation of non-unique cryptographic keys for Bitcoin wallets (CWE-1391)

CVE-2004-0063: Function returns "OK" even if another function returns a different status code than expected, leading to accepting an invalid PIN number.

CVE-2002-1446: Error checking routine in PKCS#11 library returns "OK" status even when invalid signature is detected, allowing spoofed messages.

CVE-2002-0499: Kernel function truncates long pathnames without generating an error, leading to operation on wrong directory.

CVE-2005-2459: Function returns non-error value when a particular erroneous condition is encountered, leading to resultant NULL dereference.

## Top 25 Examples

CVE-2022-24448: An issue was discovered in fs/nfs/dir.c in the Linux kernel before 5.16.5. If an application sets the O_DIRECTORY flag, and tries to open a regular file, nfs_atomic_open() performs a regular lookup. If a regular file is found, ENOTDIR should occur, but the server instead returns uninitialized data in the file descriptor.

# CWE-393 Return of Wrong Status Code

## Description

A function or operation returns an incorrect return value or status code that does not indicate an error, but causes the product to modify its behavior based on the incorrect result.

This can lead to unpredictable behavior. If the function is used to make security-critical decisions or provide security-critical information, then the wrong status code can cause the product to assume that an action is safe, even when it is not.

## Observed Examples

CVE-2003-1132: DNS server returns wrong response code for non-existent AAAA record, which effectively says that the domain is inaccessible.

CVE-2001-1509: Hardware-specific implementation of system call causes incorrect results from geteuid.

CVE-2001-1559: Chain: System call returns wrong value (CWE-393), leading to a resultant NULL dereference (CWE-476).

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversary-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

# CWE-394 Unexpected Status Code or Return Value

## Description

The product does not properly check when a function or operation returns a value that is legitimate for the function, but is not expected by the product.

## Observed Examples

CVE-2004-1395: Certain packets (zero byte and other lengths) cause a recvfrom call to produce an unexpected return code that causes a server's listening loop to exit.

CVE-2002-2124: Unchecked return code from recv() leads to infinite loop.

CVE-2005-2553: Kernel function does not properly handle when a null is returned by a function call, causing it to call another function that it shouldn't.

CVE-2005-1858: Memory not properly cleared when read() function call returns fewer bytes than expected.

CVE-2000-0536: Bypass access restrictions when connecting from IP whose DNS reverse lookup does not return a hostname.

CVE-2001-0910: Bypass access restrictions when connecting from IP whose DNS reverse lookup does not return a hostname.

CVE-2004-2371: Game server doesn't check return values for functions that handle text strings and associated size values.

CVE-2005-1267: Resultant infinite loop when function call returns -1 value.

## Top 25 Examples

CVE-2021-32846: HyperKit is a toolkit for embedding hypervisor capabilities in an application. In versions 0.20210107, function `pci_vtsock_proc_tx` in `virtio-sock` can lead to to uninitialized memory use. In this situation, there is a check for the return value to be less or equal to `VTSOCK_MAXSEGS`, but that check is not sufficient because the function can return `-1` if it finds an error it cannot recover from. Moreover, the negative return value will be used by `iovec_pull` in a while condition that can further lead to more corruption because the function is not designed to handle a negative `iov_len`. This issue may lead to a guest crashing the host causing a denial of service and, under certain circumstance, memory corruption. This issue is fixed in commit af5eba2360a7351c08dfd9767d9be863a50ebaba.

# CWE-395 Use of NullPointerException Catch to Detect NULL Pointer Dereference

## Description

Catching NullPointerException should not be used as an alternative to programmatic checks to prevent dereferencing a null pointer.

Programmers typically catch NullPointerException under three circumstances:


  - The program contains a null pointer dereference. Catching the resulting exception was easier than fixing the underlying problem.

  - The program explicitly throws a NullPointerException to signal an error condition.

  - The code is part of a test harness that supplies unexpected input to the classes under test.

Of these three circumstances, only the last is acceptable.

# CWE-396 Declaration of Catch for Generic Exception

## Description

Catching overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.

Multiple catch blocks can get ugly and repetitive, but "condensing" catch blocks by catching a high-level class like Exception can obscure exceptions that deserve special treatment or that should not be caught at this point in the program. Catching an overly broad exception essentially defeats the purpose of a language's typed exceptions, and can become particularly dangerous if the program grows and begins to throw new types of exceptions. The new exception types will not receive any attention.

# CWE-397 Declaration of Throws for Generic Exception

## Description

Throwing overly broad exceptions promotes complex error handling code that is more likely to contain security vulnerabilities.

Declaring a method to throw Exception or Throwable makes it difficult for callers to perform proper error handling and error recovery. Java's exception mechanism, for example, is set up to make it easy for callers to anticipate what can go wrong and write code to handle each specific exceptional circumstance. Declaring that a method throws a generic form of exception defeats this system.

