# CWE-6 J2EE Misconfiguration: Insufficient Session-ID Length

## Description

The J2EE application is configured to use an insufficient session ID length.

If an attacker can guess or steal a session ID, then they may be able to take over the user's session (called session hijacking). The number of possible session IDs increases with increased session ID length, making it more difficult to guess or steal a session ID.



Session ID's can be used to identify communicating parties in a web environment.


The expected number of seconds required to guess a valid session identifier is given by the equation: (2^B+1)/(2*A*S) Where: - B is the number of bits of entropy in the session identifier. - A is the number of guesses an attacker can try each second. - S is the number of valid session identifiers that are valid and available to be guessed at any given time. The number of bits of entropy in the session identifier is always less than the total number of bits in the session identifier. For example, if session identifiers were provided in ascending order, there would be close to zero bits of entropy in the session identifier no matter the identifier's length. Assuming that the session identifiers are being generated using a good source of random numbers, we will estimate the number of bits of entropy in a session identifier to be half the total number of bits in the session identifier. For realistic identifier lengths this is possible, though perhaps optimistic.


# CWE-600 Uncaught Exception in Servlet 

## Description

The Servlet does not catch all exceptions, which may reveal sensitive debugging information.

When a Servlet throws an exception, the default error response the Servlet container sends back to the user typically includes debugging information. This information is of great value to an attacker. For example, a stack trace might show the attacker a malformed SQL query string, the type of database being used, and the version of the application container. This information enables the attacker to target known vulnerabilities in these components.

# CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

## Description

A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.

An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL. By modifying the URL value to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. Because the server name in the modified link is identical to the original site, phishing attempts have a more trustworthy appearance. Whether this issue poses a vulnerability will be subject to the intended behavior of the application. For example, a search engine might intentionally provide redirects to arbitrary URLs.

Phishing is a general term for deceptive attempts to coerce private information from users that will be used for identity theft.

## Observed Examples

CVE-2005-4206: URL parameter loads the URL into a frame and causes it to appear to be part of a valid page.

CVE-2008-2951: An open redirect vulnerability in the search script in the software allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL as a parameter to the proper function.

CVE-2008-2052: Open redirect vulnerability in the software allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the proper parameter.

CVE-2020-11053: Chain: Go-based Oauth2 reverse proxy can send the authenticated user to another site at the end of the authentication flow. A redirect URL with HTML-encoded whitespace characters can bypass the validation (CWE-1289) to redirect to a malicious site (CWE-601)

## Top 25 Examples

CVE-2021-46379: DLink DIR850 ET850-1.08TRb03 is affected by an incorrect access control vulnerability through URL redirection to untrusted site.

CVE-2022-40083: Labstack Echo v4.8.0 was discovered to contain an open redirect vulnerability via the Static Handler component. This vulnerability can be leveraged by attackers to cause a Server-Side Request Forgery (SSRF).

CVE-2022-35406: A URL disclosure issue was discovered in Burp Suite before 2022.6. If a user views a crafted response in the Repeater or Intruder, it may be incorrectly interpreted as a redirect.

CVE-2022-31657: VMware Workspace ONE Access and Identity Manager contain a URL injection vulnerability. A malicious actor with network access may be able to redirect an authenticated user to an arbitrary domain.

# CWE-602 Client-Side Enforcement of Server-Side Security

## Description

The product is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.

When the server relies on protection mechanisms placed on the client side, an attacker can modify the client-side behavior to bypass the protection mechanisms, resulting in potentially unexpected interactions between the client and server. The consequences will vary, depending on what the mechanisms are trying to protect.

## Observed Examples

CVE-2022-33139: SCADA system only uses client-side authentication, allowing adversaries to impersonate other users.

CVE-2006-6994: ASP program allows upload of .asp files by bypassing client-side checks.

CVE-2007-0163: steganography products embed password information in the carrier file, which can be extracted from a modified client.

CVE-2007-0164: steganography products embed password information in the carrier file, which can be extracted from a modified client.

CVE-2007-0100: client allows server to modify client's configuration and overwrite arbitrary files.

## Top 25 Examples

CVE-2022-29457: Zoho ManageEngine ADSelfService Plus before 6121, ADAuditPlus 7060, Exchange Reporter Plus 5701, and ADManagerPlus 7131 allow NTLM Hash disclosure during certain storage-path configuration steps.

CVE-2022-24125: The matchmaking servers of Bandai Namco FromSoftware Dark Souls III through 2022-03-19 allow remote attackers to send arbitrary push requests to clients via a RequestSendMessageToPlayers request. For example, ability to send a push message to hundreds of thousands of machines is only restricted on the client side, and can thus be bypassed with a modified client.

CVE-2021-25648: Mobile application "Testes de Codigo" 11.4 and prior allows an attacker to gain access to the administrative interface and premium features by tampering the boolean value of parameters "isAdmin" and "isPremium" located on device storage.

CVE-2022-34397:  Dell Unisphere for PowerMax vApp, VASA Provider vApp, and Solution Enabler vApp version 10.0.0.5 and below contains an authorization bypass vulnerability, allowing users to perform actions in which they are not authorized. 

CVE-2022-38341: Safe Software FME Server v2021.2.5 and below does not employ server-side validation.

# CWE-603 Use of Client-Side Authentication

## Description

A client/server product performs authentication within client code but not in server code, allowing server-side authentication to be bypassed via a modified client that omits the authentication check.

Client-side authentication is extremely weak and may be breached easily. Any attacker may read the source code and reverse-engineer the authentication mechanism to access parts of the application which would otherwise be protected.

## Observed Examples

CVE-2022-33139: SCADA system only uses client-side authentication, allowing adversaries to impersonate other users.

CVE-2006-0230: Client-side check for a password allows access to a server using crafted XML requests from a modified client.

## Top 25 Examples

CVE-2022-1065: A vulnerability within the authentication process of Abacus ERP allows a remote attacker to bypass the second authentication factor. This issue affects: Abacus ERP v2022 versions prior to R1 of 2022-01-15; v2021 versions prior to R4 of 2022-01-15; v2020 versions prior to R6 of 2022-01-15; v2019 versions later than R5 (service pack); v2018 versions later than R5 (service pack). This issue does not affect: Abacus ERP v2019 versions prior to R5 of 2020-03-15; v2018 versions prior to R7 of 2020-04-15; v2017 version and prior versions and prior versions.

CVE-2022-31463: Owl Labs Meeting Owl 5.2.0.15 does not require a password for Bluetooth commands, because only client-side authentication is used.

CVE-2022-3218: Due to a reliance on client-side authentication, the WiFi Mouse (Mouse Server) from Necta LLC's authentication mechanism is trivially bypassed, which can result in remote code execution.

# CWE-605 Multiple Binds to the Same Port

## Description

When multiple sockets are allowed to bind to the same port, other services on that port may be stolen or spoofed.

On most systems, a combination of setting the SO_REUSEADDR socket option, and a call to bind() allows any process to bind to a port to which a previous process has bound with INADDR_ANY. This allows a user to bind to the specific address of a server bound to INADDR_ANY on an unprivileged port, and steal its UDP packets/TCP connection.

# CWE-606 Unchecked Input for Loop Condition

## Description

The product does not properly check inputs that are used for loop conditions, potentially leading to a denial of service or other consequences because of excessive looping.

## Top 25 Examples

CVE-2022-26477: The Security Team noticed that the termination condition of the for loop in the readExternal method is a controllable variable, which, if tampered with, may lead to CPU exhaustion. As a fix, we added an upper bound and termination condition in the read and write logic. We classify it as a "low-priority but useful improvement". SystemDS is a distributed system and needs to serialize/deserialize data but in many code paths (e.g., on Spark broadcast/shuffle or writing to sequence files) the byte stream is anyway protected by additional CRC fingerprints. In this particular case though, the number of decoders is upper-bounded by twice the number of columns, which means an attacker would need to modify two entries in the byte stream in a consistent manner. By adding these checks robustness was strictly improved with almost zero overhead. These code changes are available in versions higher than 2.2.1.

CVE-2022-41861: A flaw was found in freeradius. A malicious RADIUS client or home server can send a malformed abinary attribute which can cause the server to crash.

# CWE-607 Public Static Final Field References Mutable Object

## Description

A public or protected static final field references a mutable object, which allows the object to be changed by malicious code, or accidentally from another package.

# CWE-608 Struts: Non-private Field in ActionForm Class

## Description

An ActionForm class contains a field that has not been declared private, which can be accessed without using a setter or getter.

# CWE-609 Double-Checked Locking

## Description

The product uses double-checked locking to access a resource without the overhead of explicit synchronization, but the locking is insufficient.

Double-checked locking refers to the situation where a programmer checks to see if a resource has been initialized, grabs a lock, checks again to see if the resource has been initialized, and then performs the initialization if it has not occurred yet. This should not be done, as it is not guaranteed to work in all languages and on all architectures. In summary, other threads may not be operating inside the synchronous block and are not guaranteed to see the operations execute in the same order as they would appear inside the synchronous block.

# CWE-61 UNIX Symbolic Link (Symlink) Following

## Description

The product, when opening a file or directory, does not sufficiently account for when the file is a symbolic link that resolves to a target outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

A product that allows UNIX symbolic links (symlink) as part of paths whether in internal code or through user input can allow an attacker to spoof the symbolic link and traverse the file system to unintended locations or access arbitrary files. The symbolic link can permit an attacker to read/write/corrupt a file that they originally did not have permissions to access.

## Observed Examples

CVE-1999-1386: Some versions of Perl follow symbolic links when running with the -e option, which allows local users to overwrite arbitrary files via a symlink attack.

CVE-2000-1178: Text editor follows symbolic links when creating a rescue copy during an abnormal exit, which allows local users to overwrite the files of other users.

CVE-2004-0217: Antivirus update allows local users to create or append to arbitrary files via a symlink attack on a logfile.

CVE-2003-0517: Symlink attack allows local users to overwrite files.

CVE-2004-0689: Possible interesting example

CVE-2005-1879: Second-order symlink vulnerabilities

CVE-2005-1880: Second-order symlink vulnerabilities

CVE-2005-1916: Symlink in Python program

CVE-2000-0972: Setuid product allows file reading by replacing a file being edited with a symlink to the targeted file, leaking the result in error messages when parsing fails.

CVE-2005-0824: Signal causes a dump that follows symlinks.

CVE-2015-3629: A Libcontainer used in Docker Engine allows local users to escape containerization and write to an arbitrary file on the host system via a symlink attack in an image when respawning a container.

CVE-2020-26277: In a MySQL database deployment tool, users may craft a maliciously packaged tarball that contains symlinks to files external to the target and once unpacked, will execute.

CVE-2021-21272: "Zip Slip" vulnerability in Go-based Open Container Initiative (OCI) registries product allows writing arbitrary files outside intended directory via symbolic links or hard links in a gzipped tarball.

## Top 25 Examples

CVE-2022-20720: Multiple vulnerabilities in the Cisco IOx application hosting environment on multiple Cisco platforms could allow an attacker to inject arbitrary commands into the underlying host operating system, execute arbitrary code on the underlying host operating system, install applications without being authenticated, or conduct a cross-site scripting (XSS) attack against a user of the affected software. For more information about these vulnerabilities, see the Details section of this advisory.

CVE-2022-26612: In Apache Hadoop, The unTar function uses unTarUsingJava function on Windows and the built-in tar utility on Unix and other OSes. As a result, a TAR entry may create a symlink under the expected extraction directory which points to an external directory. A subsequent TAR entry may extract an arbitrary file into the external directory using the symlink name. This however would be caught by the same targetDirPath check on Unix because of the getCanonicalPath call. However on Windows, getCanonicalPath doesn't resolve symbolic links, which bypasses the check. unpackEntries during TAR extraction follows symbolic links which allows writing outside expected base directory on Windows. This was addressed in Apache Hadoop 3.2.3

CVE-2022-3592: A symlink following vulnerability was found in Samba, where a user can create a symbolic link that will make 'smbd' escape the configured share path. This flaw allows a remote user with access to the exported part of the file system under a share via SMB1 unix extensions or NFS to create symlinks to files outside the 'smbd' configured share path and gain access to another restricted server's filesystem.

CVE-2022-36113: Cargo is a package manager for the rust programming language. After a package is downloaded, Cargo extracts its source code in the ~/.cargo folder on disk, making it available to the Rust projects it builds. To record when an extraction is successful, Cargo writes "ok" to the .cargo-ok file at the root of the extracted source code once it extracted all the files. It was discovered that Cargo allowed packages to contain a .cargo-ok symbolic link, which Cargo would extract. Then, when Cargo attempted to write "ok" into .cargo-ok, it would actually replace the first two bytes of the file the symlink pointed to with ok. This would allow an attacker to corrupt one file on the machine using Cargo to extract the package. Note that by design Cargo allows code execution at build time, due to build scripts and procedural macros. The vulnerabilities in this advisory allow performing a subset of the possible damage in a harder to track down way. Your dependencies must still be trusted if you want to be protected from attacks, as it's possible to perform the same attacks with build scripts and procedural macros. The vulnerability is present in all versions of Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it. Since the vulnerability is just a more limited way to accomplish what a malicious build scripts or procedural macros can do, we decided not to publish Rust point releases backporting the security fix. Patch files are available for Rust 1.63.0 are available in the wg-security-response repository for people building their own toolchain. Mitigations We recommend users of alternate registries to exercise care in which package they download, by only including trusted dependencies in their projects. Please note that even with these vulnerabilities fixed, by design Cargo allows arbitrary code execution at build time thanks to build scripts and procedural macros: a malicious dependency will be able to cause damage regardless of these vulnerabilities. crates.io implemented server-side checks to reject these kinds of packages years ago, and there are no packages on crates.io exploiting these vulnerabilities. crates.io users still need to exercise care in choosing their dependencies though, as remote code execution is allowed by design there as well.

CVE-2022-24904: Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Argo CD starting with version 0.7.0 and prior to versions 2.1.15m 2.2.9, and 2.3.4 is vulnerable to a symlink following bug allowing a malicious user with repository write access to leak sensitive files from Argo CD's repo-server. A malicious Argo CD user with write access for a repository which is (or may be) used in a directory-type Application may commit a symlink which points to an out-of-bounds file. Sensitive files which could be leaked include manifest files from other Applications' source repositories (potentially decrypted files, if you are using a decryption plugin) or any JSON-formatted secrets which have been mounted as files on the repo-server. A patch for this vulnerability has been released in Argo CD versions 2.3.4, 2.2.9, and 2.1.15. Users of versions 2.3.0 or above who do not have any Jsonnet/directory-type Applications may disable the Jsonnet/directory config management tool as a workaround.

CVE-2022-35631: On MacOS and Linux, it may be possible to perform a symlink attack by replacing this predictable file name with a symlink to another file and have the Velociraptor client overwrite the other file. This issue was resolved in Velociraptor 0.6.5-2.

CVE-2022-45440: A vulnerability exists in the FTP server of the Zyxel AX7501-B0 firmware prior to V5.17(ABPC.3)C0, which processes symbolic links on external storage media. A local authenticated attacker with administrator privileges could abuse this vulnerability to access the root file system by creating a symbolic link on external storage media, such as a USB flash drive, and then logging into the FTP server on a vulnerable device.

CVE-2022-21944: A UNIX Symbolic Link (Symlink) Following vulnerability in the systemd service file for watchman of openSUSE Backports SLE-15-SP3, Factory allows local attackers to escalate to root. This issue affects: openSUSE Backports SLE-15-SP3 watchman versions prior to 4.9.0. openSUSE Factory watchman versions prior to 4.9.0-9.1.

CVE-2022-31250: A UNIX Symbolic Link (Symlink) Following vulnerability in keylime of openSUSE Tumbleweed allows local attackers to escalate from the keylime user to root. This issue affects: openSUSE Tumbleweed keylime versions prior to 6.4.2-1.1.

# CWE-610 Externally Controlled Reference to a Resource in Another Sphere

## Description

The product uses an externally controlled name or reference that resolves to a resource that is outside of the intended control sphere.

## Observed Examples

CVE-2022-3032: An email client does not block loading of remote objects in a nested document.

CVE-2022-45918: Chain: a learning management tool debugger uses external input to locate previous session logs (CWE-73) and does not properly validate the given path (CWE-20), allowing for filesystem path traversal using "../" sequences (CWE-24)

CVE-2018-1000613: Cryptography API uses unsafe reflection when deserializing a private key

CVE-2020-11053: Chain: Go-based Oauth2 reverse proxy can send the authenticated user to another site at the end of the authentication flow. A redirect URL with HTML-encoded whitespace characters can bypass the validation (CWE-1289) to redirect to a malicious site (CWE-601)

CVE-2022-42745: Recruiter software allows reading arbitrary files using XXE

CVE-2004-2331: Database system allows attackers to bypass sandbox restrictions by using the Reflection API.

## Top 25 Examples

CVE-2022-27593: An externally controlled reference to a resource vulnerability has been reported to affect QNAP NAS running Photo Station. If exploited, This could allow an attacker to modify system files. We have already fixed the vulnerability in the following versions: QTS 5.0.1: Photo Station 6.1.2 and later QTS 5.0.0/4.5.x: Photo Station 6.0.22 and later QTS 4.3.6: Photo Station 5.7.18 and later QTS 4.3.3: Photo Station 5.4.15 and later QTS 4.2.6: Photo Station 5.2.14 and later

CVE-2022-30190: A remote code execution vulnerability exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights. Please see the MSRC Blog Entry for important information about steps you can take to protect your system from this vulnerability. 

CVE-2022-3032: When receiving an HTML email that contained an <code>iframe</code> element, which used a <code>srcdoc</code> attribute to define the inner HTML document, remote objects specified in the nested document, for example images or videos, were not blocked. Rather, the network was accessed, the objects were loaded and displayed. This vulnerability affects Thunderbird < 102.2.1 and Thunderbird < 91.13.1.

# CWE-611 Improper Restriction of XML External Entity Reference

## Description

The product processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.

XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities. It is possible to define an entity by providing a substitution string in the form of a URI. The XML parser can access the contents of this URI and embed these contents back into the XML document for further processing.


By submitting an XML file that defines an external entity with a file:// URI, an attacker can cause the processing application to read the contents of a local file. For example, a URI such as "file:///c:/winnt/win.ini" designates (in Windows) the file C:\Winnt\win.ini, or file:///etc/passwd designates the password file in Unix-based systems. Using URIs with other schemes such as http://, the attacker can force the application to make outgoing requests to servers that the attacker cannot reach directly, which can be used to bypass firewall restrictions or hide the source of attacks such as port scanning.


Once the content of the URI is read, it is fed back into the application that is processing the XML. This application may echo back the data (e.g. in an error message), thereby exposing the file contents.

## Observed Examples

CVE-2022-42745: Recruiter software allows reading arbitrary files using XXE

CVE-2005-1306: A browser control can allow remote attackers to determine the existence of files via Javascript containing XML script.

CVE-2012-5656: XXE during SVG image conversion

CVE-2012-2239: XXE in PHP application allows reading the application's configuration file.

CVE-2012-3489: XXE in database server

CVE-2012-4399: XXE in rapid web application development framework allows reading arbitrary files.

CVE-2012-3363: XXE via XML-RPC request.

CVE-2012-0037: XXE in office document product using RDF.

CVE-2011-4107: XXE in web-based administration tool for database.

CVE-2010-3322: XXE in product that performs large-scale data analysis.

CVE-2009-1699: XXE in XSL stylesheet functionality in a common library used by some web browsers.

## Top 25 Examples

CVE-2022-23170: SysAid - Okta SSO integration - was found vulnerable to XML External Entity Injection vulnerability. Any SysAid environment that uses the Okta SSO integration might be vulnerable. An unauthenticated attacker could exploit the XXE vulnerability by sending a malformed POST request to the identity provider endpoint. An attacker can extract the identity provider endpoint by decoding the SAMLRequest parameter's value and searching for the AssertionConsumerServiceURL parameter's value. It often allows an attacker to view files on the application server filesystem and interact with any back-end or external systems that the application can access. In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other back-end infrastructure by leveraging the XXE vulnerability to perform server-side request forgery (SSRF) attacks.

CVE-2022-24449: Solar appScreener through 3.10.4, when a valid license is not present, allows XXE and SSRF attacks via a crafted XML document.

CVE-2022-2458: XML external entity injection(XXE) is a vulnerability that allows an attacker to interfere with an application's processing of XML data. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output. Here, XML external entity injection lead to External Service interaction & Internal file read in Business Central and also Kie-Server APIs.

CVE-2022-27193: CVRF-CSAF-Converter before 1.0.0-rc2 resolves XML External Entities (XXE). This leads to the inclusion of arbitrary (local) file content into the generated output document. An attacker can exploit this to disclose information from the system running the converter.

CVE-2022-3338: An External XML entity (XXE) vulnerability in ePO prior to 5.10 Update 14 can lead to an unauthenticated remote attacker to potentially trigger a Server Side Request Forgery attack. This can be exploited by mimicking the Agent Handler call to ePO and passing the carefully constructed XML file through the API.

CVE-2022-35741: Apache CloudStack version 4.5.0 and later has a SAML 2.0 authentication Service Provider plugin which is found to be vulnerable to XML external entity (XXE) injection. This plugin is not enabled by default and the attacker would require that this plugin be enabled to exploit the vulnerability. When the SAML 2.0 plugin is enabled in affected versions of Apache CloudStack could potentially allow the exploitation of XXE vulnerabilities. The SAML 2.0 messages constructed during the authentication flow in Apache CloudStack are XML-based and the XML data is parsed by various standard libraries that are now understood to be vulnerable to XXE injection attacks such as arbitrary file reading, possible denial of service, server-side request forgery (SSRF) on the CloudStack management server.

CVE-2022-38342: Safe Software FME Server v2021.2.5, v2022.0.0.2 and below was discovered to contain a XML External Entity (XXE) vulnerability which allows authenticated attackers to perform data exfiltration or Server-Side Request Forgery (SSRF) attacks.

CVE-2022-3980: An XML External Entity (XEE) vulnerability allows server-side request forgery (SSRF) and potential code execution in Sophos Mobile managed on-premises between versions 5.0.0 and 9.7.4.

CVE-2022-42745: CandidATS version 3.0.0 allows an external attacker to read arbitrary files from the server. This is possible because the application is vulnerable to XXE.

CVE-2022-45194: CBRN-Analysis before 22 allows XXE attacks via am mws XML document, leading to NTLMv2-SSP hash disclosure.

CVE-2022-45326: An XML external entity (XXE) injection vulnerability in Kwoksys Kwok Information Server before v2.9.5.SP31 allows remote authenticated users to conduct server-side request forgery (SSRF) attacks.

CVE-2022-46827: In JetBrains IntelliJ IDEA before 2022.3 an XXE attack leading to SSRF via requests to custom plugin repositories was possible.

CVE-2022-47514: An XML external entity (XXE) injection vulnerability in XML-RPC.NET before 2.5.0 allows remote authenticated users to conduct server-side request forgery (SSRF) attacks, as demonstrated by a pingback.aspx POST request.

CVE-2022-47873: Netcad KEOS 1.0 is vulnerable to XML External Entity (XXE) resulting in SSRF with XXE (remote).

# CWE-612 Improper Authorization of Index Containing Sensitive Information

## Description

The product creates a search index of private or sensitive documents, but it does not properly limit index access to actors who are authorized to see the original information.

Web sites and other document repositories may apply an indexing routine against a group of private documents to facilitate search. If the index's results are available to parties who do not have access to the documents being indexed, then attackers could obtain portions of the documents by conducting targeted searches and reading the results. The risk is especially dangerous if search results include surrounding text that was not part of the search query. This issue can appear in search engines that are not configured (or implemented) to ignore critical files that should remain hidden; even without permissions to download these files directly, the remote user could read them.

## Observed Examples

CVE-2022-41918: A search application's access control rules are not properly applied to indices for data streams, allowing for the viewing of sensitive information.

## Top 25 Examples

CVE-2022-22565: Dell PowerScale OneFS, versions 9.0.0-9.3.0, contain an improper authorization of index containing sensitive information. An authenticated and privileged user could potentially exploit this vulnerability, leading to disclosure or modification of sensitive data.

CVE-2022-35980: OpenSearch Security is a plugin for OpenSearch that offers encryption, authentication and authorization. Versions 2.0.0.0 and 2.1.0.0 of the security plugin are affected by an information disclosure vulnerability. Requests to an OpenSearch cluster configured with advanced access control features document level security (DLS), field level security (FLS), and/or field masking will not be filtered when the query's search pattern matches an aliased index. OpenSearch Dashboards creates an alias to `.kibana` by default, so filters with the index pattern of `*` to restrict access to documents or fields will not be applied. This issue allows requests to access sensitive information when customer have acted to restrict access that specific information. OpenSearch 2.2.0, which is compatible with OpenSearch Security 2.2.0.0, contains the fix for this issue. There is no recommended work around.

CVE-2022-41918: OpenSearch is a community-driven, open source fork of Elasticsearch and Kibana. There is an issue with the implementation of fine-grained access control rules (document-level security, field-level security and field masking) where they are not correctly applied to the indices that back data streams potentially leading to incorrect access authorization. OpenSearch 1.3.7 and 2.4.0 contain a fix for this issue. Users are advised to update. There are no known workarounds for this issue.

# CWE-613 Insufficient Session Expiration

## Description

According to WASC, "Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization."

## Top 25 Examples

CVE-2022-24895: Symfony is a PHP framework for web and console applications and a set of reusable PHP components. When authenticating users Symfony by default regenerates the session ID upon login, but preserves the rest of session attributes. Because this does not clear CSRF tokens upon login, this might enables same-site attackers to bypass the CSRF protection mechanism by performing an attack similar to a session-fixation. This issue has been fixed in the 4.4 branch. 

CVE-2022-43844: IBM Robotic Process Automation for Cloud Pak 20.12 through 21.0.3 is vulnerable to broken access control. A user is not correctly redirected to the platform log out screen when logging out of IBM RPA for Cloud Pak. IBM X-Force ID: 239081.

CVE-2022-30277: BD Synapsys™, versions 4.20, 4.20 SR1, and 4.30, contain an insufficient session expiration vulnerability. If exploited, threat actors may be able to access, modify or delete sensitive information, including electronic protected health information (ePHI), protected health information (PHI) and personally identifiable information (PII).

CVE-2021-29846: IBM Security Guardium Insights 3.0 could allow an authenticated user to obtain sensitive information due to insufficient session expiration. IBM X-Force ID: 205256.

CVE-2021-3844: Rapid7 InsightVM suffers from insufficient session expiration when an administrator performs a security relevant edit on an existing, logged on user. For example, if a user's password is changed by an administrator due to an otherwise unrelated credential leak, that user account's current session is still valid after the password change, potentially allowing the attacker who originally compromised the credential to remain logged in and able to cause further damage. This vulnerability is mitigated by the use of the Platform Login feature. This issue is related to CVE-2019-5638.

# CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

## Description

The Secure attribute for sensitive cookies in HTTPS sessions is not set, which could cause the user agent to send those cookies in plaintext over an HTTP session.

## Observed Examples

CVE-2004-0462: A product does not set the Secure attribute for sensitive cookies in HTTPS sessions, which could cause the user agent to send those cookies in plaintext over an HTTP session with the product.

CVE-2008-3663: A product does not set the secure flag for the session cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.

CVE-2008-3662: A product does not set the secure flag for the session cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.

CVE-2008-0128: A product does not set the secure flag for a cookie in an https session, which can cause the cookie to be sent in http requests and make it easier for remote attackers to capture this cookie.

## Top 25 Examples

CVE-2022-24045: A vulnerability has been identified in Desigo DXR2 (All versions < V01.21.142.5-22), Desigo PXC3 (All versions < V01.21.142.4-18), Desigo PXC4 (All versions < V02.20.142.10-10884), Desigo PXC5 (All versions < V02.20.142.10-10884). The application, after a successful login, sets the session cookie on the browser via client-side JavaScript code, without applying any security attributes (such as “Secure”, “HttpOnly”, or “SameSite”). Any attempts to browse the application via unencrypted HTTP protocol would lead to the transmission of all his/her session cookies in plaintext through the network. An attacker could then be able to sniff the network and capture sensitive information.

CVE-2021-37189: An issue was discovered on Digi TransPort Gateway devices through 5.2.13.4. They do not set the Secure attribute for sensitive cookies in HTTPS sessions, which could cause the user agent to send those cookies in cleartext over an HTTP session.

CVE-2022-26157: An issue was discovered in the web application in Cherwell Service Management (CSM) 10.2.3. The ASP.NET_Sessionid cookie is not protected by the Secure flag. This makes it prone to interception by an attacker if traffic is sent over unencrypted channels.

CVE-2022-27225: Gradle Enterprise before 2021.4.3 relies on cleartext data transmission in some situations. It uses Keycloak for identity management services. During the sign-in process, Keycloak sets browser cookies that effectively provide remember-me functionality. For backwards compatibility with older Safari versions, Keycloak sets a duplicate of the cookie without the Secure attribute, which allows the cookie to be sent when accessing the location that cookie is set for via HTTP. This creates the potential for an attacker (with the ability to impersonate the Gradle Enterprise host) to capture the login session of a user by having them click an http:// link to the server, despite the real server requiring HTTPS.

CVE-2021-40642: Textpattern CMS v4.8.7 and older vulnerability exists through Sensitive Cookie in HTTPS Session Without 'Secure' Attribute via textpattern/lib/txplib_misc.php. The secure flag is not set for txp_login session cookie in the application. If the secure flag is not set, then the cookie will be transmitted in clear-text if the user visits any HTTP URLs within the cookie's scope. An attacker may be able to induce this event by feeding a user suitable links, either directly or via another web site.

CVE-2022-21940: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute vulnerability in Johnson Controls System Configuration Tool (SCT) version 14 prior to 14.2.3 and version 15 prior to 15.0.3 could allow access to the cookie.

CVE-2022-3174: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository ikus060/rdiffweb prior to 2.4.2.

CVE-2022-3250: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository ikus060/rdiffweb prior to 2.4.6.

CVE-2022-3251: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository ikus060/minarca prior to 4.2.2.

CVE-2022-4409: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository thorsten/phpmyfaq prior to 3.1.9.

CVE-2022-4683: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute in GitHub repository usememos/memos prior to 0.9.0.

CVE-2022-34307: IBM CICS TX 11.1 does not set the secure attribute on authorization tokens or session cookies. Attackers may be able to get the cookie values by sending a http:// link to a user or by planting this link in a site the user goes to. The cookie will be sent to the insecure link and the attacker can then obtain the cookie value by snooping the traffic. IBM X-Force ID: 229436.

CVE-2021-40650: In Connx Version 6.2.0.1269 (20210623), a cookie can be issued by the application and not have the secure flag set.

CVE-2022-47715: In Last Yard 22.09.8-1, the cookie can be stolen via via unencrypted traffic.

# CWE-615 Inclusion of Sensitive Information in Source Code Comments

## Description

While adding general comments is very useful, some programmers tend to leave important data, such as: filenames related to the web application, old links or links which were not meant to be browsed by users, old code fragments, etc.

An attacker who finds these comments can map the application's structure and files, expose hidden parts of the site, and study the fragments of code to reverse engineer the application, which may help develop further attacks against the site.

## Observed Examples

CVE-2007-6197: Version numbers and internal hostnames leaked in HTML comments.

CVE-2007-4072: CMS places full pathname of server in HTML comment.

CVE-2009-2431: blog software leaks real username in HTML comment.

# CWE-616 Incomplete Identification of Uploaded File Variables (PHP)

## Description

The PHP application uses an old method for processing uploaded files by referencing the four global variables that are set for each file (e.g. $varname, $varname_size, $varname_name, $varname_type). These variables could be overwritten by attackers, causing the application to process unauthorized files.

These global variables could be overwritten by POST requests, cookies, or other methods of populating or overwriting these variables. This could be used to read or process arbitrary files by providing values such as "/etc/passwd".

## Observed Examples

CVE-2002-1460: Forum does not properly verify whether a file was uploaded or if the associated variables were set by POST, allowing remote attackers to read arbitrary files.

CVE-2002-1759: Product doesn't check if the variables for an upload were set by uploading the file, or other methods such as $_POST.

CVE-2002-1710: Product does not distinguish uploaded file from other files.

# CWE-617 Reachable Assertion

## Description

The product contains an assert() or similar statement that can be triggered by an attacker, which leads to an application exit or other behavior that is more severe than necessary.

While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.


For example, if a server handles multiple simultaneous connections, and an assert() occurs in one single connection that causes all other connections to be dropped, this is a reachable assertion that leads to a denial of service.

## Observed Examples

CVE-2023-49286: Chain: function in web caching proxy does not correctly check a return value (CWE-253) leading to a reachable assertion (CWE-617)

CVE-2006-6767: FTP server allows remote attackers to cause a denial of service (daemon abort) via crafted commands which trigger an assertion failure.

CVE-2006-6811: Chat client allows remote attackers to cause a denial of service (crash) via a long message string when connecting to a server, which causes an assertion failure.

CVE-2006-5779: Product allows remote attackers to cause a denial of service (daemon crash) via LDAP BIND requests with long authcid names, which triggers an assertion failure.

CVE-2006-4095: Product allows remote attackers to cause a denial of service (crash) via certain queries, which cause an assertion failure.

CVE-2006-4574: Chain: security monitoring product has an off-by-one error that leads to unexpected length values, triggering an assertion.

CVE-2004-0270: Anti-virus product has assert error when line length is non-numeric.

## Top 25 Examples

CVE-2022-31620: In libjpeg before 1.64, BitStream<false>::Get in bitstream.hpp has an assertion failure that may cause denial of service. This is related to out-of-bounds array access during arithmetically coded lossless scan or arithmetically coded sequential scan.

CVE-2022-31100: rulex is a new, portable, regular expression language. When parsing untrusted rulex expressions, rulex may crash, possibly enabling a Denial of Service attack. This happens when the expression contains a multi-byte UTF-8 code point in a string literal or after a backslash, because rulex tries to slice into the code point and panics as a result. This is a security concern for you, if your service parses untrusted rulex expressions (expressions provided by an untrusted user), and your service becomes unavailable when the thread running rulex panics. The crashes are fixed in version **0.4.3**. Affected users are advised to update to this version. The only known workaround for this issue is to assume that regular expression parsing will panic and to add logic to catch panics.

CVE-2022-3488: Processing of repeated responses to the same query, where both responses contain ECS pseudo-options, but where the first is broken in some way, can cause BIND to exit with an assertion failure. 'Broken' in this context is anything that would cause the resolver to reject the query response, such as a mismatch between query and answer name. This issue affects BIND 9 versions 9.11.4-S1 through 9.11.37-S1 and 9.16.8-S1 through 9.16.36-S1.

CVE-2022-36004: TensorFlow is an open source platform for machine learning. When `tf.random.gamma` receives large input shape and rates, it gives a `CHECK` fail that can trigger a denial of service attack. We have patched the issue in GitHub commit 552bfced6ce4809db5f3ca305f60ff80dd40c5a3. The fix will be included in TensorFlow 2.10.0. We will also cherrypick this commit on TensorFlow 2.9.1, TensorFlow 2.8.1, and TensorFlow 2.7.2, as these are also affected and still in supported range. There are no known workarounds for this issue.

CVE-2022-48363: In MPD before 0.23.8, as used on Automotive Grade Linux and other platforms, the PipeWire output plugin mishandles a Drain call in certain situations involving truncated files. Eventually there is an assertion failure in libmpdclient because libqtappfw passes in a NULL pointer.

CVE-2022-23572: Tensorflow is an Open Source Machine Learning Framework. Under certain scenarios, TensorFlow can fail to specialize a type during shape inference. This case is covered by the `DCHECK` function however, `DCHECK` is a no-op in production builds and an assertion failure in debug builds. In the first case execution proceeds to the `ValueOrDie` line. This results in an assertion failure as `ret` contains an error `Status`, not a value. In the second case we also get a crash due to the assertion failure. The fix will be included in TensorFlow 2.8.0. We will also cherrypick this commit on TensorFlow 2.7.1, and TensorFlow 2.6.3, as these are also affected and still in supported range.

CVE-2021-46784: In Squid 3.x through 3.5.28, 4.x through 4.17, and 5.x before 5.6, due to improper buffer management, a Denial of Service can occur when processing long Gopher server responses.

# CWE-618 Exposed Unsafe ActiveX Method

## Description

An ActiveX control is intended for use in a web browser, but it exposes dangerous methods that perform actions that are outside of the browser's security model (e.g. the zone or domain).

ActiveX controls can exercise far greater control over the operating system than typical Java or javascript. Exposed methods can be subject to various vulnerabilities, depending on the implemented behaviors of those methods, and whether input validation is performed on the provided arguments. If there is no integrity checking or origin validation, this method could be invoked by attackers.

## Observed Examples

CVE-2007-1120: download a file to arbitrary folders.

CVE-2006-6838: control downloads and executes a url in a parameter

CVE-2007-0321: resultant buffer overflow

# CWE-619 Dangling Database Cursor ('Cursor Injection')

## Description

If a database cursor is not closed properly, then it could become accessible to other users while retaining the same privileges that were originally assigned, leaving the cursor "dangling."

For example, an improper dangling cursor could arise from unhandled exceptions. The impact of the issue depends on the cursor's role, but SQL injection attacks are commonly possible.

A cursor is a feature in Oracle PL/SQL and other languages that provides a handle for executing and accessing the results of SQL queries.

# CWE-62 UNIX Hard Link

## Description

The product, when opening a file or directory, does not sufficiently account for when the name is associated with a hard link to a target that is outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

Failure for a system to check for hard links can result in vulnerability to different types of attacks. For example, an attacker can escalate their privileges if a file used by a privileged program is replaced with a hard link to a sensitive file (e.g. /etc/passwd). When the process opens the file, the attacker can assume the privileges of that process.

## Observed Examples

CVE-2001-1494: Hard link attack, file overwrite; interesting because program checks against soft links

CVE-2002-0793: Hard link and possibly symbolic link following vulnerabilities in embedded operating system allow local users to overwrite arbitrary files.

CVE-2003-0578: Server creates hard links and unlinks files as root, which allows local users to gain privileges by deleting and overwriting arbitrary files.

CVE-1999-0783: Operating system allows local users to conduct a denial of service by creating a hard link from a device special file to a file on an NFS file system.

CVE-2004-1603: Web hosting manager follows hard links, which allows local users to read or modify arbitrary files.

CVE-2004-1901: Package listing system allows local users to overwrite arbitrary files via a hard link attack on the lockfiles.

CVE-2005-0342: The Finder in Mac OS X and earlier allows local users to overwrite arbitrary files and gain privileges by creating a hard link from the .DS_Store file to an arbitrary file.

CVE-2005-1111: Hard link race condition

CVE-2021-21272: "Zip Slip" vulnerability in Go-based Open Container Initiative (OCI) registries product allows writing arbitrary files outside intended directory via symbolic links or hard links in a gzipped tarball.

CVE-2003-1366: setuid root tool allows attackers to read secret data by replacing a temp file with a hard link to a sensitive file

# CWE-620 Unverified Password Change

## Description

When setting a new password for a user, the product does not require knowledge of the original password, or using another form of authentication.

This could be used by an attacker to change passwords for another user, thus gaining the privileges associated with that user.

## Observed Examples

CVE-2007-0681: Web app allows remote attackers to change the passwords of arbitrary users without providing the original password, and possibly perform other unauthorized actions.

CVE-2000-0944: Web application password change utility doesn't check the original password.

## Top 25 Examples

CVE-2022-21935: A vulnerability in Metasys ADS/ADX/OAS 10 versions prior to 10.1.5 and Metasys ADS/ADX/OAS 11 versions prior to 11.0.2 allows unverified password change.

CVE-2022-27484: A unverified password change in Fortinet FortiADC version 6.2.0 through 6.2.3, 6.1.x, 6.0.x, 5.x.x allows an authenticated attacker to bypass the Old Password check in the password change form via a crafted HTTP request.

CVE-2022-3152: Unverified Password Change in GitHub repository phpfusion/phpfusion prior to 9.10.20.

CVE-2022-21934: Under certain circumstances an authenticated user could lock other users out of the system or take over their accounts in Metasys ADS/ADX/OAS server 10 versions prior to 10.1.5 and Metasys ADS/ADX/OAS server 11 versions prior to 11.0.2.

CVE-2022-24551: A flaw was found in StarWind Stack. The endpoint for setting a new password doesn’t check the current username and old password. An attacker could reset any local user password (including system/administrator user) using any available user This affects StarWind SAN and NAS v0.2 build 1633.

CVE-2022-0862: A lack of password change protection vulnerability in a depreciated API of McAfee Enterprise ePolicy Orchestrator (ePO) prior to 5.10 Update 13 allows a remote attacker to change the password of a compromised session without knowing the existing user's password. This functionality was removed from the User Interface in ePO 10 and the API has now been disabled. Other protection is in place to reduce the likelihood of this being successful through sending a link to a logged in user.

# CWE-621 Variable Extraction Error

## Description

The product uses external input to determine the names of variables into which information is extracted, without verifying that the names of the specified variables are valid. This could cause the program to overwrite unintended variables.

For example, in PHP, extraction can be used to provide functionality similar to register_globals, a dangerous functionality that is frequently disabled in production systems. Calling extract() or import_request_variables() without the proper arguments could allow arbitrary global variables to be overwritten, including superglobals.


Similar functionality is possible in other interpreted languages, including custom languages.

## Observed Examples

CVE-2006-7135: extract issue enables file inclusion

CVE-2006-7079: Chain: PHP app uses extract for register_globals compatibility layer (CWE-621), enabling path traversal (CWE-22)

CVE-2007-0649: extract() buried in include files makes post-disclosure analysis confusing; original report had seemed incorrect.

CVE-2006-6661: extract() enables static code injection

CVE-2006-2828: import_request_variables() buried in include files makes post-disclosure analysis confusing

# CWE-622 Improper Validation of Function Hook Arguments

## Description

The product adds hooks to user-accessible API functions, but it does not properly validate the arguments. This could lead to resultant vulnerabilities.

Such hooks can be used in defensive software that runs with privileges, such as anti-virus or firewall, which hooks kernel calls. When the arguments are not validated, they could be used to bypass the protection scheme or attack the product itself.

## Observed Examples

CVE-2007-0708: DoS in firewall using standard Microsoft functions

CVE-2006-7160: DoS in firewall using standard Microsoft functions

CVE-2007-1376: function does not verify that its argument is the proper type, leading to arbitrary memory write

CVE-2007-1220: invalid syscall arguments bypass code execution limits

CVE-2006-4541: DoS in IDS via NULL argument

# CWE-623 Unsafe ActiveX Control Marked Safe For Scripting

## Description

An ActiveX control is intended for restricted use, but it has been marked as safe-for-scripting.

This might allow attackers to use dangerous functionality via a web page that accesses the control, which can lead to different resultant vulnerabilities, depending on the control's behavior.

## Observed Examples

CVE-2007-0617: control allows attackers to add malicious email addresses to bypass spam limits

CVE-2007-0219: web browser uses certain COM objects as ActiveX

CVE-2006-6510: kiosk allows bypass to read files

# CWE-624 Executable Regular Expression Error

## Description

The product uses a regular expression that either (1) contains an executable component with user-controlled inputs, or (2) allows a user to enable execution by inserting pattern modifiers.

Case (2) is possible in the PHP preg_replace() function, and possibly in other languages when a user-controlled input is inserted into a string that is later parsed as a regular expression.

## Observed Examples

CVE-2006-2059: Executable regexp in PHP by inserting "e" modifier into first argument to preg_replace

CVE-2005-3420: Executable regexp in PHP by inserting "e" modifier into first argument to preg_replace

CVE-2006-2878: Complex curly syntax inserted into the replacement argument to PHP preg_replace(), which uses the "/e" modifier

CVE-2006-2908: Function allows remote attackers to execute arbitrary PHP code via the username field, which is used in a preg_replace function call with a /e (executable) modifier.

# CWE-625 Permissive Regular Expression

## Description

The product uses a regular expression that does not sufficiently restrict the set of allowed values.

This effectively causes the regexp to accept substrings that match the pattern, which produces a partial comparison to the target. In some cases, this can lead to other weaknesses. Common errors include:


  - not identifying the beginning and end of the target string

  - using wildcards instead of acceptable character ranges

  - others

## Observed Examples

CVE-2021-22204: Chain: regex in EXIF processor code does not correctly determine where a string ends (CWE-625), enabling eval injection (CWE-95), as exploited in the wild per CISA KEV.

CVE-2006-1895: ".*" regexp leads to static code injection

CVE-2002-2175: insertion of username into regexp results in partial comparison, causing wrong database entry to be updated when one username is a substring of another.

CVE-2006-4527: regexp intended to verify that all characters are legal, only checks that at least one is legal, enabling file inclusion.

CVE-2005-1949: Regexp for IP address isn't anchored at the end, allowing appending of shell metacharacters.

CVE-2002-2109: Regexp isn't "anchored" to the beginning or end, which allows spoofed values that have trusted values as substrings.

CVE-2006-6511: regexp in .htaccess file allows access of files whose names contain certain substrings

CVE-2006-6629: allow load of macro files whose names contain certain substrings.

## Top 25 Examples

CVE-2022-42975: socket/transport.ex in Phoenix before 1.6.14 mishandles check_origin wildcarding. NOTE: LiveView applications are unaffected by default because of the presence of a LiveView CSRF token.

CVE-2022-42717: An issue was discovered in Hashicorp Packer before 2.3.1. The recommended sudoers configuration for Vagrant on Linux is insecure. If the host has been configured according to this documentation, non-privileged users on the host can leverage a wildcard in the sudoers configuration to execute arbitrary commands as root.

CVE-2021-35368: OWASP ModSecurity Core Rule Set 3.1.x before 3.1.2, 3.2.x before 3.2.1, and 3.3.x before 3.3.2 is affected by a Request Body Bypass via a trailing pathname.

# CWE-626 Null Byte Interaction Error (Poison Null Byte)

## Description

The product does not properly handle null bytes or NUL characters when passing data between different representations or components.

A null byte (NUL character) can have different meanings across representations or languages. For example, it is a string terminator in standard C libraries, but Perl and PHP strings do not treat it as a terminator. When two representations are crossed - such as when Perl or PHP invokes underlying C functionality - this can produce an interaction error with unexpected results. Similar issues have been reported for ASP. Other interpreters written in C might also be affected.


The poison null byte is frequently useful in path traversal attacks by terminating hard-coded extensions that are added to a filename. It can play a role in regular expression processing in PHP.

## Observed Examples

CVE-2005-4155: NUL byte bypasses PHP regular expression check

CVE-2005-3153: inserting SQL after a NUL byte bypasses allowlist regexp, enabling SQL injection

## Top 25 Examples

CVE-2022-25219: A null byte interaction error has been discovered in the code that the telnetd_startup daemon uses to construct a pair of ephemeral passwords that allow a user to spawn a telnet service on the router, and to ensure that the telnet service persists upon reboot. By means of a crafted exchange of UDP packets, an unauthenticated attacker on the local network can leverage this null byte interaction error in such a way as to make those ephemeral passwords predictable (with 1-in-94 odds). Since the attacker must manipulate data processed by the OpenSSL function RSA_public_decrypt(), successful exploitation of this vulnerability depends on the use of an unpadded RSA cipher (CVE-2022-25218).

# CWE-627 Dynamic Variable Evaluation

## Description

In a language where the user can influence the name of a variable at runtime, if the variable names are not controlled, an attacker can read or write to arbitrary variables, or access arbitrary functions.

The resultant vulnerabilities depend on the behavior of the application, both at the crossover point and in any control/data flow that is reachable by the related variables or functions.

Many interpreted languages support the use of a "$$varname" construct to set a variable whose name is specified by the $varname variable. In PHP, these are referred to as "variable variables." Functions might also be invoked using similar syntax, such as $$funcname(arg1, arg2).

## Observed Examples

CVE-2009-0422: Chain: Dynamic variable evaluation allows resultant remote file inclusion and path traversal.

CVE-2007-2431: Chain: dynamic variable evaluation in PHP program used to modify critical, unexpected $_SERVER variable for resultant XSS.

CVE-2006-4904: Chain: dynamic variable evaluation in PHP program used to conduct remote file inclusion.

CVE-2006-4019: Dynamic variable evaluation in mail program allows reading and modifying attachments and preferences of other users.

# CWE-628 Function Call with Incorrectly Specified Arguments

## Description

The product calls a function, procedure, or routine with arguments that are not correctly specified, leading to always-incorrect behavior and resultant weaknesses.

There are multiple ways in which this weakness can be introduced, including:


  - the wrong variable or reference;

  - an incorrect number of arguments;

  - incorrect order of arguments;

  - wrong type of arguments; or

  - wrong value.

## Observed Examples

CVE-2006-7049: The method calls the functions with the wrong argument order, which allows remote attackers to bypass intended access restrictions.

# CWE-636 Not Failing Securely ('Failing Open')

## Description

When the product encounters an error condition or failure, its design requires it to fall back to a state that is less secure than other options that are available, such as selecting the weakest encryption algorithm or using the most permissive access control restrictions.

By entering a less secure state, the product inherits the weaknesses associated with that state, making it easier to compromise. At the least, it causes administrators to have a false sense of security. This weakness typically occurs as a result of wanting to "fail functional" to minimize administration and support costs, instead of "failing safe."

## Observed Examples

CVE-2007-5277: The failure of connection attempts in a web browser resets DNS pin restrictions. An attacker can then bypass the same origin policy by rebinding a domain name to a different IP address. This was an attempt to "fail functional."

CVE-2006-4407: Incorrect prioritization leads to the selection of a weaker cipher. Although it is not known whether this issue occurred in implementation or design, it is feasible that a poorly designed algorithm could be a factor.

# CWE-637 Unnecessary Complexity in Protection Mechanism (Not Using 'Economy of Mechanism')

## Description

The product uses a more complex mechanism than necessary, which could lead to resultant weaknesses when the mechanism is not correctly understood, modeled, configured, implemented, or used.

Security mechanisms should be as simple as possible. Complex security mechanisms may engender partial implementations and compatibility problems, with resulting mismatches in assumptions and implemented security. A corollary of this principle is that data specifications should be as simple as possible, because complex data specifications result in complex validation code. Complex tasks and systems may also need to be guarded by complex security checks, so simple systems should be preferred.

## Observed Examples

CVE-2007-6067: Support for complex regular expressions leads to a resultant algorithmic complexity weakness (CWE-407).

CVE-2007-1552: Either a filename extension and a Content-Type header could be used to infer the file type, but the developer only checks the Content-Type, enabling unrestricted file upload (CWE-434).

CVE-2007-6479: In Apache environments, a "filename.php.gif" can be redirected to the PHP interpreter instead of being sent as an image/gif directly to the user. Not knowing this, the developer only checks the last extension of a submitted filename, enabling arbitrary code execution.

CVE-2005-2148: The developer cleanses the $_REQUEST superglobal array, but PHP also populates $_GET, allowing attackers to bypass the protection mechanism and conduct SQL injection attacks against code that uses $_GET.

# CWE-638 Not Using Complete Mediation

## Description

The product does not perform access checks on a resource every time the resource is accessed by an entity, which can create resultant weaknesses if that entity's rights or privileges change over time.

## Observed Examples

CVE-2007-0408: Server does not properly validate client certificates when reusing cached connections.

# CWE-639 Authorization Bypass Through User-Controlled Key

## Description

The system's authorization functionality does not prevent one user from gaining access to another user's data or record by modifying the key value identifying the data.

Retrieval of a user record occurs in the system based on some key value that is under user control. The key would typically identify a user-related record stored in the system and would be used to lookup that record for presentation to the user. It is likely that an attacker would have to be an authenticated user in the system. However, the authorization process would not properly check the data access operation to ensure that the authenticated user performing the operation has sufficient entitlements to perform the requested data access, hence bypassing any other authorization checks present in the system.


For example, attackers can look at places where user specific data is retrieved (e.g. search screens) and determine whether the key for the item being looked up is controllable externally. The key may be a hidden field in the HTML form field, might be passed as a URL parameter or as an unencrypted cookie variable, then in each of these cases it will be possible to tamper with the key value.


One manifestation of this weakness is when a system uses sequential or otherwise easily-guessable session IDs that would allow one user to easily switch to another user's session and read/modify their data.

## Observed Examples

CVE-2021-36539: An educational application does not appropriately restrict file IDs to a particular user. The attacker can brute-force guess IDs, indicating IDOR.

## Top 25 Examples

CVE-2021-40579: https://www.sourcecodester.com/ Online Enrollment Management System in PHP and PayPal Free Source Code 1.0 is affected by: Incorrect Access Control. The impact is: gain privileges (remote).

CVE-2022-0731: Improper Access Control (IDOR) in GitHub repository dolibarr/dolibarr prior to 16.0.

CVE-2022-0732: The backend infrastructure shared by multiple mobile device monitoring services does not adequately authenticate or authorize API requests, creating an IDOR (Insecure Direct Object Reference) vulnerability.

CVE-2022-22331: IBM SterlingPartner Engagement Manager 6.2.0 could allow a remote authenticated attacker to obtain sensitive information or modify user details caused by an insecure direct object vulnerability (IDOR). IBM X-Force ID: 219130.

CVE-2022-25336: Ibexa DXP ezsystems/ezpublish-kernel 7.5.x before 7.5.26 and 1.3.x before 1.3.12 allows Insecure Direct Object Reference (IDOR) attacks against image files because the image path and filename can be correctly deduced.

CVE-2022-2824: Authorization Bypass Through User-Controlled Key in GitHub repository openemr/openemr prior to 7.0.0.1. 

CVE-2022-30495: In oretnom23 Automotive Shop Management System v1.0, the name id parameter is vulnerable to IDOR - Broken Access Control allowing attackers to change the admin password(vertical privilege escalation)

CVE-2022-34770: Tabit - sensitive information disclosure. Several APIs on the web system display, without authorization, sensitive information such as health statements, previous bills in a specific restaurant, alcohol consumption and smoking habits. Each of the described API’s, has in its URL one or more MongoDB ID which is not so simple to enumerate. However, they each receive a ‘tiny URL’ in Tabit’s domain, in the form of https://tbit.be/{suffix} with suffix being a 5 characters long string containing numbers, lower- and upper-case letters. It is not so simple to enumerate them all, but really easy to find some that work and lead to a personal endpoint. This is both an example of OWASP: API4 - rate limiting and OWASP: API1 - Broken object level authorization. Furthermore, the redirect URL disclosed the MongoDB IDs discussed above, and we could use them to query other endpoints disclosing more personal information. For example: The URL https://tabitisrael.co.il/online-reservations/health-statement?orgId={org_id}&healthStatementId={health_statement_id} is used to invite friends to fill a health statement before attending the restaurant. We can use the health_statement_id to access the https://tgm-api.tabit.cloud/health-statement/{health_statement_id} API which disclose medical information as well as id number.

CVE-2022-36202: Doctor's Appointment System1.0 is vulnerable to Incorrect Access Control via edoc/patient/settings.php. The settings.php is affected by Broken Access Control (IDOR) via id= parameter.

CVE-2022-39945: An improper access control vulnerability [CWE-284] in FortiMail 7.2.0, 7.0.0 through 7.0.3, 6.4 all versions, 6.2 all versions, 6.0 all versions may allow an authenticated admin user assigned to a specific domain to access and modify other domains information via insecure direct object references (IDOR).

CVE-2021-43820: Seafile is an open source cloud storage system. A sync token is used in Seafile file syncing protocol to authorize access to library data. To improve performance, the token is cached in memory in seaf-server. Upon receiving a token from sync client or SeaDrive client, the server checks whether the token exist in the cache. However, if the token exists in cache, the server doesn't check whether it's associated with the specific library in the URL. This vulnerability makes it possible to use any valid sync token to access data from any **known** library. Note that the attacker has to first find out the ID of a library which it has no access to. The library ID is a random UUID, which is not possible to be guessed. There are no workarounds for this issue.

CVE-2022-1949: An access control bypass vulnerability found in 389-ds-base. That mishandling of the filter that would yield incorrect results, but as that has progressed, can be determined that it actually is an access control bypass. This may allow any remote unauthenticated user to issue a filter that allows searching for database items they do not have access to, including but not limited to potentially userPassword hashes and other sensitive data.

CVE-2022-29287: Kentico CMS before 13.0.66 has an Insecure Direct Object Reference vulnerability. It allows an attacker with user management rights (default is Administrator) to export the user options of any user, even ones with higher privileges (like Global Administrators) than the current user. The exported XML contains every option of the exported user (even the hashed password).

CVE-2022-1810: Authorization Bypass Through User-Controlled Key in GitHub repository publify/publify prior to 9.2.9.

CVE-2022-22190: An Improper Access Control vulnerability in the Juniper Networks Paragon Active Assurance Control Center allows an unauthenticated attacker to leverage a crafted URL to generate PDF reports, potentially containing sensitive configuration information. A feature was introduced in version 3.1 of the Paragon Active Assurance Control Center which allows users to selective share account data using a unique identifier. Knowing the proper format of the URL and the identifier of an existing object in an application it is possible to get access to that object without being logged in, even if the object is not shared, resulting in the opportunity for malicious exfiltration of user data. Note that the Paragon Active Assurance Control Center SaaS offering is not affected by this issue. This issue affects Juniper Networks Paragon Active Assurance version 3.1.0.

CVE-2022-22832: An issue was discovered in Servisnet Tessa 0.0.2. Authorization data is available via an unauthenticated /data-service/users/ request.

CVE-2022-4505: Authorization Bypass Through User-Controlled Key in GitHub repository openemr/openemr prior to 7.0.0.2. 

CVE-2022-23856: An issue was discovered in Saviynt Enterprise Identity Cloud (EIC) 5.5 SP2.x. An attacker can enumerate users by changing the id parameter, such as for the ECM/maintenance/forgotpasswordstep1 URI.

CVE-2022-34775: Tabit - Excessive data exposure. Another endpoint mapped by the tiny url, was one for reservation cancellation, containing the MongoDB ID of the reservation, and organization. This can be used to query the http://tgm-api.tabit.cloud/rsv/management/{reservationId}?organization={orgId} API which returns a lot of data regarding the reservation (OWASP: API3): Name, mail, phone number, the number of visits of the user to this specific restaurant, the money he spent there, the money he spent on alcohol, whether he left a deposit etc. This information can easily be used for a phishing attack.

CVE-2021-4142: The Candlepin component of Red Hat Satellite was affected by an improper authentication flaw. Few factors could allow an attacker to use the SCA (simple content access) certificate for authentication with Candlepin.

CVE-2021-44949: glFusion CMS 1.7.9 is affected by an access control vulnerability via /public_html/users.php.

CVE-2022-4686: Authorization Bypass Through User-Controlled Key in GitHub repository usememos/memos prior to 0.9.0.

CVE-2022-31131: Nextcloud mail is a Mail app for the Nextcloud home server product. Versions of Nextcloud mail prior to 1.12.2 were found to be missing user account ownership checks when performing tasks related to mail attachments. Attachments may have been exposed to incorrect system users. It is recommended that the Nextcloud Mail app is upgraded to 1.12.2. There are no known workarounds for this issue. ### Workarounds No workaround available ### References * [Pull request](https://github.com/nextcloud/mail/pull/6600) * [HackerOne](https://hackerone.com/reports/1579820) ### For more information If you have any questions or comments about this advisory: * Create a post in [nextcloud/security-advisories](https://github.com/nextcloud/security-advisories/discussions) * Customers: Open a support ticket at [support.nextcloud.com](https://support.nextcloud.com)

CVE-2022-1245: A privilege escalation flaw was found in the token exchange feature of keycloak. Missing authorization allows a client application holding a valid access token to exchange tokens for any target client by passing the client_id of the target. This could allow a client to gain unauthorized access to additional services.

CVE-2022-2034: The Sensei LMS WordPress plugin before 4.5.0 does not have proper permissions set in one of its REST endpoint, allowing unauthenticated users to access private messages sent to teachers

CVE-2022-21713: Grafana is an open-source platform for monitoring and observability. Affected versions of Grafana expose multiple API endpoints which do not properly handle user authorization. `/teams/:teamId` will allow an authenticated attacker to view unintended data by querying for the specific team ID, `/teams/:search` will allow an authenticated attacker to search for teams and see the total number of available teams, including for those teams that the user does not have access to, and `/teams/:teamId/members` when editors_can_admin flag is enabled, an authenticated attacker can see unintended data by querying for the specific team ID. Users are advised to upgrade as soon as possible. There are no known workarounds for this issue.

CVE-2022-2243: An access control vulnerability in GitLab EE/CE affecting all versions from 14.8 prior to 14.10.5, 15.0 prior to 15.0.4, and 15.1 prior to 15.1.1, allows authenticated users to enumerate issues in non-linked sentry projects.

CVE-2022-3413: Incorrect authorization during display of Audit Events in GitLab EE affecting all versions from 14.5 prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2, allowed Developers to view the project's Audit Events and Developers or Maintainers to view the group's Audit Events. These should have been restricted to Project Maintainers, Group Owners, and above.

CVE-2022-4811: Authorization Bypass Through User-Controlled Key vulnerability in usememos usememos/memos.This issue affects usememos/memos before 0.9.1. 

CVE-2022-0442: The UsersWP WordPress plugin before 1.2.3.1 is missing access controls when updating a user avatar, and does not make sure file names for user avatars are unique, allowing a logged in user to overwrite another users avatar.

CVE-2021-36539: Instructure Canvas LMS didn't properly deny access to locked/unpublished files when the unprivileged user access the DocViewer based file preview URL (canvadoc_session_url).

# CWE-64 Windows Shortcut Following (.LNK)

## Description

The product, when opening a file or directory, does not sufficiently handle when the file is a Windows shortcut (.LNK) whose target is outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

The shortcut (file with the .lnk extension) can permit an attacker to read/write a file that they originally did not have permissions to access.

## Observed Examples

CVE-2019-19793: network access control service executes program with high privileges and allows symlink to invoke another executable or perform DLL injection.

CVE-2000-0342: Mail client allows remote attackers to bypass the user warning for executable attachments such as .exe, .com, and .bat by using a .lnk file that refers to the attachment, aka "Stealth Attachment."

CVE-2001-1042: FTP server allows remote attackers to read arbitrary files and directories by uploading a .lnk (link) file that points to the target file.

CVE-2001-1043: FTP server allows remote attackers to read arbitrary files and directories by uploading a .lnk (link) file that points to the target file.

CVE-2005-0587: Browser allows remote malicious web sites to overwrite arbitrary files by tricking the user into downloading a .LNK (link) file twice, which overwrites the file that was referenced in the first .LNK file.

CVE-2001-1386: ".LNK." - .LNK with trailing dot

CVE-2003-1233: Rootkits can bypass file access restrictions to Windows kernel directories using NtCreateSymbolicLinkObject function to create symbolic link

# CWE-640 Weak Password Recovery Mechanism for Forgotten Password

## Description

The product contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak.

It is common for an application to have a mechanism that provides a means for a user to gain access to their account in the event they forget their password. Very often the password recovery mechanism is weak, which has the effect of making it more likely that it would be possible for a person other than the legitimate system user to gain access to that user's account. Weak password recovery schemes completely undermine a strong password authentication scheme.


This weakness may be that the security question is too easy to guess or find an answer to (e.g. because the question is too common, or the answers can be found using social media). Or there might be an implementation weakness in the password recovery mechanism code that may for instance trick the system into e-mailing the new password to an e-mail account other than that of the user. There might be no throttling done on the rate of password resets so that a legitimate user can be denied service by an attacker if an attacker tries to recover their password in a rapid succession. The system may send the original password to the user rather than generating a new temporary password. In summary, password recovery functionality, if not carefully designed and implemented can often become the system's weakest link that can be misused in a way that would allow an attacker to gain unauthorized access to the system.

## Top 25 Examples

CVE-2022-23855: An issue was discovered in Saviynt Enterprise Identity Cloud (EIC) 5.5 SP2.x. An authentication bypass in ECM/maintenance/forgotpasswordstep1 allows an unauthenticated user to reset passwords and login as any local account.

# CWE-641 Improper Restriction of Names for Files and Other Resources

## Description

The product constructs the name of a file or other resource using input from an upstream component, but it does not restrict or incorrectly restricts the resulting name.

This may produce resultant weaknesses. For instance, if the names of these resources contain scripting characters, it is possible that a script may get executed in the client's browser if the application ever displays the name of the resource on a dynamically generated web page. Alternately, if the resources are consumed by some application parser, a specially crafted name can exploit some vulnerability internal to the parser, potentially resulting in execution of arbitrary code on the server machine. The problems will vary based on the context of usage of such malformed resource names and whether vulnerabilities are present in or assumptions are made by the targeted technology that would make code execution possible.

## Top 25 Examples

CVE-2022-36302: File path manipulation vulnerability in BF-OS version 3.00 up to and including 3.83 allows an attacker to modify the file path to access different resources, which may contain sensitive information.

# CWE-642 External Control of Critical State Data

## Description

The product stores security-critical state information about its users, or the product itself, in a location that is accessible to unauthorized actors.

If an attacker can modify the state information without detection, then it could be used to perform unauthorized actions or access unexpected resources, since the application programmer does not expect that the state can be changed.


State information can be stored in various locations such as a cookie, in a hidden web form field, input parameter or argument, an environment variable, a database record, within a settings file, etc. All of these locations have the potential to be modified by an attacker. When this state information is used to control security or determine resource usage, then it may create a vulnerability. For example, an application may perform authentication, then save the state in an "authenticated=true" cookie. An attacker may simply create this cookie in order to bypass the authentication.

## Observed Examples

CVE-2005-2428: Mail client stores password hashes for unrelated accounts in a hidden form field.

CVE-2008-0306: Privileged program trusts user-specified environment variable to modify critical configuration settings.

CVE-1999-0073: Telnet daemon allows remote clients to specify critical environment variables for the server, leading to code execution.

CVE-2007-4432: Untrusted search path vulnerability through modified LD_LIBRARY_PATH environment variable.

CVE-2006-7191: Untrusted search path vulnerability through modified LD_LIBRARY_PATH environment variable.

CVE-2008-5738: Calendar application allows bypass of authentication by setting a certain cookie value to 1.

CVE-2008-5642: Setting of a language preference in a cookie enables path traversal attack.

CVE-2008-5125: Application allows admin privileges by setting a cookie value to "admin."

CVE-2008-5065: Application allows admin privileges by setting a cookie value to "admin."

CVE-2008-4752: Application allows admin privileges by setting a cookie value to "admin."

CVE-2000-0102: Shopping cart allows price modification via hidden form field.

CVE-2000-0253: Shopping cart allows price modification via hidden form field.

CVE-2008-1319: Server allows client to specify the search path, which can be modified to point to a program that the client has uploaded.

## Top 25 Examples

CVE-2022-22154: In a Junos Fusion scenario an External Control of Critical State Data vulnerability in the Satellite Device (SD) control state machine of Juniper Networks Junos OS allows an attacker who is able to make physical changes to the cabling of the device to cause a denial of service (DoS). An SD can get rebooted and subsequently controlled by an Aggregation Device (AD) which does not belong to the original Fusion setup and is just connected to an extended port of the SD. To carry out this attack the attacker needs to have physical access to the cabling between the SD and the original AD. This issue affects: Juniper Networks Junos OS 16.1R1 and later versions prior to 18.4R3-S10; 19.1 versions prior to 19.1R3-S7; 19.2 versions prior to 19.2R3-S4. This issue does not affect Juniper Networks Junos OS versions prior to 16.1R1.

# CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')

## Description

The product uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input. This allows an attacker to control the structure of the query.

The net effect is that the attacker will have control over the information selected from the XML database and may use that ability to control application flow, modify logic, retrieve unauthorized data, or bypass important checks (e.g. authentication).

# CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax

## Description

The product does not neutralize or incorrectly neutralizes web scripting syntax in HTTP headers that can be used by web browser components that can process raw headers, such as Flash.

An attacker may be able to conduct cross-site scripting and other attacks against users who have these components enabled.


If a product does not neutralize user controlled data being placed in the header of an HTTP response coming from the server, the header may contain a script that will get executed in the client's browser context, potentially resulting in a cross site scripting vulnerability or possibly an HTTP response splitting attack. It is important to carefully control data that is being placed both in HTTP response header and in the HTTP response body to ensure that no scripting syntax is present, taking various encodings into account.

## Observed Examples

CVE-2006-3918: Web server does not remove the Expect header from an HTTP request when it is reflected back in an error message, allowing a Flash SWF file to perform XSS attacks.

# CWE-645 Overly Restrictive Account Lockout Mechanism

## Description

The product contains an account lockout protection mechanism, but the mechanism is too restrictive and can be triggered too easily, which allows attackers to deny service to legitimate users by causing their accounts to be locked out.

Account lockout is a security feature often present in applications as a countermeasure to the brute force attack on the password based authentication mechanism of the system. After a certain number of failed login attempts, the users' account may be disabled for a certain period of time or until it is unlocked by an administrator. Other security events may also possibly trigger account lockout. However, an attacker may use this very security feature to deny service to legitimate system users. It is therefore important to ensure that the account lockout security mechanism is not overly restrictive.

# CWE-646 Reliance on File Name or Extension of Externally-Supplied File

## Description

The product allows a file to be uploaded, but it relies on the file name or extension of the file to determine the appropriate behaviors. This could be used by attackers to cause the file to be misclassified and processed in a dangerous fashion.

An application might use the file name or extension of a user-supplied file to determine the proper course of action, such as selecting the correct process to which control should be passed, deciding what data should be made available, or what resources should be allocated. If the attacker can cause the code to misclassify the supplied file, then the wrong action could occur. For example, an attacker could supply a file that ends in a ".php.gif" extension that appears to be a GIF image, but would be processed as PHP code. In extreme cases, code execution is possible, but the attacker could also cause exhaustion of resources, denial of service, exposure of debug or system data (including application source code), or being bound to a particular server side process. This weakness may be due to a vulnerability in any of the technologies used by the web and application servers, due to misconfiguration, or resultant from another flaw in the application itself.

# CWE-647 Use of Non-Canonical URL Paths for Authorization Decisions

## Description

The product defines policy namespaces and makes authorization decisions based on the assumption that a URL is canonical. This can allow a non-canonical URL to bypass the authorization.

If an application defines policy namespaces and makes authorization decisions based on the URL, but it does not require or convert to a canonical URL before making the authorization decision, then it opens the application to attack. For example, if the application only wants to allow access to http://www.example.com/mypage, then the attacker might be able to bypass this restriction using equivalent URLs such as:


  - http://WWW.EXAMPLE.COM/mypage

  - http://www.example.com/%6Dypage (alternate encoding)

  - http://192.168.1.1/mypage (IP address)

  - http://www.example.com/mypage/ (trailing /)

  - http://www.example.com:80/mypage

Therefore it is important to specify access control policy that is based on the path information in some canonical form with all alternate encodings rejected (which can be accomplished by a default deny rule).

# CWE-648 Incorrect Use of Privileged APIs

## Description

The product does not conform to the API requirements for a function call that requires extra privileges. This could allow attackers to gain privileges by causing the function to be called incorrectly.

When a product contains certain functions that perform operations requiring an elevated level of privilege, the caller of a privileged API must be careful to:


  - ensure that assumptions made by the APIs are valid, such as validity of arguments

  - account for known weaknesses in the design/implementation of the API

  - call the API from a safe context

If the caller of the API does not follow these requirements, then it may allow a malicious user or process to elevate their privilege, hijack the process, or steal sensitive data.

For instance, it is important to know if privileged APIs do not shed their privileges before returning to the caller or if the privileged function might make certain assumptions about the data, context or state information passed to it by the caller. It is important to always know when and how privileged APIs can be called in order to ensure that their elevated level of privilege cannot be exploited.

## Observed Examples

CVE-2003-0645: A Unix utility that displays online help files, if installed setuid, could allow a local attacker to gain privileges when a particular file-opening function is called.

## Top 25 Examples

CVE-2022-2023: Incorrect Use of Privileged APIs in GitHub repository polonel/trudesk prior to 1.2.4.

CVE-2022-4687: Incorrect Use of Privileged APIs in GitHub repository usememos/memos prior to 0.9.0.

CVE-2022-25089: Printix Secure Cloud Print Management through 1.3.1106.0 incorrectly uses Privileged APIs to modify values in HKEY_LOCAL_MACHINE via UITasks.PersistentRegistryData.

CVE-2022-32633: In Wi-Fi, there is a possible memory access violation due to a logic error. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07441637; Issue ID: ALPS07441637.

# CWE-649 Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity Checking

## Description

The product uses obfuscation or encryption of inputs that should not be mutable by an external actor, but the product does not use integrity checks to detect if those inputs have been modified.

When an application relies on obfuscation or incorrectly applied / weak encryption to protect client-controllable tokens or parameters, that may have an effect on the user state, system state, or some decision made on the server. Without protecting the tokens/parameters for integrity, the application is vulnerable to an attack where an adversary traverses the space of possible values of the said token/parameter in order to attempt to gain an advantage. The goal of the attacker is to find another admissible value that will somehow elevate their privileges in the system, disclose information or change the behavior of the system in some way beneficial to the attacker. If the application does not protect these critical tokens/parameters for integrity, it will not be able to determine that these values have been tampered with. Measures that are used to protect data for confidentiality should not be relied upon to provide the integrity service.

## Observed Examples

CVE-2005-0039: An IPSec configuration does not perform integrity checking of the IPSec packet as the result of either not configuring ESP properly to support the integrity service or using AH improperly. In either case, the security gateway receiving the IPSec packet would not validate the integrity of the packet to ensure that it was not changed. Thus if the packets were intercepted the attacker could undetectably change some of the bits in the packets. The meaningful bit flipping was possible due to the known weaknesses in the CBC encryption mode. Since the attacker knew the structure of the packet, they were able (in one variation of the attack) to use bit flipping to change the destination IP of the packet to the destination machine controlled by the attacker. And so the destination security gateway would decrypt the packet and then forward the plaintext to the machine controlled by the attacker. The attacker could then read the original message. For instance if VPN was used with the vulnerable IPSec configuration the attacker could read the victim's e-mail. This vulnerability demonstrates the need to enforce the integrity service properly when critical data could be modified by an attacker. This problem might have also been mitigated by using an encryption mode that is not susceptible to bit flipping attacks, but the preferred mechanism to address this problem still remains message verification for integrity. While this attack focuses on the network layer and requires an entity that controls part of the communication path such as a router, the situation is not much different at the software level, where an attacker can modify tokens/parameters used by the application.

# CWE-65 Windows Hard Link

## Description

The product, when opening a file or directory, does not sufficiently handle when the name is associated with a hard link to a target that is outside of the intended control sphere. This could allow an attacker to cause the product to operate on unauthorized files.

Failure for a system to check for hard links can result in vulnerability to different types of attacks. For example, an attacker can escalate their privileges if a file used by a privileged program is replaced with a hard link to a sensitive file (e.g. AUTOEXEC.BAT). When the process opens the file, the attacker can assume the privileges of that process, or prevent the program from accurately processing data.

## Observed Examples

CVE-2002-0725: File system allows local attackers to hide file usage activities via a hard link to the target file, which causes the link to be recorded in the audit trail instead of the target file.

CVE-2003-0844: Web server plugin allows local users to overwrite arbitrary files via a symlink attack on predictable temporary filenames.

# CWE-650 Trusting HTTP Permission Methods on the Server Side

## Description

The server contains a protection mechanism that assumes that any URI that is accessed using HTTP GET will not cause a state change to the associated resource. This might allow attackers to bypass intended access restrictions and conduct resource modification and deletion attacks, since some applications allow GET to modify state.

The HTTP GET method and some other methods are designed to retrieve resources and not to alter the state of the application or resources on the server side. Furthermore, the HTTP specification requires that GET requests (and other requests) should not have side effects. Believing that it will be enough to prevent unintended resource alterations, an application may disallow the HTTP requests to perform DELETE, PUT and POST operations on the resource representation. However, there is nothing in the HTTP protocol itself that actually prevents the HTTP GET method from performing more than just query of the data. Developers can easily code programs that accept a HTTP GET request that do in fact create, update or delete data on the server. For instance, it is a common practice with REST based Web Services to have HTTP GET requests modifying resources on the server side. However, whenever that happens, the access control needs to be properly enforced in the application. No assumptions should be made that only HTTP DELETE, PUT, POST, and other methods have the power to alter the representation of the resource being accessed in the request.

## Top 25 Examples

CVE-2021-45327: Gitea before 1.11.2 is affected by Trusting HTTP Permission Methods on the Server Side when referencing the vulnerable admin or user API. which could let a remote malisious user execute arbitrary code.

# CWE-651 Exposure of WSDL File Containing Sensitive Information

## Description

The Web services architecture may require exposing a Web Service Definition Language (WSDL) file that contains information on the publicly accessible services and how callers of these services should interact with them (e.g. what parameters they expect and what types they return).

An information exposure may occur if any of the following apply:


  - The WSDL file is accessible to a wider audience than intended.

  - The WSDL file contains information on the methods/services that should not be publicly accessible or information about deprecated methods. This problem is made more likely due to the WSDL often being automatically generated from the code.

  - Information in the WSDL file helps guess names/locations of methods/resources that should not be publicly accessible.

# CWE-652 Improper Neutralization of Data within XQuery Expressions ('XQuery Injection')

## Description

The product uses external input to dynamically construct an XQuery expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input. This allows an attacker to control the structure of the query.

The net effect is that the attacker will have control over the information selected from the XML database and may use that ability to control application flow, modify logic, retrieve unauthorized data, or bypass important checks (e.g. authentication).

# CWE-653 Improper Isolation or Compartmentalization

## Description

The product does not properly compartmentalize or isolate functionality, processes, or resources that require different privilege levels, rights, or permissions.

When a weakness occurs in functionality that is accessible by lower-privileged users, then without strong boundaries, an attack might extend the scope of the damage to higher-privileged users.

## Observed Examples

CVE-2021-33096: Improper isolation of shared resource in a network-on-chip leads to denial of service

CVE-2019-6260: Baseboard Management Controller (BMC) device implements Advanced High-performance Bus (AHB) bridges that do not require authentication for arbitrary read and write access to the BMC's physical address space from the host, and possibly the network [REF-1138].

## Top 25 Examples

CVE-2022-3044: Inappropriate implementation in Site Isolation in Google Chrome prior to 105.0.5195.52 allowed a remote attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page.

# CWE-654 Reliance on a Single Factor in a Security Decision

## Description

A protection mechanism relies exclusively, or to a large extent, on the evaluation of a single condition or the integrity of a single object or entity in order to make a decision about granting access to restricted resources or functionality.

## Observed Examples

CVE-2022-35248: Chat application skips validation when Central Authentication Service (CAS) is enabled, effectively removing the second factor from two-factor authentication

# CWE-655 Insufficient Psychological Acceptability

## Description

The product has a protection mechanism that is too difficult or inconvenient to use, encouraging non-malicious users to disable or bypass the mechanism, whether by accident or on purpose.

# CWE-656 Reliance on Security Through Obscurity

## Description

The product uses a protection mechanism whose strength depends heavily on its obscurity, such that knowledge of its algorithms or key data is sufficient to defeat the mechanism.

This reliance on "security through obscurity" can produce resultant weaknesses if an attacker is able to reverse engineer the inner workings of the mechanism. Note that obscurity can be one small part of defense in depth, since it can create more work for an attacker; however, it is a significant risk if used as the primary means of protection.

## Observed Examples

CVE-2006-6588: Reliance on hidden form fields in a web application. Many web application vulnerabilities exist because the developer did not consider that "hidden" form fields can be processed using a modified client.

CVE-2006-7142: Hard-coded cryptographic key stored in executable program.

CVE-2005-4002: Hard-coded cryptographic key stored in executable program.

CVE-2006-4068: Hard-coded hashed values for username and password contained in client-side script, allowing brute-force offline attacks.

# CWE-657 Violation of Secure Design Principles

## Description

The product violates well-established principles for secure design.

This can introduce resultant weaknesses or make it easier for developers to introduce related weaknesses during implementation. Because code is centered around design, it can be resource-intensive to fix design problems.

## Observed Examples

CVE-2019-6260: Baseboard Management Controller (BMC) device implements Advanced High-performance Bus (AHB) bridges that do not require authentication for arbitrary read and write access to the BMC's physical address space from the host, and possibly the network [REF-1138].

CVE-2007-5277: The failure of connection attempts in a web browser resets DNS pin restrictions. An attacker can then bypass the same origin policy by rebinding a domain name to a different IP address. This was an attempt to "fail functional."

CVE-2006-7142: Hard-coded cryptographic key stored in executable program.

CVE-2007-0408: Server does not properly validate client certificates when reusing cached connections.

## Top 25 Examples

CVE-2022-30683: Adobe Experience Manager versions 6.5.13.0 (and earlier) is affected by a Violation of Secure Design Principles vulnerability that could lead to bypass the security feature of the encryption mechanism in the backend . An attacker could leverage this vulnerability to decrypt secrets, however, this is a high-complexity attack as the threat actor needs to already possess those secrets. Exploitation of this issue requires low-privilege access to AEM.

CVE-2022-28244: Acrobat Reader DC versions 22.001.20085 (and earlier), 20.005.3031x (and earlier) and 17.012.30205 (and earlier) is affected by a violation of secure design principles through bypassing the content security policy, which could result in an attacker sending arbitrarily configured requests to the cross-origin attack target domain. Exploitation requires user interaction in which the victim needs to access a crafted PDF file on an attacker's server.

CVE-2022-30707: Violation of secure design principles exists in the communication of CAMS for HIS. Affected products and versions are CENTUM series where LHS4800 is installed (CENTUM CS 3000 and CENTUM CS 3000 Small R3.08.10 to R3.09.00), CENTUM series where CAMS function is used (CENTUM VP, CENTUM VP Small, and CENTUM VP Basic R4.01.00 to R4.03.00), CENTUM series regardless of the use of CAMS function (CENTUM VP, CENTUM VP Small, and CENTUM VP Basic R5.01.00 to R5.04.20 and R6.01.00 to R6.09.00), Exaopc R3.72.00 to R3.80.00 (only if NTPF100-S6 'For CENTUM VP Support CAMS for HIS' is installed), B/M9000 CS R5.04.01 to R5.05.01, and B/M9000 VP R6.01.01 to R8.03.01). If an adjacent attacker successfully compromises a computer using CAMS for HIS software, they can use credentials from the compromised machine to access data from another machine using CAMS for HIS software. This can lead to a disabling of CAMS for HIS software functions on any affected machines, or information disclosure/alteration.

# CWE-66 Improper Handling of File Names that Identify Virtual Resources

## Description

The product does not handle or incorrectly handles a file name that identifies a "virtual" resource that is not directly specified within the directory that is associated with the file name, causing the product to perform file-based operations on a resource that is not a file.

Virtual file names are represented like normal file names, but they are effectively aliases for other resources that do not behave like normal files. Depending on their functionality, they could be alternate entities. They are not necessarily listed in directories.

## Observed Examples

CVE-1999-0278: In IIS, remote attackers can obtain source code for ASP files by appending "::$DATA" to the URL.

CVE-2004-1084: Server allows remote attackers to read files and resource fork content via HTTP requests to certain special file names related to multiple data streams in HFS+.

CVE-2002-0106: Server allows remote attackers to cause a denial of service via a series of requests to .JSP files that contain an MS-DOS device name.

# CWE-662 Improper Synchronization

## Description

The product utilizes multiple threads or processes to allow temporary access to a shared resource that can only be exclusive to one process at a time, but it does not properly synchronize these actions, which might cause simultaneous accesses of this resource by multiple threads or processes.

Synchronization refers to a variety of behaviors and mechanisms that allow two or more independently-operating processes or threads to ensure that they operate on shared resources in predictable ways that do not interfere with each other. Some shared resource operations cannot be executed atomically; that is, multiple steps must be guaranteed to execute sequentially, without any interference by other processes. Synchronization mechanisms vary widely, but they may include locking, mutexes, and semaphores. When a multi-step operation on a shared resource cannot be guaranteed to execute independent of interference, then the resulting behavior can be unpredictable. Improper synchronization could lead to data or memory corruption, denial of service, etc.

## Observed Examples

CVE-2021-1782: Chain: improper locking (CWE-667) leads to race condition (CWE-362), as exploited in the wild per CISA KEV.

CVE-2009-0935: Attacker provides invalid address to a memory-reading function, causing a mutex to be unlocked twice

## Top 25 Examples

CVE-2022-2962: A DMA reentrancy issue was found in the Tulip device emulation in QEMU. When Tulip reads or writes to the rx/tx descriptor or copies the rx/tx frame, it doesn't check whether the destination address is its own MMIO address. This can cause the device to trigger MMIO handlers multiple times, possibly leading to a stack or heap overflow. A malicious guest could use this flaw to crash the QEMU process on the host, resulting in a denial of service condition.

CVE-2022-32609: In vcu, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07203410; Issue ID: ALPS07203410.

CVE-2022-32610: In vcu, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07203476; Issue ID: ALPS07203476.

CVE-2022-32642: In ccd, there is a possible memory corruption due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07326547; Issue ID: ALPS07326547.

CVE-2022-32643: In ccd, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07341261; Issue ID: ALPS07341261.

CVE-2022-32644: In vow, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07494473; Issue ID: ALPS07494473.

CVE-2022-32648: In disp, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06535964; Issue ID: ALPS06535964.

# CWE-663 Use of a Non-reentrant Function in a Concurrent Context

## Description

The product calls a non-reentrant function in a concurrent context in which a competing code sequence (e.g. thread or signal handler) may have an opportunity to call the same function or otherwise influence its state.

## Observed Examples

CVE-2001-1349: unsafe calls to library functions from signal handler

CVE-2004-2259: SIGCHLD signal to FTP server can cause crash under heavy load while executing non-reentrant functions like malloc/free.

# CWE-664 Improper Control of a Resource Through its Lifetime

## Description

The product does not maintain or incorrectly maintains control over a resource throughout its lifetime of creation, use, and release.

Resources often have explicit instructions on how to be created, used and destroyed. When code does not follow these instructions, it can lead to unexpected behaviors and potentially exploitable states.


Even without explicit instructions, various principles are expected to be adhered to, such as "Do not use an object until after its creation is complete," or "do not use an object after it has been slated for destruction."

## Observed Examples

CVE-2018-1000613: Cryptography API uses unsafe reflection when deserializing a private key

CVE-2022-21668: Chain: Python library does not limit the resources used to process images that specify a very large number of bands (CWE-1284), leading to excessive memory consumption (CWE-789) or an integer overflow (CWE-190).

## Top 25 Examples

CVE-2022-22249: An Improper Control of a Resource Through its Lifetime vulnerability in the Packet Forwarding Engine (PFE) of Juniper Networks Junos OS on MX Series allows an unauthenticated adjacent attacker to cause a Denial of Service (DoS). When there is a continuous mac move a memory corruption causes one or more FPCs to crash and reboot. These MAC moves can be between two local interfaces or between core/EVPN and local interface. The below error logs can be seen in PFE syslog when this issue happens: xss_event_handler(1071): EA[0:0]_PPE 46.xss[0] ADDR Error. ppe_error_interrupt(4298): EA[0:0]_PPE 46 Errors sync xtxn error xss_event_handler(1071): EA[0:0]_PPE 1.xss[0] ADDR Error. ppe_error_interrupt(4298): EA[0:0]_PPE 1 Errors sync xtxn error xss_event_handler(1071): EA[0:0]_PPE 2.xss[0] ADDR Error. This issue affects Juniper Networks Junos OS on MX Series: All versions prior to 15.1R7-S13; 19.1 versions prior to 19.1R3-S9; 19.2 versions prior to 19.2R3-S6; 19.3 versions prior to 19.3R3-S6; 19.4 versions prior to 19.4R2-S7, 19.4R3-S8; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S5; 20.3 versions prior to 20.3R3-S5; 20.4 versions prior to 20.4R3-S2; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2.

CVE-2022-22250: An Improper Control of a Resource Through its Lifetime vulnerability in Packet Forwarding Engine (PFE) of Juniper Networks Junos OS and Junos OS Evolved allows unauthenticated adjacent attacker to cause a Denial of Service (DoS). In an EVPN-MPLS scenario, if MAC is learned locally on an access interface but later a request to delete is received indicating that the MAC was learnt remotely, this can lead to memory corruption which can result in line card crash and reload. This issue affects: Juniper Networks Junos OS All versions 17.3R1 and later versions prior to 19.2R3-S5; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to 19.4R2-S6, 19.4R3-S8; 20.1 version 20.1R1 and later versions; 20.2 versions prior to 20.2R3-S4; 20.3 versions prior to 20.3R3-S3; 20.4 versions prior to 20.4R3-S3; 21.1 versions prior to 21.1R3-S1; 21.2 versions prior to 21.2R3; 21.3 versions prior to 21.3R2; 21.4 versions prior to 21.4R1-S1, 21.4R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R3-S3-EVO; 21.1-EVO version 21.1R1-EVO and later versions; 21.2-EVO versions prior to 21.2R3-EVO; 21.3-EVO versions prior to 21.3R2-EVO; 21.4-EVO versions prior to 21.4R1-S1-EVO, 21.4R2-EVO. This issue does not affect Juniper Networks Junos OS versions prior to 17.3R1.

CVE-2022-27518: Unauthenticated remote arbitrary code execution 

CVE-2022-39949: An improper control of a resource through its lifetime vulnerability [CWE-664] in FortiEDR CollectorWindows 4.0.0 through 4.1, 5.0.0 through 5.0.3.751, 5.1.0 may allow a privileged user to terminate the FortiEDR processes with special tools and bypass the EDR protection.

CVE-2021-43204: A improper control of a resource through its lifetime in Fortinet FortiClientWindows version 6.4.1 and 6.4.0, version 6.2.9 and below, version 6.0.10 and below allows attacker to cause a complete denial of service of its components via changes of directory access permissions.

CVE-2022-23446: A improper control of a resource through its lifetime in Fortinet FortiEDR version 5.0.3 and earlier allows attacker to make the whole application unresponsive via changing its root directory access permission.

# CWE-665 Improper Initialization

## Description

The product does not initialize or incorrectly initializes a resource, which might leave the resource in an unexpected state when it is accessed or used.

This can have security implications when the associated resource is expected to have certain properties or values, such as a variable that determines whether a user has been authenticated or not.

## Observed Examples

CVE-2001-1471: chain: an invalid value prevents a library file from being included, skipping initialization of key variables, leading to resultant eval injection.

CVE-2008-3637: Improper error checking in protection mechanism produces an uninitialized variable, allowing security bypass and code execution.

CVE-2008-4197: Use of uninitialized memory may allow code execution.

CVE-2008-2934: Free of an uninitialized pointer leads to crash and possible code execution.

CVE-2007-3749: OS kernel does not reset a port when starting a setuid program, allowing local users to access the port and gain privileges.

CVE-2008-0063: Product does not clear memory contents when generating an error message, leading to information leak.

CVE-2008-0062: Lack of initialization triggers NULL pointer dereference or double-free.

CVE-2008-0081: Uninitialized variable leads to code execution in popular desktop application.

CVE-2008-3688: chain: Uninitialized variable leads to infinite loop.

CVE-2008-3475: chain: Improper initialization leads to memory corruption.

CVE-2008-5021: Composite: race condition allows attacker to modify an object while it is still being initialized, causing software to access uninitialized memory.

CVE-2005-1036: Chain: Bypass of access restrictions due to improper authorization (CWE-862) of a user results from an improperly initialized (CWE-909) I/O permission bitmap

CVE-2008-3597: chain: game server can access player data structures before initialization has happened leading to NULL dereference

CVE-2009-2692: chain: uninitialized function pointers can be dereferenced allowing code execution

CVE-2009-0949: chain: improper initialization of memory can lead to NULL dereference

CVE-2009-3620: chain: some unprivileged ioctls do not verify that a structure has been initialized before invocation, leading to NULL dereference

## Top 25 Examples

CVE-2022-2620: Use after free in WebUI in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2472: Improper Initialization vulnerability in the local server component of EZVIZ CS-C6N-A0-1C2WFR allows a local attacker to read the contents of the memory space containing the encrypted admin password. This issue affects: EZVIZ CS-C6N-A0-1C2WFR versions prior to 5.3.0 build 220428.

CVE-2022-29695: Unicorn Engine v2.0.0-rc7 contains memory leaks caused by an incomplete unicorn engine initialization.

CVE-2022-46505: An issue in MatrixSSL 4.5.1-open and earlier leads to failure to securely check the SessionID field, resulting in the misuse of an all-zero MasterSecret that can decrypt secret data.

# CWE-666 Operation on Resource in Wrong Phase of Lifetime

## Description

The product performs an operation on a resource at the wrong phase of the resource's lifecycle, which can lead to unexpected behaviors.

A resource's lifecycle includes several phases: initialization, use, and release. For each phase, it is important to follow the specifications outlined for how to operate on the resource and to ensure that the resource is in the expected phase. Otherwise, if a resource is in one phase but the operation is not valid for that phase (i.e., an incorrect phase of the resource's lifetime), then this can produce resultant weaknesses. For example, using a resource before it has been fully initialized could cause corruption or incorrect data to be used.

## Observed Examples

CVE-2006-5051: Chain: Signal handler contains too much functionality (CWE-828), introducing a race condition (CWE-362) that leads to a double free (CWE-415).

# CWE-667 Improper Locking

## Description

The product does not properly acquire or release a lock on a resource, leading to unexpected resource state changes and behaviors.

Locking is a type of synchronization behavior that ensures that multiple independently-operating processes or threads do not interfere with each other when accessing the same resource. All processes/threads are expected to follow the same steps for locking. If these steps are not followed precisely - or if no locking is done at all - then another process/thread could modify the shared resource in a way that is not visible or predictable to the original process. This can lead to data or memory corruption, denial of service, etc.

## Observed Examples

CVE-2021-1782: Chain: improper locking (CWE-667) leads to race condition (CWE-362), as exploited in the wild per CISA KEV.

CVE-2009-0935: Attacker provides invalid address to a memory-reading function, causing a mutex to be unlocked twice

CVE-2010-4210: function in OS kernel unlocks a mutex that was not previously locked, causing a panic or overwrite of arbitrary memory.

CVE-2008-4302: Chain: OS kernel does not properly handle a failure of a function call (CWE-755), leading to an unlock of a resource that was not locked (CWE-832), with resultant crash.

CVE-2009-1243: OS kernel performs an unlock in some incorrect circumstances, leading to panic.

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

CVE-2001-0682: Program can not execute when attacker obtains a mutex.

CVE-2002-1914: Program can not execute when attacker obtains a lock on a critical output file.

CVE-2002-1915: Program can not execute when attacker obtains a lock on a critical output file.

CVE-2002-0051: Critical file can be opened with exclusive read access by user, preventing application of security policy. Possibly related to improper permissions, large-window race condition.

CVE-2000-0338: Chain: predictable file names used for locking, allowing attacker to create the lock beforehand. Resultant from permissions and randomness.

CVE-2000-1198: Chain: Lock files with predictable names. Resultant from randomness.

CVE-2002-1869: Product does not check if it can write to a log file, allowing attackers to avoid logging by accessing the file using an exclusive lock. Overlaps unchecked error condition. This is not quite CWE-412, but close.

## Top 25 Examples

CVE-2022-20016: In vow driver, there is a possible memory corruption due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS05862986; Issue ID: ALPS05862986.

CVE-2022-21775: In sched driver, there is a possible use after free due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06479032; Issue ID: ALPS06479032.

CVE-2022-26452: In isp, there is a possible use after free due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07262305; Issue ID: ALPS07262305.

CVE-2022-26473: In vdec fmt, there is a possible use after free due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07342197; Issue ID: ALPS07342197.

CVE-2022-32811: A memory corruption vulnerability was addressed with improved locking. This issue is fixed in macOS Monterey 12.5, macOS Big Sur 11.6.8, Security Update 2022-005 Catalina. An app may be able to execute arbitrary code with kernel privileges.

CVE-2022-39131: In camera driver, there is a possible memory corruption due to improper locking. This could lead to local denial of service in kernel.

CVE-2022-42775: In camera driver, there is a possible memory corruption due to improper locking. This could lead to local denial of service in kernel.

CVE-2022-26356: Racy interactions between dirty vram tracking and paging log dirty hypercalls Activation of log dirty mode done by XEN_DMOP_track_dirty_vram (was named HVMOP_track_dirty_vram before Xen 4.9) is racy with ongoing log dirty hypercalls. A suitably timed call to XEN_DMOP_track_dirty_vram can enable log dirty while another CPU is still in the process of tearing down the structures related to a previously enabled log dirty mode (XEN_DOMCTL_SHADOW_OP_OFF). This is due to lack of mutually exclusive locking between both operations and can lead to entries being added in already freed slots, resulting in a memory leak.

CVE-2021-1782: A race condition was addressed with improved locking. This issue is fixed in macOS Big Sur 11.2, Security Update 2021-001 Catalina, Security Update 2021-001 Mojave, watchOS 7.3, tvOS 14.4, iOS 14.4 and iPadOS 14.4. A malicious application may be able to elevate privileges. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-0147: Improper locking in the Power Management Controller (PMC) for some Intel Chipset firmware before versions pmc_fw_lbg_c1-21ww02a and pmc_fw_lbg_b0-21ww02a may allow a privileged user to potentially enable denial of service via local access.

CVE-2021-39640: In __dwc3_gadget_ep0_queue of ep0.c, there is a possible out of bounds write due to improper locking. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-157294279References: N/A

CVE-2021-39649: In regmap_exit of regmap.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-174049006References: N/A

CVE-2022-20153: In rcu_cblist_dequeue of rcu_segcblist.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-222091980References: Upstream kernel

CVE-2022-20376: In trusty_log_seq_start of trusty-log.c, there is a possible use after free due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-216130110References: N/A

CVE-2022-26451: In ged, there is a possible use after free due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS07202966; Issue ID: ALPS07202966.

CVE-2022-38690: In camera driver, there is a possible memory corruption due to improper locking. This could lead to local denial of service in kernel.

CVE-2022-48216: Uniswap Universal Router before 1.1.0 mishandles reentrancy. This would have allowed theft of funds.

# CWE-668 Exposure of Resource to Wrong Sphere

## Description

The product exposes a resource to the wrong control sphere, providing unintended actors with inappropriate access to the resource.

Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object. For example, a program may intend that private files can only be provided to a specific user. This effectively defines a control sphere that is intended to prevent attackers from accessing these private files. If the file permissions are insecure, then parties other than the user will be able to access those files.


A separate control sphere might effectively require that the user can only access the private files, but not any other files on the system. If the program does not ensure that the user is only requesting private files, then the user might be able to access other files on the system.


In either case, the end result is that a resource has been exposed to the wrong party.

## Top 25 Examples

CVE-2022-0815: Improper access control vulnerability in McAfee WebAdvisor Chrome and Edge browser extensions up to 8.1.0.1895 allows a remote attacker to gain access to McAfee WebAdvisor settings and other details about the user’s system. This could lead to unexpected behaviors including; settings being changed, fingerprinting of the system leading to targeted scams, and not triggering the malicious software if McAfee software is detected.

CVE-2021-36710: ToaruOS 1.99.2 is affected by incorrect access control via the kernel. Improper MMU management and having a low GDT address allows it to be mapped in userland. A call gate can then be written to escalate to CPL 0.

CVE-2021-38505: Microsoft introduced a new feature in Windows 10 known as Cloud Clipboard which, if enabled, will record data copied to the clipboard to the cloud, and make it available on other computers in certain scenarios. Applications that wish to prevent copied data from being recorded in Cloud History must use specific clipboard formats; and Firefox before versions 94 and ESR 91.3 did not implement them. This could have caused sensitive data to be recorded to a user's Microsoft account. *This bug only affects Firefox for Windows 10+ with Cloud Clipboard enabled. Other operating systems are unaffected.*. This vulnerability affects Firefox < 94, Thunderbird < 91.3, and Firefox ESR < 91.3.

CVE-2021-44522: A vulnerability has been identified in SiPass integrated V2.76 (All versions), SiPass integrated V2.80 (All versions), SiPass integrated V2.85 (All versions), Siveillance Identity V1.5 (All versions), Siveillance Identity V1.6 (All versions < V1.6.284.0). Affected applications insufficiently limit the access to the internal message broker system. This could allow an unauthenticated remote attacker to subscribe to arbitrary message queues.

CVE-2021-44523: A vulnerability has been identified in SiPass integrated V2.76 (All versions), SiPass integrated V2.80 (All versions), SiPass integrated V2.85 (All versions), Siveillance Identity V1.5 (All versions), Siveillance Identity V1.6 (All versions < V1.6.284.0). Affected applications insufficiently limit the access to the internal activity feed database. This could allow an unauthenticated remote attacker to read, modify or delete activity feed entries.

CVE-2022-28160: Jenkins Tests Selector Plugin 1.3.3 and earlier allows users with Item/Configure permission to read arbitrary files on the Jenkins controller.

CVE-2022-39015: Under certain conditions, BOE AdminTools/ BOE SDK allows an attacker to access information which would otherwise be restricted.

CVE-2022-32249: Under special integration scenario of SAP Business one and SAP HANA - version 10.0, an attacker can exploit HANA cockpit?s data volume to gain access to highly sensitive information (e.g., high privileged account credentials)

CVE-2022-26121: An exposure of resource to wrong sphere vulnerability [CWE-668] in FortiAnalyzer and FortiManager GUI 7.0.0 through 7.0.3, 6.4.0 through 6.4.8, 6.2.0 through 6.2.9, 6.0.0 through 6.0.11, 5.6.0 through 5.6.11 may allow an unauthenticated and remote attacker to access report template images via referencing the name in the URL path.

CVE-2022-28924: An information disclosure vulnerability in UniverSIS-Students before v1.5.0 allows attackers to obtain sensitive information via a crafted GET request to the endpoint /api/students/me/courses/.

CVE-2022-3866: HashiCorp Nomad and Nomad Enterprise 1.4.0 up to 1.4.1 workload identity token can list non-sensitive metadata for paths under nomad/ that belong to other jobs in the same namespace. Fixed in 1.4.2.

CVE-2022-45438: When explicitly enabling the feature flag DASHBOARD_CACHE (disabled by default), the system allowed for an unauthenticated user to access dashboard configuration metadata using a REST API Get endpoint. This issue affects Apache Superset version 1.5.2 and prior versions and version 2.0.0. 

CVE-2022-46756:  Dell VxRail, versions prior to 7.0.410, contain a Container Escape Vulnerability. A local high-privileged attacker could potentially exploit this vulnerability, leading to the execution of arbitrary OS commands on the container's underlying OS. Exploitation may lead to a system take over by an attacker. 

CVE-2022-22515: A remote, authenticated attacker could utilize the control program of the CODESYS Control runtime system to use the vulnerability in order to read and modify the configuration file(s) of the affected products.

CVE-2022-22732: A CWE-668: Exposure of Resource to Wrong Sphere vulnerability exists that could cause all remote domains to access the resources (data) supplied by the server when an attacker sends a fetch request from third-party site or malicious site. Affected Products: EcoStruxure Power Commission (Versions prior to V2.22)

CVE-2022-32530: A CWE-668 Exposure of Resource to Wrong Sphere vulnerability exists that could cause users to be misled, hiding alarms, showing the wrong server connection option or the wrong control request when a mobile device has been compromised by a malicious application. Affected Product: Geo SCADA Mobile (Build 222 and prior)

CVE-2022-34464: A vulnerability has been identified in SICAM GridEdge Essential ARM (All versions), SICAM GridEdge Essential Intel (All versions < V2.7.3), SICAM GridEdge Essential with GDS ARM (All versions), SICAM GridEdge Essential with GDS Intel (All versions < V2.7.3). Affected software uses an improperly protected file to import SSH keys. Attackers with access to the filesystem of the host on which SICAM GridEdge runs, are able to inject a custom SSH key to that file.

CVE-2022-24074: Whale Bridge, a default extension in Whale browser before 3.12.129.18, allowed to receive any SendMessage request from the content script itself that could lead to controlling Whale Bridge if the rendering process compromises.

# CWE-669 Incorrect Resource Transfer Between Spheres

## Description

The product does not properly transfer a resource/behavior to another sphere, or improperly imports a resource/behavior from another sphere, in a manner that provides unintended control over that resource.

A "control sphere" is a set of resources and behaviors that are accessible to a single actor, or a group of actors. A product's security model will typically define multiple spheres, possibly implicitly. For example, a server might define one sphere for "administrators" who can create new user accounts with subdirectories under /home/server/, and a second sphere might cover the set of users who can create or delete files within their own subdirectories. A third sphere might be "users who are authenticated to the operating system on which the product is installed." Each sphere has different sets of actors and allowable behaviors.

## Observed Examples

CVE-2021-22909: Chain: router's firmware update procedure uses curl with "-k" (insecure) option that disables certificate validation (CWE-295), allowing adversary-in-the-middle (AITM) compromise with a malicious firmware image (CWE-494).

CVE-2023-5227: PHP-based FAQ management app does not check the MIME type for uploaded images

CVE-2005-0406: Some image editors modify a JPEG image, but the original EXIF thumbnail image is left intact within the JPEG. (Also an interaction error).

# CWE-67 Improper Handling of Windows Device Names

## Description

The product constructs pathnames from user input, but it does not handle or incorrectly handles a pathname containing a Windows device name such as AUX or CON. This typically leads to denial of service or an information exposure when the application attempts to process the pathname as a regular file.

Not properly handling virtual filenames (e.g. AUX, CON, PRN, COM1, LPT1) can result in different types of vulnerabilities. In some cases an attacker can request a device via injection of a virtual filename in a URL, which may cause an error that leads to a denial of service or an error page that reveals sensitive information. A product that allows device names to bypass filtering runs the risk of an attacker injecting malicious code in a file with the name of a device.

Historically, there was a bug in the Windows operating system that caused a blue screen of death. Even after that issue was fixed DOS device names continue to be a factor.

## Observed Examples

CVE-2002-0106: Server allows remote attackers to cause a denial of service via a series of requests to .JSP files that contain an MS-DOS device name.

CVE-2002-0200: Server allows remote attackers to cause a denial of service via an HTTP request for an MS-DOS device name.

CVE-2002-1052: Product allows remote attackers to use MS-DOS device names in HTTP requests to cause a denial of service or obtain the physical path of the server.

CVE-2001-0493: Server allows remote attackers to cause a denial of service via a URL that contains an MS-DOS device name.

CVE-2001-0558: Server allows a remote attacker to create a denial of service via a URL request which includes a MS-DOS device name.

CVE-2000-0168: Microsoft Windows 9x operating systems allow an attacker to cause a denial of service via a pathname that includes file device names, aka the "DOS Device in Path Name" vulnerability.

CVE-2001-0492: Server allows remote attackers to determine the physical path of the server via a URL containing MS-DOS device names.

CVE-2004-0552: Product does not properly handle files whose names contain reserved MS-DOS device names, which can allow malicious code to bypass detection when it is installed, copied, or executed.

CVE-2005-2195: Server allows remote attackers to cause a denial of service (application crash) via a URL with a filename containing a .cgi extension and an MS-DOS device name.

# CWE-670 Always-Incorrect Control Flow Implementation

## Description

The code contains a control flow path that does not reflect the algorithm that the path is intended to implement, leading to incorrect behavior any time this path is navigated.

This weakness captures cases in which a particular code segment is always incorrect with respect to the algorithm that it is implementing. For example, if a C programmer intends to include multiple statements in a single block but does not include the enclosing braces (CWE-483), then the logic is always incorrect. This issue is in contrast to most weaknesses in which the code usually behaves correctly, except when it is externally manipulated in malicious ways.

## Observed Examples

CVE-2021-3011: virtual interrupt controller in a virtualization product allows crash of host by writing a certain invalid value to a register, which triggers a fatal error instead of returning an error code

## Top 25 Examples

CVE-2022-45196: Hyperledger Fabric 2.3 allows attackers to cause a denial of service (orderer crash) by repeatedly sending a crafted channel tx with the same Channel name. NOTE: the official Fabric with Raft prevents exploitation via a locking mechanism and a check for names that already exist.

# CWE-671 Lack of Administrator Control over Security

## Description

The product uses security features in a way that prevents the product's administrator from tailoring security settings to reflect the environment in which the product is being used. This introduces resultant weaknesses or prevents it from operating at a level of security that is desired by the administrator.

If the product's administrator does not have the ability to manage security-related decisions at all times, then protecting the product from outside threats - including the product's developer - can become impossible. For example, a hard-coded account name and password cannot be changed by the administrator, thus exposing that product to attacks that the administrator can not prevent.

## Observed Examples

CVE-2022-29953: Condition Monitor firmware has a maintenance interface with hard-coded credentials

CVE-2000-0127: GUI configuration tool does not enable a security option when a checkbox is selected, although that option is honored when manually set in the configuration file.

## Top 25 Examples

CVE-2021-20612: Lack of administrator control over security vulnerability in MELSEC-F series FX3U-ENET Firmware version 1.14 and prior, FX3U-ENET-L Firmware version 1.14 and prior and FX3U-ENET-P502 Firmware version 1.14 and prior allows a remote unauthenticated attacker to cause a denial-of-service (DoS) condition in communication function of the product or other unspecified effects by sending specially crafted packets to an unnecessary opening of TCP port. Control by MELSEC-F series PLC is not affected by this vulnerability, but system reset is required for recovery.

# CWE-672 Operation on a Resource after Expiration or Release

## Description

The product uses, accesses, or otherwise operates on a resource after that resource has been expired, released, or revoked.

## Observed Examples

CVE-2009-3547: Chain: race condition (CWE-362) might allow resource to be released before operating on it, leading to NULL dereference (CWE-476)

# CWE-673 External Influence of Sphere Definition

## Description

The product does not prevent the definition of control spheres from external actors.

Typically, a product defines its control sphere within the code itself, or through configuration by the product's administrator. In some cases, an external party can change the definition of the control sphere. This is typically a resultant weakness.

## Observed Examples

CVE-2008-2613: setuid program allows compromise using path that finds and loads a malicious library.

# CWE-674 Uncontrolled Recursion

## Description

The product does not properly control the amount of recursion that takes place,  consuming excessive resources, such as allocated memory or the program stack.

## Observed Examples

CVE-2007-1285: Deeply nested arrays trigger stack exhaustion.

CVE-2007-3409: Self-referencing pointers create infinite loop and resultant stack exhaustion.

CVE-2016-10707: Javascript application accidentally changes input in a way that prevents a recursive call from detecting an exit condition.

CVE-2016-3627: An attempt to recover a corrupted XML file infinite recursion protection counter was not always incremented missing the exit condition.

CVE-2019-15118: USB-audio driver's descriptor code parsing allows unlimited recursion leading to stack exhaustion.

## Top 25 Examples

CVE-2021-3622: A flaw was found in the hivex library. This flaw allows an attacker to input a specially crafted Windows Registry (hive) file, which would cause hivex to recursively call the _get_children() function, leading to a stack overflow. The highest threat from this vulnerability is to system availability.

CVE-2021-41752: Stack overflow vulnerability in Jerryscript before commit e1ce7dd7271288be8c0c8136eea9107df73a8ce2 on Oct 20, 2021 due to an unbounded recursive call to the new opt() function.

CVE-2021-45832: A Stack-based Buffer Overflow Vulnerability exists in HDF5 1.13.1-1 at at hdf5/src/H5Eint.c, which causes a Denial of Service (context-dependent).

CVE-2021-46505: Jsish v3.5.0 was discovered to contain a stack overflow via /usr/lib/x86_64-linux-gnu/libasan.so.4+0x5b1e5.

CVE-2021-46507: Jsish v3.5.0 was discovered to contain a stack overflow via Jsi_LogMsg at src/jsiUtils.c.

CVE-2021-46509: Cesanta MJS v2.20.0 was discovered to contain a stack overflow via snquote at mjs/src/mjs_json.c.

CVE-2022-20382: In (TBD) of (TBD), there is a possible out of bounds write due to kernel stack overflow. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-214245176References: Upstream kernel

CVE-2022-21708: graphql-go is a GraphQL server with a focus on ease of use. In versions prior to 1.3.0 there exists a DoS vulnerability that is possible due to a bug in the library that would allow an attacker with specifically designed queries to cause stack overflow panics. Any user with access to the GraphQL handler can send these queries and cause stack overflows. This in turn could potentially compromise the ability of the server to serve data to its users. The issue has been patched in version `v1.3.0`. The only known workaround for this issue is to disable the `graphql.MaxDepth` option from your schema which is not recommended.

CVE-2022-23591: Tensorflow is an Open Source Machine Learning Framework. The `GraphDef` format in TensorFlow does not allow self recursive functions. The runtime assumes that this invariant is satisfied. However, a `GraphDef` containing a fragment such as the following can be consumed when loading a `SavedModel`. This would result in a stack overflow during execution as resolving each `NodeDef` means resolving the function itself and its nodes. The fix will be included in TensorFlow 2.8.0. We will also cherrypick this commit on TensorFlow 2.7.1, TensorFlow 2.6.3, and TensorFlow 2.5.3, as these are also affected and still in supported range.

CVE-2022-24675: encoding/pem in Go before 1.17.9 and 1.18.x before 1.18.1 has a Decode stack overflow via a large amount of PEM data.

CVE-2022-31019: Vapor is a server-side Swift HTTP web framework. When using automatic content decoding an attacker can craft a request body that can make the server crash with the following request: `curl -d "array[_0][0][array][_0][0][array]$(for f in $(seq 1100); do echo -n '[_0][0][array]'; done)[string][_0]=hello%20world" http://localhost:8080/foo`. The issue is unbounded, attacker controlled stack growth which will at some point lead to a stack overflow and a process crash. This issue has been fixed in version 4.61.1.

CVE-2022-31099: rulex is a new, portable, regular expression language. When parsing untrusted rulex expressions, the stack may overflow, possibly enabling a Denial of Service attack. This happens when parsing an expression with several hundred levels of nesting, causing the process to abort immediately. This is a security concern for you, if your service parses untrusted rulex expressions (expressions provided by an untrusted user), and your service becomes unavailable when the process running rulex aborts due to a stack overflow. The crash is fixed in version **0.4.3**. Affected users are advised to update to this version. There are no known workarounds for this issue.

CVE-2022-3216: A vulnerability has been found in Nintendo Game Boy Color and classified as problematic. This vulnerability affects unknown code of the component Mobile Adapter GB. The manipulation leads to memory corruption. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. VDB-208606 is the identifier assigned to this vulnerability.

CVE-2022-38334: XPDF v4.04 and earlier was discovered to contain a stack overflow via the function Catalog::countPageTree() at Catalog.cc.

CVE-2022-41966: XStream serializes Java objects to XML and back again. Versions prior to 1.4.20 may allow a remote attacker to terminate the application with a stack overflow error, resulting in a denial of service only via manipulation the processed input stream. The attack uses the hash code implementation for collections and maps to force recursive hash calculation causing a stack overflow. This issue is patched in version 1.4.20 which handles the stack overflow and raises an InputManipulationException instead. A potential workaround for users who only use HashMap or HashSet and whose XML refers these only as default map or set, is to change the default implementation of java.util.Map and java.util per the code example in the referenced advisory. However, this implies that your application does not care about the implementation of the map and all elements are comparable.

CVE-2022-47662: GPAC MP4Box 2.1-DEV-rev649-ga8f438d20 has a segment fault (/stack overflow) due to infinite recursion in Media_GetSample isomedia/media.c:662

CVE-2022-23460: Jsonxx or Json++ is a JSON parser, writer and reader written in C++. In affected versions of jsonxx json parsing may lead to stack exhaustion in an address sanitized (ASAN) build. This issue may lead to Denial of Service if the program using the jsonxx library crashes. This issue exists on the current commit of the jsonxx project and the project itself has been archived. Updates are not expected. Users are advised to find a replacement.

CVE-2022-23606: Envoy is an open source edge and service proxy, designed for cloud-native applications. When a cluster is deleted via Cluster Discovery Service (CDS) all idle connections established to endpoints in that cluster are disconnected. A recursion was introduced in the procedure of disconnecting idle connections that can lead to stack exhaustion and abnormal process termination when a cluster has a large number of idle connections. This infinite recursion causes Envoy to crash. Users are advised to upgrade.

CVE-2022-24921: regexp.Compile in Go before 1.16.15 and 1.17.x before 1.17.8 allows stack exhaustion via a deeply nested expression.

CVE-2022-25313: In Expat (aka libexpat) before 2.4.5, an attacker can trigger stack exhaustion in build_model via a large nesting depth in the DTD element.

CVE-2022-27810: It was possible to trigger an infinite recursion condition in the error handler when Hermes executed specific maliciously formed JavaScript. This condition was only possible to trigger in dev-mode (when asserts were enabled). This issue affects Hermes versions prior to v0.12.0.

CVE-2022-28201: An issue was discovered in MediaWiki before 1.35.6, 1.36.x before 1.36.4, and 1.37.x before 1.37.2. Users with the editinterface permission can trigger infinite recursion, because a bare local interwiki is mishandled for the mainpage message.

CVE-2022-28773: Due to an uncontrolled recursion in SAP Web Dispatcher and SAP Internet Communication Manager, the application may crash, leading to denial of service, but can be restarted automatically. 

CVE-2022-31173: Juniper is a GraphQL server library for Rust. Affected versions of Juniper are vulnerable to uncontrolled recursion resulting in a program crash. This issue has been addressed in version 0.15.10. Users are advised to upgrade. Users unable to upgrade should limit the recursion depth manually.

CVE-2022-37315: graphql-go (aka GraphQL for Go) through 0.8.0 has infinite recursion in the type definition parser.

CVE-2022-41881: Netty project is an event-driven asynchronous network application framework. In versions prior to 4.1.86.Final, a StackOverflowError can be raised when parsing a malformed crafted message due to an infinite recursion. This issue is patched in version 4.1.86.Final. There is no workaround, except using a custom HaProxyMessageDecoder.

CVE-2022-27943: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

CVE-2022-40150: Those using Jettison to parse untrusted XML or JSON data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by Out of memory. This effect may support a denial of service attack.

# CWE-675 Multiple Operations on Resource in Single-Operation Context

## Description

The product performs the same operation on a resource two or more times, when the operation should only be applied once.

## Observed Examples

CVE-2009-0935: Attacker provides invalid address to a memory-reading function, causing a mutex to be unlocked twice

CVE-2019-13351: file descriptor double close can cause the wrong file to be associated with a file descriptor.

CVE-2004-1939: XSS protection mechanism attempts to remove "/" that could be used to close tags, but it can be bypassed using double encoded slashes (%252F)

## Top 25 Examples

CVE-2022-39190: An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of service can occur upon binding to an already bound chain.

# CWE-676 Use of Potentially Dangerous Function

## Description

The product invokes a potentially dangerous function that could introduce a vulnerability if it is used incorrectly, but the function can also be used safely.

## Observed Examples

CVE-2007-1470: Library has multiple buffer overflows using sprintf() and strcpy()

CVE-2009-3849: Buffer overflow using strcat()

CVE-2006-2114: Buffer overflow using strcpy()

CVE-2006-0963: Buffer overflow using strcpy()

CVE-2011-0712: Vulnerable use of strcpy() changed to use safer strlcpy()

CVE-2008-5005: Buffer overflow using strcpy()

## Top 25 Examples

CVE-2022-26531: Multiple improper input validation flaws were identified in some CLI commands of Zyxel USG/ZyWALL series firmware versions 4.09 through 4.71, USG FLEX series firmware versions 4.50 through 5.21, ATP series firmware versions 4.32 through 5.21, VPN series firmware versions 4.30 through 5.21, NSG series firmware versions 1.00 through 1.33 Patch 4, NXC2500 firmware version 6.10(AAIG.3) and earlier versions, NAP203 firmware version 6.25(ABFA.7) and earlier versions, NWA50AX firmware version 6.25(ABYW.5) and earlier versions, WAC500 firmware version 6.30(ABVS.2) and earlier versions, and WAX510D firmware version 6.30(ABTF.2) and earlier versions, that could allow a local authenticated attacker to cause a buffer overflow or a system crash via a crafted payload.

CVE-2022-27255: In Realtek eCos RSDK 1.5.7p1 and MSDK 4.9.4p1, the SIP ALG function that rewrites SDP data has a stack-based buffer overflow. This allows an attacker to remotely execute code without authentication via a crafted SIP packet that contains malicious SDP data.

CVE-2022-0736: Insecure Temporary File in GitHub repository mlflow/mlflow prior to 1.23.1.

# CWE-680 Integer Overflow to Buffer Overflow

## Description

The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.

## Observed Examples

CVE-2021-43537: Chain: in a web browser, an unsigned 64-bit integer is forcibly cast to a 32-bit integer (CWE-681) and potentially leading to an integer overflow (CWE-190). If an integer overflow occurs, this can cause heap memory corruption (CWE-122)

CVE-2017-1000121: chain: unchecked message size metadata allows integer overflow (CWE-190) leading to buffer overflow (CWE-119).

## Top 25 Examples

CVE-2022-33248: Memory corruption in User Identity Module due to integer overflow to buffer overflow when a segement is received via qmi http.

# CWE-681 Incorrect Conversion between Numeric Types

## Description

When converting from one data type to another, such as long to integer, data can be omitted or translated in a way that produces unexpected values. If the resulting values are used in a sensitive context, then dangerous behaviors may occur.

## Observed Examples

CVE-2022-2639: Chain: integer coercion error (CWE-192) prevents a return value from indicating an error, leading to out-of-bounds write (CWE-787)

CVE-2021-43537: Chain: in a web browser, an unsigned 64-bit integer is forcibly cast to a 32-bit integer (CWE-681) and potentially leading to an integer overflow (CWE-190). If an integer overflow occurs, this can cause heap memory corruption (CWE-122)

CVE-2007-4268: Chain: integer signedness error (CWE-195) passes signed comparison, leading to heap overflow (CWE-122)

CVE-2007-4988: Chain: signed short width value in image processor is sign extended during conversion to unsigned int, which leads to integer overflow and heap-based buffer overflow.

CVE-2009-0231: Integer truncation of length value leads to heap-based buffer overflow.

CVE-2008-3282: Size of a particular type changes for 64-bit platforms, leading to an integer truncation in document processor causes incorrect index to be generated.

## Top 25 Examples

CVE-2021-0964: In C2SoftMP3::process() of C2SoftMp3Dec.cpp, there is a possible out of bounds write due to a heap buffer overflow. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-9Android ID: A-193363621

# CWE-682 Incorrect Calculation

## Description

The product performs a calculation that generates incorrect or unintended results that are later used in security-critical decisions or resource management.

When product performs a security-critical calculation incorrectly, it might lead to incorrect resource allocations, incorrect privilege assignments, or failed comparisons among other things. Many of the direct results of an incorrect calculation can lead to even larger problems such as failed protection mechanisms or even arbitrary code execution.

## Observed Examples

CVE-2020-0022: chain: mobile phone Bluetooth implementation does not include offset when calculating packet length (CWE-682), leading to out-of-bounds write (CWE-787)

CVE-2004-1363: substitution overflow: buffer overflow using environment variables that are expanded after the length check is performed

## Top 25 Examples

CVE-2021-44847: A stack-based buffer overflow in handle_request function in DHT.c in toxcore 0.1.9 through 0.1.11 and 0.2.0 through 0.2.12 (caused by an improper length calculation during the handling of received network packets) allows remote attackers to crash the process or potentially execute arbitrary code via a network packet.

CVE-2022-31748: Mozilla developers Gabriele Svelto, Timothy Nikkel, Randell Jesup, Jon Coppeard, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 100. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 101.

CVE-2022-30780: Lighttpd 1.4.56 through 1.4.58 allows a remote attacker to cause a denial of service (CPU consumption from stuck connections) because connection_read_header_more in connections.c has a typo that disrupts use of multiple read operations on large headers.

# CWE-683 Function Call With Incorrect Order of Arguments

## Description

The product calls a function, procedure, or routine, but the caller specifies the arguments in an incorrect order, leading to resultant weaknesses.

While this weakness might be caught by the compiler in some languages, it can occur more frequently in cases in which the called function accepts variable numbers or types of arguments, such as format strings in C. It also can occur in languages or environments that do not enforce strong typing.

## Observed Examples

CVE-2006-7049: Application calls functions with arguments in the wrong order, allowing attacker to bypass intended access restrictions.

# CWE-684 Incorrect Provision of Specified Functionality

## Description

The code does not function according to its published specifications, potentially leading to incorrect usage.

When providing functionality to an external party, it is important that the product behaves in accordance with the details specified. When requirements of nuances are not documented, the functionality may produce unintended behaviors for the caller, possibly leading to an exploitable state.

## Observed Examples

CVE-2002-1446: Error checking routine in PKCS#11 library returns "OK" status even when invalid signature is detected, allowing spoofed messages.

CVE-2001-1559: Chain: System call returns wrong value (CWE-393), leading to a resultant NULL dereference (CWE-476).

CVE-2003-0187: Program uses large timeouts on unconfirmed connections resulting from inconsistency in linked lists implementations.

CVE-1999-1446: UI inconsistency; visited URLs list not cleared when "Clear History" option is selected.

# CWE-685 Function Call With Incorrect Number of Arguments

## Description

The product calls a function, procedure, or routine, but the caller specifies too many arguments, or too few arguments, which may lead to undefined behavior and resultant weaknesses.

# CWE-686 Function Call With Incorrect Argument Type

## Description

The product calls a function, procedure, or routine, but the caller specifies an argument that is the wrong data type, which may lead to resultant weaknesses.

This weakness is most likely to occur in loosely typed languages, or in strongly typed languages in which the types of variable arguments cannot be enforced at compilation time, or where there is implicit casting.

# CWE-687 Function Call With Incorrectly Specified Argument Value

## Description

The product calls a function, procedure, or routine, but the caller specifies an argument that contains the wrong value, which may lead to resultant weaknesses.

# CWE-688 Function Call With Incorrect Variable or Reference as Argument

## Description

The product calls a function, procedure, or routine, but the caller specifies the wrong variable or reference as one of the arguments, which may lead to undefined behavior and resultant weaknesses.

## Observed Examples

CVE-2005-2548: Kernel code specifies the wrong variable in first argument, leading to resultant NULL pointer dereference.

# CWE-689 Permission Race Condition During Resource Copy

## Description

The product, while copying or cloning a resource, does not set the resource's permissions or access control until the copy is complete, leaving the resource exposed to other spheres while the copy is taking place.

## Observed Examples

CVE-2002-0760: Archive extractor decompresses files with world-readable permissions, then later sets permissions to what the archive specified.

CVE-2005-2174: Product inserts a new object into database before setting the object's permissions, introducing a race condition.

CVE-2006-5214: Error file has weak permissions before a chmod is performed.

CVE-2005-2475: Archive permissions issue using hard link.

CVE-2003-0265: Database product creates files world-writable before initializing the setuid bits, leading to modification of executables.

# CWE-69 Improper Handling of Windows ::DATA Alternate Data Stream

## Description

The product does not properly prevent access to, or detect usage of, alternate data streams (ADS).

An attacker can use an ADS to hide information about a file (e.g. size, the name of the process) from a system or file browser tools such as Windows Explorer and 'dir' at the command line utility. Alternately, the attacker might be able to bypass intended access restrictions for the associated data fork.

Alternate data streams (ADS) were first implemented in the Windows NT operating system to provide compatibility between NTFS and the Macintosh Hierarchical File System (HFS). In HFS, data and resource forks are used to store information about a file. The data fork provides information about the contents of the file while the resource fork stores metadata such as file type.

## Observed Examples

CVE-1999-0278: In IIS, remote attackers can obtain source code for ASP files by appending "::$DATA" to the URL.

CVE-2000-0927: Product does not properly record file sizes if they are stored in alternative data streams, which allows users to bypass quota restrictions.

# CWE-690 Unchecked Return Value to NULL Pointer Dereference

## Description

The product does not check for an error after calling a function that can return with a NULL pointer if the function fails, which leads to a resultant NULL pointer dereference.

While unchecked return value weaknesses are not limited to returns of NULL pointers (see the examples in CWE-252), functions often return NULL to indicate an error status. When this error condition is not checked, a NULL pointer dereference can occur.

## Observed Examples

CVE-2008-1052: Large Content-Length value leads to NULL pointer dereference when malloc fails.

CVE-2006-6227: Large message length field leads to NULL pointer dereference when malloc fails.

CVE-2006-2555: Parsing routine encounters NULL dereference when input is missing a colon separator.

CVE-2003-1054: URI parsing API sets argument to NULL when a parsing failure occurs, such as when the Referer header is missing a hostname, leading to NULL dereference.

CVE-2008-5183: chain: unchecked return value can lead to NULL dereference

# CWE-691 Insufficient Control Flow Management

## Description

The code does not sufficiently manage its control flow during execution, creating conditions in which the control flow can be modified in unexpected ways.

## Observed Examples

CVE-2019-9805: Chain: Creation of the packet client occurs before initialization is complete (CWE-696) resulting in a read from uninitialized memory (CWE-908), causing memory corruption.

CVE-2014-1266: chain: incorrect "goto" in Apple SSL product bypasses certificate validation, allowing Adversary-in-the-Middle (AITM) attack (Apple "goto fail" bug). CWE-705 (Incorrect Control Flow Scoping) -> CWE-561 (Dead Code) -> CWE-295 (Improper Certificate Validation) -> CWE-393 (Return of Wrong Status Code) -> CWE-300 (Channel Accessible by Non-Endpoint).

CVE-2011-1027: Chain: off-by-one error (CWE-193) leads to infinite loop (CWE-835) using invalid hex-encoded characters.

## Top 25 Examples

CVE-2021-0073: Insufficient control flow management in Intel(R) DSA before version 20.11.50.9 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2021-0127: Insufficient control flow management in some Intel(R) Processors may allow an authenticated user to potentially enable a denial of service via local access.

CVE-2021-33061: Insufficient control flow management for the Intel(R) 82599 Ethernet Controllers and Adapters may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-21128: Insufficient control flow management in the Intel(R) Advisor software before version 7.6.0.37 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-21793: Insufficient control flow management in the Intel(R) Ethernet 500 Series Controller drivers for VMWare before version 1.11.4.0 and in the Intel(R) Ethernet 700 Series Controller drivers for VMWare before version 2.1.5.0 may allow an authenticated user to potentially enable a denial of service via local access.

CVE-2022-26841: Insufficient control flow management for the Intel(R) SGX SDK software for Linux before version 2.16.100.1 may allow an authenticated user to potentially enable information disclosure via local access.

CVE-2022-27808: Insufficient control flow management in some Intel(R) Ethernet Controller Administrative Tools drivers for Windows before version 1.5.0.2 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-33902: Insufficient control flow management in the Intel(R) Quartus Prime Pro and Standard edition software may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-36278: Insufficient control flow management in the Intel(R) Battery Life Diagnostic Tool software before version 2.2.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

# CWE-692 Incomplete Denylist to Cross-Site Scripting

## Description

The product uses a denylist-based protection mechanism to defend against XSS attacks, but the denylist is incomplete, allowing XSS variants to succeed.

While XSS might seem simple to prevent, web browsers vary so widely in how they parse web pages, that a denylist cannot keep track of all the variations. The "XSS Cheat Sheet" [REF-714] contains a large number of attacks that are intended to bypass incomplete denylists.

## Observed Examples

CVE-2007-5727: Denylist only removes <SCRIPT> tag.

CVE-2006-3617: Denylist only removes <SCRIPT> tag.

CVE-2006-4308: Denylist only checks "javascript:" tag

# CWE-693 Protection Mechanism Failure

## Description

The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

This weakness covers three distinct situations. A "missing" protection mechanism occurs when the application does not define any mechanism against a certain class of attack. An "insufficient" protection mechanism might provide some defenses - for example, against the most common attacks - but it does not protect against everything that is intended. Finally, an "ignored" mechanism occurs when a mechanism is available and in active use within the product, but the developer has not applied it in some code path.

## Top 25 Examples

CVE-2021-20872: Protection mechanism failure vulnerability in KONICA MINOLTA bizhub series (bizhub C750i G00-35 and earlier, bizhub C650i/C550i/C450i G00-B6 and earlier, bizhub C360i/C300i/C250i G00-B6 and earlier, bizhub 750i/650i/550i/450i G00-37 and earlier, bizhub 360i/300i G00-33 and earlier, bizhub C287i/C257i/C227i G00-19 and earlier, bizhub 306i/266i/246i/226i G00-B6 and earlier, bizhub C759/C659 GC7-X8 and earlier, bizhub C658/C558/C458 GC7-X8 and earlier, bizhub 958/808/758 GC7-X8 and earlier, bizhub 658e/558e/458e GC7-X8 and earlier, bizhub C287/C227 GC7-X8 and earlier, bizhub 287/227 GC7-X8 and earlier, bizhub 368e/308e GC7-X8 and earlier, bizhub C368/C308/C258 GC9-X4 and earlier, bizhub 558/458/368/308 GC9-X4 and earlier, bizhub C754e/C654e GDQ-M0 and earlier, bizhub 754e/654e GDQ-M0 and earlier, bizhub C554e/C454e GDQ-M1 and earlier, bizhub C364e/C284e/C224e GDQ-M1 and earlier, bizhub 554e/454e/364e/284e/224e GDQ-M1 and earlier, bizhub C754/C654 C554/C454 GR1-M0 and earlier, bizhub C364/C284/C224 GR1-M0 and earlier, bizhub 754/654 GR1-M0 and earlier, bizhub C3851FS/C3851/C3351 GC9-X4 and earlier, bizhub 4752/4052 GC9-X4 and earlier) allows a physical attacker to bypass the firmware integrity verification and to install malicious firmware.

CVE-2021-31362: A Protection Mechanism Failure vulnerability in RPD (routing protocol daemon) of Juniper Networks Junos OS and Junos OS Evolved allows an adjacent unauthenticated attacker to cause established IS-IS adjacencies to go down by sending a spoofed hello PDU leading to a Denial of Service (DoS) condition. Continued receipted of these spoofed PDUs will create a sustained Denial of Service (DoS) condition. This issue affects: Juniper Networks Junos OS All versions prior to 18.2R3-S8; 18.3 versions prior to 18.3R3-S5; 18.4 versions prior to 18.4R3-S9; 19.1 versions prior to 19.1R3-S7; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior to 19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R3-S3; 20.1 versions prior to 20.1R3; 20.2 versions prior to 20.2R3; 20.3 versions prior to 20.3R3; 20.4 versions prior to 20.4R2. Juniper Networks Junos OS Evolved All versions prior to 20.4R2-EVO; 21.1 versions prior to 21.1R2-EVO.

CVE-2021-33079: Protection mechanism failure in firmware for some Intel(R) SSD DC Products may allow a privileged user to potentially enable information disclosure via local access.

CVE-2021-33081: Protection mechanism failure in firmware for some Intel(R) SSD DC Products may allow a privileged user to potentially enable information disclosure via local access.

CVE-2022-27170: Protection mechanism failure in the Intel(R) Media SDK software before version 22.2.2 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-30530: Protection mechanism failure in the Intel(R) DSA software before version 22.4.26 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-33942: Protection mechanism failure in the Intel(R) DCM software before version 5.0 may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

CVE-2022-36289: Protection mechanism failure in the Intel(R) Media SDK software before version 22.2.2 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-36416: Protection mechanism failure in the Intel(R) Ethernet 500 Series Controller drivers for VMware before version 1.10.0.13 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-36797: Protection mechanism failure in the Intel(R) Ethernet 500 Series Controller drivers for VMware before version 1.10.0.1 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-1349: The WPQA Builder Plugin WordPress plugin before 5.2, used as a companion plugin for the Discy and Himer , does not validate that the value passed to the image_id parameter of the ajax action wpqa_remove_image belongs to the requesting user, allowing any users (with privileges as low as Subscriber) to delete the profile pictures of any other user.

# CWE-694 Use of Multiple Resources with Duplicate Identifier

## Description

The product uses multiple resources that can have the same identifier, in a context in which unique identifiers are required.

If the product assumes that each resource has a unique identifier, the product could operate on the wrong resource if attackers can cause multiple resources to be associated with the same identifier.

## Observed Examples

CVE-2013-4787: chain: mobile OS verifies cryptographic signature of file in an archive, but then installs a different file with the same name that is also listed in the archive.

## Top 25 Examples

CVE-2021-3436: BT: Possible to overwrite an existing bond during keys distribution phase when the identity address of the bond is known. Zephyr versions >= 1.14.2, >= 2.4.0, >= 2.5.0 contain Use of Multiple Resources with Duplicate Identifier (CWE-694). For more information, see https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-j76f-35mc-4h63

# CWE-695 Use of Low-Level Functionality

## Description

The product uses low-level functionality that is explicitly prohibited by the framework or specification under which the product is supposed to operate.

The use of low-level functionality can violate the specification in unexpected ways that effectively disable built-in protection mechanisms, introduce exploitable inconsistencies, or otherwise expose the functionality to attack.

# CWE-696 Incorrect Behavior Order

## Description

The product performs multiple related behaviors, but the behaviors are performed in the wrong order in ways which may produce resultant weaknesses.

## Observed Examples

CVE-2019-9805: Chain: Creation of the packet client occurs before initialization is complete (CWE-696) resulting in a read from uninitialized memory (CWE-908), causing memory corruption.

CVE-2007-5191: file-system management programs call the setuid and setgid functions in the wrong order and do not check the return values, allowing attackers to gain unintended privileges

CVE-2007-1588: C++ web server program calls Process::setuid before calling Process::setgid, preventing it from dropping privileges, potentially allowing CGI programs to be called with higher privileges than intended

CVE-2022-37734: Chain: lexer in Java-based GraphQL server does not enforce maximum of tokens early enough (CWE-696), allowing excessive CPU consumption (CWE-1176)

## Top 25 Examples

CVE-2021-31379: An Incorrect Behavior Order vulnerability in the MAP-E automatic tunneling mechanism of Juniper Networks Junos OS allows an attacker to send certain malformed IPv4 or IPv6 packets to cause a Denial of Service (DoS) to the PFE on the device which is disabled as a result of the processing of these packets. Continued receipt and processing of these malformed IPv4 or IPv6 packets will create a sustained Denial of Service (DoS) condition. This issue only affects MPC 7/8/9/10/11 cards, when MAP-E IP reassembly is enabled on these cards. An indicator of compromise is the output: FPC ["FPC ID" # e.g. "0"] PFE #{PFE ID # e.g. "1"] : Fabric Disabled Example: FPC 0 PFE #1 : Fabric Disabled when using the command: show chassis fabric fpcs An example of a healthy result of the command use would be: user@device-re1> show chassis fabric fpcs Fabric management FPC state: FPC 0 PFE #0 Plane 0: Plane enabled Plane 1: Plane enabled Plane 2: Plane enabled Plane 3: Plane enabled Plane 4: Plane enabled Plane 5: Plane enabled Plane 6: Plane enabled Plane 7: Plane enabled This issue affects: Juniper Networks Junos OS on MX Series with MPC 7/8/9/10/11 cards, when MAP-E IP reassembly is enabled on these cards. 17.2 version 17.2R1 and later versions; 17.3 versions prior to 17.3R3-S9; 17.4 versions prior to 17.4R2-S12, 17.4R3-S3; 18.1 versions prior to 18.1R3-S11; 18.2 versions prior to 18.2R2-S6, 18.2R3-S3; 18.3 versions prior to 18.3R2-S4, 18.3R3-S1; 18.4 versions prior to 18.4R1-S8, 18.4R2-S5, 18.4R3; 19.1 versions prior to 19.1R1-S6, 19.1R2-S2, 19.1R3; 19.2 versions prior to 19.2R1-S5, 19.2R2; 19.3 versions prior to 19.3R2-S5, 19.3R3. This issue does not affect Juniper Networks Junos OS versions prior to 17.2R1.

CVE-2022-2456: An issue has been discovered in GitLab CE/EE affecting all versions before 15.0.5, all versions starting from 15.1 before 15.1.4, all versions starting from 15.2 before 15.2.1. It may be possible for malicious group or project maintainers to change their corresponding group or project visibility by crafting a malicious POST request.

CVE-2021-21968: A file write vulnerability exists in the OTA update task functionality of Sealevel Systems, Inc. SeaConnect 370W v1.3.34. A specially-crafted MQTT payload can lead to arbitrary file overwrite. An attacker can perform a man-in-the-middle attack to trigger this vulnerability.

CVE-2022-37734: graphql-java before19.0 is vulnerable to Denial of Service. An attacker can send a malicious GraphQL query that consumes CPU resources. The fixed versions are 19.0 and later, 18.3, and 17.4, and 0.0.0-2022-07-26T05-45-04-226aabd9.

CVE-2022-41723: A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient to cause a denial of service from a small number of small requests.

# CWE-697 Incorrect Comparison

## Description

The product compares two entities in a security-relevant context, but the comparison is incorrect, which may lead to resultant weaknesses.

This Pillar covers several possibilities:


  - the comparison checks one factor incorrectly;

  - the comparison should consider multiple factors, but it does not check at least one of those factors at all;

  - the comparison checks the wrong factor.

## Observed Examples

CVE-2021-3116: Chain: Python-based HTTP Proxy server uses the wrong boolean operators (CWE-480) causing an incorrect comparison (CWE-697) that identifies an authN failure if all three conditions are met instead of only one, allowing bypass of the proxy authentication (CWE-1390)

CVE-2020-15811: Chain: Proxy uses a substring search instead of parsing the Transfer-Encoding header (CWE-697), allowing request splitting (CWE-113) and cache poisoning

CVE-2016-10003: Proxy performs incorrect comparison of request headers, leading to infoleak

## Top 25 Examples

CVE-2022-22990: A limited authentication bypass vulnerability was discovered that could allow an attacker to achieve remote code execution and escalate privileges on the My Cloud devices. Addressed this vulnerability by changing access token validation logic and rewriting rule logic on PHP scripts.

# CWE-698 Execution After Redirect (EAR)

## Description

The web application sends a redirect to another location, but instead of exiting, it executes additional code.

## Observed Examples

CVE-2013-1402: Execution-after-redirect allows access to application configuration details.

CVE-2009-1936: chain: library file sends a redirect if it is directly requested but continues to execute, allowing remote file inclusion and path traversal.

CVE-2007-2713: Remote attackers can obtain access to administrator functionality through EAR.

CVE-2007-4932: Remote attackers can obtain access to administrator functionality through EAR.

CVE-2007-5578: Bypass of authentication step through EAR.

CVE-2007-2713: Chain: Execution after redirect triggers eval injection.

CVE-2007-6652: chain: execution after redirect allows non-administrator to perform static code injection.

