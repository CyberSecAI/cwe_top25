# CWE-40 Path Traversal: '\\UNC\share\name\' (Windows UNC Share)

## Description

The product accepts input that identifies a Windows UNC share ('\\UNC\share\name') that potentially redirects access to an unintended location or arbitrary file.

## Observed Examples

CVE-2001-0687: FTP server allows a remote attacker to retrieve privileged web server system information by specifying arbitrary paths in the UNC format (\\computername\sharename).

## Top 25 Examples

CVE-2022-21999: Windows Print Spooler Elevation of Privilege Vulnerability

CVE-2022-1128: Inappropriate implementation in Web Share API in Google Chrome on Windows prior to 100.0.4896.60 allowed an attacker on the local network segment to leak cross-origin data via a crafted HTML page.

# CWE-400 Uncontrolled Resource Consumption

## Description

The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources.

Limited resources include memory, file system storage, database connection pool entries, and CPU. If an attacker can trigger the allocation of these limited resources, but the number or size of the resources is not controlled, then the attacker could cause a denial of service that consumes all available resources. This would prevent valid users from accessing the product, and it could potentially have an impact on the surrounding environment. For example, a memory exhaustion attack against an application could slow down the application as well as its host operating system.


There are at least three distinct scenarios which can commonly lead to resource exhaustion:


  - Lack of throttling for the number of allocated resources

  - Losing all references to a resource before reaching the shutdown stage

  - Not closing/returning a resource after processing

Resource exhaustion problems are often result due to an incorrect implementation of the following situations:

  - Error conditions and other exceptional circumstances.

  - Confusion over which part of the program is responsible for releasing the resource.

## Observed Examples

CVE-2022-21668: Chain: Python library does not limit the resources used to process images that specify a very large number of bands (CWE-1284), leading to excessive memory consumption (CWE-789) or an integer overflow (CWE-190).

CVE-2020-7218: Go-based workload orchestrator does not limit resource usage with unauthenticated connections, allowing a DoS by flooding the service

CVE-2020-3566: Resource exhaustion in distributed OS because of "insufficient" IGMP queue management, as exploited in the wild per CISA KEV.

CVE-2009-2874: Product allows attackers to cause a crash via a large number of connections.

CVE-2009-1928: Malformed request triggers uncontrolled recursion, leading to stack exhaustion.

CVE-2009-2858: Chain: memory leak (CWE-404) leads to resource exhaustion.

CVE-2009-2726: Driver does not use a maximum width when invoking sscanf style functions, causing stack consumption.

CVE-2009-2540: Large integer value for a length property in an object causes a large amount of memory allocation.

CVE-2009-2299: Web application firewall consumes excessive memory when an HTTP request contains a large Content-Length value but no POST data.

CVE-2009-2054: Product allows exhaustion of file descriptors when processing a large number of TCP packets.

CVE-2008-5180: Communication product allows memory consumption with a large number of SIP requests, which cause many sessions to be created.

CVE-2008-2121: TCP implementation allows attackers to consume CPU and prevent new connections using a TCP SYN flood attack.

CVE-2008-2122: Port scan triggers CPU consumption with processes that attempt to read data from closed sockets.

CVE-2008-1700: Product allows attackers to cause a denial of service via a large number of directives, each of which opens a separate window.

CVE-2007-4103: Product allows resource exhaustion via a large number of calls that do not complete a 3-way handshake.

CVE-2006-1173: Mail server does not properly handle deeply nested multipart MIME messages, leading to stack exhaustion.

CVE-2007-0897: Chain: anti-virus product encounters a malformed file but returns from a function without closing a file descriptor (CWE-775) leading to file descriptor consumption (CWE-400) and failed scans.

## Top 25 Examples

CVE-2022-40513: Transient DOS due to uncontrolled resource consumption in WLAN firmware when peer is freed in non qos state.

CVE-2022-43572: In Splunk Enterprise versions below 8.2.9, 8.1.12, and 9.0.2, sending a malformed file through the Splunk-to-Splunk (S2S) or HTTP Event Collector (HEC) protocols to an indexer results in a blockage or denial-of-service preventing further indexing. 

CVE-2021-22642: An attacker could use specially crafted invalid Modbus frames to crash the Ovarro TBox system.

CVE-2021-3629: A flaw was found in Undertow. A potential security issue in flow control handling by the browser over http/2 may potentially cause overhead or a denial of service in the server. The highest threat from this vulnerability is availability. This flaw affects Undertow versions prior to 2.0.40.Final and prior to 2.2.11.Final.

CVE-2022-0476: Denial of Service in GitHub repository radareorg/radare2 prior to 5.6.4.

CVE-2022-0488: An issue has been discovered in GitLab CE/EE affecting all versions starting with version 8.10. It was possible to trigger a timeout on a page with markdown by using a specific amount of block-quotes.

CVE-2022-0489: An issue has been discovered in GitLab CE/EE affecting all versions starting with 8.15 . It was possible to trigger a DOS by using the math feature with a specific formula in issue comments.

CVE-2022-0671: A flaw was found in vscode-xml in versions prior to 0.19.0. Schema download could lead to blind SSRF or DoS via a large file.

CVE-2022-0695: Denial of Service in GitHub repository radareorg/radare2 prior to 5.6.4.

CVE-2022-1099: Adding a very large number of tags to a runner in GitLab CE/EE affecting all versions prior to 14.7.7, 14.8 prior to 14.8.5, and 14.9 prior to 14.9.2 allows an attacker to impact the performance of GitLab

CVE-2022-1259: A flaw was found in Undertow. A potential security issue in flow control handling by the browser over HTTP/2 may cause overhead or a denial of service in the server. This flaw exists because of an incomplete fix for CVE-2021-3629.

CVE-2022-1468: On all versions of 17.0.x, 16.1.x, 15.1.x, 14.1.x, 13.1.x, 12.1.x, and 11.6.x on F5 BIG-IP, an authenticated iControl REST user with at least guest role privileges can cause processing delays to iControl REST requests via undisclosed requests. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-1677: In OpenShift Container Platform, a user with permissions to create or modify Routes can craft a payload that inserts a malformed entry into one of the cluster router's HAProxy configuration files. This malformed entry can match any arbitrary hostname, or all hostnames in the cluster, and direct traffic to an arbitrary application within the cluster, including one under attacker control.

CVE-2022-1797: A malformed Class 3 common industrial protocol message with a cached connection can cause a denial-of-service condition in Rockwell Automation Logix Controllers, resulting in a major nonrecoverable fault. If the target device becomes unavailable, a user would have to clear the fault and redownload the user project file to bring the device back online.

CVE-2022-1982: Uncontrolled resource consumption in Mattermost version 6.6.0 and earlier allows an authenticated attacker to crash the server via a crafted SVG attachment on a post.

CVE-2022-2004: AutomationDirect DirectLOGIC is vulnerable to a a specially crafted packet can be sent continuously to the PLC to prevent access from DirectSoft and other devices, causing a denial-of-service condition. This issue affects: AutomationDirect DirectLOGIC D0-06 series CPUs D0-06DD1 versions prior to 2.72; D0-06DD2 versions prior to 2.72; D0-06DR versions prior to 2.72; D0-06DA versions prior to 2.72; D0-06AR versions prior to 2.72; D0-06AA versions prior to 2.72; D0-06DD1-D versions prior to 2.72; D0-06DD2-D versions prior to 2.72; D0-06DR-D versions prior to 2.72;

CVE-2022-20425: In addAutomaticZenRule of ZenModeHelper.java, there is a possible permanent degradation of performance due to resource exhaustion. This could lead to local denial of service with User execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12L Android-13Android ID: A-235823407

CVE-2022-20482: In createNotificationChannel of NotificationManager.java, there is a possible way to make the device unusable and require factory reset due to resource exhaustion. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12L Android-13Android ID: A-240422263

CVE-2022-22101: Denial of service in multimedia due to uncontrolled resource consumption while parsing an incoming HAB message in Snapdragon Auto

CVE-2022-22145: CAMS for HIS Log Server contained in the following Yokogawa Electric products is vulnerable to uncontrolled resource consumption. CENTUM CS 3000 versions from R3.08.10 to R3.09.00, CENTUM VP versions from R4.01.00 to R4.03.00, from R5.01.00 to R5.04.20, from R6.01.00 to R6.08.00, Exaopc versions from R3.72.00 to R3.79.00.

CVE-2022-22161: An Uncontrolled Resource Consumption vulnerability in the kernel of Juniper Networks Junos OS allows an unauthenticated network based attacker to cause 100% CPU load and the device to become unresponsive by sending a flood of traffic to the out-of-band management ethernet port. Continued receipted of a flood will create a sustained Denial of Service (DoS) condition. Once the flood subsides the system will recover by itself. An indication that the system is affected by this issue would be that an irq handled by the fman process is shown to be using a high percentage of CPU cycles like in the following example output: user@host> show system processes extensive ... PID USERNAME PRI NICE SIZE RES STATE TIME WCPU COMMAND 31 root -84 -187 0K 16K WAIT 22.2H 56939.26% irq96: fman0 This issue affects Juniper Networks Junos OS: All versions prior to 18.3R3-S6; 18.4 versions prior to 18.4R2-S9, 18.4R3-S9; 19.1 versions prior to 19.1R2-S3, 19.1R3-S7; 19.2 versions prior to 19.2R1-S7, 19.2R3-S3; 19.3 versions prior to 19.3R2-S7, 19.3R3-S4; 19.4 versions prior to 19.4R2-S5, 19.4R3-S5; 20.1 versions prior to 20.1R3-S1; 20.2 versions prior to 20.2R3-S2; 20.3 versions prior to 20.3R3-S1; 20.4 versions prior to 20.4R2-S2, 20.4R3; 21.1 versions prior to 21.1R2; 21.2 versions prior to 21.2R1-S1, 21.2R2.

CVE-2022-2238: A vulnerability was found in the search-api container in Red Hat Advanced Cluster Management for Kubernetes when a query in the search filter gets parsed by the backend. This flaw allows an attacker to craft specific strings containing special characters that lead to crashing the pod and affects system availability while restarting.

CVE-2022-22556: Dell PowerStore contains an Uncontrolled Resource Consumption Vulnerability in PowerStore User Interface. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to the Denial of Service.

CVE-2022-22724: A CWE-400: Uncontrolled Resource Consumption vulnerability exists that could cause a denial of service on ports 80 (HTTP) and 502 (Modbus), when sending a large number of TCP RST or FIN packets to any open TCP port of the PLC. Affected Product: Modicon M340 CPUs: BMXP34 (All Versions)

CVE-2022-23015: On BIG-IP versions 16.x before 16.1.0, 15.1.x before 15.1.4.1, and 14.1.2.6-14.1.4.4, when a Client SSL profile is configured on a virtual server with Client Certificate Authentication set to request/require and Session Ticket enabled and configured, processing SSL traffic can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-23023: On BIG-IP version 16.1.x before 16.1.2.1, 15.1.x before 15.1.5, 14.1.x before 14.1.4.5, and all versions of 13.1.x and 12.1.x, and BIG-IQ all versions of 8.x and 7.x, undisclosed requests by an authenticated iControl REST user can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-23024: On BIG-IP AFM version 16.x before 16.1.0, 15.1.x before 15.1.4.1, 14.1.x before 14.1.4.2, and all versions of 13.1.x, when the IPsec application layer gateway (ALG) logging profile is configured on an IPsec ALG virtual server, undisclosed IPsec traffic can cause the Traffic Management Microkernel (TMM) to terminate. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-23030: On version 16.1.x before 16.1.2, 15.1.x before 15.1.4.1, 14.1.x before 14.1.4.5, and all versions of 13.1.x, when the BIG-IP Virtual Edition (VE) uses the ixlv driver (which is used in SR-IOV mode and requires Intel X710/XL710/XXV710 family of network adapters on the Hypervisor) and TCP Segmentation Offload configuration is enabled, undisclosed requests may cause an increase in CPU resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-24118: Certain General Electric Renewable Energy products allow attackers to use a code to trigger a reboot into the factory default configuration. This affects iNET and iNET II before 8.3.0, SD before 6.4.7, TD220X before 2.0.16, and TD220MAX before 1.2.6.

CVE-2022-2455: A business logic issue in the handling of large repositories in all versions of GitLab CE/EE from 10.0 before 15.1.6, all versions starting from 15.2 before 15.2.4, all versions starting from 15.3 before 15.3.2 allowed an authenticated and authorized user to exhaust server resources by importing a malicious project.

CVE-2022-25622: The PROFINET (PNIO) stack, when integrated with the Interniche IP stack, improperly handles internal resources for TCP segments where the minimum TCP-Header length is less than defined. This could allow an attacker to create a denial of service condition for TCP services on affected devices by sending specially crafted TCP segments.

CVE-2022-26372: On F5 BIG-IP 15.1.x versions prior to 15.1.0.2, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all versions of 12.1.x and 11.6.x, when a DNS listener is configured on a virtual server with DNS queueing (default), undisclosed requests can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-27181: On F5 BIG-IP APM 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all versions of 12.1.x and 11.6.x, when APM is configured on a virtual server and the associated access profile is configured with APM AAA NTLM Auth, undisclosed requests can cause an increase in internal resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-27182: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, and 14.1.x versions prior to 14.1.4.6, when BIG-IP packet filters are enabled and a virtual server is configured with the type set to Reject, undisclosed requests can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-27194: A vulnerability has been identified in SIMATIC PCS neo (Administration Console) (All versions < V3.1 SP1), SINETPLAN (All versions), TIA Portal (V15, V15.1, V16 and V17). The affected system cannot properly process specially crafted packets sent to port 8888/tcp. A remote attacker could exploit this vulnerability to cause a Denial-of-Service condition. The affected devices must be restarted manually.

CVE-2022-2741: The denial-of-service can be triggered by transmitting a carefully crafted CAN frame on the same CAN network as the vulnerable node. The frame must have a CAN ID matching an installed filter in the vulnerable node (this can easily be guessed based on CAN traffic analyses). The frame must contain the opposite RTR bit as what the filter installed in the vulnerable node contains (if the filter matches RTR frames, the frame must be a data frame or vice versa).

CVE-2022-27507: Authenticated denial of service

CVE-2022-27508: Unauthenticated denial of service

CVE-2022-27640: A vulnerability has been identified in SIMATIC CP 442-1 RNA (All versions < V1.5.18), SIMATIC CP 443-1 RNA (All versions < V1.5.18). The affected devices improperly handles excessive ARP broadcast requests. This could allow an attacker to create a denial of service condition by performing ARP storming attacks, which can cause the device to reboot.

CVE-2022-28191: NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (nvidia.ko), where uncontrolled resource consumption can be triggered by an unprivileged regular user, which may lead to denial of service.

CVE-2022-28691: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5, 14.1.x versions prior to 14.1.4.6, and 13.1.x versions prior to 13.1.5, when a Real Time Streaming Protocol (RTSP) profile is configured on a virtual server, undisclosed traffic can cause an increase in Traffic Management Microkernel (TMM) resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-28701: On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, when the stream profile is configured on a virtual server, undisclosed requests can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-29480: On F5 BIG-IP 13.1.x versions prior to 13.1.5, and all versions of 12.1.x and 11.6.x, when multiple route domains are configured, undisclosed requests to big3d can cause an increase in CPU resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

CVE-2022-29864: OPC UA .NET Standard Stack 1.04.368 allows a remote attacker to cause a server to crash via a large number of messages that trigger Uncontrolled Resource Consumption.

CVE-2022-29866: OPC UA .NET Standard Stack 1.04.368 allows a remote attacker to exhaust the memory resources of a server via a crafted request that triggers Uncontrolled Resource Consumption.

CVE-2022-30551: OPC UA Legacy Java Stack 2022-04-01 allows a remote attacker to cause a server to stop processing messages by sending crafted messages that exhaust available resources.

CVE-2022-30691: Uncontrolled resource consumption in the Intel(R) Support Android application before version 22.02.28 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-30791: In CmpBlkDrvTcp of CODESYS V3 in multiple versions an uncontrolled ressource consumption allows an unauthorized attacker to block new TCP connections. Existing connections are not affected.

CVE-2022-30792: In CmpChannelServer of CODESYS V3 in multiple versions an uncontrolled ressource consumption allows an unauthorized attacker to block new communication channel connections. Existing connections are not affected.

CVE-2022-31006: indy-node is the server portion of Hyperledger Indy, a distributed ledger purpose-built for decentralized identity. In vulnerable versions of indy-node, an attacker can max out the number of client connections allowed by the ledger, leaving the ledger unable to be used for its intended purpose. However, the ledger content will not be impacted and the ledger will resume functioning after the attack. This attack exploits the trade-off between resilience and availability. Any protection against abusive client connections will also prevent the network being accessed by certain legitimate users. As a result, validator nodes must tune their firewall rules to ensure the right trade-off for their network's expected users. The guidance to network operators for the use of firewall rules in the deployment of Indy networks has been modified to better protect against denial of service attacks by increasing the cost and complexity in mounting such attacks. The mitigation for this vulnerability is not in the Hyperledger Indy code per se, but rather in the individual deployments of Indy. The mitigations should be applied to all deployments of Indy, and are not related to a particular release.

CVE-2022-31030: containerd is an open source container runtime. A bug was found in the containerd's CRI implementation where programs inside a container can cause the containerd daemon to consume memory without bound during invocation of the `ExecSync` API. This can cause containerd to consume all available memory on the computer, denying service to other legitimate workloads. Kubernetes and crictl can both be configured to use containerd's CRI implementation; `ExecSync` may be used when running probes or when executing processes via an "exec" facility. This bug has been fixed in containerd 1.6.6 and 1.5.13. Users should update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted images and commands are used.

CVE-2022-31073: KubeEdge is an open source system for extending native containerized application orchestration capabilities to hosts at Edge. Prior to versions 1.11.1, 1.10.2, and 1.9.4, the ServiceBus server on the edge side may be susceptible to a DoS attack if an HTTP request containing a very large Body is sent to it. It is possible for the node to be exhausted of memory. The consequence of the exhaustion is that other services on the node, e.g. other containers, will be unable to allocate memory and thus causing a denial of service. Malicious apps accidentally pulled by users on the host and have the access to send HTTP requests to localhost may make an attack. It will be affected only when users enable the `ServiceBus` module in the config file `edgecore.yaml`. This bug has been fixed in Kubeedge 1.11.1, 1.10.2, and 1.9.4. As a workaround, disable the `ServiceBus` module in the config file `edgecore.yaml`.

CVE-2022-31074: KubeEdge is an open source system for extending native containerized application orchestration capabilities to hosts at Edge. Prior to versions 1.11.1, 1.10.2, and 1.9.4, several endpoints in the Cloud AdmissionController may be susceptible to a DoS attack if an HTTP request containing a very large Body is sent to it. The consequence of the exhaustion is that the Cloud AdmissionController will be in denial of service. This bug has been fixed in Kubeedge 1.11.1, 1.10.2, and 1.9.4. There is currently no known workaround.

CVE-2022-3283: A potential DOS vulnerability was discovered in GitLab CE/EE affecting all versions before before 15.2.5, all versions starting from 15.3 before 15.3.4, all versions starting from 15.4 before 15.4.1 While cloning an issue with special crafted content added to the description could have been used to trigger high CPU usage.

CVE-2022-33203: In BIG-IP Versions 16.1.x before 16.1.3, 15.1.x before 15.1.6.1, and 14.1.x before 14.1.5, when a BIG-IP APM access policy with Service Connect agent is configured on a virtual server, undisclosed requests can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-34335:  IBM Sterling Partner Engagement Manager 6.1.2, 6.2.0, and 6.2.1 could allow an authenticated user to exhaust server resources which could lead to a denial of service. IBM X-Force ID: 229705. 

CVE-2022-35236: In BIG-IP Versions 16.1.x before 16.1.2.2, 15.1.x before 15.1.6.1, and 14.1.x before 14.1.5, when an HTTP2 profile is configured on a virtual server, undisclosed traffic can cause an increase in memory resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-35241: In versions 2.x before 2.3.1 and all versions of 1.x, when NGINX Instance Manager is in use, undisclosed requests can cause an increase in disk resource utilization. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

CVE-2022-3639: A potential DOS vulnerability was discovered in GitLab CE/EE affecting all versions from 10.8 before 15.1.6, all versions starting from 15.2 before 15.2.4, all versions starting from 15.3 before 15.3.2. Improper data handling on branch creation could have been used to trigger high CPU usage.

CVE-2022-3818: An uncontrolled resource consumption issue when parsing URLs in GitLab CE/EE affecting all versions prior to 15.3.5, 15.4 prior to 15.4.4, and 15.5 prior to 15.5.2 allows an attacker to cause performance issues and potentially a denial of service on the GitLab instance.

CVE-2022-39278: Istio is an open platform-independent service mesh that provides traffic management, policy enforcement, and telemetry collection. Prior to versions 1.15.2, 1.14.5, and 1.13.9, the Istio control plane, istiod, is vulnerable to a request processing error, allowing a malicious attacker that sends a specially crafted or oversized message which results in the control plane crashing when the Kubernetes validating or mutating webhook service is exposed publicly. This endpoint is served over TLS port 15017, but does not require any authentication from the attacker. For simple installations, Istiod is typically only reachable from within the cluster, limiting the blast radius. However, for some deployments, especially external istiod topologies, this port is exposed over the public internet. Versions 1.15.2, 1.14.5, and 1.13.9 contain patches for this issue. There are no effective workarounds, beyond upgrading. This bug is due to an error in `regexp.Compile` in Go.

CVE-2022-39330: Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Nextcloud Server prior to versions 23.0.10 and 24.0.6 and Nextcloud Enterprise Server prior to versions 22.2.10, 23.0.10, and 24.0.6 are vulnerable to a logged-in attacker slowing down the system by generating a lot of database/cpu load. Nextcloud Server versions 23.0.10 and 24.0.6 and Nextcloud Enterprise Server versions 22.2.10, 23.0.10, and 24.0.6 contain patches for this issue. As a workaround, disable the Circles app.

CVE-2022-40735: The Diffie-Hellman Key Agreement Protocol allows use of long exponents that arguably make certain calculations unnecessarily expensive, because the 1996 van Oorschot and Wiener paper found that "(appropriately) short exponents" can be used when there are adequate subgroup constraints, and these short exponents can lead to less expensive calculations than for long exponents. This issue is different from CVE-2002-20001 because it is based on an observation about exponent size, rather than an observation about numbers that are not public keys. The specific situations in which calculation expense would constitute a server-side vulnerability depend on the protocol (e.g., TLS, SSH, or IKE) and the DHE implementation details. In general, there might be an availability concern because of server-side resource consumption from DHE modular-exponentiation calculations. Finally, it is possible for an attacker to exploit this vulnerability and CVE-2002-20001 together.

CVE-2022-41770: In BIG-IP versions 17.0.x before 17.0.0.1, 16.1.x before 16.1.3.1, 15.1.x before 15.1.7, 14.1.x before 14.1.5.1, and all versions of 13.1.x, and BIG-IQ all versions of 8.x and 7.x, an authenticated iControl REST user can cause an increase in memory resource utilization, via undisclosed requests.

CVE-2022-41806: In versions 16.1.x before 16.1.3.2 and 15.1.x before 15.1.5.1, when BIG-IP AFM Network Address Translation policy with IPv6/IPv4 translation rules is configured on a virtual server, undisclosed requests can cause an increase in memory resource utilization.

CVE-2022-41833: In all BIG-IP 13.1.x versions, when an iRule containing the HTTP::collect command is configured on a virtual server, undisclosed requests can cause Traffic Management Microkernel (TMM) to terminate.

CVE-2022-4344: Memory exhaustion in the Kafka protocol dissector in Wireshark 4.0.0 to 4.0.1 and 3.6.0 to 3.6.9 allows denial of service via packet injection or crafted capture file

CVE-2022-20692: A vulnerability in the NETCONF over SSH feature of Cisco IOS XE Software could allow a low-privileged, authenticated, remote attacker to cause a denial of service condition (DoS) on an affected device. This vulnerability is due to insufficient resource management. An attacker could exploit this vulnerability by initiating a large number of NETCONF over SSH connections. A successful exploit could allow the attacker to exhaust resources, causing the device to reload and resulting in a DoS condition on an affected device.

CVE-2022-20760: A vulnerability in the DNS inspection handler of Cisco Adaptive Security Appliance (ASA) Software and Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial of service condition (DoS) on an affected device. This vulnerability is due to a lack of proper processing of incoming requests. An attacker could exploit this vulnerability by sending crafted DNS requests at a high rate to an affected device. A successful exploit could allow the attacker to cause the device to stop responding, resulting in a DoS condition.

CVE-2022-20808: A vulnerability in Cisco Smart Software Manager On-Prem (SSM On-Prem) could allow an authenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to incorrect handling of multiple simultaneous device registrations on Cisco SSM On-Prem. An attacker could exploit this vulnerability by sending multiple device registration requests to Cisco SSM On-Prem. A successful exploit could allow the attacker to cause a DoS condition on an affected device.

CVE-2022-20937: A vulnerability in a feature that monitors RADIUS requests on Cisco Identity Services Engine (ISE) Software could allow an unauthenticated, remote attacker to negatively affect the performance of an affected device. This vulnerability is due to insufficient management of system resources. An attacker could exploit this vulnerability by taking actions that cause Cisco ISE Software to receive specific RADIUS traffic. A successful and sustained exploit of this vulnerability could allow the attacker to cause reduced performance of the affected device, resulting in significant delays to RADIUS authentications. There are workarounds that address this vulnerability.

CVE-2022-43564: In Splunk Enterprise versions below 8.1.12, 8.2.9, and 9.0.2, a remote user who can create search macros and schedule search reports can cause a denial of service through the use of specially crafted search macros.

CVE-2022-44608: Uncontrolled resource consumption vulnerability in Cybozu Remote Service 4.0.0 to 4.0.3 allows a remote authenticated attacker to consume huge storage space, which may result in a denial-of-service (DoS) condition.

CVE-2022-45044: A vulnerability has been identified in SIPROTEC 5 6MD84 (CP300) (All versions < V9.50), SIPROTEC 5 6MD85 (CP200) (All versions), SIPROTEC 5 6MD85 (CP300) (All versions < V9.50), SIPROTEC 5 6MD86 (CP200) (All versions), SIPROTEC 5 6MD86 (CP300) (All versions < V9.50), SIPROTEC 5 6MD89 (CP300) (All versions < V9.64), SIPROTEC 5 6MU85 (CP300) (All versions < V9.50), SIPROTEC 5 7KE85 (CP200) (All versions), SIPROTEC 5 7KE85 (CP300) (All versions < V9.64), SIPROTEC 5 7SA82 (CP100) (All versions), SIPROTEC 5 7SA82 (CP150) (All versions < V9.50), SIPROTEC 5 7SA84 (CP200) (All versions), SIPROTEC 5 7SA86 (CP200) (All versions), SIPROTEC 5 7SA86 (CP300) (All versions < V9.50), SIPROTEC 5 7SA87 (CP200) (All versions), SIPROTEC 5 7SA87 (CP300) (All versions < V9.50), SIPROTEC 5 7SD82 (CP100) (All versions), SIPROTEC 5 7SD82 (CP150) (All versions < V9.50), SIPROTEC 5 7SD84 (CP200) (All versions), SIPROTEC 5 7SD86 (CP200) (All versions), SIPROTEC 5 7SD86 (CP300) (All versions < V9.50), SIPROTEC 5 7SD87 (CP200) (All versions), SIPROTEC 5 7SD87 (CP300) (All versions < V9.50), SIPROTEC 5 7SJ81 (CP100) (All versions < V8.89), SIPROTEC 5 7SJ81 (CP150) (All versions < V9.50), SIPROTEC 5 7SJ82 (CP100) (All versions < V8.89), SIPROTEC 5 7SJ82 (CP150) (All versions < V9.50), SIPROTEC 5 7SJ85 (CP200) (All versions), SIPROTEC 5 7SJ85 (CP300) (All versions < V9.50), SIPROTEC 5 7SJ86 (CP200) (All versions), SIPROTEC 5 7SJ86 (CP300) (All versions < V9.50), SIPROTEC 5 7SK82 (CP100) (All versions < V8.89), SIPROTEC 5 7SK82 (CP150) (All versions < V9.50), SIPROTEC 5 7SK85 (CP200) (All versions), SIPROTEC 5 7SK85 (CP300) (All versions < V9.50), SIPROTEC 5 7SL82 (CP100) (All versions), SIPROTEC 5 7SL82 (CP150) (All versions < V9.50), SIPROTEC 5 7SL86 (CP200) (All versions), SIPROTEC 5 7SL86 (CP300) (All versions < V9.50), SIPROTEC 5 7SL87 (CP200) (All versions), SIPROTEC 5 7SL87 (CP300) (All versions < V9.50), SIPROTEC 5 7SS85 (CP200) (All versions), SIPROTEC 5 7SS85 (CP300) (All versions < V9.50), SIPROTEC 5 7ST85 (CP200) (All versions), SIPROTEC 5 7ST85 (CP300) (All versions < V9.64), SIPROTEC 5 7ST86 (CP300) (All versions < V9.64), SIPROTEC 5 7SX82 (CP150) (All versions < V9.50), SIPROTEC 5 7SX85 (CP300) (All versions < V9.50), SIPROTEC 5 7UM85 (CP300) (All versions < V9.50), SIPROTEC 5 7UT82 (CP100) (All versions), SIPROTEC 5 7UT82 (CP150) (All versions < V9.50), SIPROTEC 5 7UT85 (CP200) (All versions), SIPROTEC 5 7UT85 (CP300) (All versions < V9.50), SIPROTEC 5 7UT86 (CP200) (All versions), SIPROTEC 5 7UT86 (CP300) (All versions < V9.50), SIPROTEC 5 7UT87 (CP200) (All versions), SIPROTEC 5 7UT87 (CP300) (All versions < V9.50), SIPROTEC 5 7VE85 (CP300) (All versions < V9.50), SIPROTEC 5 7VK87 (CP200) (All versions), SIPROTEC 5 7VK87 (CP300) (All versions < V9.50), SIPROTEC 5 7VU85 (CP300) (All versions < V9.50), SIPROTEC 5 Communication Module ETH-BA-2EL (All versions < V8.89 installed on CP100 devices), SIPROTEC 5 Communication Module ETH-BA-2EL (All versions < V9.50 installed on CP150 and CP300 devices), SIPROTEC 5 Communication Module ETH-BA-2EL (All versions installed on CP200 devices), SIPROTEC 5 Communication Module ETH-BB-2FO (All versions < V8.89 installed on CP100 devices), SIPROTEC 5 Communication Module ETH-BB-2FO (All versions < V9.50 installed on CP150 and CP300 devices), SIPROTEC 5 Communication Module ETH-BB-2FO (All versions installed on CP200 devices), SIPROTEC 5 Communication Module ETH-BD-2FO (All versions < V9.50), SIPROTEC 5 Compact 7SX800 (CP050) (All versions < V9.50). Affected devices do not properly restrict secure client-initiated renegotiations within the SSL and TLS protocols. This could allow an attacker to create a denial of service condition on the ports 443/tcp and 4443/tcp for the duration of the attack.

CVE-2022-45199: Pillow before 9.3.0 allows denial of service via SAMPLESPERPIXEL.

CVE-2022-46351: A vulnerability has been identified in SCALANCE X204RNA (HSR) (All versions < V3.2.7), SCALANCE X204RNA (PRP) (All versions < V3.2.7), SCALANCE X204RNA EEC (HSR) (All versions < V3.2.7), SCALANCE X204RNA EEC (PRP) (All versions < V3.2.7), SCALANCE X204RNA EEC (PRP/HSR) (All versions < V3.2.7). Specially crafted PROFINET DCP packets could cause a denial of service condition of affected products on a local Ethernet segment (Layer 2).

CVE-2022-46352: A vulnerability has been identified in SCALANCE X204RNA (HSR) (All versions < V3.2.7), SCALANCE X204RNA (PRP) (All versions < V3.2.7), SCALANCE X204RNA EEC (HSR) (All versions < V3.2.7), SCALANCE X204RNA EEC (PRP) (All versions < V3.2.7), SCALANCE X204RNA EEC (PRP/HSR) (All versions < V3.2.7). Specially crafted PROFINET DCP packets could cause a denial of service condition of affected products.

CVE-2022-4767: Denial of Service in GitHub repository usememos/memos prior to 0.9.1.

CVE-2022-24040: A vulnerability has been identified in Desigo DXR2 (All versions < V01.21.142.5-22), Desigo PXC3 (All versions < V01.21.142.4-18), Desigo PXC4 (All versions < V02.20.142.10-10884), Desigo PXC5 (All versions < V02.20.142.10-10884). The web application fails to enforce an upper bound to the cost factor of the PBKDF2 derived key during the creation or update of an account. An attacker with the user profile access privilege could cause a denial of service (DoS) condition through CPU consumption by setting a PBKDF2 derived key with a remarkably high cost effort and then attempting a login to the so-modified account.

CVE-2022-39158: Affected devices improperly handle partial HTTP requests which makes them vulnerable to slowloris attacks. This could allow a remote attacker to create a denial of service condition that persists until the attack ends.

CVE-2022-41333: An uncontrolled resource consumption vulnerability [CWE-400] in FortiRecorder version 6.4.3 and below, 6.0.11 and below login authentication mechanism may allow an unauthenticated attacker to make the device unavailable via crafted GET requests.

# CWE-401 Missing Release of Memory after Effective Lifetime

## Description

The product does not sufficiently track and release allocated memory after it has been used, which slowly consumes remaining memory.

This is often triggered by improper handling of malformed data or unexpectedly interrupted sessions. In some languages, developers are responsible for tracking memory allocation and releasing the memory. If there are no more pointers or references to the memory, then it can no longer be tracked and identified for release.

## Observed Examples

CVE-2005-3119: Memory leak because function does not free() an element of a data structure.

CVE-2004-0427: Memory leak when counter variable is not decremented.

CVE-2002-0574: chain: reference count is not decremented, leading to memory leak in OS by sending ICMP packets.

CVE-2005-3181: Kernel uses wrong function to release a data structure, preventing data from being properly tracked by other code.

CVE-2004-0222: Memory leak via unknown manipulations as part of protocol test suite.

CVE-2001-0136: Memory leak via a series of the same command.

## Top 25 Examples

CVE-2022-20046: In Bluetooth, there is a possible memory corruption due to a logic error. This could lead to local denial of service with no additional execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06142410; Issue ID: ALPS06142410.

CVE-2021-33437: An issue was discovered in mjs (mJS: Restricted JavaScript engine), ES6 (JavaScript version 6). There are memory leaks in frozen_cb() in mjs.c.

CVE-2021-42197: An issue was discovered in swftools through 20201222 through a memory leak in the swftools when swfdump is used. It allows an attacker to cause code execution.

CVE-2022-0854: A memory leak flaw was found in the Linux kernel’s DMA subsystem, in the way a user calls DMA_FROM_DEVICE. This flaw allows a local user to read random memory from the kernel space.

CVE-2022-22155: An Uncontrolled Resource Consumption vulnerability in the handling of IPv6 neighbor state change events in Juniper Networks Junos OS allows an adjacent attacker to cause a memory leak in the Flexible PIC Concentrator (FPC) of an ACX5448 router. The continuous flapping of an IPv6 neighbor with specific timing will cause the FPC to run out of resources, leading to a Denial of Service (DoS) condition. Once the condition occurs, further packet processing will be impacted, creating a sustained Denial of Service (DoS) condition, requiring a manual PFE restart to restore service. The following error messages will be seen after the FPC resources have been exhausted: fpc0 DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 fpc0 DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 fpc0 DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 fpc0 DNX_NH::dnx_nh_tag_ipv4_hw_install(),3135: dnx_nh_tag_ipv4_hw_install: BCM L3 Egress create object failed for NH 602 (-14:No resources for operation), BCM NH Params: unit:0 Port:41, L3_INTF:0 Flags: 0x40 This issue only affects the ACX5448 router. No other products or platforms are affected by this vulnerability. This issue affects Juniper Networks Junos OS on ACX5448: 18.4 versions prior to 18.4R3-S10; 19.1 versions prior to 19.1R3-S5; 19.2 versions prior to 19.2R1-S8, 19.2R3-S2; 19.3 versions prior to 19.3R2-S6, 19.3R3-S2; 19.4 versions prior to 19.4R1-S3, 19.4R2-S2, 19.4R3; 20.1 versions prior to 20.1R2; 20.2 versions prior to 20.2R1-S1, 20.2R2.

CVE-2022-26878: drivers/bluetooth/virtio_bt.c in the Linux kernel before 5.16.3 has a memory leak (socket buffers have memory allocated but not freed).

CVE-2022-35110: SWFTools commit 772e55a2 was discovered to contain a memory leak via /lib/mem.c.

CVE-2022-36152: tifig v0.2.2 was discovered to contain a memory leak via operator new[](unsigned long) at /asan/asan_new_delete.cpp.

CVE-2022-38177: By spoofing the target resolver with responses that have a malformed ECDSA signature, an attacker can trigger a small memory leak. It is possible to gradually erode available memory to the point where named crashes for lack of resources.

CVE-2022-38178: By spoofing the target resolver with responses that have a malformed EdDSA signature, an attacker can trigger a small memory leak. It is possible to gradually erode available memory to the point where named crashes for lack of resources.

CVE-2022-23471: containerd is an open source container runtime. A bug was found in containerd's CRI implementation where a user can exhaust memory on the host. In the CRI stream server, a goroutine is launched to handle terminal resize events if a TTY is requested. If the user's process fails to launch due to, for example, a faulty command, the goroutine will be stuck waiting to send without a receiver, resulting in a memory leak. Kubernetes and crictl can both be configured to use containerd's CRI implementation and the stream server is used for handling container IO. This bug has been fixed in containerd 1.6.12 and 1.5.16. Users should update to these versions to resolve the issue. Users unable to upgrade should ensure that only trusted images and commands are used and that only trusted users have permissions to execute commands in running containers. 

CVE-2021-42522: There is a Information Disclosure vulnerability in anjuta/plugins/document-manager/anjuta-bookmarks.c. This issue was caused by the incorrect use of libxml2 API. The vendor forgot to call 'g_free()' to release the return value of 'xmlGetProp()'.

CVE-2021-42523: There are two Information Disclosure vulnerabilities in colord, and they lie in colord/src/cd-device-db.c and colord/src/cd-profile-db.c separately. They exist because the 'err_msg' of 'sqlite3_exec' is not releasing after use, while libxml2 emphasizes that the caller needs to release it.

CVE-2022-26365: Linux disk/nic frontends data leaks T[his CNA information record relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Linux Block and Network PV device frontends don't zero memory regions before sharing them with the backend (CVE-2022-26365, CVE-2022-33740). Additionally the granularity of the grant table doesn't allow sharing less than a 4K page, leading to unrelated data residing in the same 4K page as data shared with a backend being accessible by such backend (CVE-2022-33741, CVE-2022-33742).

CVE-2021-3690: A flaw was found in Undertow. A buffer leak on the incoming WebSocket PONG message may lead to memory exhaustion. This flaw allows an attacker to cause a denial of service. The highest threat from this vulnerability is availability.

CVE-2022-38371: A vulnerability has been identified in APOGEE MBC (PPC) (BACnet) (All versions), APOGEE MBC (PPC) (P2 Ethernet) (All versions), APOGEE MEC (PPC) (BACnet) (All versions), APOGEE MEC (PPC) (P2 Ethernet) (All versions), APOGEE PXC Compact (BACnet) (All versions < V3.5.7), APOGEE PXC Compact (P2 Ethernet) (All versions < V2.8.21), APOGEE PXC Modular (BACnet) (All versions < V3.5.7), APOGEE PXC Modular (P2 Ethernet) (All versions < V2.8.21), Desigo PXC00-E.D (All versions >= V2.3), Desigo PXC00-U (All versions >= V2.3), Desigo PXC001-E.D (All versions >= V2.3), Desigo PXC100-E.D (All versions >= V2.3), Desigo PXC12-E.D (All versions >= V2.3), Desigo PXC128-U (All versions >= V2.3), Desigo PXC200-E.D (All versions >= V2.3), Desigo PXC22-E.D (All versions >= V2.3), Desigo PXC22.1-E.D (All versions >= V2.3), Desigo PXC36.1-E.D (All versions >= V2.3), Desigo PXC50-E.D (All versions >= V2.3), Desigo PXC64-U (All versions >= V2.3), Desigo PXM20-E (All versions >= V2.3), Nucleus NET for Nucleus PLUS V1 (All versions < V5.2a), Nucleus NET for Nucleus PLUS V2 (All versions < V5.4), Nucleus ReadyStart V3 V2012 (All versions < V2012.08.1), Nucleus ReadyStart V3 V2017 (All versions < V2017.02.4), Nucleus Source Code (All versions including affected FTP server), TALON TC Compact (BACnet) (All versions < V3.5.7), TALON TC Modular (BACnet) (All versions < V3.5.7). The FTP server does not properly release memory resources that were reserved for incomplete connection attempts by FTP clients. This could allow a remote attacker to generate a denial of service condition on devices that incorporate a vulnerable version of the FTP server.

# CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')

## Description

The product makes resources available to untrusted parties when those resources are only intended to be accessed by the product.

## Observed Examples

CVE-2003-0740: Server leaks a privileged file descriptor, allowing the server to be hijacked.

CVE-2004-1033: File descriptor leak allows read of restricted files.

## Top 25 Examples

CVE-2022-30231: A vulnerability has been identified in SICAM GridEdge Essential ARM (All versions < V2.6.6), SICAM GridEdge Essential Intel (All versions < V2.6.6), SICAM GridEdge Essential with GDS ARM (All versions < V2.6.6), SICAM GridEdge Essential with GDS Intel (All versions < V2.6.6). The affected software discloses password hashes of other users upon request. This could allow an authenticated user to retrieve another users password hash.

# CWE-403 Exposure of File Descriptor to Unintended Control Sphere ('File Descriptor Leak')

## Description

A process does not close sensitive file descriptors before invoking a child process, which allows the child to perform unauthorized I/O operations using those descriptors.

When a new process is forked or executed, the child process inherits any open file descriptors. When the child process has fewer privileges than the parent process, this might introduce a vulnerability if the child process can access the file descriptor but does not have the privileges to access the associated file.

## Observed Examples

CVE-2003-0740: Server leaks a privileged file descriptor, allowing the server to be hijacked.

CVE-2004-1033: File descriptor leak allows read of restricted files.

CVE-2000-0094: Access to restricted resource using modified file descriptor for stderr.

CVE-2002-0638: Open file descriptor used as alternate channel in complex race condition.

CVE-2003-0489: Program does not fully drop privileges after creating a file descriptor, which allows access to the descriptor via a separate vulnerability.

CVE-2003-0937: User bypasses restrictions by obtaining a file descriptor then calling setuid program, which does not close the descriptor.

CVE-2004-2215: Terminal manager does not properly close file descriptors, allowing attackers to access terminals of other users.

CVE-2006-5397: Module opens a file for reading twice, allowing attackers to read files.

# CWE-404 Improper Resource Shutdown or Release

## Description

The product does not release or incorrectly releases a resource before it is made available for re-use.

When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set period of time or revocation.

## Observed Examples

CVE-1999-1127: Does not shut down named pipe connections if malformed data is sent.

CVE-2001-0830: Sockets not properly closed when attacker repeatedly connects and disconnects from server.

CVE-2002-1372: Chain: Return values of file/socket operations are not checked (CWE-252), allowing resultant consumption of file descriptors (CWE-772).

## Top 25 Examples

CVE-2022-3318: Use after free in ChromeOS Notifications in Google Chrome on ChromeOS prior to 106.0.5249.62 allowed a remote attacker who convinced a user to reboot Chrome OS to potentially exploit heap corruption via UI interaction. (Chromium security severity: Low)

CVE-2021-0984: In onNullBinding of ManagedServices.java, there is a possible permission bypass due to an incorrectly unbound service. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12Android ID: A-192475653

CVE-2021-44717: Go before 1.16.12 and 1.17.x before 1.17.5 on UNIX allows write operations to an unintended file or unintended network connection as a consequence of erroneous closing of file descriptor 0 after file-descriptor exhaustion.

CVE-2022-23033: arm: guest_physmap_remove_page not removing the p2m mappings The functions to remove one or more entries from a guest p2m pagetable on Arm (p2m_remove_mapping, guest_physmap_remove_page, and p2m_set_entry with mfn set to INVALID_MFN) do not actually clear the pagetable entry if the entry doesn't have the valid bit set. It is possible to have a valid pagetable entry without the valid bit set when a guest operating system uses set/way cache maintenance instructions. For instance, a guest issuing a set/way cache maintenance instruction, then calling the XENMEM_decrease_reservation hypercall to give back memory pages to Xen, might be able to retain access to those pages even after Xen started reusing them for other purposes.

CVE-2022-23634: Puma is a Ruby/Rack web server built for parallelism. Prior to `puma` version `5.6.2`, `puma` may not always call `close` on the response body. Rails, prior to version `7.0.2.2`, depended on the response body being closed in order for its `CurrentAttributes` implementation to work correctly. The combination of these two behaviors (Puma not closing the body + Rails' Executor implementation) causes information leakage. This problem is fixed in Puma versions 5.6.2 and 4.3.11. This problem is fixed in Rails versions 7.02.2, 6.1.4.6, 6.0.4.6, and 5.2.6.2. Upgrading to a patched Rails _or_ Puma version fixes the vulnerability.

CVE-2022-1210: A vulnerability classified as problematic was found in LibTIFF 4.3.0. Affected by this vulnerability is the TIFF File Handler of tiff2ps. Opening a malicious file leads to a denial of service. The attack can be launched remotely but requires user interaction. The exploit has been disclosed to the public and may be used.

CVE-2022-33746: P2M pool freeing may take excessively long The P2M pool backing second level address translation for guests may be of significant size. Therefore its freeing may take more time than is reasonable without intermediate preemption checks. Such checking for the need to preempt was so far missing.

CVE-2022-33747: Arm: unbounded memory consumption for 2nd-level page tables Certain actions require e.g. removing pages from a guest's P2M (Physical-to-Machine) mapping. When large pages are in use to map guest pages in the 2nd-stage page tables, such a removal operation may incur a memory allocation (to replace a large mapping with individual smaller ones). These memory allocations are taken from the global memory pool. A malicious guest might be able to cause the global memory pool to be exhausted by manipulating its own P2M mappings.

# CWE-405 Asymmetric Resource Consumption (Amplification)

## Description

The product does not properly control situations in which an adversary can cause the product to consume or produce excessive resources without requiring the adversary to invest equivalent work or otherwise prove authorization, i.e., the adversary's influence is "asymmetric."

This can lead to poor performance due to "amplification" of resource consumption, typically in a non-linear fashion. This situation is worsened if the product allows malicious users or attackers to consume more resources than their access level permits.

## Observed Examples

CVE-1999-0513: Classic "Smurf" attack, using spoofed ICMP packets to broadcast addresses.

CVE-2003-1564: Parsing library allows XML bomb

CVE-2004-2458: Tool creates directories before authenticating user.

CVE-2020-10735: Python has "quadratic complexity" issue when converting string to int with many digits in unexpected bases

CVE-2020-5243: server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.

CVE-2013-5211: composite: NTP feature generates large responses (high amplification factor) with spoofed UDP source addresses.

CVE-2002-20001: Diffie-Hellman (DHE) Key Agreement Protocol allows attackers to send arbitrary numbers that are not public keys, which causes the server to perform expensive, unnecessary computation of modular exponentiation.

CVE-2022-40735: The Diffie-Hellman Key Agreement Protocol allows use of long exponents, which are more computationally expensive than using certain "short exponents" with particular properties.

# CWE-406 Insufficient Control of Network Message Volume (Network Amplification)

## Description

The product does not sufficiently monitor or control transmitted network traffic volume, so that an actor can cause the product to transmit more traffic than should be allowed for that actor.

In the absence of a policy to restrict asymmetric resource consumption, the application or system cannot distinguish between legitimate transmissions and traffic intended to serve as an amplifying attack on target systems. Systems can often be configured to restrict the amount of traffic sent out on behalf of a client, based on the client's origin or access level. This is usually defined in a resource allocation policy. In the absence of a mechanism to keep track of transmissions, the system or application can be easily abused to transmit asymmetrically greater traffic than the request or client should be permitted to.

## Observed Examples

CVE-1999-0513: Classic "Smurf" attack, using spoofed ICMP packets to broadcast addresses.

CVE-1999-1379: DNS query with spoofed source address causes more traffic to be returned to spoofed address than was sent by the attacker.

CVE-2000-0041: Large datagrams are sent in response to malformed datagrams.

CVE-1999-1066: Game server sends a large amount.

CVE-2013-5211: composite: NTP feature generates large responses (high amplification factor) with spoofed UDP source addresses.

## Top 25 Examples

CVE-2022-0028: A PAN-OS URL filtering policy misconfiguration could allow a network-based attacker to conduct reflected and amplified TCP denial-of-service (RDoS) attacks. The DoS attack would appear to originate from a Palo Alto Networks PA-Series (hardware), VM-Series (virtual) and CN-Series (container) firewall against an attacker-specified target. To be misused by an external attacker, the firewall configuration must have a URL filtering profile with one or more blocked categories assigned to a source zone that has an external facing interface. This configuration is not typical for URL filtering and, if set, is likely unintended by the administrator. If exploited, this issue would not impact the confidentiality, integrity, or availability of our products. However, the resulting denial-of-service (DoS) attack may help obfuscate the identity of the attacker and implicate the firewall as the source of the attack. We have taken prompt action to address this issue in our PAN-OS software. All software updates for this issue are expected to be released no later than the week of August 15, 2022. This issue does not impact Panorama M-Series or Panorama virtual appliances. This issue has been resolved for all Cloud NGFW and Prisma Access customers and no additional action is required from them.

# CWE-407 Inefficient Algorithmic Complexity

## Description

An algorithm in a product has an inefficient worst-case computational complexity that may be detrimental to system performance and can be triggered by an attacker, typically using crafted manipulations that ensure that the worst case is being reached.

## Observed Examples

CVE-2021-32617: C++ library for image metadata has "quadratic complexity" issue with unnecessarily repetitive parsing each time an invalid character is encountered

CVE-2020-10735: Python has "quadratic complexity" issue when converting string to int with many digits in unexpected bases

CVE-2020-5243: server allows ReDOS with crafted User-Agent strings, due to overlapping capture groups that cause excessive backtracking.

CVE-2014-1474: Perl-based email address parser has "quadratic complexity" issue via a string that does not contain a valid address

CVE-2003-0244: CPU consumption via inputs that cause many hash table collisions.

CVE-2003-0364: CPU consumption via inputs that cause many hash table collisions.

CVE-2002-1203: Product performs unnecessary processing before dropping an invalid packet.

CVE-2001-1501: CPU and memory consumption using many wildcards.

CVE-2004-2527: Product allows attackers to cause multiple copies of a program to be loaded more quickly than the program can detect that other copies are running, then exit. This type of error should probably have its own category, where teardown takes more time than initialization.

CVE-2006-6931: Network monitoring system allows remote attackers to cause a denial of service (CPU consumption and detection outage) via crafted network traffic, aka a "backtracking attack."

CVE-2006-3380: Wiki allows remote attackers to cause a denial of service (CPU consumption) by performing a diff between large, crafted pages that trigger the worst case algorithmic complexity.

CVE-2006-3379: Wiki allows remote attackers to cause a denial of service (CPU consumption) by performing a diff between large, crafted pages that trigger the worst case algorithmic complexity.

CVE-2005-2506: OS allows attackers to cause a denial of service (CPU consumption) via crafted Gregorian dates.

CVE-2005-1792: Memory leak by performing actions faster than the software can clear them.

## Top 25 Examples

CVE-2021-33582: Cyrus IMAP before 3.4.2 allows remote attackers to cause a denial of service (multiple-minute daemon hang) via input that is mishandled during hash-table interaction. Because there are many insertions into a single bucket, strcmp becomes slow. This is fixed in 3.4.2, 3.2.8, and 3.0.16.

CVE-2021-41168: Snudown is a reddit-specific fork of the Sundown Markdown parser used by GitHub, with Python integration added. In affected versions snudown was found to be vulnerable to denial of service attacks to its reference table implementation. References written in markdown ` [reference_name]: https://www.example.com` are inserted into a hash table which was found to have a weak hash function, meaning that an attacker can reliably generate a large number of collisions for it. This makes the hash table vulnerable to a hash-collision DoS attack, a type of algorithmic complexity attack. Further the hash table allowed for duplicate entries resulting in long retrieval times. Proofs of concept and further discussion of the hash collision issue are discussed on the snudown GHSA(https://github.com/reddit/snudown/security/advisories/GHSA-6gvv-9q92-w5f6). Users are advised to update to version 1.7.0.

CVE-2022-39209: cmark-gfm is GitHub's fork of cmark, a CommonMark parsing and rendering library and program in C. In versions prior to 0.29.0.gfm.6 a polynomial time complexity issue in cmark-gfm's autolink extension may lead to unbounded resource exhaustion and subsequent denial of service. Users may verify the patch by running `python3 -c 'print("![l"* 100000 + "\\n")' | ./cmark-gfm -e autolink`, which will resource exhaust on unpatched cmark-gfm but render correctly on patched cmark-gfm. This vulnerability has been patched in 0.29.0.gfm.6. Users are advised to upgrade. Users unable to upgrade should disable the use of the autolink extension.

CVE-2022-40188: Knot Resolver before 5.5.3 allows remote attackers to cause a denial of service (CPU consumption) because of algorithmic complexity. During an attack, an authoritative server must return large NS sets or address sets.

CVE-2022-45061: An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname. For example, the attack payload could be placed in the Location header of an HTTP response with status code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16.

# CWE-408 Incorrect Behavior Order: Early Amplification

## Description

The product allows an entity to perform a legitimate but expensive operation before authentication or authorization has taken place.

## Observed Examples

CVE-2004-2458: Tool creates directories before authenticating user.

## Top 25 Examples

CVE-2022-2576: In Eclipse Californium version 2.0.0 to 2.7.2 and 3.0.0-3.5.0 a DTLS resumption handshake falls back to a DTLS full handshake on a parameter mismatch without using a HelloVerifyRequest. Especially, if used with certificate based cipher suites, that results in message amplification (DDoS other peers) and high CPU load (DoS own peer). The misbehavior occurs only with DTLS_VERIFY_PEERS_ON_RESUMPTION_THRESHOLD values larger than 0.

# CWE-409 Improper Handling of Highly Compressed Data (Data Amplification)

## Description

The product does not handle or incorrectly handles a compressed input with a very high compression ratio that produces a large output.

An example of data amplification is a "decompression bomb," a small ZIP file that can produce a large amount of data when it is decompressed.

## Observed Examples

CVE-2009-1955: XML bomb in web server module

CVE-2003-1564: Parsing library allows XML bomb

## Top 25 Examples

CVE-2022-22780: The Zoom Client for Meetings chat functionality was susceptible to Zip bombing attacks in the following product versions: Android before version 5.8.6, iOS before version 5.9.0, Linux before version 5.8.6, macOS before version 5.7.3, and Windows before version 5.6.3. This could lead to availability issues on the client host by exhausting system resources.

CVE-2022-29225: Envoy is a cloud-native high-performance proxy. In versions prior to 1.22.1 secompressors accumulate decompressed data into an intermediate buffer before overwriting the body in the decode/encodeBody. This may allow an attacker to zip bomb the decompressor by sending a small highly compressed payload. Maliciously constructed zip files may exhaust system memory and cause a denial of service. Users are advised to upgrade. Users unable to upgrade may consider disabling decompression.

CVE-2022-36114: Cargo is a package manager for the rust programming language. It was discovered that Cargo did not limit the amount of data extracted from compressed archives. An attacker could upload to an alternate registry a specially crafted package that extracts way more data than its size (also known as a "zip bomb"), exhausting the disk space on the machine using Cargo to download the package. Note that by design Cargo allows code execution at build time, due to build scripts and procedural macros. The vulnerabilities in this advisory allow performing a subset of the possible damage in a harder to track down way. Your dependencies must still be trusted if you want to be protected from attacks, as it's possible to perform the same attacks with build scripts and procedural macros. The vulnerability is present in all versions of Cargo. Rust 1.64, to be released on September 22nd, will include a fix for it. Since the vulnerability is just a more limited way to accomplish what a malicious build scripts or procedural macros can do, we decided not to publish Rust point releases backporting the security fix. Patch files are available for Rust 1.63.0 are available in the wg-security-response repository for people building their own toolchain. We recommend users of alternate registries to excercise care in which package they download, by only including trusted dependencies in their projects. Please note that even with these vulnerabilities fixed, by design Cargo allows arbitrary code execution at build time thanks to build scripts and procedural macros: a malicious dependency will be able to cause damage regardless of these vulnerabilities. crates.io implemented server-side checks to reject these kinds of packages years ago, and there are no packages on crates.io exploiting these vulnerabilities. crates.io users still need to excercise care in choosing their dependencies though, as the same concerns about build scripts and procedural macros apply here.

# CWE-41 Improper Resolution of Path Equivalence

## Description

The product is vulnerable to file system contents disclosure through path equivalence. Path equivalence involves the use of special characters in file and directory names. The associated manipulations are intended to generate multiple names for the same object.

Path equivalence is usually employed in order to circumvent access controls expressed using an incomplete set of file name or file path representations. This is different from path traversal, wherein the manipulations are performed to generate a name for a different object.

## Observed Examples

CVE-2000-1114: Source code disclosure using trailing dot

CVE-2002-1986: Source code disclosure using trailing dot

CVE-2004-2213: Source code disclosure using trailing dot or trailing encoding space "%20"

CVE-2005-3293: Source code disclosure using trailing dot

CVE-2004-0061: Bypass directory access restrictions using trailing dot in URL

CVE-2000-1133: Bypass directory access restrictions using trailing dot in URL

CVE-2001-1386: Bypass check for ".lnk" extension using ".lnk."

CVE-2001-0693: Source disclosure via trailing encoded space "%20"

CVE-2001-0778: Source disclosure via trailing encoded space "%20"

CVE-2001-1248: Source disclosure via trailing encoded space "%20"

CVE-2004-0280: Source disclosure via trailing encoded space "%20"

CVE-2005-0622: Source disclosure via trailing encoded space "%20"

CVE-2005-1656: Source disclosure via trailing encoded space "%20"

CVE-2002-1603: Source disclosure via trailing encoded space "%20"

CVE-2001-0054: Multi-Factor Vulnerability (MFV). directory traversal and other issues in FTP server using Web encodings such as "%20"; certain manipulations have unusual side effects.

CVE-2002-1451: Trailing space ("+" in query string) leads to source code disclosure.

CVE-2000-0293: Filenames with spaces allow arbitrary file deletion when the product does not properly quote them; some overlap with path traversal.

CVE-2001-1567: "+" characters in query string converted to spaces before sensitive file/extension (internal space), leading to bypass of access restrictions to the file.

CVE-2002-0253: Overlaps infoleak

CVE-2001-0446: Application server allows remote attackers to read source code for .jsp files by appending a / to the requested URL.

CVE-2004-0334: Bypass Basic Authentication for files using trailing "/"

CVE-2001-0893: Read sensitive files with trailing "/"

CVE-2001-0892: Web server allows remote attackers to view sensitive files under the document root (such as .htpasswd) via a GET request with a trailing /.

CVE-2004-1814: Directory traversal vulnerability in server allows remote attackers to read protected files via .. (dot dot) sequences in an HTTP request.

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

CVE-2002-1078: Directory listings in web server using multiple trailing slash

CVE-2004-0847: ASP.NET allows remote attackers to bypass authentication for .aspx files in restricted directories via a request containing a (1) "\" (backslash) or (2) "%5C" (encoded backslash), aka "Path Validation Vulnerability."

CVE-2000-0004: Server allows remote attackers to read source code for executable files by inserting a . (dot) into the URL.

CVE-2002-0304: Server allows remote attackers to read password-protected files via a /./ in the HTTP request.

CVE-1999-1083: Possibly (could be a cleansing error)

CVE-2004-0815: "/./////etc" cleansed to ".///etc" then "/etc"

CVE-2002-0112: Server allows remote attackers to view password protected files via /./ in the URL.

CVE-2004-0696: List directories using desired path and "*"

CVE-2002-0433: List files in web server using "*.ext"

CVE-2001-1152: Proxy allows remote attackers to bypass denylist restrictions and connect to unauthorized web servers by modifying the requested URL, including (1) a // (double slash), (2) a /SUBDIR/.. where the desired file is in the parentdir, (3) a /./, or (4) URL-encoded characters.

CVE-2000-0191: application check access for restricted URL before canonicalization

CVE-2005-1366: CGI source disclosure using "dirname/../cgi-bin"

CVE-1999-0012: Multiple web servers allow restriction bypass using 8.3 names instead of long names

CVE-2001-0795: Source code disclosure using 8.3 file name.

CVE-2005-0471: Multi-Factor Vulnerability. Product generates temporary filenames using long filenames, which become predictable in 8.3 format.

## Top 25 Examples

CVE-2021-37315: Incorrect Access Control issue discoverd in Cloud Disk in ASUS RT-AC68U router firmware version before 3.0.0.4.386.41634 allows remote attackers to write arbitrary files via improper sanitation on the source for COPY and MOVE operations.

# CWE-410 Insufficient Resource Pool

## Description

The product's resource pool is not large enough to handle peak demand, which allows an attacker to prevent others from accessing the resource by using a (relatively) large number of requests for resources.

Frequently the consequence is a "flood" of connection or sessions.

## Observed Examples

CVE-1999-1363: Large number of locks on file exhausts the pool and causes crash.

CVE-2001-1340: Product supports only one connection and does not disconnect a user who does not provide credentials.

CVE-2002-0406: Large number of connections without providing credentials allows connection exhaustion.

## Top 25 Examples

CVE-2022-46679:  Dell PowerScale OneFS 8.2.x, 9.0.0.x - 9.4.0.x, contain an insufficient resource pool vulnerability. A remote unauthenticated attacker could potentially exploit this vulnerability, leading to denial of service. 

CVE-2022-2048: In Eclipse Jetty HTTP/2 server implementation, when encountering an invalid HTTP/2 request, the error handling has a bug that can wind up not properly cleaning up the active connections and associated resources. This can lead to a Denial of Service scenario where there are no enough resources left to process good requests.

CVE-2022-22191: A Denial of Service (DoS) vulnerability in the processing of a flood of specific ARP traffic in Juniper Networks Junos OS on the EX4300 switch, sent from the local broadcast domain, may allow an unauthenticated network-adjacent attacker to trigger a PFEMAN watchdog timeout, causing the Packet Forwarding Engine (PFE) to crash and restart. After the restart, transit traffic will be temporarily interrupted until the PFE is reprogrammed. In a virtual chassis (VC), the impacted Flexible PIC Concentrator (FPC) may split from the VC temporarily, and join back into the VC once the PFE restarts. Continued receipt and processing of these packets will create a sustained Denial of Service (DoS) condition. This issue affects Juniper Networks Junos OS on the EX4300: All versions prior to 15.1R7-S12; 18.4 versions prior to 18.4R2-S10, 18.4R3-S11; 19.1 versions prior to 19.1R3-S8; 19.2 versions prior to 19.2R1-S9, 19.2R3-S4; 19.3 versions prior to 19.3R3-S5; 19.4 versions prior to 19.4R2-S6, 19.4R3-S7; 20.1 versions prior to 20.1R3-S3; 20.2 versions prior to 20.2R3-S3; 20.3 versions prior to 20.3R3-S2; 20.4 versions prior to 20.4R3-S1; 21.1 versions prior to 21.1R3; 21.2 versions prior to 21.2R2-S1, 21.2R3; 21.3 versions prior to 21.3R1-S2, 21.3R2.

# CWE-412 Unrestricted Externally Accessible Lock

## Description

The product properly checks for the existence of a lock, but the lock can be externally controlled or influenced by an actor that is outside of the intended sphere of control.

This prevents the product from acting on associated resources or performing other behaviors that are controlled by the presence of the lock. Relevant locks might include an exclusive lock or mutex, or modifying a shared resource that is treated as a lock. If the lock can be held for an indefinite period of time, then the denial of service could be permanent.

## Observed Examples

CVE-2001-0682: Program can not execute when attacker obtains a mutex.

CVE-2002-1914: Program can not execute when attacker obtains a lock on a critical output file.

CVE-2002-1915: Program can not execute when attacker obtains a lock on a critical output file.

CVE-2002-0051: Critical file can be opened with exclusive read access by user, preventing application of security policy. Possibly related to improper permissions, large-window race condition.

CVE-2000-0338: Chain: predictable file names used for locking, allowing attacker to create the lock beforehand. Resultant from permissions and randomness.

CVE-2000-1198: Chain: Lock files with predictable names. Resultant from randomness.

CVE-2002-1869: Product does not check if it can write to a log file, allowing attackers to avoid logging by accessing the file using an exclusive lock. Overlaps unchecked error condition. This is not quite CWE-412, but close.

# CWE-413 Improper Resource Locking

## Description

The product does not lock or does not correctly lock a resource when the product must have exclusive access to the resource.

When a resource is not properly locked, an attacker could modify the resource while it is being operated on by the product. This might violate the product's assumption that the resource will not change, potentially leading to unexpected behaviors.

## Observed Examples

CVE-2022-20141: Chain: an operating system kernel has insufficent resource locking (CWE-413) leading to a use after free (CWE-416).

## Top 25 Examples

CVE-2022-20141: In ip_check_mc_rcu of igmp.c, there is a possible use after free due to improper locking. This could lead to local escalation of privilege when opening and closing inet sockets with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-112551163References: Upstream kernel

CVE-2022-20371: In dm_bow_dtr and related functions of dm-bow.c, there is a possible use after free due to a race condition. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-195565510References: Upstream kernel

CVE-2022-20422: In emulation_proc_handler of armv8_deprecated.c, there is a possible way to corrupt memory due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-237540956References: Upstream kernel

CVE-2022-24946: Improper Resource Locking vulnerability in Mitsubishi Electric MELSEC iQ-R Series R12CCPU-V firmware versions "16" and prior, Mitsubishi Electric MELSEC-Q Series Q03UDECPU the first 5 digits of serial No. "24061" and prior, Mitsubishi Electric MELSEC-Q Series Q04/06/10/13/20/26/50/100UDEHCPU the first 5 digits of serial No. "24061" and prior, Mitsubishi Electric MELSEC-Q Series Q03/04/06/13/26UDVCPU the first 5 digits of serial number "24051" and prior, Mitsubishi Electric MELSEC-Q Series Q04/06/13/26UDPVCPU the first 5 digits of serial number "24051" and prior, Mitsubishi Electric MELSEC-Q Series Q12DCCPU-V all versions, Mitsubishi Electric MELSEC-Q Series Q24DHCCPU-V(G) all versions, Mitsubishi Electric MELSEC-Q Series Q24/26DHCCPU-LS all versions, Mitsubishi Electric MELSEC-L series L02/06/26CPU(-P) the first 5 digits of serial number "24051" and prior, Mitsubishi Electric MELSEC-L series L26CPU-(P)BT the first 5 digits of serial number "24051" and prior and Mitsubishi Electric MELIPC Series MI5122-VW firmware versions "05" and prior allows a remote unauthenticated attacker to cause a denial of service (DoS) condition in Ethernet communications by sending specially crafted packets. A system reset of the products is required for recovery.

# CWE-414 Missing Lock Check

## Description

A product does not check to see if a lock is present before performing sensitive operations on a resource.

## Observed Examples

CVE-2004-1056: Product does not properly check if a lock is present, allowing other attackers to access functionality.

# CWE-415 Double Free

## Description

The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations.

When a program calls free() twice with the same argument, the program's memory management data structures become corrupted. This corruption can cause the program to crash or, in some circumstances, cause two later calls to malloc() to return the same pointer. If malloc() returns the same value twice and the program later gives the attacker control over the data that is written into this doubly-allocated memory, the program becomes vulnerable to a buffer overflow attack.

## Observed Examples

CVE-2006-5051: Chain: Signal handler contains too much functionality (CWE-828), introducing a race condition (CWE-362) that leads to a double free (CWE-415).

CVE-2004-0642: Double free resultant from certain error conditions.

CVE-2004-0772: Double free resultant from certain error conditions.

CVE-2005-1689: Double free resultant from certain error conditions.

CVE-2003-0545: Double free from invalid ASN.1 encoding.

CVE-2003-1048: Double free from malformed GIF.

CVE-2005-0891: Double free from malformed GIF.

CVE-2002-0059: Double free from malformed compressed data.

## Top 25 Examples

CVE-2021-23158: A flaw was found in htmldoc in v1.9.12. Double-free in function pspdf_export(),in ps-pdf.cxx may result in a write-what-where condition, allowing an attacker to execute arbitrary code and denial of service.

CVE-2022-2008: Double free in WebGL in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-40304: An issue was discovered in libxml2 before 2.10.3. Certain invalid XML entity definitions can corrupt a hash table key, potentially leading to subsequent logic errors. In one case, a double-free can be provoked.

# CWE-416 Use After Free

## Description

The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because the memory "belongs" to the code that operates on the new pointer.

## Observed Examples

CVE-2022-20141: Chain: an operating system kernel has insufficent resource locking (CWE-413) leading to a use after free (CWE-416).

CVE-2022-2621: Chain: two threads in a web browser use the same resource (CWE-366), but one of those threads can destroy the resource before the other has completed (CWE-416).

CVE-2021-0920: Chain: mobile platform race condition (CWE-362) leading to use-after-free (CWE-416), as exploited in the wild per CISA KEV.

CVE-2020-6819: Chain: race condition (CWE-362) leads to use-after-free (CWE-416), as exploited in the wild per CISA KEV.

CVE-2010-4168: Use-after-free triggered by closing a connection while data is still being transmitted.

CVE-2010-2941: Improper allocation for invalid data leads to use-after-free.

CVE-2010-2547: certificate with a large number of Subject Alternate Names not properly handled in realloc, leading to use-after-free

CVE-2010-1772: Timers are not disabled when a related object is deleted

CVE-2010-1437: Access to a "dead" object that is being cleaned up

CVE-2010-1208: object is deleted even with a non-zero reference count, and later accessed

CVE-2010-0629: use-after-free involving request containing an invalid version number

CVE-2010-0378: unload of an object that is currently being accessed by other functionality

CVE-2010-0302: incorrectly tracking a reference count leads to use-after-free

CVE-2010-0249: use-after-free related to use of uninitialized memory

CVE-2010-0050: HTML document with incorrectly-nested tags

CVE-2009-3658: Use after free in ActiveX object by providing a malformed argument to a method

CVE-2009-3616: use-after-free by disconnecting during data transfer, or a message containing incorrect data types

CVE-2009-3553: disconnect during a large data transfer causes incorrect reference count, leading to use-after-free

CVE-2009-2416: use-after-free found by fuzzing

CVE-2009-1837: Chain: race condition (CWE-362) from improper handling of a page transition in web client while an applet is loading (CWE-368) leads to use after free (CWE-416)

CVE-2009-0749: realloc generates new buffer and pointer, but previous pointer is still retained, leading to use after free

CVE-2010-3328: Use-after-free in web browser, probably resultant from not initializing memory.

CVE-2008-5038: use-after-free when one thread accessed memory that was freed by another thread

CVE-2008-0077: assignment of malformed values to certain properties triggers use after free

CVE-2006-4434: mail server does not properly handle a long header.

CVE-2010-2753: chain: integer overflow leads to use-after-free

CVE-2006-4997: freed pointer dereference

## Top 25 Examples

CVE-2021-35120: Improper handling between export and release functions on the same handle from client can lead to use after free in Snapdragon Compute, Snapdragon Connectivity, Snapdragon Industrial IOT, Snapdragon Mobile

CVE-2021-3700: A use-after-free vulnerability was found in usbredir in versions prior to 0.11.0 in the usbredirparser_serialize() in usbredirparser/usbredirparser.c. This issue occurs when serializing large amounts of buffered write data in the case of a slow or blocked destination.

CVE-2021-38005: Use after free in loader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-38006: Use after free in storage foundation in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-38008: Use after free in media in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-38011: Use after free in storage foundation in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-39812: In TBD of TBD, there is a possible out of bounds read due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-205522359References: N/A

CVE-2021-4052: Use after free in web apps in Google Chrome prior to 96.0.4664.93 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.

CVE-2021-4053: Use after free in UI in Google Chrome on Linux prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4057: Use after free in file API in Google Chrome prior to 96.0.4664.93 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4063: Use after free in developer tools in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4064: Use after free in screen capture in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4065: Use after free in autofill in Google Chrome prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4067: Use after free in window manager in Google Chrome on ChromeOS prior to 96.0.4664.93 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4099: Use after free in Swiftshader in Google Chrome prior to 96.0.4664.110 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-4102: Use after free in V8 in Google Chrome prior to 96.0.4664.110 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0096: Use after free in Storage in Google Chrome prior to 97.0.4692.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0098: Use after free in Screen Capture in Google Chrome on Chrome OS prior to 97.0.4692.71 allowed an attacker who convinced a user to perform specific user gestures to potentially exploit heap corruption via specific user gestures.

CVE-2022-0099: Use after free in Sign-in in Google Chrome prior to 97.0.4692.71 allowed a remote attacker who convinced a user to perform specific user gestures to potentially exploit heap corruption via specific user gesture.

CVE-2022-0103: Use after free in SwiftShader in Google Chrome prior to 97.0.4692.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0105: Use after free in PDF Accessibility in Google Chrome prior to 97.0.4692.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0106: Use after free in Autofill in Google Chrome prior to 97.0.4692.71 allowed a remote attacker who convinced a user to perform specific user gesture to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0107: Use after free in File Manager API in Google Chrome on Chrome OS prior to 97.0.4692.71 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0289: Use after free in Safe browsing in Google Chrome prior to 97.0.4692.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0293: Use after free in Web packaging in Google Chrome prior to 97.0.4692.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0295: Use after free in Omnibox in Google Chrome prior to 97.0.4692.99 allowed a remote attacker who convinced the user to engage is specific user interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0296: Use after free in Printing in Google Chrome prior to 97.0.4692.99 allowed a remote attacker who convinced the user to engage is specific user interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0297: Use after free in Vulkan in Google Chrome prior to 97.0.4692.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0298: Use after free in Scheduling in Google Chrome prior to 97.0.4692.99 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0300: Use after free in Text Input Method Editor in Google Chrome on Android prior to 97.0.4692.99 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0301: Heap buffer overflow in DevTools in Google Chrome prior to 97.0.4692.99 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0302: Use after free in Omnibox in Google Chrome prior to 97.0.4692.99 allowed an attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0304: Use after free in Bookmarks in Google Chrome prior to 97.0.4692.99 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0307: Use after free in Optimization Guide in Google Chrome prior to 97.0.4692.99 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0308: Use after free in Data Transfer in Google Chrome on Chrome OS prior to 97.0.4692.99 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0453: Use after free in Reader Mode in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0456: Use after free in Web Search in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to potentially exploit heap corruption via profile destruction.

CVE-2022-0458: Use after free in Thumbnail Tab Strip in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0459: Use after free in Screen Capture in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who had compromised the renderer process and convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0460: Use after free in Window Dialogue in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0463: Use after free in Accessibility in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.

CVE-2022-0464: Use after free in Accessibility in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.

CVE-2022-0465: Use after free in Extensions in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to potentially exploit heap corruption via user interaction.

CVE-2022-0468: Use after free in Payments in Google Chrome prior to 98.0.4758.80 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0469: Use after free in Cast in Google Chrome prior to 98.0.4758.80 allowed a remote attacker who convinced a user to engage in specific interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0603: Use after free in File Manager in Google Chrome on Chrome OS prior to 98.0.4758.102 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0605: Use after free in Webstore API in Google Chrome prior to 98.0.4758.102 allowed an attacker who convinced a user to install a malicious extension and convinced a user to enage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0606: Use after free in ANGLE in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0607: Use after free in GPU in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0609: Use after free in Animation in Google Chrome prior to 98.0.4758.102 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0646: A flaw use after free in the Linux kernel Management Component Transport Protocol (MCTP) subsystem was found in the way user triggers cancel_work_sync after the unregister_netdev during removing device. A local user could use this flaw to crash the system or escalate their privileges on the system. It is actual from Linux Kernel 5.17-rc1 (when mctp-serial.c introduced) till 5.17-rc5.

CVE-2022-0791: Use after free in Omnibox in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via user interactions.

CVE-2022-0793: Use after free in Cast in Google Chrome prior to 99.0.4844.51 allowed an attacker who convinced a user to install a malicious extension and engage in specific user interaction to potentially exploit heap corruption via a crafted Chrome Extension.

CVE-2022-0794: Use after free in WebShare in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0796: Use after free in Media in Google Chrome prior to 99.0.4844.51 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0798: Use after free in MediaStream in Google Chrome prior to 99.0.4844.51 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.

CVE-2022-0805: Use after free in Browser Switcher in Google Chrome prior to 99.0.4844.51 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.

CVE-2022-0808: Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 99.0.4844.51 allowed a remote attacker who convinced a user to engage in a series of user interaction to potentially exploit heap corruption via user interactions.

CVE-2022-0971: Use after free in Blink Layout in Google Chrome on Android prior to 99.0.4844.74 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0972: Use after free in Extensions in Google Chrome prior to 99.0.4844.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0973: Use after free in Safe Browsing in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0974: Use after free in Splitscreen in Google Chrome on Chrome OS prior to 99.0.4844.74 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0975: Use after free in ANGLE in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0977: Use after free in Browser UI in Google Chrome on Chrome OS prior to 99.0.4844.74 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0978: Use after free in ANGLE in Google Chrome prior to 99.0.4844.74 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0979: Use after free in Safe Browsing in Google Chrome on Android prior to 99.0.4844.74 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-0980: Use after free in New Tab Page in Google Chrome prior to 99.0.4844.74 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific user interactions.

CVE-2022-1125: Use after free in Portals in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.

CVE-2022-1127: Use after free in QR Code Generator in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via user interaction.

CVE-2022-1131: Use after free in Cast UI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1133: Use after free in WebRTC Perf in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1135: Use after free in Shopping Cart in Google Chrome prior to 100.0.4896.60 allowed a remote attacker to potentially exploit heap corruption via standard feature user interaction.

CVE-2022-1136: Use after free in Tab Strip in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific set of user gestures.

CVE-2022-1141: Use after free in File Manager in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific user gesture.

CVE-2022-1144: Use after free in WebUI in Google Chrome prior to 100.0.4896.60 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific input into DevTools.

CVE-2022-1145: Use after free in Extensions in Google Chrome prior to 100.0.4896.60 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific user interaction and profile destruction.

CVE-2022-1305: Use after free in storage in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1308: Use after free in BFCache in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1310: Use after free in regular expressions in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1311: Use after free in shell in Google Chrome on ChromeOS prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1313: Use after free in tab groups in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1477: Use after free in Vulkan in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1478: Use after free in SwiftShader in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1479: Use after free in ANGLE in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1481: Use after free in Sharing in Google Chrome on Mac prior to 101.0.4951.41 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1485: Use after free in File System API in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1487: Use after free in Ozone in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via running a Wayland test.

CVE-2022-1490: Use after free in Browser Switcher in Google Chrome prior to 101.0.4951.41 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1491: Use after free in Bookmarks in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via specific and direct user interaction.

CVE-2022-1493: Use after free in Dev Tools in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via specific and direct user interaction.

CVE-2022-1496: Use after free in File Manager in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via specific and direct user interaction.

CVE-2022-1633: Use after free in Sharesheet in Google Chrome on Chrome OS prior to 101.0.4951.64 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific user interactions.

CVE-2022-1634: Use after free in Browser UI in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who had convinced a user to engage in specific UI interaction to potentially exploit heap corruption via specific user interactions.

CVE-2022-1635: Use after free in Permission Prompts in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific user interactions.

CVE-2022-1636: Use after free in Performance APIs in Google Chrome prior to 101.0.4951.64 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1639: Use after free in ANGLE in Google Chrome prior to 101.0.4951.64 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1640: Use after free in Sharing in Google Chrome prior to 101.0.4951.64 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1641: Use after free in Web UI Diagnostics in Google Chrome on Chrome OS prior to 101.0.4951.64 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific user interaction.

CVE-2022-1734: A flaw in Linux Kernel found in nfcmrvl_nci_unregister_dev() in drivers/nfc/nfcmrvl/main.c can lead to use after free both read or write when non synchronized between cleanup routine and firmware download routine.

CVE-2022-1854: Use after free in ANGLE in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1855: Use after free in Messaging in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1856: Use after free in User Education in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension or specific user interaction.

CVE-2022-1859: Use after free in Performance Manager in Google Chrome prior to 102.0.5005.61 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-1860: Use after free in UI Foundations in Google Chrome on Chrome OS prior to 102.0.5005.61 allowed a remote attacker who convinced a user to engage in specific user interaction to potentially exploit heap corruption via specific user interactions.

CVE-2022-1861: Use after free in Sharing in Google Chrome on Chrome OS prior to 102.0.5005.61 allowed a remote attacker who convinced a user to enage in specific user interactions to potentially exploit heap corruption via specific user interaction.

CVE-2022-1863: Use after free in Tab Groups in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension and specific user interaction.

CVE-2022-1864: Use after free in WebApp Installs in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension and specific user interaction.

CVE-2022-1865: Use after free in Bookmarks in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension and specific user interaction.

CVE-2022-1866: Use after free in Tablet Mode in Google Chrome on Chrome OS prior to 102.0.5005.61 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via specific user interactions.

CVE-2022-1870: Use after free in App Service in Google Chrome prior to 102.0.5005.61 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension.

CVE-2022-1919: Use after free in Codecs in Google Chrome prior to 101.0.4951.41 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2007: Use after free in WebGPU in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2011: Use after free in ANGLE in Google Chrome prior to 102.0.5005.115 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-20447: In PAN_WriteBuf of pan_api.cc, there is a possible out of bounds read due to a use after free. This could lead to remote information disclosure over Bluetooth with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-233604485

CVE-2022-20552: In btif_a2dp_sink_command_ready of btif_a2dp_sink.cc, there is a possible out of bounds read due to a use after free. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-243922806

CVE-2022-20554: In removeEventHubDevice of InputDevice.cpp, there is a possible OOB read due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-13Android ID: A-245770596

CVE-2022-20581: In the Pixel camera driver, there is a possible use after free due to a logic error in the code. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-245916120References: N/A

CVE-2022-2156: Use after free in Core in Google Chrome prior to 103.0.5060.53 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2157: Use after free in Interest groups in Google Chrome prior to 103.0.5060.53 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2158: Type confusion in V8 in Google Chrome prior to 103.0.5060.53 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2161: Use after free in WebApp Provider in Google Chrome prior to 103.0.5060.53 allowed a remote attacker who convinced the user to engage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2163: Use after free in Cast UI and Toolbar in Google Chrome prior to 103.0.5060.134 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via UI interaction.

CVE-2022-2296: Use after free in Chrome OS Shell in Google Chrome on Chrome OS prior to 103.0.5060.114 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via direct UI interactions.

CVE-2022-23608: PJSIP is a free and open source multimedia communication library written in C language implementing standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In versions up to and including 2.11.1 when in a dialog set (or forking) scenario, a hash key shared by multiple UAC dialogs can potentially be prematurely freed when one of the dialogs is destroyed . The issue may cause a dialog set to be registered in the hash table multiple times (with different hash keys) leading to undefined behavior such as dialog list collision which eventually leading to endless loop. A patch is available in commit db3235953baa56d2fb0e276ca510fefca751643f which will be included in the next release. There are no known workarounds for this issue.

CVE-2022-2399: Use after free in WebGPU in Google Chrome prior to 100.0.4896.88 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2477: Use after free in Guest View in Google Chrome prior to 103.0.5060.134 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2478: Use after free in PDF in Google Chrome prior to 103.0.5060.134 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2480: Use after free in Service Worker API in Google Chrome prior to 103.0.5060.134 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2481: Use after free in Views in Google Chrome prior to 103.0.5060.134 allowed a remote attacker who convinced a user to engage in specific user interactions to potentially exploit heap corruption via UI interaction.

CVE-2022-2603: Use after free in Omnibox in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2604: Use after free in Safe Browsing in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2606: Use after free in Managed devices API in Google Chrome prior to 104.0.5112.79 allowed a remote attacker who convinced a user to enable a specific Enterprise policy to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2613: Use after free in Input in Google Chrome on Chrome OS prior to 104.0.5112.79 allowed a remote attacker who convinced a user to enage in specific user interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2614: Use after free in Sign-In Flow in Google Chrome prior to 104.0.5112.79 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-28269: Acrobat Reader DC versions 22.001.20085 (and earlier), 20.005.3031x (and earlier) and 17.012.30205 (and earlier) are affected by a use-after-free vulnerability in the processing of Annotation objects that could result in a memory leak in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2022-2852: Use after free in FedCM in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2855: Use after free in ANGLE in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-2858: Use after free in Sign-In Flow in Google Chrome prior to 104.0.5112.101 allowed a remote attacker to potentially exploit heap corruption via specific UI interaction.

CVE-2022-2859: Use after free in Chrome OS Shell in Google Chrome prior to 104.0.5112.101 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific UI interactions.

CVE-2022-2896: Measuresoft ScadaPro Server (All Versions) allows use after free while processing a specific project file.

CVE-2022-2998: Use after free in Browser Creation in Google Chrome prior to 104.0.5112.101 allowed a remote attacker who had convinced a user to engage in a specific UI interaction to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3038: Use after free in Network Service in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3039: Use after free in WebSQL in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3041: Use after free in WebSQL in Google Chrome prior to 105.0.5195.52 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3046: Use after free in Browser Tag in Google Chrome prior to 105.0.5195.52 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3055: Use after free in Passwords in Google Chrome prior to 105.0.5195.52 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page.

CVE-2022-3058: Use after free in Sign-In Flow in Google Chrome prior to 105.0.5195.52 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via crafted UI interaction.

CVE-2022-3196: Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file. (Chromium security severity: High)

CVE-2022-3197: Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file. (Chromium security severity: High)

CVE-2022-3198: Use after free in PDF in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially exploit heap corruption via a crafted PDF file. (Chromium security severity: High)

CVE-2022-3199: Use after free in Frames in Google Chrome prior to 105.0.5195.125 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-32317: The MPlayer Project v1.5 was discovered to contain a heap use-after-free resulting in a double free in the preinit function at libvo/vo_v4l2.c. This vulnerability can lead to a Denial of Service (DoS) via a crafted file. The device=strdup statement is not executed on every call. Note: This has been disputed by third parties as invalid and not reproduceable.

CVE-2022-3445: Use after free in Skia in Google Chrome prior to 106.0.5249.119 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-3448: Use after free in Permissions API in Google Chrome prior to 106.0.5249.119 allowed a remote attacker who convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-34484: The Mozilla Fuzzing Team reported potential vulnerabilities present in Thunderbird 91.10. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox < 102, Firefox ESR < 91.11, Thunderbird < 102, and Thunderbird < 91.11.

CVE-2022-3449: Use after free in Safe Browsing in Google Chrome prior to 106.0.5249.119 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity: High)

CVE-2022-34568: SDL v1.2 was discovered to contain a use-after-free via the XFree function at /src/video/x11/SDL_x11yuv.c.

CVE-2022-3654: Use after free in Layout in Google Chrome prior to 107.0.5304.62 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-3657: Use after free in Extensions in Google Chrome prior to 107.0.5304.62 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity: Medium)

CVE-2022-3658: Use after free in Feedback service on Chrome OS in Google Chrome on Chrome OS prior to 107.0.5304.62 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via specific UI interaction. (Chromium security severity: Medium)

CVE-2022-3659: Use after free in Accessibility in Google Chrome on Chrome OS prior to 107.0.5304.62 allowed a remote attacker who convinced a user to engage in specific UI interactions to potentially exploit heap corruption via specific UI interactions. (Chromium security severity: Medium)

CVE-2022-3842: Use after free in Passwords in Google Chrome prior to 105.0.5195.125 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-3863: Use after free in Browser History in Google Chrome prior to 100.0.4896.75 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chrome security severity: High)

CVE-2022-3885: Use after free in V8 in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-3886: Use after free in Speech Recognition in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-3887: Use after free in Web Workers in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-3888: Use after free in WebCodecs in Google Chrome prior to 107.0.5304.106 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4175: Use after free in Camera Capture in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4177: Use after free in Extensions in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to install an extension to potentially exploit heap corruption via a crafted Chrome Extension and UI interaction. (Chromium security severity: High)

CVE-2022-4178: Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4179: Use after free in Audio in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity: High)

CVE-2022-4180: Use after free in Mojo in Google Chrome prior to 108.0.5359.71 allowed an attacker who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted Chrome Extension. (Chromium security severity: High)

CVE-2022-4181: Use after free in Forms in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4191: Use after free in Sign-In in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced a user to engage in specific UI interaction to potentially exploit heap corruption via profile destruction. (Chromium security severity: Medium)

CVE-2022-4192: Use after free in Live Caption in Google Chrome prior to 108.0.5359.71 allowed a remote attacker who convinced a user to engage in specific UI interaction to potentially exploit heap corruption via UI interaction. (Chromium security severity: Medium)

CVE-2022-4194: Use after free in Accessibility in Google Chrome prior to 108.0.5359.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)

CVE-2022-42332: x86 shadow plus log-dirty mode use-after-free In environments where host assisted address translation is necessary but Hardware Assisted Paging (HAP) is unavailable, Xen will run guests in so called shadow mode. Shadow mode maintains a pool of memory used for both shadow page tables as well as auxiliary data structures. To migrate or snapshot guests, Xen additionally runs them in so called log-dirty mode. The data structures needed by the log-dirty tracking are part of aformentioned auxiliary data. In order to keep error handling efforts within reasonable bounds, for operations which may require memory allocations shadow mode logic ensures up front that enough memory is available for the worst case requirements. Unfortunately, while page table memory is properly accounted for on the code path requiring the potential establishing of new shadows, demands by the log-dirty infrastructure were not taken into consideration. As a result, just established shadow page tables could be freed again immediately, while other code is still accessing them on the assumption that they would remain allocated.

CVE-2022-4436: Use after free in Blink Media in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4437: Use after free in Mojo IPC in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4438: Use after free in Blink Frames in Google Chrome prior to 108.0.5359.124 allowed a remote attacker who convinced the user to engage in specific UI interactions to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-4439: Use after free in Aura in Google Chrome on Windows prior to 108.0.5359.124 allowed a remote attacker who convinced the user to engage in specific UI interactions to potentially exploit heap corruption via specific UI interactions. (Chromium security severity: High)

CVE-2022-4440: Use after free in Profiles in Google Chrome prior to 108.0.5359.124 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)

CVE-2022-44550: The graphics display module has a UAF vulnerability when traversing graphic layers. Successful exploitation of this vulnerability may affect system availability.

CVE-2022-45406: If an out-of-memory condition occurred when creating a JavaScript global, a JavaScript realm may be deleted while references to it lived on in a BaseShape. This could lead to a use-after-free causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 102.5, Thunderbird < 102.5, and Firefox < 107.

CVE-2022-29228: Envoy is a cloud-native high-performance proxy. In versions prior to 1.22.1 the OAuth filter would try to invoke the remaining filters in the chain after emitting a local response, which triggers an ASSERT() in newer versions and corrupts memory on earlier versions. continueDecoding() shouldn’t ever be called from filters after a local reply has been sent. Users are advised to upgrade. There are no known workarounds for this issue.

CVE-2022-23459: Jsonxx or Json++ is a JSON parser, writer and reader written in C++. In affected versions of jsonxx use of the Value class may lead to memory corruption via a double free or via a use after free. The value class has a default assignment operator which may be used with pointer types which may point to alterable data where the pointer itself is not updated. This issue exists on the current commit of the jsonxx project. The project itself has been archived and updates are not expected. Users are advised to find a replacement.

CVE-2022-3370: Use after free in Custom Elements in Google Chrome prior to 106.0.5249.91 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

CVE-2022-43945: The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC message with garbage data is still correctly formed according to the specification and is passed forward to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H

CVE-2021-1048: In ep_loop_check_proc of eventpoll.c, there is a possible way to corrupt memory due to a use after free. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-204573007References: Upstream kernel

CVE-2021-1905: Possible use after free due to improper handling of memory mapping of multiple processes simultaneously. in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2021-21193: Use after free in Blink in Google Chrome prior to 89.0.4389.90 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-21206: Use after free in Blink in Google Chrome prior to 89.0.4389.128 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-25370: An incorrect implementation handling file descriptor in dpu driver prior to SMR Mar-2021 Release 1 results in memory corruption leading to kernel panic.

CVE-2021-26411: Internet Explorer Memory Corruption Vulnerability

CVE-2021-28550: Acrobat Reader DC versions versions 2021.001.20150 (and earlier), 2020.001.30020 (and earlier) and 2017.011.30194 (and earlier) are affected by a Use After Free vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2021-28663: The Arm Mali GPU kernel driver allows privilege escalation or information disclosure because GPU memory operations are mishandled, leading to a use-after-free. This affects Bifrost r0p0 through r28p0 before r29p0, Valhall r19p0 through r28p0 before r29p0, and Midgard r4p0 through r30p0.

CVE-2021-30554: Use after free in WebGL in Google Chrome prior to 91.0.4472.114 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-30633: Use after free in Indexed DB API in Google Chrome prior to 93.0.4577.82 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

CVE-2021-30661: A use after free issue was addressed with improved memory management. This issue is fixed in Safari 14.1, iOS 12.5.3, iOS 14.5 and iPadOS 14.5, watchOS 7.4, tvOS 14.5, macOS Big Sur 11.3. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-30762: A use after free issue was addressed with improved memory management. This issue is fixed in iOS 12.5.4. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

CVE-2021-30858: A use after free issue was addressed with improved memory management. This issue is fixed in iOS 14.8 and iPadOS 14.8, macOS Big Sur 11.6. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited.

CVE-2021-31166: HTTP Protocol Stack Remote Code Execution Vulnerability

CVE-2021-34486: Windows Event Tracing Elevation of Privilege Vulnerability

CVE-2021-37973: Use after free in Portals in Google Chrome prior to 94.0.4606.61 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.

CVE-2021-37975: Use after free in V8 in Google Chrome prior to 94.0.4606.71 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.

CVE-2021-40449: Win32k Elevation of Privilege Vulnerability

CVE-2022-22620: A use after free issue was addressed with improved memory management. This issue is fixed in macOS Monterey 12.2.1, iOS 15.3.1 and iPadOS 15.3.1, Safari 15.3 (v. 16612.4.9.1.8 and 15612.4.9.1.8). Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been actively exploited..

CVE-2022-26485: Removing an XSLT parameter during processing could have lead to an exploitable use-after-free. We have had reports of attacks in the wild abusing this flaw. This vulnerability affects Firefox < 97.0.2, Firefox ESR < 91.6.1, Firefox for Android < 97.3.0, Thunderbird < 91.6.2, and Focus < 97.3.0.

CVE-2022-26486: An unexpected message in the WebGPU IPC framework could lead to a use-after-free and exploitable sandbox escape. We have had reports of attacks in the wild abusing this flaw. This vulnerability affects Firefox < 97.0.2, Firefox ESR < 91.6.1, Firefox for Android < 97.3.0, Thunderbird < 91.6.2, and Focus < 97.3.0.

CVE-2022-38181: The Arm Mali GPU kernel driver allows unprivileged users to access freed memory because GPU memory operations are mishandled. This affects Bifrost r0p0 through r38p1, and r39p0; Valhall r19p0 through r38p1, and r39p0; and Midgard r4p0 through r32p0.

CVE-2022-0523: Use After Free in GitHub repository radareorg/radare2 prior to 5.6.2.

CVE-2022-22034: Windows Graphics Component Elevation of Privilege Vulnerability

CVE-2022-0581: Crash in the CMS protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of service via packet injection or crafted capture file

CVE-2022-3541: A vulnerability classified as critical has been found in Linux Kernel. This affects the function spl2sw_nvmem_get_mac_address of the file drivers/net/ethernet/sunplus/spl2sw_driver.c of the component BPF. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211041 was assigned to this vulnerability.

CVE-2022-3545: A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211045 was assigned to this vulnerability.

CVE-2022-3559: A vulnerability was found in Exim and classified as problematic. This issue affects some unknown processing of the component Regex Handler. The manipulation leads to use after free. The name of the patch is 4e9ed49f8f12eb331b29bd5b6dc3693c520fddc2. It is recommended to apply a patch to fix this issue. The identifier VDB-211073 was assigned to this vulnerability.

CVE-2022-3620: A vulnerability was found in Exim and classified as problematic. This issue affects the function dmarc_dns_lookup of the file dmarc.c of the component DMARC Handler. The manipulation leads to use after free. The attack may be initiated remotely. The name of the patch is 12fb3842f81bcbd4a4519d5728f2d7e0e3ca1445. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211919.

CVE-2022-3625: A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211929 was assigned to this vulnerability.

CVE-2022-3636: A vulnerability, which was classified as critical, was found in Linux Kernel. This affects the function __mtk_ppe_check_skb of the file drivers/net/ethernet/mediatek/mtk_ppe.c of the component Ethernet Handler. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211935.

CVE-2022-3640: A vulnerability, which was classified as critical, was found in Linux Kernel. Affected is the function l2cap_conn_del of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211944.

CVE-2022-3649: A vulnerability was found in Linux Kernel. It has been classified as problematic. Affected is the function nilfs_new_inode of the file fs/nilfs2/inode.c of the component BPF. The manipulation leads to use after free. It is possible to launch the attack remotely. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-211992.

CVE-2022-3705: A vulnerability was found in vim and classified as problematic. Affected by this issue is the function qf_update_buffer of the file quickfix.c of the component autocmd Handler. The manipulation leads to use after free. The attack may be launched remotely. Upgrading to version 9.0.0805 is able to address this issue. The name of the patch is d0fab10ed2a86698937e3c3fed2f10bd9bb5e731. It is recommended to upgrade the affected component. The identifier of this vulnerability is VDB-212324.

CVE-2021-30262: Improper validation of a socket state when socket events are being sent to clients can lead to invalid access of memory in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Voice & Music, Snapdragon Wearables

CVE-2022-35254: An unauthenticated attacker can cause a denial-of-service to the following products: Ivanti Connect Secure (ICS) in versions prior to 9.1R14.3, 9.1R15.2, 9.1R16.2, and 22.2R4, Ivanti Policy Secure (IPS) in versions prior to 9.1R17 and 22.3R1, and Ivanti Neurons for Zero-Trust Access in versions prior to 22.3R1.

# CWE-419 Unprotected Primary Channel

## Description

The product uses a primary channel for administration or restricted functionality, but it does not properly protect the channel.

## Top 25 Examples

CVE-2022-33932: Dell PowerScale OneFS, versions 9.0.0 up to and including 9.1.0.19, 9.2.1.12, 9.3.0.6, and 9.4.0.2, contain an unprotected primary channel vulnerability. An unauthenticated network malicious attacker may potentially exploit this vulnerability, leading to a denial of filesystem services.

# CWE-42 Path Equivalence: 'filename.' (Trailing Dot)

## Description

The product accepts path input in the form of trailing dot ('filedir.') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2000-1114: Source code disclosure using trailing dot

CVE-2002-1986: Source code disclosure using trailing dot

CVE-2004-2213: Source code disclosure using trailing dot

CVE-2005-3293: Source code disclosure using trailing dot

CVE-2004-0061: Bypass directory access restrictions using trailing dot in URL

CVE-2000-1133: Bypass directory access restrictions using trailing dot in URL

CVE-2001-1386: Bypass check for ".lnk" extension using ".lnk."

# CWE-420 Unprotected Alternate Channel

## Description

The product protects a primary channel, but it does not use the same level of protection for an alternate channel.

## Observed Examples

CVE-2020-8004: When the internal flash is protected by blocking access on the Data Bus (DBUS), it can still be indirectly accessed through the Instruction Bus (IBUS).

CVE-2002-0567: DB server assumes that local clients have performed authentication, allowing attacker to directly connect to a process to load libraries and execute commands; a socket interface also exists (another alternate channel), so attack can be remote.

CVE-2002-1578: Product does not restrict access to underlying database, so attacker can bypass restrictions by directly querying the database.

CVE-2003-1035: User can avoid lockouts by using an API instead of the GUI to conduct brute force password guessing.

CVE-2002-1863: FTP service can not be disabled even when other access controls would require it.

CVE-2002-0066: Windows named pipe created without authentication/access control, allowing configuration modification.

CVE-2004-1461: Router management interface spawns a separate TCP connection after authentication, allowing hijacking by attacker coming from the same IP address.

## Top 25 Examples

CVE-2022-25786: Unprotected Alternate Channel vulnerability in debug console of GateManager allows system administrator to obtain sensitive information. This issue affects: GateManager all versions prior to 9.7.

# CWE-421 Race Condition During Access to Alternate Channel

## Description

The product opens an alternate channel to communicate with an authorized user, but the channel is accessible to other actors.

This creates a race condition that allows an attacker to access the channel before the authorized user does.

## Observed Examples

CVE-1999-0351: FTP "Pizza Thief" vulnerability. Attacker can connect to a port that was intended for use by another client.

CVE-2003-0230: Product creates Windows named pipe during authentication that another attacker can hijack by connecting to it.

# CWE-422 Unprotected Windows Messaging Channel ('Shatter')

## Description

The product does not properly verify the source of a message in the Windows Messaging System while running at elevated privileges, creating an alternate channel through which an attacker can directly send a message to the product.

## Observed Examples

CVE-2002-0971: Bypass GUI and access restricted dialog box.

CVE-2002-1230: Gain privileges via Windows message.

CVE-2003-0350: A control allows a change to a pointer for a callback function using Windows message.

CVE-2003-0908: Product launches Help functionality while running with raised privileges, allowing command execution using Windows message to access "open file" dialog.

CVE-2004-0213: Attacker uses Shatter attack to bypass GUI-enforced protection for CVE-2003-0908.

CVE-2004-0207: User can call certain API functions to modify certain properties of privileged programs.

# CWE-424 Improper Protection of Alternate Path

## Description

The product does not sufficiently protect all possible paths that a user can take to access restricted functionality or resources.

## Observed Examples

CVE-2022-29238: Access-control setting in web-based document collaboration tool is not properly implemented by the code, which prevents listing hidden directories but does not prevent direct requests to files in those directories.

## Top 25 Examples

CVE-2022-24932: Improper Protection of Alternate Path vulnerability in Setup wizard process prior to SMR Mar-2022 Release 1 allows physical attacker package installation before finishing Setup wizard.

# CWE-425 Direct Request ('Forced Browsing')

## Description

The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.

Web applications susceptible to direct request attacks often make the false assumption that such resources can only be reached through a given navigation path and so only apply authorization at certain points in the path.

## Observed Examples

CVE-2022-29238: Access-control setting in web-based document collaboration tool is not properly implemented by the code, which prevents listing hidden directories but does not prevent direct requests to files in those directories.

CVE-2022-23607: Python-based HTTP library did not scope cookies to a particular domain such that "supercookies" could be sent to any domain on redirect.

CVE-2004-2144: Bypass authentication via direct request.

CVE-2005-1892: Infinite loop or infoleak triggered by direct requests.

CVE-2004-2257: Bypass auth/auth via direct request.

CVE-2005-1688: Direct request leads to infoleak by error.

CVE-2005-1697: Direct request leads to infoleak by error.

CVE-2005-1698: Direct request leads to infoleak by error.

CVE-2005-1685: Authentication bypass via direct request.

CVE-2005-1827: Authentication bypass via direct request.

CVE-2005-1654: Authorization bypass using direct request.

CVE-2005-1668: Access privileged functionality using direct request.

CVE-2002-1798: Upload arbitrary files via direct request.

## Top 25 Examples

CVE-2021-26085: Affected versions of Atlassian Confluence Server allow remote attackers to view restricted resources via a Pre-Authorization Arbitrary File Read vulnerability in the /s/ endpoint. The affected versions are before version 7.4.10, and from version 7.5.0 before 7.12.3.

CVE-2022-36158: Contec FXA3200 version 1.13.00 and under suffers from Insecure Permissions in the Wireless LAN Manager interface which allows malicious actors to execute Linux commands with root privilege via a hidden web page (/usr/www/ja/mnt_cmd.cgi).

CVE-2022-40845: The Tenda AC1200 Router model W15Ev2 V15.11.0.10(1576) is affected by a password exposure vulnerability. When combined with the improper authorization/improper session management vulnerability, an attacker with access to the router may be able to expose sensitive information which they're not explicitly authorized to have.

CVE-2022-47700: COMFAST (Shenzhen Sihai Zhonglian Network Technology Co., Ltd) CF-WR623N Router firmware V2.3.0.1 and before is vulnerable to Incorrect Access Control. Improper authentication allows requests to be made to back-end scripts without a valid session or authentication.

CVE-2022-31480: An unauthenticated attacker could arbitrarily upload firmware files to the target device, ultimately causing a Denial-of-Service (DoS). This vulnerability impacts products based on HID Mercury Intelligent Controllers LP1501, LP1502, LP2500, LP4502, and EP4502 which contain firmware versions prior to 1.302 for the LP series and 1.296 for the EP series. The attacker needs to have a properly signed and encrypted binary, loading the firmware to the device ultimately triggers a reboot.

CVE-2022-1077: A vulnerability was found in TEM FLEX-1080 and FLEX-1085 1.6.0. It has been declared as problematic. This vulnerability log.cgi of the component Log Handler. A direct request leads to information disclosure of hardware information. The attack can be initiated remotely and does not require any form of authentication.

CVE-2022-42197: In Simple Exam Reviewer Management System v1.0 the User List function has improper access control that allows low privileged users to modify user permissions to higher privileges.

CVE-2021-42748: In Beaver Builder through 2.5.0.3, attackers can bypass the visibility controls protection mechanism via the REST API.

CVE-2022-26159: The auto-completion plugin in Ametys CMS before 4.5.0 allows a remote unauthenticated attacker to read documents such as plugins/web/service/search/auto-completion/<domain>/en.xml (and similar pathnames for other languages), which contain all characters typed by all users, including the content of private pages. For example, a private page may contain usernames, e-mail addresses, and possibly passwords.

CVE-2022-26653: Zoho ManageEngine Remote Access Plus before 10.1.2137.15 allows guest users to view domain details (such as the username and GUID of an administrator).

CVE-2022-26777: Zoho ManageEngine Remote Access Plus before 10.1.2137.15 allows guest users to view license details.

CVE-2022-28365: Reprise License Manager 14.2 is affected by an Information Disclosure vulnerability via a GET request to /goforms/rlminfo. No authentication is required. The information disclosed is associated with software versions, process IDs, network configuration, hostname(s), system architecture, and file/directory details.

CVE-2022-42953: Certain ZKTeco products (ZEM500-510-560-760, ZEM600-800, ZEM720, ZMM) allow access to sensitive information via direct requests for the form/DataApp?style=1 and form/DataApp?style=0 URLs. The affected versions may be before 8.88 (ZEM500-510-560-760, ZEM600-800, ZEM720) and 15.00 (ZMM200-220-210). The fixed versions are firmware version 8.88 (ZEM500-510-560-760, ZEM600-800, ZEM720) and firmware version 15.00 (ZMM200-220-210).

CVE-2022-42238: A Vertical Privilege Escalation issue in Merchandise Online Store v.1.0 allows an attacker to get access to the admin dashboard.

CVE-2022-42438: IBM Cloud Pak for Multicloud Management Monitoring 2.0 and 2.3 allows users without admin roles access to admin functions by specifying direct URL paths. IBM X-Force ID: 238210.

CVE-2022-28991: Multi Store Inventory Management System v1.0 was discovered to contain an information disclosure vulnerability which allows attackers to access sensitive files.

CVE-2022-31847: A vulnerability in /cgi-bin/ExportAllSettings.sh of WAVLINK WN579 X3 M79X3.V5030.180719 allows attackers to obtain sensitive router information via a crafted POST request.

CVE-2022-45276: An issue in the /index/user/user_edit.html component of YJCMS v1.0.9 allows unauthenticated attackers to obtain the Administrator account password.

CVE-2021-24831: All AJAX actions of the Tab WordPress plugin before 1.3.2 are available to both unauthenticated and authenticated users, allowing unauthenticated attackers to modify various data in the plugin, such as add/edit/delete arbitrary tabs.

CVE-2022-27480: A vulnerability has been identified in SICAM A8000 CP-8031 (All versions < V4.80), SICAM A8000 CP-8050 (All versions < V4.80). Affected devices do not require an user to be authenticated to access certain files. This could allow unauthenticated attackers to download these files.

CVE-2022-34572: An access control issue in Wavlink WiFi-Repeater RPTA2-77W.M4300.01.GD.2017Sep19 allows attackers to obtain the telnet password via accessing the page tftp.txt.

CVE-2022-34573: An access control issue in Wavlink WiFi-Repeater RPTA2-77W.M4300.01.GD.2017Sep19 allows attackers to arbitrarily configure device settings via accessing the page mb_wifibasic.shtml.

CVE-2022-34574: An access control issue in Wavlink WiFi-Repeater RPTA2-77W.M4300.01.GD.2017Sep19 allows attackers to obtain the key information of the device via accessing Tftpd32.ini.

CVE-2021-30144: The Dashboard plugin through 1.0.2 for GLPI allows remote low-privileged users to bypass access control on viewing information about the last ten events, the connected users, and the users in the tech category. For example, plugins/dashboard/front/main2.php can be used.

CVE-2022-26279: EyouCMS v1.5.5 was discovered to have no access control in the component /data/sqldata.

CVE-2022-34570: WAVLINK WN579 X3 M79X3.V5030.191012/M79X3.V5030.191012 contains an information leak which allows attackers to obtain the key information via accessing the messages.txt page.

CVE-2022-34571: An access control issue in Wavlink WiFi-Repeater RPTA2-77W.M4300.01.GD.2017Sep19 allows attackers to obtain the system key information and execute arbitrary commands via accessing the page syslog.shtml.

CVE-2021-40616: thinkcmf v5.1.7 has an unauthorized vulnerability. The attacker can modify the password of the administrator account with id 1 through the background user management group permissions. The use condition is that the background user management group authority is required.

CVE-2022-1551: The SP Project & Document Manager WordPress plugin before 4.58 uses an easily guessable path to store user files, bad actors could use that to access other users' sensitive files.

CVE-2022-4057: The Autoptimize WordPress plugin before 3.1.0 uses an easily guessable path to store plugin's exported settings and logs.

# CWE-426 Untrusted Search Path

## Description

The product searches for critical resources using an externally-supplied search path that can point to resources that are not under the product's direct control.

This might allow attackers to execute their own programs, access unauthorized data files, or modify configuration in unexpected ways. If the product uses a search path to locate critical resources such as programs, then an attacker could modify that search path to point to a malicious program, which the targeted product would then execute. The problem extends to any type of critical resource that the product trusts.


Some of the most common variants of untrusted search path are:


  - In various UNIX and Linux-based systems, the PATH environment variable may be consulted to locate executable programs, and LD_PRELOAD may be used to locate a separate library.

  - In various Microsoft-based systems, the PATH environment variable is consulted to locate a DLL, if the DLL is not found in other paths that appear earlier in the search order.

## Observed Examples

CVE-1999-1120: Application relies on its PATH environment variable to find and execute program.

CVE-2008-1810: Database application relies on its PATH environment variable to find and execute program.

CVE-2007-2027: Chain: untrusted search path enabling resultant format string by loading malicious internationalization messages.

CVE-2008-3485: Untrusted search path using malicious .EXE in Windows environment.

CVE-2008-2613: setuid program allows compromise using path that finds and loads a malicious library.

CVE-2008-1319: Server allows client to specify the search path, which can be modified to point to a program that the client has uploaded.

## Top 25 Examples

CVE-2022-22047: Windows Client Server Run-time Subsystem (CSRSS) Elevation of Privilege Vulnerability

CVE-2021-3305: Beijing Feishu Technology Co., Ltd Feishu v3.40.3 was discovered to contain an untrusted search path vulnerability.

CVE-2022-36403: Untrusted search path vulnerability in the installer of Device Software Manager prior to Ver.2.20.3.0 allows an attacker to gain privileges via a Trojan horse DLL in an unspecified directory.

CVE-2021-36666: An issue was discovered in Druva 6.9.0 for MacOS, allows attackers to gain escalated local privileges via the inSyncDecommission.

CVE-2022-38060: A privilege escalation vulnerability exists in the sudo functionality of OpenStack Kolla git master 05194e7618. A misconfiguration in /etc/sudoers within a container can lead to increased privileges.

CVE-2022-25366: Cryptomator through 1.6.5 allows DYLIB injection because, although it has the flag 0x1000 for Hardened Runtime, it has the com.apple.security.cs.disable-library-validation and com.apple.security.cs.allow-dyld-environment-variables entitlements. An attacker can exploit this by creating a malicious .dylib file that can be executed via the DYLD_INSERT_LIBRARIES environment variable.

CVE-2022-39245: Mist is the command-line interface for the makedeb Package Repository. Prior to version 0.9.5, a user-provided `sudo` binary via the `PATH` variable can allow a local user to run arbitrary commands on the user's system with root permissions. Versions 0.9.5 and later contain a patch. No known workarounds exist.

CVE-2021-21817: An information disclosure vulnerability exists in the Zebra IP Routing Manager functionality of D-LINK DIR-3040 1.13B03. A specially crafted network request can lead to the disclosure of sensitive information. An attacker can send a sequence of requests to trigger this vulnerability.

# CWE-427 Uncontrolled Search Path Element

## Description

The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.

Although this weakness can occur with any type of resource, it is frequently introduced when a product uses a directory search path to find executables or code libraries, but the path contains a directory that can be modified by an attacker, such as "/tmp" or the current working directory.


In Windows-based systems, when the LoadLibrary or LoadLibraryEx function is called with a DLL name that does not contain a fully qualified path, the function follows a search order that includes two path elements that might be uncontrolled:


  - the directory from which the program has been loaded

  - the current working directory

In some cases, the attack can be conducted remotely, such as when SMB or WebDAV network shares are used.

One or more locations in that path could include the Windows drive root or its subdirectories. This often exists in Linux-based code assuming the controlled nature of the root directory (/) or its subdirectories (/etc, etc), or a code that recursively accesses the parent directory. In Windows, the drive root and some of its subdirectories have weak permissions by default, which makes them uncontrolled.


In some Unix-based systems, a PATH might be created that contains an empty element, e.g. by splicing an empty variable into the PATH. This empty element can be interpreted as equivalent to the current working directory, which might be an untrusted search element.


In software package management frameworks (e.g., npm, RubyGems, or PyPi), the framework may identify dependencies on third-party libraries or other packages, then consult a repository that contains the desired package. The framework may search a public repository before a private repository. This could be exploited by attackers by placing a malicious package in the public repository that has the same name as a package from the private repository. The search path might not be directly under control of the developer relying on the framework, but this search order effectively contains an untrusted element.

## Observed Examples

CVE-2023-25815: chain: a change in an underlying package causes the gettext function to use implicit initialization with a hard-coded path (CWE-1419) under the user-writable C:\ drive, introducing an untrusted search path element (CWE-427) that enables spoofing of messages.

CVE-2022-4826: Go-based git extension on Windows can search for and execute a malicious "..exe" in a repository because Go searches the current working directory if git.exe is not found in the PATH

CVE-2020-26284: A Static Site Generator built in Go, when running on Windows, searches the current working directory for a command, possibly allowing code execution using a malicious .exe or .bat file with the name being searched

CVE-2022-24765: Windows-based fork of git creates a ".git" folder in the C: drive, allowing local attackers to create a .git folder with a malicious config file

CVE-2019-1552: SSL package searches under "C:/usr/local" for configuration files and other critical data, but C:/usr/local might be world-writable.

CVE-2010-3402: "DLL hijacking" issue in document editor.

CVE-2010-3397: "DLL hijacking" issue in encryption software.

CVE-2010-3138: "DLL hijacking" issue in library used by multiple media players.

CVE-2010-3152: "DLL hijacking" issue in illustration program.

CVE-2010-3147: "DLL hijacking" issue in address book.

CVE-2010-3135: "DLL hijacking" issue in network monitoring software.

CVE-2010-3131: "DLL hijacking" issue in web browser.

CVE-2010-1795: "DLL hijacking" issue in music player/organizer.

CVE-2002-1576: Product uses the current working directory to find and execute a program, which allows local users to gain privileges by creating a symlink that points to a malicious version of the program.

CVE-1999-1461: Product trusts the PATH environmental variable to find and execute a program, which allows local users to obtain root access by modifying the PATH to point to a malicous version of that program.

CVE-1999-1318: Software uses a search path that includes the current working directory (.), which allows local users to gain privileges via malicious programs.

CVE-2003-0579: Admin software trusts the user-supplied -uv.install command line option to find and execute the uv.install program, which allows local users to gain privileges by providing a pathname that is under control of the user.

CVE-2000-0854: When a document is opened, the directory of that document is first used to locate DLLs , which could allow an attacker to execute arbitrary commands by inserting malicious DLLs into the same directory as the document.

CVE-2001-0943: Database trusts the PATH environment variable to find and execute programs, which allows local users to modify the PATH to point to malicious programs.

CVE-2001-0942: Database uses an environment variable to find and execute a program, which allows local users to execute arbitrary programs by changing the environment variable.

CVE-2001-0507: Server uses relative paths to find system files that will run in-process, which allows local users to gain privileges via a malicious file.

CVE-2002-2017: Product allows local users to execute arbitrary code by setting an environment variable to reference a malicious program.

CVE-1999-0690: Product includes the current directory in root's PATH variable.

CVE-2001-0912: Error during packaging causes product to include a hard-coded, non-standard directory in search path.

CVE-2001-0289: Product searches current working directory for configuration file.

CVE-2005-1705: Product searches current working directory for configuration file.

CVE-2005-1307: Product executable other program from current working directory.

CVE-2002-2040: Untrusted path.

CVE-2005-2072: Modification of trusted environment variable leads to untrusted path vulnerability.

CVE-2005-1632: Product searches /tmp for modules before other paths.

## Top 25 Examples

CVE-2022-28965: Multiple DLL hijacking vulnerabilities via the components instup.exe and wsc_proxy.exe in Avast Premium Security before v21.11.2500 allows attackers to execute arbitrary code or cause a Denial of Service (DoS) via a crafted DLL file.

CVE-2022-1098: Delta Electronics DIAEnergie (all versions prior to 1.8.02.004) are vulnerable to a DLL hijacking condition. When combined with the Incorrect Default Permissions vulnerability of 4.2.2 above, this makes it possible for an attacker to escalate privileges

CVE-2022-23050: ManageEngine AppManager15 (Build No:15510) allows an authenticated admin user to upload a DLL file to perform a DLL hijack attack inside the 'working' folder through the 'Upload Files / Binaries' functionality.

CVE-2022-22736: If Firefox was installed to a world-writable directory, a local privilege escalation could occur when Firefox searched the current directory for system libraries. However the install directory is not world-writable by default.<br>*This bug only affects Firefox for Windows in a non-default installation. Other operating systems are unaffected.*. This vulnerability affects Firefox < 96.

CVE-2022-32222: A cryptographic vulnerability exists on Node.js on linux in versions of 18.x prior to 18.40.0 which allowed a default path for openssl.cnf that might be accessible under some circumstances to a non-admin user instead of /etc/ssl as was the case in versions prior to the upgrade to OpenSSL 3.

CVE-2021-36631: Untrusted search path vulnerability in Baidunetdisk Version 7.4.3 and earlier allows an attacker to gain privileges via a Trojan horse DLL in an unspecified directory.

CVE-2022-25348: Untrusted search path vulnerability in AttacheCase ver.4.0.2.7 and earlier allows an attacker to gain privileges and execute arbitrary code via a Trojan horse DLL in an unspecified directory.

CVE-2022-28128: Untrusted search path vulnerability in AttacheCase ver.3.6.1.0 and earlier allows an attacker to gain privileges and execute arbitrary code via a Trojan horse DLL in an unspecified directory.

CVE-2022-41796: Untrusted search path vulnerability in the installer of Content Transfer (for Windows) Ver.1.3 and prior allows an attacker to gain privileges via a Trojan horse DLL in an unspecified directory.

CVE-2022-48422: ONLYOFFICE Docs through 7.3 on certain Linux distributions allows local users to gain privileges via a Trojan horse libgcc_s.so.1 in the current working directory, which may be any directory in which an ONLYOFFICE document is located.

CVE-2022-0166: A privilege escalation vulnerability in the McAfee Agent prior to 5.7.5. McAfee Agent uses openssl.cnf during the build process to specify the OPENSSLDIR variable as a subdirectory within the installation directory. A low privilege user could have created subdirectories and executed arbitrary code with SYSTEM privileges by creating the appropriate pathway to the specifically created malicious openssl.cnf file.

CVE-2022-39286: Jupyter Core is a package for the core common functionality of Jupyter projects. Jupyter Core prior to version 4.11.2 contains an arbitrary code execution vulnerability in `jupyter_core` that stems from `jupyter_core` executing untrusted files in CWD. This vulnerability allows one user to run code as another. Version 4.11.2 contains a patch for this issue. There are no known workarounds.

CVE-2022-20001: fish is a command line shell. fish version 3.1.0 through version 3.3.1 is vulnerable to arbitrary code execution. git repositories can contain per-repository configuration that change the behavior of git, including running arbitrary commands. When using the default configuration of fish, changing to a directory automatically runs `git` commands in order to display information about the current repository in the prompt. If an attacker can convince a user to change their current directory into one controlled by the attacker, such as on a shared file system or extracted archive, fish will run arbitrary commands under the attacker's control. This problem has been fixed in fish 3.4.0. Note that running git in these directories, including using the git tab completion, remains a potential trigger for this issue. As a workaround, remove the `fish_git_prompt` function from the prompt.

CVE-2021-28953: The unofficial C/C++ Advanced Lint extension before 1.9.0 for Visual Studio Code allows attackers to execute arbitrary binaries if the user opens a crafted repository.

CVE-2022-23853: The LSP (Language Server Protocol) plugin in KDE Kate before 21.12.2 and KTextEditor before 5.91.0 tries to execute the associated LSP server binary when opening a file of a given type. If this binary is absent from the PATH, it will try running the LSP server binary in the directory of the file that was just opened (due to a misunderstanding of the QProcess API, that was never intended). This can be an untrusted directory.

CVE-2022-22528: SAP Adaptive Server Enterprise (ASE) - version 16.0, installation makes an entry in the system PATH environment variable in Windows platform which, under certain conditions, allows a Standard User to execute malicious Windows binaries which may lead to privilege escalation on the local system. The issue is with the ASE installer and does not impact other ASE binaries. 

# CWE-428 Unquoted Search Path or Element

## Description

The product uses a search path that contains an unquoted element, in which the element contains whitespace or other separators. This can cause the product to access resources in a parent path.

If a malicious individual has access to the file system, it is possible to elevate privileges by inserting such a file as "C:\Program.exe" to be run by a privileged program making use of WinExec.

## Observed Examples

CVE-2005-1185: Small handful of others. Program doesn't quote the "C:\Program Files\" path when calling a program to be executed - or any other path with a directory or file whose name contains a space - so attacker can put a malicious program.exe into C:.

CVE-2005-2938: CreateProcess() and CreateProcessAsUser() can be misused by applications to allow "program.exe" style attacks in C:

CVE-2000-1128: Applies to "Common Files" folder, with a malicious common.exe, instead of "Program Files"/program.exe.

## Top 25 Examples

CVE-2022-39959: Panini Everest Engine 2.0.4 allows unprivileged users to create a file named Everest.exe in the %PROGRAMDATA%\\Panini folder. This leads to privilege escalation because a service, running as SYSTEM, uses the unquoted path of %PROGRAMDATA%\\Panini\\Everest Engine\\EverestEngine.exe and therefore a Trojan horse %PROGRAMDATA%\\Panini\\Everest.exe may be executed instead of the intended vendor-supplied EverestEngine.exe file.

# CWE-43 Path Equivalence: 'filename....' (Multiple Trailing Dot)

## Description

The product accepts path input in the form of multiple trailing dot ('filedir....') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2004-0281: Multiple trailing dot allows directory listing

# CWE-430 Deployment of Wrong Handler

## Description

The wrong "handler" is assigned to process an object.

An example of deploying the wrong handler would be calling a servlet to reveal source code of a .JSP file, or automatically "determining" type of the object even if it is contradictory to an explicitly specified type.

## Observed Examples

CVE-2001-0004: Source code disclosure via manipulated file extension that causes parsing by wrong DLL.

CVE-2002-0025: Web browser does not properly handle the Content-Type header field, causing a different application to process the document.

CVE-2000-1052: Source code disclosure by directly invoking a servlet.

CVE-2002-1742: Arbitrary Perl functions can be loaded by calling a non-existent function that activates a handler.

# CWE-431 Missing Handler

## Description

A handler is not available or implemented.

When an exception is thrown and not caught, the process has given up an opportunity to decide if a given failure or event is worth a change in execution.

## Observed Examples

CVE-2022-25302: SDK for OPC Unified Architecture (OPC UA) is missing a handler for when a cast fails, allowing for a crash

## Top 25 Examples

CVE-2022-25302: All versions of package asneg/opcuastack are vulnerable to Denial of Service (DoS) due to a missing handler for failed casting when unvalidated data is forwarded to boost::get function in OpcUaNodeIdBase.h. Exploiting this vulnerability is possible when sending a specifically crafted OPC UA message with a special encoded NodeId.

# CWE-432 Dangerous Signal Handler not Disabled During Sensitive Operations

## Description

The product uses a signal handler that shares state with other signal handlers, but it does not properly mask or prevent those signal handlers from being invoked while the original signal handler is still running.

During the execution of a signal handler, it can be interrupted by another handler when a different signal is sent. If the two handlers share state - such as global variables - then an attacker can corrupt the state by sending another signal before the first handler has completed execution.

# CWE-433 Unparsed Raw Web Content Delivery

## Description

The product stores raw content or supporting code under the web document root with an extension that is not specifically handled by the server.

If code is stored in a file with an extension such as ".inc" or ".pl", and the web server does not have a handler for that extension, then the server will likely send the contents of the file directly to the requester without the pre-processing that was expected. When that file contains sensitive information such as database credentials, this may allow the attacker to compromise the application or associated components.

## Observed Examples

CVE-2002-1886: ".inc" file stored under web document root and returned unparsed by the server

CVE-2002-2065: ".inc" file stored under web document root and returned unparsed by the server

CVE-2005-2029: ".inc" file stored under web document root and returned unparsed by the server

CVE-2001-0330: direct request to .pl file leaves it unparsed

CVE-2002-0614: .inc file

CVE-2004-2353: unparsed config.conf file

CVE-2007-3365: Chain: uppercase file extensions causes web server to return script source code instead of executing the script.

# CWE-434 Unrestricted Upload of File with Dangerous Type

## Description

The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.

## Observed Examples

CVE-2023-5227: PHP-based FAQ management app does not check the MIME type for uploaded images

CVE-2001-0901: Web-based mail product stores ".shtml" attachments that could contain SSI

CVE-2002-1841: PHP upload does not restrict file types

CVE-2005-1868: upload and execution of .php file

CVE-2005-1881: upload file with dangerous extension

CVE-2005-0254: program does not restrict file types

CVE-2004-2262: improper type checking of uploaded files

CVE-2006-4558: Double "php" extension leaves an active php extension in the generated filename.

CVE-2006-6994: ASP program allows upload of .asp files by bypassing client-side checks

CVE-2005-3288: ASP file upload

CVE-2006-2428: ASP file upload

## Top 25 Examples

CVE-2022-1045: Stored XSS viva .svg file upload in GitHub repository polonel/trudesk prior to v1.2.0.

CVE-2022-1345: Stored XSS viva .svg file upload in GitHub repository causefx/organizr prior to 2.1.1810. This allows attackers to execute malicious scripts in the user's browser and it can lead to session hijacking, sensitive data exposure, and worse.

CVE-2022-24688: An issue was discovered in DSK DSKNet 2.16.136.0 and 2.17.136.5. The Touch settings allow unrestricted file upload (and consequently Remote Code Execution) via PDF upload with PHP content and a .php extension. The attacker must hijack or obtain privileged user access to the Parameters page in order to exploit this issue. (That can be easily achieved by exploiting the Broken Access Control with further Brute-force attack or SQL Injection.) The uploaded file is stored within the database and copied to the sync web folder if the attacker visits a certain .php?action= page.

CVE-2022-25581: Classcms v2.5 and below contains an arbitrary file upload via the component \\class\\classupload. This vulnerability allows attackers to execute code injection via a crafted .txt file.

CVE-2022-39301: sra-admin is a background rights management system that separates the front and back end. sra-admin version 1.1.1 has a storage cross-site scripting (XSS) vulnerability. After logging into the sra-admin background, an attacker can upload an html page containing xss attack code in "Personal Center" - "Profile Picture Upload" allowing theft of the user's personal information. This issue has been patched in 1.1.2. There are no known workarounds.

CVE-2022-41681: There is a vulnerability on Forma LMS version 3.1.0 and earlier that could allow an authenticated attacker (with the role of student) to privilege escalate in order to upload a Zip file through the SCORM importer feature. The exploitation of this vulnerability could lead to a remote code injection.

CVE-2022-42925: There is a vulnerability on Forma LMS version 3.1.0 and earlier that could allow an authenticated attacker (with the role of student) to privilege escalate in order to upload a Zip file through the plugin upload component. The exploitation of this vulnerability could lead to a remote code injection.

CVE-2022-0959: A malicious, but authorised and authenticated user can construct an HTTP request using their existing CSRF token and session cookie to manually upload files to any location that the operating system user account under which pgAdmin is running has permission to write.

CVE-2022-2180: The GREYD.SUITE WordPress theme does not properly validate uploaded custom font packages, and does not perform any authorization or csrf checks, allowing an unauthenticated attacker to upload arbitrary files including php source files, leading to possible remote code execution (RCE).

CVE-2021-20022: SonicWall Email Security version 10.0.9.x contains a vulnerability that allows a post-authenticated attacker to upload an arbitrary file to the remote host.

CVE-2021-22968: A bypass of adding remote files in Concrete CMS (previously concrete5) File Manager leads to remote code execution in Concrete CMS (concrete5) versions 8.5.6 and below.The external file upload feature stages files in the public directory even if they have disallowed file extensions. They are stored in a directory with a random name, but it's possible to stall the uploads and brute force the directory name. You have to be an admin with the ability to upload files, but this bug gives you the ability to upload restricted file types and execute them depending on server configuration.To fix this, a check for allowed file extensions was added before downloading files to a tmp directory.Concrete CMS Security Team gave this a CVSS v3.1 score of 5.4 AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:H/A:NThis fix is also in Concrete version 9.0.0

CVE-2022-1811: Unrestricted Upload of File with Dangerous Type in GitHub repository publify/publify prior to 9.2.9.

CVE-2022-0950: Unrestricted Upload of File with Dangerous Type in GitHub repository star7th/showdoc prior to 2.10.4.

CVE-2022-3458: A vulnerability has been found in SourceCodester Human Resource Management System 1.0 and classified as critical. Affected by this vulnerability is an unknown functionality of the file /employeeview.php of the component Image File Handler. The manipulation leads to unrestricted upload. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-210559.

CVE-2022-3770: A vulnerability classified as critical was found in Yunjing CMS. This vulnerability affects unknown code of the file /index/user/upload_img.html. The manipulation of the argument file leads to unrestricted upload. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-212500.

# CWE-435 Improper Interaction Between Multiple Correctly-Behaving Entities

## Description

An interaction error occurs when two entities have correct behavior when running independently of each other, but when they are integrated as components in a larger system or process, they introduce incorrect behaviors that may cause resultant weaknesses.

When a system or process combines multiple independent components, this often produces new, emergent behaviors at the system level. However, if the interactions between these components are not fully accounted for, some of the emergent behaviors can be incorrect or even insecure.

## Observed Examples

CVE-2002-0485: Anti-virus product allows bypass via Content-Type and Content-Disposition headers that are mixed case, which are still processed by some clients.

CVE-2003-0411: chain: Code was ported from a case-sensitive Unix platform to a case-insensitive Windows platform where filetype handlers treat .jsp and .JSP as different extensions. JSP source code may be read because .JSP defaults to the filetype "text".

# CWE-436 Interpretation Conflict

## Description

Product A handles inputs or steps differently than Product B, which causes A to perform incorrect actions based on its perception of B's state.

This is generally found in proxies, firewalls, anti-virus software, and other intermediary devices that monitor, allow, deny, or modify traffic based on how the client or server is expected to behave.

## Observed Examples

CVE-2005-1215: Bypass filters or poison web cache using requests with multiple Content-Length headers, a non-standard behavior.

CVE-2002-0485: Anti-virus product allows bypass via Content-Type and Content-Disposition headers that are mixed case, which are still processed by some clients.

CVE-2002-1978: FTP clients sending a command with "PASV" in the argument can cause firewalls to misinterpret the server's error as a valid response, allowing filter bypass.

CVE-2002-1979: FTP clients sending a command with "PASV" in the argument can cause firewalls to misinterpret the server's error as a valid response, allowing filter bypass.

CVE-2002-0637: Virus product bypass with spaces between MIME header fields and the ":" separator, a non-standard message that is accepted by some clients.

CVE-2002-1777: AV product detection bypass using inconsistency manipulation (file extension in MIME Content-Type vs. Content-Disposition field).

CVE-2005-3310: CMS system allows uploads of files with GIF/JPG extensions, but if they contain HTML, Internet Explorer renders them as HTML instead of images.

CVE-2005-4260: Interpretation conflict allows XSS via invalid "<" when a ">" is expected, which is treated as ">" by many web browsers.

CVE-2005-4080: Interpretation conflict (non-standard behavior) enables XSS because browser ignores invalid characters in the middle of tags.

## Top 25 Examples

CVE-2022-48279: In ModSecurity before 2.9.6 and 3.x before 3.0.8, HTTP multipart requests were incorrectly parsed and could bypass the Web Application Firewall. NOTE: this is related to CVE-2022-39956 but can be considered independent changes to the ModSecurity (C language) codebase.

# CWE-437 Incomplete Model of Endpoint Features

## Description

A product acts as an intermediary or monitor between two or more endpoints, but it does not have a complete model of an endpoint's features, behaviors, or state, potentially causing the product to perform incorrect actions based on this incomplete model.

# CWE-439 Behavioral Change in New Version or Environment

## Description

A's behavior or functionality changes with a new version of A, or a new environment, which is not known (or manageable) by B.

## Observed Examples

CVE-2002-1976: Linux kernel 2.2 and above allow promiscuous mode using a different method than previous versions, and ifconfig is not aware of the new method (alternate path property).

CVE-2005-1711: Product uses defunct method from another product that does not return an error code and allows detection avoidance.

CVE-2003-0411: chain: Code was ported from a case-sensitive Unix platform to a case-insensitive Windows platform where filetype handlers treat .jsp and .JSP as different extensions. JSP source code may be read because .JSP defaults to the filetype "text".

# CWE-44 Path Equivalence: 'file.name' (Internal Dot)

## Description

The product accepts path input in the form of internal dot ('file.ordir') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

# CWE-440 Expected Behavior Violation

## Description

A feature, API, or function does not perform according to its specification.

## Observed Examples

CVE-2003-0187: Program uses large timeouts on unconfirmed connections resulting from inconsistency in linked lists implementations.

CVE-2003-0465: "strncpy" in Linux kernel acts different than libc on x86, leading to expected behavior difference - sort of a multiple interpretation error?

CVE-2005-3265: Buffer overflow in product stems the use of a third party library function that is expected to have internal protection against overflows, but doesn't.

# CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

## Description

The product receives a request, message, or directive from an upstream component, but the product does not sufficiently preserve the original source of the request before forwarding the request to an external actor that is outside of the product's control sphere. This causes the product to appear to be the source of the request, leading it to act as a proxy or other intermediary between the upstream component and the external actor.

If an attacker cannot directly contact a target, but the product has access to the target, then the attacker can send a request to the product and have it be forwarded to the target. The request would appear to be coming from the product's system, not the attacker's system. As a result, the attacker can bypass access controls (such as firewalls) or hide the source of malicious requests, since the requests would not be coming directly from the attacker.


Since proxy functionality and message-forwarding often serve a legitimate purpose, this issue only becomes a vulnerability when:


  - The product runs with different privileges or on a different system, or otherwise has different levels of access than the upstream component;

  - The attacker is prevented from making the request directly to the target; and

  - The attacker can create a request that the proxy does not explicitly intend to be forwarded on the behalf of the requester. Such a request might point to an unexpected hostname, port number, hardware IP, or service. Or, the request might be sent to an allowed service, but the request could contain disallowed directives, commands, or resources.

## Observed Examples

CVE-1999-0017: FTP bounce attack. The design of the protocol allows an attacker to modify the PORT command to cause the FTP server to connect to other machines besides the attacker's.

CVE-1999-0168: RPC portmapper could redirect service requests from an attacker to another entity, which thinks the requests came from the portmapper.

CVE-2005-0315: FTP server does not ensure that the IP address in a PORT command is the same as the FTP user's session, allowing port scanning by proxy.

CVE-2002-1484: Web server allows attackers to request a URL from another server, including other ports, which allows proxied scanning.

CVE-2004-2061: CGI script accepts and retrieves incoming URLs.

CVE-2001-1484: Bounce attack allows access to TFTP from trusted side.

CVE-2010-1637: Web-based mail program allows internal network scanning using a modified POP3 port number.

CVE-2009-0037: URL-downloading library automatically follows redirects to file:// and scp:// URLs

## Top 25 Examples

CVE-2022-36537: ZK Framework v9.6.1, 9.6.0.1, 9.5.1.3, 9.0.1.2 and 8.6.4.1 allows attackers to access sensitive information via a crafted POST request sent to the component AuUploader.

CVE-2021-20042: An unauthenticated remote attacker can use SMA 100 as an unintended proxy or intermediary undetectable proxy to bypass firewall rules. This vulnerability affected SMA 200, 210, 400, 410 and 500v appliances.

CVE-2021-36190: A unintended proxy or intermediary ('confused deputy') in Fortinet FortiWeb version 6.4.1 and below, 6.3.15 and below allows an unauthenticated attacker to access protected hosts via crafted HTTP requests.

# CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')

## Description

The product acts as an intermediary HTTP agent
         (such as a proxy or firewall) in the data flow between two
         entities such as a client and server, but it does not
         interpret malformed HTTP requests or responses in ways that
         are consistent with how the messages will be processed by
         those entities that are at the ultimate destination.

HTTP requests or responses ("messages") can be malformed or unexpected in ways that cause web servers or clients to interpret the messages in different ways than intermediary HTTP agents such as load balancers, reverse proxies, web caching proxies, application firewalls, etc. For example, an adversary may be able to add duplicate or different header fields that a client or server might interpret as one set of messages, whereas the intermediary might interpret the same sequence of bytes as a different set of messages. For example, discrepancies can arise in how to handle duplicate headers like two Transfer-encoding (TE) or two Content-length (CL), or the malicious HTTP message will have different headers for TE and CL.


The inconsistent parsing and interpretation of messages can allow the adversary to "smuggle" a message to the client/server without the intermediary being aware of it.


This weakness is usually the result of the usage of outdated or incompatible HTTP protocol versions in the HTTP agents.

## Observed Examples

CVE-2022-24766: SSL/TLS-capable proxy allows HTTP smuggling when used in tandem with HTTP/1.0 services, due to inconsistent interpretation and input sanitization of HTTP messages within the body of another message

CVE-2021-37147: Chain: caching proxy server has improper input validation (CWE-20) of headers, allowing HTTP response smuggling (CWE-444) using an "LF line ending"

CVE-2020-8287: Node.js platform allows request smuggling via two Transfer-Encoding headers

CVE-2006-6276: Web servers allow request smuggling via inconsistent HTTP headers.

CVE-2005-2088: HTTP server allows request smuggling with both a "Transfer-Encoding: chunked" header and a Content-Length header

CVE-2005-2089: HTTP server allows request smuggling with both a "Transfer-Encoding: chunked" header and a Content-Length header

## Top 25 Examples

CVE-2021-21445: SAP Commerce Cloud, versions - 1808, 1811, 1905, 2005, 2011, allows an authenticated attacker to include invalidated data in the HTTP response Content Type header, due to improper input validation, and sent to a Web user. A successful exploitation of this vulnerability may lead to advanced attacks, including cross-site scripting and page hijacking.

CVE-2022-21826: Pulse Secure version 9.115 and below may be susceptible to client-side http request smuggling, When the application receives a POST request, it ignores the request's Content-Length header and leaves the POST body on the TCP/TLS socket. This body ends up prefixing the next HTTP request sent down that connection, this means when someone loads website attacker may be able to make browser issue a POST to the application, enabling XSS.

CVE-2022-38114: This vulnerability occurs when a web server fails to correctly process the Content-Length of POST requests. This can lead to HTTP request smuggling or XSS. 

CVE-2022-22536: SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server 7.53 and SAP Web Dispatcher are vulnerable for request smuggling and request concatenation. An unauthenticated attacker can prepend a victim's request with arbitrary data. This way, the attacker can execute functions impersonating the victim or poison intermediary Web caches. A successful attack could result in complete compromise of Confidentiality, Integrity and Availability of the system. 

CVE-2021-46825: Symantec Advanced Secure Gateway (ASG) and ProxySG are susceptible to an HTTP desync vulnerability. When a remote unauthenticated attacker and other web clients communicate through the proxy with the same web server, the attacker can send crafted HTTP requests and cause the proxy to forward web server responses to unintended clients. Severity/CVSSv3: High / 8.1 AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

CVE-2022-2466: It was found that Quarkus 2.10.x does not terminate HTTP requests header context which may lead to unpredictable behavior.

# CWE-446 UI Discrepancy for Security Feature

## Description

The user interface does not correctly enable or configure a security feature, but the interface provides feedback that causes the user to believe that the feature is in a secure state.

When the user interface does not properly reflect what the user asks of it, then it can lead the user into a false sense of security. For example, the user might check a box to enable a security option to enable encrypted communications, but the product does not actually enable the encryption. Alternately, the user might provide a "restrict ALL" access control rule, but the product only implements "restrict SOME".

## Observed Examples

CVE-1999-1446: UI inconsistency; visited URLs list not cleared when "Clear History" option is selected.

# CWE-447 Unimplemented or Unsupported Feature in UI

## Description

A UI function for a security feature appears to be supported and gives feedback to the user that suggests that it is supported, but the underlying functionality is not implemented.

## Observed Examples

CVE-2000-0127: GUI configuration tool does not enable a security option when a checkbox is selected, although that option is honored when manually set in the configuration file.

CVE-2001-0863: Router does not implement a specific keyword when it is used in an ACL, allowing filter bypass.

CVE-2001-0865: Router does not implement a specific keyword when it is used in an ACL, allowing filter bypass.

CVE-2004-0979: Web browser does not properly modify security setting when the user sets it.

# CWE-448 Obsolete Feature in UI

## Description

A UI function is obsolete and the product does not warn the user.

# CWE-449 The UI Performs the Wrong Action

## Description

The UI performs the wrong action with respect to the user's request.

## Observed Examples

CVE-2001-1387: Network firewall accidentally implements one command line option as if it were another, possibly leading to behavioral infoleak.

CVE-2001-0081: Command line option correctly suppresses a user prompt but does not properly disable a feature, although when the product prompts the user, the feature is properly disabled.

CVE-2002-1977: Product does not "time out" according to user specification, leaving sensitive data available after it has expired.

# CWE-45 Path Equivalence: 'file...name' (Multiple Internal Dot)

## Description

The product accepts path input in the form of multiple internal dot ('file...dir') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

# CWE-450 Multiple Interpretations of UI Input

## Description

The UI has multiple interpretations of user input but does not prompt the user when it selects the less secure interpretation.

# CWE-451 User Interface (UI) Misrepresentation of Critical Information

## Description

The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed. This is often a component in phishing attacks.

If an attacker can cause the UI to display erroneous data, or to otherwise convince the user to display information that appears to come from a trusted source, then the attacker could trick the user into performing the wrong action. This is often a component in phishing attacks, but other kinds of problems exist. For example, if the UI is used to monitor the security state of a system or network, then omitting or obscuring an important indicator could prevent the user from detecting and reacting to a security-critical event.


UI misrepresentation can take many forms:


  - Incorrect indicator: incorrect information is displayed, which prevents the user from understanding the true state of the product or the environment the product is monitoring, especially of potentially-dangerous conditions or operations. This can be broken down into several different subtypes.

  - Overlay: an area of the display is intended to give critical information, but another process can modify the display by overlaying another element on top of it. The user is not interacting with the expected portion of the user interface. This is the problem that enables clickjacking attacks, although many other types of attacks exist that involve overlay.

  - Icon manipulation: the wrong icon, or the wrong color indicator, can be influenced (such as making a dangerous .EXE executable look like a harmless .GIF)

  - Timing: the product is performing a state transition or context switch that is presented to the user with an indicator, but a race condition can cause the wrong indicator to be used before the product has fully switched context. The race window could be extended indefinitely if the attacker can trigger an error.

  - Visual truncation: important information could be truncated from the display, such as a long filename with a dangerous extension that is not displayed in the GUI because the malicious portion is truncated. The use of excessive whitespace can also cause truncation, or place the potentially-dangerous indicator outside of the user's field of view (e.g. "filename.txt .exe"). A different type of truncation can occur when a portion of the information is removed due to reasons other than length, such as the accidental insertion of an end-of-input marker in the middle of an input, such as a NUL byte in a C-style string.

  - Visual distinction: visual information might be presented in a way that makes it difficult for the user to quickly and correctly distinguish between critical and unimportant segments of the display.

  - Homographs: letters from different character sets, fonts, or languages can appear very similar (i.e. may be visually equivalent) in a way that causes the human user to misread the text (for example, to conduct phishing attacks to trick a user into visiting a malicious web site with a visually-similar name as a trusted site). This can be regarded as a type of visual distinction issue.

## Observed Examples

CVE-2004-2227: Web browser's filename selection dialog only shows the beginning portion of long filenames, which can trick users into launching executables with dangerous extensions.

CVE-2001-0398: Attachment with many spaces in filename bypasses "dangerous content" warning and uses different icon. Likely resultant.

CVE-2001-0643: Misrepresentation and equivalence issue.

CVE-2005-0593: Lock spoofing from several different weaknesses.

CVE-2004-1104: Incorrect indicator: web browser can be tricked into presenting the wrong URL

CVE-2005-0143: Incorrect indicator: Lock icon displayed when an insecure page loads a binary file loaded from a trusted site.

CVE-2005-0144: Incorrect indicator: Secure "lock" icon is presented for one channel, while an insecure page is being simultaneously loaded in another channel.

CVE-2004-0761: Incorrect indicator: Certain redirect sequences cause security lock icon to appear in web browser, even when page is not encrypted.

CVE-2004-2219: Incorrect indicator: Spoofing via multi-step attack that causes incorrect information to be displayed in browser address bar.

CVE-2004-0537: Overlay: Wide "favorites" icon can overlay and obscure address bar

CVE-2005-2271: Visual distinction: Web browsers do not clearly associate a Javascript dialog box with the web page that generated it, allowing spoof of the source of the dialog. "origin validation error" of a sort?

CVE-2005-2272: Visual distinction: Web browsers do not clearly associate a Javascript dialog box with the web page that generated it, allowing spoof of the source of the dialog. "origin validation error" of a sort?

CVE-2005-2273: Visual distinction: Web browsers do not clearly associate a Javascript dialog box with the web page that generated it, allowing spoof of the source of the dialog. "origin validation error" of a sort?

CVE-2005-2274: Visual distinction: Web browsers do not clearly associate a Javascript dialog box with the web page that generated it, allowing spoof of the source of the dialog. "origin validation error" of a sort?

CVE-2001-1410: Visual distinction: Browser allows attackers to create chromeless windows and spoof victim's display using unprotected Javascript method.

CVE-2002-0197: Visual distinction: Chat client allows remote attackers to spoof encrypted, trusted messages with lines that begin with a special sequence, which makes the message appear legitimate.

CVE-2005-0831: Visual distinction: Product allows spoofing names of other users by registering with a username containing hex-encoded characters.

CVE-2003-1025: Visual truncation: Special character in URL causes web browser to truncate the user portion of the "user@domain" URL, hiding real domain in the address bar.

CVE-2005-0243: Visual truncation: Chat client does not display long filenames in file dialog boxes, allowing dangerous extensions via manipulations including (1) many spaces and (2) multiple file extensions.

CVE-2005-1575: Visual truncation: Web browser file download type can be hidden using whitespace.

CVE-2004-2530: Visual truncation: Visual truncation in chat client using whitespace to hide dangerous file extension.

CVE-2005-0590: Visual truncation: Dialog box in web browser allows user to spoof the hostname via a long "user:pass" sequence in the URL, which appears before the real hostname.

CVE-2004-1451: Visual truncation: Null character in URL prevents entire URL from being displayed in web browser.

CVE-2004-2258: Miscellaneous -- [step-based attack, GUI] -- Password-protected tab can be bypassed by switching to another tab, then back to original tab.

CVE-2005-1678: Miscellaneous -- Dangerous file extensions not displayed.

CVE-2002-0722: Miscellaneous -- Web browser allows remote attackers to misrepresent the source of a file in the File Download dialog box.

## Top 25 Examples

CVE-2022-1520: When viewing an email message A, which contains an attached message B, where B is encrypted or digitally signed or both, Thunderbird may show an incorrect encryption or signature status. After opening and viewing the attached message B, when returning to the display of message A, the message A might be shown with the security status of message B. This vulnerability affects Thunderbird < 91.9.

CVE-2021-0369: In CrossProfileAppsServiceImpl.java, there is the possibility of an application's INTERACT_ACROSS_PROFILES grant state not displaying properly in the setting UI due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-11Android ID: A-166561076

CVE-2021-39631: In clear_data_dlg_text of strings.xml, there is a possible situation when "Clear storage" functionality sets up the wrong security/privacy expectations due to a misleading message. This could lead to local information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12Android ID: A-193890833

CVE-2022-1111: A business logic error in Project Import in GitLab CE/EE versions 14.9 prior to 14.9.2, 14.8 prior to 14.8.5, and 14.0 prior to 14.7.7 under certain conditions caused imported projects to show an incorrect user in the 'Access Granted' column in the project membership pages

CVE-2022-22654: A user interface issue was addressed. This issue is fixed in watchOS 8.5, Safari 15.4. Visiting a malicious website may lead to address bar spoofing.

CVE-2022-22660: This issue was addressed with a new entitlement. This issue is fixed in macOS Monterey 12.3. An app may be able to spoof system notifications and UI.

CVE-2022-3660: Inappropriate implementation in Full screen mode in Google Chrome on Android prior to 107.0.5304.62 allowed a remote attacker to hide the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security severity: Medium)

# CWE-453 Insecure Default Variable Initialization

## Description

The product, by default, initializes an internal variable with an insecure or less secure value than is possible.

## Observed Examples

CVE-2022-36349: insecure default variable initialization in BIOS firmware for a hardware board allows DoS

## Top 25 Examples

CVE-2022-47194: An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `twitter` field for a user.

CVE-2022-47196: An insecure default vulnerability exists in the Post Creation functionality of Ghost Foundation Ghost 5.9.4. Default installations of Ghost allow non-administrator users to inject arbitrary Javascript in posts, which allow privilege escalation to administrator via XSS. To trigger this vulnerability, an attacker can send an HTTP request to inject Javascript in a post to trick an administrator into visiting the post.A stored XSS vulnerability exists in the `codeinjection_head` for a post.

CVE-2022-46831: In JetBrains TeamCity between 2022.10 and 2022.10.1 connecting to AWS using the "Default Credential Provider Chain" allowed TeamCity project administrators to access AWS resources normally limited to TeamCity system administrators.

CVE-2022-36349: Insecure default variable initialization in BIOS firmware for some Intel(R) NUC Boards and Intel(R) NUC Kits before version MYi30060 may allow an authenticated user to potentially enable denial of service via local access.

CVE-2022-4224: In multiple products of CODESYS v3 in multiple versions a remote low privileged user could utilize this vulnerability to read and modify system files and OS resources or DoS the device.

# CWE-454 External Initialization of Trusted Variables or Data Stores

## Description

The product initializes critical internal variables or data stores using inputs that can be modified by untrusted actors.

A product system should be reluctant to trust variables that have been initialized outside of its trust boundary, especially if they are initialized by users. The variables may have been initialized incorrectly. If an attacker can initialize the variable, then they can influence what the vulnerable system will do.

## Observed Examples

CVE-2022-43468: WordPress module sets internal variables based on external inputs, allowing false reporting of the number of views

CVE-2000-0959: Does not clear dangerous environment variables, enabling symlink attack.

CVE-2001-0033: Specify alternate configuration directory in environment variable, enabling untrusted path.

CVE-2001-0872: Dangerous environment variable not cleansed.

CVE-2001-0084: Specify arbitrary modules using environment variable.

## Top 25 Examples

CVE-2022-43468: External initialization of trusted variables or data stores vulnerability exists in WordPress Popular Posts 6.0.5 and earlier, therefore the vulnerable product accepts untrusted external inputs to update certain internal variables. As a result, the number of views for an article may be manipulated through a crafted input.

# CWE-455 Non-exit on Failed Initialization

## Description

The product does not exit or otherwise modify its operation when security-relevant errors occur during initialization, such as when a configuration file has a format error or a hardware security module (HSM) cannot be activated, which can cause the product to execute in a less secure fashion than intended by the administrator.

## Observed Examples

CVE-2005-1345: Product does not trigger a fatal error if missing or invalid ACLs are in a configuration file.

# CWE-456 Missing Initialization of a Variable

## Description

The product does not initialize critical variables, which causes the execution environment to use unexpected values.

## Observed Examples

CVE-2020-6078: Chain: The return value of a function returning a pointer is not checked for success (CWE-252) resulting in the later use of an uninitialized variable (CWE-456) and a null pointer dereference (CWE-476)

CVE-2009-2692: Chain: Use of an unimplemented network socket operation pointing to an uninitialized handler function (CWE-456) causes a crash because of a null pointer dereference (CWE-476).

CVE-2020-20739: A variable that has its value set in a conditional statement is sometimes used when the conditional fails, sometimes causing data leakage

CVE-2005-2978: Product uses uninitialized variables for size and index, leading to resultant buffer overflow.

CVE-2005-2109: Internal variable in PHP application is not initialized, allowing external modification.

CVE-2005-2193: Array variable not initialized in PHP application, leading to resultant SQL injection.

## Top 25 Examples

CVE-2021-22482: There is an Uninitialized variable vulnerability in Huawei Smartphone.Successful exploitation of this vulnerability may cause transmission of invalid data.

CVE-2022-22704: The zabbix-agent2 package before 5.4.9-r1 for Alpine Linux sometimes allows privilege escalation to root because the design incorrectly expected that systemd would (in effect) determine part of the configuration.

# CWE-457 Use of Uninitialized Variable

## Description

The code uses a variable that has not been initialized, leading to unpredictable or unintended results.

In some languages such as C and C++, stack variables are not initialized by default. They generally contain junk data with the contents of stack memory before the function was invoked. An attacker can sometimes control or read these contents. In other languages or conditions, a variable that is not explicitly initialized can be given a default value that has security implications, depending on the logic of the program. The presence of an uninitialized variable can sometimes indicate a typographic error in the code.

## Observed Examples

CVE-2019-15900: Chain: sscanf() call is used to check if a username and group exists, but the return value of sscanf() call is not checked (CWE-252), causing an uninitialized variable to be checked (CWE-457), returning success to allow authorization bypass for executing a privileged (CWE-863).

CVE-2008-3688: Chain: A denial of service may be caused by an uninitialized variable (CWE-457) allowing an infinite loop (CWE-835) resulting from a connection to an unresponsive server.

CVE-2008-0081: Uninitialized variable leads to code execution in popular desktop application.

CVE-2007-4682: Crafted input triggers dereference of an uninitialized object pointer.

CVE-2007-3468: Crafted audio file triggers crash when an uninitialized variable is used.

CVE-2007-2728: Uninitialized random seed variable used.

## Top 25 Examples

CVE-2022-31741: A crafted CMS message could have been processed incorrectly, leading to an invalid memory read, and potentially further memory corruption. This vulnerability affects Thunderbird < 91.10, Firefox < 101, and Firefox ESR < 91.10.

CVE-2021-35991: Adobe Bridge version 11.0.2 (and earlier) is affected by an Access of Uninitialized Pointer vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to disclose arbitrary memory information in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2021-36007: Adobe Prelude version 10.0 (and earlier) are affected by an uninitialized variable vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to disclose arbitrary memory information in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

CVE-2022-28488: The function wav_format_write in libwav.c in libwav through 2017-04-20 has an Use of Uninitialized Variable vulnerability.

CVE-2022-31026: Trilogy is a client library for MySQL. When authenticating, a malicious server could return a specially crafted authentication packet, causing the client to read and return up to 12 bytes of data from an uninitialized variable in stack memory. Users of the trilogy gem should upgrade to version 2.1.1 This issue can be avoided by only connecting to trusted servers.

CVE-2022-34390: Dell BIOS contains a use of uninitialized variable vulnerability. A local authenticated malicious user may potentially exploit this vulnerability by using an SMI to gain arbitrary code execution in SMRAM.

CVE-2022-47012: Use of uninitialized variable in function gen_eth_recv in GNS3 dynamips 0.2.21.

CVE-2022-40768: drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.

# CWE-459 Incomplete Cleanup

## Description

The product does not properly "clean up" and remove temporary or supporting resources after they have been used.

## Observed Examples

CVE-2000-0552: World-readable temporary file not deleted after use.

CVE-2005-2293: Temporary file not deleted after use, leaking database usernames and passwords.

CVE-2002-0788: Interaction error creates a temporary file that can not be deleted due to strong permissions.

CVE-2002-2066: Alternate data streams for NTFS files are not cleared when files are wiped (alternate channel / infoleak).

CVE-2002-2067: Alternate data streams for NTFS files are not cleared when files are wiped (alternate channel / infoleak).

CVE-2002-2068: Alternate data streams for NTFS files are not cleared when files are wiped (alternate channel / infoleak).

CVE-2002-2069: Alternate data streams for NTFS files are not cleared when files are wiped (alternate channel / infoleak).

CVE-2002-2070: Alternate data streams for NTFS files are not cleared when files are wiped (alternate channel / infoleak).

CVE-2005-1744: Users not logged out when application is restarted after security-relevant changes were made.

## Top 25 Examples

CVE-2022-23035: Insufficient cleanup of passed-through device IRQs The management of IRQs associated with physical devices exposed to x86 HVM guests involves an iterative operation in particular when cleaning up after the guest's use of the device. In the case where an interrupt is not quiescent yet at the time this cleanup gets invoked, the cleanup attempt may be scheduled to be retried. When multiple interrupts are involved, this scheduling of a retry may get erroneously skipped. At the same time pointers may get cleared (resulting in a de-reference of NULL) and freed (resulting in a use-after-free), while other code would continue to assume them to be valid.

CVE-2022-1473: The OPENSSL_LH_flush() function, which empties a hash table, contains a bug that breaks reuse of the memory occuppied by the removed hash table entries. This function is used when decoding certificates or keys. If a long lived process periodically decodes certificates or keys its memory usage will expand without bounds and the process might be terminated by the operating system causing a denial of service. Also traversing the empty hash table entries will take increasingly more time. Typically such long lived processes might be TLS clients or TLS servers configured to accept client certificate authentication. The function was added in the OpenSSL 3.0 version thus older releases are not affected by the issue. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2).

CVE-2022-27639: Incomplete cleanup in some Intel(R) XMM(TM) 7560 Modem software before version M2_7560_R_01.2146.00 may allow a privileged user to potentially enable escalation of privilege via adjacent access.

CVE-2022-29160: Nextcloud Android is the Android client for Nextcloud, a self-hosted productivity platform. Prior to version 3.19.0, sensitive tokens, images, and user related details exist after deletion of a user account. This could result in misuse of the former account holder's information. Nextcloud Android version 3.19.0 contains a patch for this issue. There are no known workarounds available.

CVE-2022-25664: Information disclosure due to exposure of information while GPU reads the data in Snapdragon Auto, Snapdragon Compute, Snapdragon Connectivity, Snapdragon Consumer IOT, Snapdragon Industrial IOT, Snapdragon Mobile, Snapdragon Wearables

# CWE-46 Path Equivalence: 'filename ' (Trailing Space)

## Description

The product accepts path input in the form of trailing space ('filedir ') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2001-0693: Source disclosure via trailing encoded space "%20"

CVE-2001-0778: Source disclosure via trailing encoded space "%20"

CVE-2001-1248: Source disclosure via trailing encoded space "%20"

CVE-2004-0280: Source disclosure via trailing encoded space "%20"

CVE-2004-2213: Source disclosure via trailing encoded space "%20"

CVE-2005-0622: Source disclosure via trailing encoded space "%20"

CVE-2005-1656: Source disclosure via trailing encoded space "%20"

CVE-2002-1603: Source disclosure via trailing encoded space "%20"

CVE-2001-0054: Multi-Factor Vulnerability (MFV). directory traversal and other issues in FTP server using Web encodings such as "%20"; certain manipulations have unusual side effects.

CVE-2002-1451: Trailing space ("+" in query string) leads to source code disclosure.

# CWE-460 Improper Cleanup on Thrown Exception

## Description

The product does not clean up its state or incorrectly cleans up its state when an exception is thrown, leading to unexpected state or control flow.

Often, when functions or loops become complicated, some level of resource cleanup is needed throughout execution. Exceptions can disturb the flow of the code and prevent the necessary cleanup from happening.

## Top 25 Examples

CVE-2022-22150: A memory corruption vulnerability exists in the JavaScript engine of Foxit Software’s PDF Reader, version 11.1.0.52543. A specially-crafted PDF document can trigger an exception which is improperly handled, leaving the engine in an invalid state, which can lead to memory corruption and arbitrary code execution. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. Exploitation is also possible if a user visits a specially-crafted, malicious site if the browser plugin extension is enabled.

# CWE-462 Duplicate Key in Associative List (Alist)

## Description

Duplicate keys in associative lists can lead to non-unique keys being mistaken for an error.

A duplicate key entry -- if the alist is designed properly -- could be used as a constant time replace function. However, duplicate key entries could be inserted by mistake. Because of this ambiguity, duplicate key entries in an association list are not recommended and should not be allowed.

# CWE-463 Deletion of Data Structure Sentinel

## Description

The accidental deletion of a data-structure sentinel can cause serious programming logic problems.

Often times data-structure sentinels are used to mark structure of the data structure. A common example of this is the null character at the end of strings. Another common example is linked lists which may contain a sentinel to mark the end of the list. It is dangerous to allow this type of control data to be easily accessible. Therefore, it is important to protect from the deletion or modification outside of some wrapper interface which provides safety.

# CWE-464 Addition of Data Structure Sentinel

## Description

The accidental addition of a data-structure sentinel can cause serious programming logic problems.

Data-structure sentinels are often used to mark the structure of data. A common example of this is the null character at the end of strings or a special sentinel to mark the end of a linked list. It is dangerous to allow this type of control data to be easily accessible. Therefore, it is important to protect from the addition or modification of sentinels.

# CWE-466 Return of Pointer Value Outside of Expected Range

## Description

A function can return a pointer to memory that is outside of the buffer that the pointer is expected to reference.

# CWE-467 Use of sizeof() on a Pointer Type

## Description

The code calls sizeof() on a malloced pointer type, which always returns the wordsize/8. This can produce an unexpected result if the programmer intended to determine how much memory has been allocated.

The use of sizeof() on a pointer can sometimes generate useful information. An obvious case is to find out the wordsize on a platform. More often than not, the appearance of sizeof(pointer) indicates a bug.

# CWE-468 Incorrect Pointer Scaling

## Description

In C and C++, one may often accidentally refer to the wrong memory due to the semantics of when math operations are implicitly scaled.

# CWE-469 Use of Pointer Subtraction to Determine Size

## Description

The product subtracts one pointer from another in order to determine size, but this calculation can be incorrect if the pointers do not exist in the same memory chunk.

# CWE-47 Path Equivalence: ' filename' (Leading Space)

## Description

The product accepts path input in the form of leading space (' filedir') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

# CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')

## Description

The product uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.

If the product uses external inputs to determine which class to instantiate or which method to invoke, then an attacker could supply values to select unexpected classes or methods. If this occurs, then the attacker could create control flow paths that were not intended by the developer. These paths could bypass authentication or access control checks, or otherwise cause the product to behave in an unexpected manner. This situation becomes a doomsday scenario if the attacker can upload files into a location that appears on the product's classpath (CWE-427) or add new entries to the product's classpath (CWE-426). Under either of these conditions, the attacker can use reflection to introduce new, malicious behavior into the product.

## Observed Examples

CVE-2018-1000613: Cryptography API uses unsafe reflection when deserializing a private key

CVE-2004-2331: Database system allows attackers to bypass sandbox restrictions by using the Reflection API.

## Top 25 Examples

CVE-2021-21327: GLPI is an open-source asset and IT management software package that provides ITIL Service Desk features, licenses tracking and software auditing. In GLPI before version 9.5.4 non-authenticated user can remotely instantiate object of any class existing in the GLPI environment that can be used to carry out malicious attacks, or to start a “POP chain”. As an example of direct impact, this vulnerability affects integrity of the GLPI core platform and third-party plugins runtime misusing classes which implement some sensitive operations in their constructors or destructors. This is fixed in version 9.5.4.

# CWE-471 Modification of Assumed-Immutable Data (MAID)

## Description

The product does not properly protect an assumed-immutable element from being modified by an attacker.

This occurs when a particular input is critical enough to the functioning of the application that it should not be modifiable at all, but it is. Certain resources are often assumed to be immutable when they are not, such as hidden form fields in web applications, cookies, and reverse DNS lookups.

## Observed Examples

CVE-2002-1757: Relies on $PHP_SELF variable for authentication.

CVE-2005-1905: Gain privileges by modifying assumed-immutable code addresses that are accessed by a driver.

# CWE-472 External Control of Assumed-Immutable Web Parameter

## Description

The web application does not sufficiently verify inputs that are assumed to be immutable but are actually externally controllable, such as hidden form fields.

If a web product does not properly protect assumed-immutable values from modification in hidden form fields, parameters, cookies, or URLs, this can lead to modification of critical data. Web applications often mistakenly make the assumption that data passed to the client in hidden fields or cookies is not susceptible to tampering. Improper validation of data that are user-controllable can lead to the application processing incorrect, and often malicious, input.


For example, custom cookies commonly store session data or persistent data across sessions. This kind of session data is normally involved in security related decisions on the server side, such as user authentication and access control. Thus, the cookies might contain sensitive data such as user credentials and privileges. This is a dangerous practice, as it can often lead to improper reliance on the value of the client-provided cookie by the server side application.

## Observed Examples

CVE-2002-0108: Forum product allows spoofed messages of other users via hidden form fields for name and e-mail address.

CVE-2000-0253: Shopping cart allows price modification via hidden form field.

CVE-2000-0254: Shopping cart allows price modification via hidden form field.

CVE-2000-0926: Shopping cart allows price modification via hidden form field.

CVE-2000-0101: Shopping cart allows price modification via hidden form field.

CVE-2000-0102: Shopping cart allows price modification via hidden form field.

CVE-2000-0758: Allows admin access by modifying value of form field.

CVE-2002-1880: Read messages by modifying message ID parameter.

CVE-2000-1234: Send email to arbitrary users by modifying email parameter.

CVE-2005-1652: Authentication bypass by setting a parameter.

CVE-2005-1784: Product does not check authorization for configuration change admin script, leading to password theft via modified e-mail address field.

CVE-2005-2314: Logic error leads to password disclosure.

CVE-2005-1682: Modification of message number parameter allows attackers to read other people's messages.

## Top 25 Examples

CVE-2021-41322: Poly VVX 400/410 5.3.1 allows low-privileged users to change the Admin password by modifying a POST parameter to 120 during the password reset process.

CVE-2021-45896: Nokia FastMile 3TG00118ABAD52 devices allow privilege escalation by an authenticated user via is_ctc_admin=1 to login_web_app.cgi and use of Import Config File.

CVE-2022-0441: The MasterStudy LMS WordPress plugin before 2.7.6 does to validate some parameters given when registering a new account, allowing unauthenticated users to register as an admin

CVE-2021-43129: A bypass exists for Desire2Learn/D2L Brightspace’s “Disable Right Click” option in the quizzing feature, which allows a quiz-taker to access print and copy functionality via the browser’s right click menu even when “Disable Right Click” is enabled on the quiz.

CVE-2022-4808: Improper Privilege Management in GitHub repository usememos/memos prior to 0.9.1.

CVE-2021-27770: The vulnerability was discovered within the “FaviconService”. The service takes a base64-encoded URL which is then requested by the webserver. We assume this service is used by the “meetings”-function where users can specify an external URL where the online meeting will take place.

CVE-2021-39409: A vulnerability exists in Online Student Rate System v1.0 that allows any user to register as an administrator without needing to be authenticated.

# CWE-473 PHP External Variable Modification

## Description

A PHP application does not properly protect against the modification of variables from external sources, such as query parameters or cookies. This can expose the application to numerous weaknesses that would not exist otherwise.

## Observed Examples

CVE-2000-0860: File upload allows arbitrary file read by setting hidden form variables to match internal variable names.

CVE-2001-0854: Mistakenly trusts $PHP_SELF variable to determine if include script was called by its parent.

CVE-2002-0764: PHP remote file inclusion by modified assumed-immutable variable.

CVE-2001-1025: Modify key variable when calling scripts that don't load a library that initializes it.

CVE-2003-0754: Authentication bypass by modifying array used for authentication.

# CWE-474 Use of Function with Inconsistent Implementations

## Description

The code uses a function that has inconsistent implementations across operating systems and versions.

The use of inconsistent implementations can cause changes in behavior when the code is ported or built under a different environment than the programmer expects, which can lead to security problems in some cases.


The implementation of many functions varies by platform, and at times, even by different versions of the same platform. Implementation differences can include:


  - Slight differences in the way parameters are interpreted leading to inconsistent results.

  - Some implementations of the function carry significant security risks.

  - The function might not be defined on all platforms.

  - The function might change which return codes it can provide, or change the meaning of its return codes.

# CWE-475 Undefined Behavior for Input to API

## Description

The behavior of this function is undefined unless its control parameter is set to a specific value.

# CWE-476 NULL Pointer Dereference

## Description

The product dereferences a pointer that it expects to be valid but is NULL.

## Observed Examples

CVE-2005-3274: race condition causes a table to be corrupted if a timer activates while it is being modified, leading to resultant NULL dereference; also involves locking.

CVE-2002-1912: large number of packets leads to NULL dereference

CVE-2005-0772: packet with invalid error status value triggers NULL dereference

CVE-2009-4895: Chain: race condition for an argument value, possibly resulting in NULL dereference

CVE-2020-29652: ssh component for Go allows clients to cause a denial of service (nil pointer dereference) against SSH servers.

CVE-2009-2692: Chain: Use of an unimplemented network socket operation pointing to an uninitialized handler function (CWE-456) causes a crash because of a null pointer dereference (CWE-476).

CVE-2009-3547: Chain: race condition (CWE-362) might allow resource to be released before operating on it, leading to NULL dereference (CWE-476)

CVE-2009-3620: Chain: some unprivileged ioctls do not verify that a structure has been initialized before invocation, leading to NULL dereference

CVE-2009-2698: Chain: IP and UDP layers each track the same value with different mechanisms that can get out of sync, possibly resulting in a NULL dereference

CVE-2009-2692: Chain: uninitialized function pointers can be dereferenced allowing code execution

CVE-2009-0949: Chain: improper initialization of memory can lead to NULL dereference

CVE-2008-3597: Chain: game server can access player data structures before initialization has happened leading to NULL dereference

CVE-2020-6078: Chain: The return value of a function returning a pointer is not checked for success (CWE-252) resulting in the later use of an uninitialized variable (CWE-456) and a null pointer dereference (CWE-476)

CVE-2008-0062: Chain: a message having an unknown message type may cause a reference to uninitialized memory resulting in a null pointer dereference (CWE-476) or dangling pointer (CWE-825), possibly crashing the system or causing heap corruption.

CVE-2008-5183: Chain: unchecked return value can lead to NULL dereference

CVE-2004-0079: SSL software allows remote attackers to cause a denial of service (crash) via a crafted SSL/TLS handshake that triggers a null dereference.

CVE-2004-0365: Network monitor allows remote attackers to cause a denial of service (crash) via a malformed RADIUS packet that triggers a null dereference.

CVE-2003-1013: Network monitor allows remote attackers to cause a denial of service (crash) via a malformed Q.931, which triggers a null dereference.

CVE-2003-1000: Chat client allows remote attackers to cause a denial of service (crash) via a passive DCC request with an invalid ID number, which causes a null dereference.

CVE-2004-0389: Server allows remote attackers to cause a denial of service (crash) via malformed requests that trigger a null dereference.

CVE-2004-0119: OS allows remote attackers to cause a denial of service (crash from null dereference) or execute arbitrary code via a crafted request during authentication protocol selection.

CVE-2004-0458: Game allows remote attackers to cause a denial of service (server crash) via a missing argument, which triggers a null pointer dereference.

CVE-2002-0401: Network monitor allows remote attackers to cause a denial of service (crash) or execute arbitrary code via malformed packets that cause a NULL pointer dereference.

CVE-2001-1559: Chain: System call returns wrong value (CWE-393), leading to a resultant NULL dereference (CWE-476).

## Top 25 Examples

CVE-2021-36613: Mikrotik RouterOs before stable 6.48.2 suffers from a memory corruption vulnerability in the ptp process. An authenticated remote attacker can cause a Denial of Service (NULL pointer dereference).

CVE-2021-36614: Mikrotik RouterOs before stable 6.48.2 suffers from a memory corruption vulnerability in the tr069-client process. An authenticated remote attacker can cause a Denial of Service (NULL pointer dereference).

CVE-2022-1516: A NULL pointer dereference flaw was found in the Linux kernel’s X.25 set of standardized network protocols functionality in the way a user terminates their session using a simulated Ethernet card and continued usage of this connection. This flaw allows a local user to crash the system.

CVE-2022-1649: Null pointer dereference in libr/bin/format/mach0/mach0.c in radareorg/radare2 in GitHub repository radareorg/radare2 prior to 5.7.0. It is likely to be exploitable. For more general description of heap buffer overflow, see [CWE](https://cwe.mitre.org/data/definitions/476.html).

CVE-2022-25258: An issue was discovered in drivers/usb/gadget/composite.c in the Linux kernel before 5.16.10. The USB Gadget subsystem lacks certain validation of interface OS descriptor requests (ones with a large array index and ones associated with NULL function pointer retrieval). Memory corruption might occur.

CVE-2022-26093: Null pointer dereference vulnerability in parser_irot function in libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by remote attacker.

CVE-2022-26094: Null pointer dereference vulnerability in parser_auxC function in libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by remote attacker.

CVE-2022-26095: Null pointer dereference vulnerability in parser_colr function in libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by remote attacker.

CVE-2022-26096: Null pointer dereference vulnerability in parser_ispe function in libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by remote attacker.

CVE-2022-26097: Null pointer dereference vulnerability in parser_unknown_property function in libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by remote attacker.

CVE-2022-26099: Null pointer dereference vulnerability in parser_infe function of libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds read by remote attackers.

CVE-2022-27567: Null pointer dereference vulnerability in parser_hvcC function of libsimba library prior to SMR Apr-2022 Release 1 allows out of bounds write by remote attackers.

CVE-2022-41858: A flaw was found in the Linux kernel. A NULL pointer dereference may occur while a slip driver is in progress to detach in sl_tx_timeout in drivers/net/slip/slip.c. This issue could allow an attacker to crash the system or leak internal kernel information.

CVE-2022-42928: Certain types of allocations were missing annotations that, if the Garbage Collector was in a specific state, could have lead to memory corruption and a potentially exploitable crash. This vulnerability affects Firefox < 106, Firefox ESR < 102.4, and Thunderbird < 102.4.

CVE-2021-33456: An issue was discovered in yasm version 1.3.0. There is a NULL pointer dereference in hash() in modules/preprocs/nasm/nasm-pp.c.

CVE-2021-38567: An issue was discovered in Foxit PDF Editor before 11.0.1 and PDF Reader before 11.0.1 on macOS. It mishandles missing dictionary entries, leading to a NULL pointer dereference, aka CNVD-C-2021-95204.

CVE-2021-4209: A NULL pointer dereference flaw was found in GnuTLS. As Nettle's hash update functions internally call memcpy, providing zero-length input may cause undefined behavior. This flaw leads to a denial of service after authentication in rare circumstances.

CVE-2021-4236: Web Sockets do not execute any AuthenticateMethod methods which may be set, leading to a nil pointer dereference if the returned UserData pointer is assumed to be non-nil, or authentication bypass. This issue only affects WebSockets with an AuthenticateMethod hook. Request handlers that do not explicitly use WebSockets are not vulnerable.

CVE-2022-2832: A flaw was found in Blender 3.3.0. A null pointer dereference exists in source/blender/gpu/opengl/gl_backend.cc that may lead to loss of confidentiality and integrity.

CVE-2022-47359: In log service, there is a missing permission check. This could lead to local denial of service in log service.

CVE-2022-47360: In log service, there is a missing permission check. This could lead to local denial of service in log service.

CVE-2022-0582: Unaligned access in the CSN.1 protocol dissector in Wireshark 3.6.0 to 3.6.1 and 3.4.0 to 3.4.11 allows denial of service via packet injection or crafted capture file

CVE-2022-20796: On May 4, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier and 0.104.2 and earlier was disclosed: A vulnerability in Clam AntiVirus (ClamAV) versions 0.103.4, 0.103.5, 0.104.1, and 0.104.2 could allow an authenticated, local attacker to cause a denial of service condition on an affected device. For a description of this vulnerability, see the ClamAV blog.

CVE-2022-25310: A segmentation fault (SEGV) flaw was found in the Fribidi package and affects the fribidi_remove_bidi_marks() function of the lib/fribidi.c file. This flaw allows an attacker to pass a specially crafted file to Fribidi, leading to a crash and causing a denial of service.

CVE-2022-35108: SWFTools commit 772e55a2 was discovered to contain a segmentation violation via DCTStream::getChar() at /xpdf/Stream.cc.

CVE-2022-35484: OTFCC v0.10.4 was discovered to contain a segmentation violation via /release-x64/otfccdump+0x6b6a8f.

CVE-2022-36151: tifig v0.2.2 was discovered to contain a segmentation violation via getType() at /common/bbox.cpp.

CVE-2022-36153: tifig v0.2.2 was discovered to contain a segmentation violation via std::vector<unsigned int, std::allocator<unsigned int> >::size() const at /bits/stl_vector.h.

CVE-2022-38307: LIEF commit 5d1d643 was discovered to contain a segmentation violation via the function LIEF::MachO::SegmentCommand::file_offset() at /MachO/SegmentCommand.cpp.

CVE-2022-38497: LIEF commit 365a16a was discovered to contain a segmentation violation via the component CoreFile.tcc:69.

# CWE-477 Use of Obsolete Function

## Description

The code uses deprecated or obsolete functions, which suggests that the code has not been actively reviewed or maintained.

As programming languages evolve, functions occasionally become obsolete due to:


  - Advances in the language

  - Improved understanding of how operations should be performed effectively and securely

  - Changes in the conventions that govern certain operations

Functions that are removed are usually replaced by newer counterparts that perform the same task in some different and hopefully improved way.

# CWE-478 Missing Default Case in Multiple Condition Expression

## Description

The code does not have a default case in an expression with multiple conditions, such as a switch statement.

If a multiple-condition expression (such as a switch in C) omits the default case but does not consider or handle all possible values that could occur, then this might lead to complex logical errors and resultant weaknesses. Because of this, further decisions are made based on poor information, and cascading failure results. This cascading failure may result in any number of security issues, and constitutes a significant failure in the system.

# CWE-479 Signal Handler Use of a Non-reentrant Function

## Description

The product defines a signal handler that calls a non-reentrant function.

Non-reentrant functions are functions that cannot safely be called, interrupted, and then recalled before the first call has finished without resulting in memory corruption. This can lead to an unexpected system state and unpredictable results with a variety of potential consequences depending on context, including denial of service and code execution.


Many functions are not reentrant, but some of them can result in the corruption of memory if they are used in a signal handler. The function call syslog() is an example of this. In order to perform its functionality, it allocates a small amount of memory as "scratch space." If syslog() is suspended by a signal call and the signal handler calls syslog(), the memory used by both of these functions enters an undefined, and possibly, exploitable state. Implementations of malloc() and free() manage metadata in global structures in order to track which memory is allocated versus which memory is available, but they are non-reentrant. Simultaneous calls to these functions can cause corruption of the metadata.

## Observed Examples

CVE-2005-0893: signal handler calls function that ultimately uses malloc()

CVE-2004-2259: SIGCHLD signal to FTP server can cause crash under heavy load while executing non-reentrant functions like malloc/free.

# CWE-48 Path Equivalence: 'file name' (Internal Whitespace)

## Description

The product accepts path input in the form of internal space ('file(SPACE)name') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2000-0293: Filenames with spaces allow arbitrary file deletion when the product does not properly quote them; some overlap with path traversal.

CVE-2001-1567: "+" characters in query string converted to spaces before sensitive file/extension (internal space), leading to bypass of access restrictions to the file.

# CWE-480 Use of Incorrect Operator

## Description

The product accidentally uses the wrong operator, which changes the logic in security-relevant ways.

These types of errors are generally the result of a typo by the programmer.

## Observed Examples

CVE-2022-3979: Chain: data visualization program written in PHP uses the "!=" operator instead of the type-strict "!==" operator (CWE-480) when validating hash values, potentially leading to an incorrect type conversion (CWE-704)

CVE-2021-3116: Chain: Python-based HTTP Proxy server uses the wrong boolean operators (CWE-480) causing an incorrect comparison (CWE-697) that identifies an authN failure if all three conditions are met instead of only one, allowing bypass of the proxy authentication (CWE-1390)

## Top 25 Examples

CVE-2021-32648: octobercms in a CMS platform based on the Laravel PHP Framework. In affected versions of the october/system package an attacker can request an account password reset and then gain access to the account using a specially crafted request. The issue has been patched in Build 472 and v1.1.5.

# CWE-481 Assigning instead of Comparing

## Description

The code uses an operator for assignment when the intention was to perform a comparison.

In many languages the compare statement is very close in appearance to the assignment statement and are often confused. This bug is generally the result of a typo and usually causes obvious problems with program execution. If the comparison is in an if statement, the if statement will usually evaluate the value of the right-hand side of the predicate.

# CWE-482 Comparing instead of Assigning

## Description

The code uses an operator for comparison when the intention was to perform an assignment.

In many languages, the compare statement is very close in appearance to the assignment statement; they are often confused.

# CWE-483 Incorrect Block Delimitation

## Description

The code does not explicitly delimit a block that is intended to contain 2 or more statements, creating a logic error.

In some languages, braces (or other delimiters) are optional for blocks. When the delimiter is omitted, it is possible to insert a logic error in which a statement is thought to be in a block but is not. In some cases, the logic error can have security implications.

## Observed Examples

CVE-2014-1266: incorrect indentation of "goto" statement makes it more difficult to detect an incorrect goto (Apple's "goto fail")

# CWE-484 Omitted Break Statement in Switch

## Description

The product omits a break statement within a switch or similar construct, causing code associated with multiple conditions to execute. This can cause problems when the programmer only intended to execute code associated with one condition.

This can lead to critical code executing in situations where it should not.

# CWE-486 Comparison of Classes by Name

## Description

The product compares classes by name, which can cause it to use the wrong class when multiple classes can have the same name.

If the decision to trust the methods and data of an object is based on the name of a class, it is possible for malicious users to send objects of the same name as trusted classes and thereby gain the trust afforded to known classes and types.

# CWE-487 Reliance on Package-level Scope

## Description

Java packages are not inherently closed; therefore, relying on them for code security is not a good practice.

The purpose of package scope is to prevent accidental access by other parts of a program. This is an ease-of-software-development feature but not a security feature.

# CWE-488 Exposure of Data Element to Wrong Session

## Description

The product does not sufficiently enforce boundaries between the states of different sessions, causing data to be provided to, or used by, the wrong session.

Data can "bleed" from one session to another through member variables of singleton objects, such as Servlets, and objects from a shared pool.


In the case of Servlets, developers sometimes do not understand that, unless a Servlet implements the SingleThreadModel interface, the Servlet is a singleton; there is only one instance of the Servlet, and that single instance is used and re-used to handle multiple requests that are processed simultaneously by different threads. A common result is that developers use Servlet member fields in such a way that one user may inadvertently see another user's data. In other words, storing user data in Servlet member fields introduces a data access race condition.

## Top 25 Examples

CVE-2022-23505: Passport-wsfed-saml2 is a ws-federation protocol and SAML2 tokens authentication provider for Passport. In versions prior to 4.6.3, a remote attacker may be able to bypass WSFed authentication on a website using passport-wsfed-saml2. A successful attack requires that the attacker is in possession of an arbitrary IDP signed assertion. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. This issue is patched in version 4.6.3. Use of SAML2 authentication instead of WSFed is a workaround.

# CWE-489 Active Debug Code

## Description

The product is deployed to unauthorized actors with debugging code still enabled or active, which can create unintended entry points or expose sensitive information.

A common development practice is to add "back door" code specifically designed for debugging or testing purposes that is not intended to be shipped or deployed with the product. These back door entry points create security risks because they are not considered during design or testing and fall outside of the expected operating conditions of the product.

## Top 25 Examples

CVE-2022-20089: In aee driver, there is a possible memory corruption due to active debug code. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation. Patch ID: ALPS06240397; Issue ID: ALPS06240397.

CVE-2022-33323: Active Debug Code vulnerability in robot controller of Mitsubishi Electric Corporation industrial robot MELFA SD/SQ Series and MELFA F-Series allows a remote unauthenticated attacker to gain unauthorized access by authentication bypass through an unauthorized telnet login. As for the affected model names, controller types and firmware versions, see the Mitsubishi Electric's advisory which is listed in [References] section.

CVE-2021-28112: Draeger X-Dock Firmware before 03.00.13 has Active Debug Code on a debug port, leading to remote code execution by an authenticated attacker.

CVE-2022-36348: Active debug code in some Intel (R) SPS firmware before version SPS_E5_04.04.04.300.0 may allow an authenticated user to potentially enable escalation of privilege via local access.

CVE-2022-24797: Pomerium is an identity-aware access proxy. In distributed service mode, Pomerium's Authenticate service exposes pprof debug and prometheus metrics handlers to untrusted traffic. This can leak potentially sensitive environmental information or lead to limited denial of service conditions. This issue is patched in version v0.17.1 Workarounds: Block access to `/debug` and `/metrics` paths on the authenticate service. This can be done with any L7 proxy, including Pomerium's own proxy service.

# CWE-49 Path Equivalence: 'filename/' (Trailing Slash)

## Description

The product accepts path input in the form of trailing slash ('filedir/') without appropriate validation, which can lead to ambiguous path resolution and allow an attacker to traverse the file system to unintended locations or access arbitrary files.

## Observed Examples

CVE-2002-0253: Overlaps infoleak

CVE-2001-0446: Application server allows remote attackers to read source code for .jsp files by appending a / to the requested URL.

CVE-2004-0334: Bypass Basic Authentication for files using trailing "/"

CVE-2001-0893: Read sensitive files with trailing "/"

CVE-2001-0892: Web server allows remote attackers to view sensitive files under the document root (such as .htpasswd) via a GET request with a trailing /.

CVE-2004-1814: Directory traversal vulnerability in server allows remote attackers to read protected files via .. (dot dot) sequences in an HTTP request.

# CWE-491 Public cloneable() Method Without Final ('Object Hijack')

## Description

A class has a cloneable() method that is not declared final, which allows an object to be created without calling the constructor. This can cause the object to be in an unexpected state.

# CWE-492 Use of Inner Class Containing Sensitive Data

## Description

Inner classes are translated into classes that are accessible at package scope and may expose code that the programmer intended to keep private to attackers.

Inner classes quietly introduce several security concerns because of the way they are translated into Java bytecode. In Java source code, it appears that an inner class can be declared to be accessible only by the enclosing class, but Java bytecode has no concept of an inner class, so the compiler must transform an inner class declaration into a peer class with package level access to the original outer class. More insidiously, since an inner class can access private fields in its enclosing class, once an inner class becomes a peer class in bytecode, the compiler converts private fields accessed by the inner class into protected fields.

# CWE-493 Critical Public Variable Without Final Modifier

## Description

The product has a critical public variable that is not final, which allows the variable to be modified to contain unexpected values.

If a field is non-final and public, it can be changed once the value is set by any function that has access to the class which contains the field. This could lead to a vulnerability if other parts of the program make assumptions about the contents of that field.

Mobile code, such as a Java Applet, is code that is transmitted across a network and executed on a remote machine. Because mobile code developers have little if any control of the environment in which their code will execute, special security concerns become relevant. One of the biggest environmental threats results from the risk that the mobile code will run side-by-side with other, potentially malicious, mobile code. Because all of the popular web browsers execute code from multiple sources together in the same JVM, many of the security guidelines for mobile code are focused on preventing manipulation of your objects' state and behavior by adversaries who have access to the same virtual machine where your program is running.
Final provides security by only allowing non-mutable objects to be changed after being set. However, only objects which are not extended can be made final.

# CWE-494 Download of Code Without Integrity Check

## Description

The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

An attacker can execute malicious code by compromising the host server, performing DNS spoofing, or modifying the code in transit.

## Observed Examples

CVE-2019-9534: Satellite phone does not validate its firmware image.

CVE-2021-22909: Chain: router's firmware update procedure uses curl with "-k" (insecure) option that disables certificate validation (CWE-295), allowing adversary-in-the-middle (AITM) compromise with a malicious firmware image (CWE-494).

CVE-2008-3438: OS does not verify authenticity of its own updates.

CVE-2008-3324: online poker client does not verify authenticity of its own updates.

CVE-2001-1125: anti-virus product does not verify automatic updates for itself.

CVE-2002-0671: VOIP phone downloads applications from web sites without verifying integrity.

## Top 25 Examples

CVE-2021-44168: A download of code without integrity check vulnerability in the "execute restore src-vis" command of FortiOS before 7.0.3 may allow a local authenticated attacker to download arbitrary files on the device via specially crafted update packages.

# CWE-495 Private Data Structure Returned From A Public Method

## Description

The product has a method that is declared public, but returns a reference to a private data structure, which could then be modified in unexpected ways.

# CWE-496 Public Data Assigned to Private Array-Typed Field

## Description

Assigning public data to a private array is equivalent to giving public access to the array.

# CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere

## Description

The product does not properly prevent sensitive system-level information from being accessed by unauthorized actors who do not have the same level of access to the underlying system as the product does.

Network-based products, such as web applications, often run on top of an operating system or similar environment. When the product communicates with outside parties, details about the underlying system are expected to remain hidden, such as path names for data files, other OS users, installed packages, the application environment, etc. This system information may be provided by the product itself, or buried within diagnostic or debugging messages. Debugging information helps an adversary learn about the system and form an attack plan.


An information exposure occurs when system data or debugging information leaves the program through an output stream or logging function that makes it accessible to unauthorized parties. Using other weaknesses, an attacker could cause errors to occur; the response to these errors can reveal detailed system information, along with other impacts. An attacker can use messages that reveal technologies, operating systems, and product versions to tune the attack against known vulnerabilities in these technologies. A product may use diagnostic methods that provide significant implementation details such as stack traces as part of its error handling mechanism.

## Observed Examples

CVE-2021-32638: Code analysis product passes access tokens as a command-line parameter or through an environment variable, making them visible to other processes via the ps command.

## Top 25 Examples

CVE-2022-22303: An exposure of sensitive system information to an unauthorized control sphere vulnerability [CWE-497] in FortiManager versions prior to 7.0.2, 6.4.7 and 6.2.9 may allow a low privileged authenticated user to gain access to the FortiGate users credentials via the config conflict file.

CVE-2022-34458:  Dell Command | Update, Dell Update, and Alienware Update versions prior to 4.7 contain a Exposure of Sensitive System Information to an Unauthorized Control Sphere vulnerability in download operation component. A local malicious user could potentially exploit this vulnerability leading to the disclosure of confidential data. 

CVE-2022-22961: VMware Workspace ONE Access, Identity Manager and vRealize Automation contain an information disclosure vulnerability due to returning excess information. A malicious actor with remote access may leak the hostname of the target system. Successful exploitation of this issue can lead to targeting victims.

CVE-2022-28651: In JetBrains IntelliJ IDEA before 2021.3.3 it was possible to get passwords from protected fields

CVE-2022-20734: A vulnerability in Cisco SD-WAN vManage Software could allow an authenticated, local attacker to view sensitive information on an affected system. This vulnerability is due to insufficient file system restrictions. An authenticated attacker with netadmin privileges could exploit this vulnerability by accessing the vshell of an affected system. A successful exploit could allow the attacker to read sensitive information on the underlying operating system.

# CWE-498 Cloneable Class Containing Sensitive Information

## Description

The code contains a class with sensitive data, but the class is cloneable. The data can then be accessed by cloning the class.

Cloneable classes are effectively open classes, since data cannot be hidden in them. Classes that do not explicitly deny cloning can be cloned by any other class without running the constructor.

# CWE-499 Serializable Class Containing Sensitive Data

## Description

The code contains a class with sensitive data, but the class does not explicitly deny serialization. The data can be accessed by serializing the class through another class.

Serializable classes are effectively open classes since data cannot be hidden in them. Classes that do not explicitly deny serialization can be serialized by any other class, which can then in turn use the data stored inside it.

