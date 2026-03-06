var metadata = {
    groupIdNumber: "1.2",
    stigId: "CISC-RT-000050",
    ruleId: "RULE ID: SV-216555r929040",
    groupId: "GROUP ID: V-216555",
    severity: "HIGH",
    description: "The Cisco router must be configured to enable routing protocol authentication using  FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.  GROUP ID: V-216555  RULE ID: SV-216555r929040",
    rationale: "A rogue router could send a fictitious routing update to convince a site's perimeter router  to send traffic to an incorrect or even a rogue destination. This diverted traffic could be  analyzed to learn confidential information about the site's network or used to disrupt the  network's ability to communicate with other networks. This is known as a \"traffic  attraction attack\" and is prevented by configuring neighbor router authentication using  FIPS 198-1 algorithms for routing updates. If the keys used for authentication are  guessed, the malicious user could create havoc within the network by advertising  incorrect routes and redirecting traffic. Some routing protocols allow the use of key  chains for authentication. A key chain is a set of keys that is used in succession, with  each having a lifetime of no more than 180 days. Changing the keys frequently reduces  the risk of them eventually being guessed. If a time period occurs during which no key is  activated, neighbor authentication cannot occur, and therefore routing updates will fail.  Internal Only - General",
    audit: "Review the router configuration using the configuration examples below for BGP and  OSPF.  EIGRP, RIP, and IS-IS only support MD5 and will incur a permanent finding for those  protocols.  Note: The 180-day key lifetime is Not Applicable for the DODIN Backbone. The  remainder of the requirement still applies.  Verify that neighbor router authentication is enabled for all routing protocols. If neighbor  authentication is not enabled this is a finding.  Verify that authentication is configured to use FIPS 198-1 message authentication  algorithms. If the routing protocol authentication is not configured to use FIPS 198-1  algorithms this is a finding.  Verify that the protocol key lifetime is configured to not exceed 180 days. If any protocol  key lifetime is configured to exceed 180 days this is a finding.  BGP Example:  key chain <KEY-CHAIN-NAME> tcp  key <KEY-ID>  send-id <ID>  recv-id <ID>  cryptographic-algorithm hmac-sha256  key-string <KEY>  accept-lifetime 00:00:00 Jan 1 2022 duration 180  send-lifetime 00:00:00 Jan 1 2022 duration 180  !  !  router bgp <ASN>  no synchronization  bgp log-neighbor-changes  neighbor x.x.x.x remote-as <ASN>  neighbor x.x.x.x ao <KEY-CHAIN-NAME>  Note: TCP-AO is used to replace MD5 in BGP authentication.  OSPF Example:  key chain OSPF_KEY_CHAIN  key 1  key-string xxxxxxx  send-lifetime 00:00:00 Jan 1 2018 23:59:59 Mar 31 2018  accept-lifetime 00:00:00 Jan 1 2018 01:05:00 Apr 1 2018  cryptographic-algorithm hmac-sha-256  key 2       Internal Only - General  key-string yyyyyyy  send-lifetime 00:00:00 Apr 1 2018 23:59:59 Jun 30 2018  accept-lifetime 23:55:00 Mar 31 2018 01:05:00 Jul 1 2018  cryptographic-algorithm hmac-sha-256  …  …  …  interface GigabitEthernet0/1  ip address x.x.x.x 255.255.255.0  ip ospf authentication key-chain OSPF_KEY_CHAIN  Internal Only - General",
    remediation: "Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message  authentication code algorithm with keys not exceeding 180 days of lifetime as shown in  the examples.  BGP Example:  Step 1: Configure a keychain using a FIPS 198-1 algorithm with a key duration not  exceeding 180 days.  key chain <KEY-CHAIN-NAME> tcp  key <KEY-ID>  send-id <ID>  recv-id <ID>  cryptographic-algorithm hmac-sha256  key-string <KEY>  accept-lifetime 00:00:00 Jan 1 2022 duration 180  send-lifetime 00:00:00 Jan 1 2022 duration 180  !  Step 2: Configure BGP autonomous system to use the keychain for authentication.  router bgp <ASN>  no synchronization  bgp log-neighbor-changes  neighbor x.x.x.x remote-as <ASN>  neighbor x.x.x.x ao <KEY-CHAIN-NAME>  OSPF Example:  Step 1: Configure a keychain using a FIPS 198-1 algorithm with a key duration not  exceeding 180 days.  key chain OSPF_KEY_CHAIN  key 1  key-string xxxxxxx  send-lifetime 00:00:00 Jan 1 2018 23:59:59 Mar 31 2018  accept-lifetime 00:00:00 Jan 1 2018 01:05:00 Apr 1 2018  cryptographic-algorithm hmac-sha-256  key 2  key-string yyyyyyy  send-lifetime 00:00:00 Apr 1 2018 23:59:59 Jun 30 2018  accept-lifetime 23:55:00 Mar 31 2018 01:05:00 Jul 1 2018  cryptographic-algorithm hmac-sha-256  Step 2: Configure OSPF to use the keychain for authentication.  interface GigabitEthernet0/1  ip address x.x.x.x 255.255.255.0  ip ospf authentication key-chain OSPF_KEY_CHAIN     Internal Only - General",
    cci: "CCI-000803, CCI-002205",
    expectedState: "Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message authentication code algorithm with keys not exceeding 180 days of lifetime as shown in the examples.",
    generatedOn: "2026-03-06",
    generatorVersion: "2.0",
    benchmark: "STIG"
};

function check(config) {

    if (!config) {
        return { status: "ERROR", line: 0 };
    }

    var lines = String(config).split("\n");
    var matched = false;
    var foundLine = 0;
    var pass = true;

    for (var i = 0; i < lines.length; i++) {

        var line = lines[i].toLowerCase();

        if (line.indexOf("###NO_MATCH###".toLowerCase()) !== -1) {

            matched = true;
            foundLine = i + 1;

            var numberMatch = line.match(/\d+/);
            var actual = numberMatch ? parseInt(numberMatch[0]) : null;

            pass = true;
        }
    }

    if ("exists" === "not_exists") {
        if (matched) {
            return { status: "FAIL", line: foundLine };
        } else {
            return { status: "PASS", line: 0 };
        }
    }

    if (!matched) {
        return { status: "FAIL", line: 0 };
    }

    if (pass) {
        return { status: "PASS", line: foundLine };
    }

    return { status: "FAIL", line: foundLine };
}

check(config);
