Oracle Forms Test Scripts
-------------------------

Proof-of-Concept scripts to test Oracle Forms based applications.

The `OracleFormsTester/` directory contains a Burp Suite extension that performs decryption, Message parsing and Scanner insertion point selection (Eclipse project).

The files outside this directory are simple utility programs that can help further develop the extension.

To use these programs first unzip the `frmall.jar` archive provided by Oracle Forms and include the resulting directory in the classpath.

* MessageTester.java - Message parsers that allows easy debugging of the deserialization process.
* OracleFormsBruteForce.java - Primitive brute-forcer for encrypted protocol messages.
* OracleFormsSyncingBruteForce.java - Primitive brute-forcer that demonstrates the attack against an out-of-sync cipher stream. 

Further information can be found in my [GWAPT Gold Paper: Automated Security Testing of Oracle Forms Applications](https://www.sans.org/reading-room/whitepapers/testing/automated-security-testing-oracle-forms-applications-35970).

## Pro Tips

* FRM-92095: Oracle Forms won't start until you convince it that Java is still owned by Sun Microsystems... Create a system wide environment variable (as described [here](https://blogs.oracle.com/ptian/solution-for-error-frm-92095:-oracle-jnitiator-version-too-low)): `JAVA_TOOL_OPTIONS='-Djava.vendor="Sun Microsystems Inc."'`
