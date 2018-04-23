Oracle Forms Test Scripts
=========================

Proof-of-Concept scripts to test Oracle Forms based applications.

OracleFormsTester
-----------------

The `OracleFormsTester/` directory contains a Burp Suite extension that performs decryption, Message parsing and Scanner insertion point selection (Eclipse project).

The files outside this directory are simple utility programs that can help further develop the extension.

To use these programs first unzip the `frmall.jar` archive provided by Oracle Forms and include the resulting directory in the classpath.

* MessageTester.java - Message parsers that allows easy debugging of the deserialization process.
* OracleFormsBruteForce.java - Primitive brute-forcer for encrypted protocol messages.
* OracleFormsSyncingBruteForce.java - Primitive brute-forcer that demonstrates the attack against an out-of-sync cipher stream. 

Further information can be found in my [GWAPT Gold Paper: Automated Security Testing of Oracle Forms Applications](https://www.sans.org/reading-room/whitepapers/testing/automated-security-testing-oracle-forms-applications-35970).

OracleFormsSerializer
---------------------

**You probably want to use this**

This is a new implementation that moves encryption state away from the client and Burp. Instead of juggling with state saving and restore for every possible message we simply kill encryption from the client (so Burp can work with plaintext messages) and reimplement it in a [MitMproxy](https://github.com/mitmproxy/mitmproxy) script.

Start MitMproxy with the provided script:
```
mitmproxy -s mitmproxy_oracleforms.py -p 8081
```

The script was written for MitMproxy 3.x.x, earlier major versions will not work!

Configure Burp to use the upstream proxy 127.0.0.1:8081! 

Now you can start your Oracle Form application, configured to use Burp as its proxy. The MitMproxy script will corrupt the key exchange, so the client won't encrypt its messages. Encryption will instead happen within the MitM layer, and the server will not be aware of the encryption break.
The OracleFormSerializer extension can then do message serialization for you. Messages will be translated to standard HTTP GET requests in the OracleForms request editor tab with String parameters provided in a query string in the Message body. If you edit these parameters the extension will automatically update the original binary Forms message appropriately (e.g. in Repeater). The extension will also register new insertion points for the Scanner so you can use that too (keep in mind that insertion points provided by Burp will probably break stuff though!).

Common Errors
-------------

* FRM-92095: Oracle Forms won't start until you convince it that Java is still owned by Sun Microsystems... Create a system wide environment variable (as described [here](https://blogs.oracle.com/ptian/solution-for-error-frm-92095:-oracle-jnitiator-version-too-low)): `JAVA_TOOL_OPTIONS='-Djava.vendor="Sun Microsystems Inc."'`
* `ifError: 11/xxx` on server responses: These messages [instruct the client](https://community.oracle.com/docs/DOC-893120) to wait xxx milliseconds and try to send the request again. This error usually comes up when you try to send requests from multiple threads (this can happen when the legit client and some test tool are running simultaneously). Don't issue multi-threaded requests as we only have a single keystream to work with, always use a single thread! Another possibility is that the frequency of your requests is too high and/or the server load is too high.

Pro Tips
--------

* If something goes wrong you'll probably want to restart MitMproxy so the objects will be reinitialized to a clean state
* Scan only with a single thread
* Disable default Scanner insertion points
