# Otrv1-Demo
## Introduction
This is a demo project for the Ortv1 Protocol.
There a differenc to the original version, the same cryptographic standard are used. But they have different parameters.
Which are safe to use toady, the one choosen from 2004 are all insecure today. 
For technical Details see the docs for the Code.
## Building
Requirments:
[Openssl Rust Bindings](https://docs.rs/openssl/latest/openssl/) install the requirments. It is statistcly linked with the rest of the code.
[Sqlite Requirments](https://lib.rs/crates/sqlx) Sqlite must be installed on the system.
Rust version: 1.92 stable
This was the only version that was tested for building.
Supported Platform: Linux,Windows,Mac should be all supported because of [iced](https://github.com/iced-rs/iced) supporting it.
Only Linux x64-x86 tested;

## Test
Run the test to check if the Sqlite is working correctly.
# Warning
Do not use in a open network, this application has no DDOS protection. It should only be run in a localnetowork or on localhost. 
# Use
In the /key directory are two X509 files. And then two Pkcs12 files with the .p12 extension.
Password for both Pkcs12 is **password123**. Should you close a window, it should reconnect when opening the same window again with the same configs.

## Limitation
Like the OTRv1 Protcol says only two people can chat and must be online for it. And that the Rekying not happening every message, it is happening every minute or after a limit of messages.
## Example
- A User1
- bob.pem 
- alice.p12 
- -----------
- B User2
- alice.pem
- bob.p12

# Conclusion
For more infos read the docs of the rust code. With '''cargo doc --open --no-deps''' to open the docs.
