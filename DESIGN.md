# Design Doc

## Dependencies:
- polkit
- GTK4
- UHID linux kernel
- Sqlite

## How it works:
- The application consists of mainly three components: 
  - a keystore stored each individual user's home directory
  - a service that runs as an unpriviledged user 
  - GUI key management tool.

- The service on system startup creates a virtual HID device through UHID and listens on it. A CTAP relying party (for example browsers) communicates with the service through the virtual HID device.

- Once the service receives a register or attest command through the virtual HID device, the service uses polkit o spawn a user authentication prompt. Once the user authenticates, the service receives enviroment variables through polkit using which the service can run a process as the authenticated user. This gives the ability to use multiple methods of authentication (fingerprint,kerberos,ldap,etc) through pam modules.

- The service then uses the keystore stored in the user's home directory, to perform key creation/signing. A GTK4 GUI window is shown by the service for the user the select which key they want to use.

- The GUI key management tool will be used to initialize the keystore, and gives an interface for the user to manage their keys.

## Keystore Design
- The keystore will be stored in a hidden folder in each user's home directory.

- The folder will contain a GNUPGP keystore for on disk storage and a sqlite database to store meta-data. The sqlite database is used instead of the default GNUPGP metadata because other forms of key storage can be used (For Example: TPM,etc)

- The Sqlite database will be encrypted to prevent against file disclosure attacks. The encryption key will be derived from system and user environment variables through key derivation function. An additional user specified secret can be appended to the input of the key derivation function for additional confidentiality.

## Implementation
- 
