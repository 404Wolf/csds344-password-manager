# Password Manager

## A simple console-based password manager implemented in Java.
Features
- Create and manage a secure password file
- Add new passwords with labels
- Read stored passwords
- Encrypt and decrypt passwords using Java cryptography

## Usage

Install the latest open jdk, or use the `nix` development shell with `nix develop`. Then build with `mvn compile`, and run with `java -cp target/classes com.cwru.PasswordManager`.

You start by entering the master password to access the password manager, and if no password file exists, a new one will be created, or if one does exist you will unlock the vault.
Then you can choose to add a new password, read an existing password, or quit the program. All passwords are stored hashed and encrypted in `passwords.txt`. A salt and token are stored at the top of the file. The keys themselves that passwords are stored under are plain text.

## Authors
Wolf Mermelstein and Kaleb Kim
