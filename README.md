# csfs
The Clean Slate Virtual File System
This project addresses the need of data access control and privacy on an occasion of device theft/loss or any other scenario where the attacker gains physical access to the device. Theft/Loss of mobile storage devices is a pressing issue as of present as the number of mobile devices’ users increase. Furthermore user’s ignorance towards security only makes matters worse. Clean slate is an attempt at dealing with the after effects of such mishaps in a way that’s easy and user friendly. Clean slate is a FUSE (File System in User Space) based cryptographic virtual file system. It transparently encrypts the data locally, but stores the secret keys remotely, away from the device itself, managed by a key service. We also include the concept of trusted device pairing, via the usage of digital certificates so that the device itself can detect if it is lostorstolen and deny access to remotely stored decryption keys and consequently the data. If all else fails we need to know if any data has been compromised and for that we propose a logging service. This way we are able to take better informed decisions. If it is deployed correctly, this can be a very effective solution, but with some impact on I/O performance, which we have attempted to address in this project.

Original research paper can be found at:
http://kaustubh.tech/docs/clean_slate.pdf

and
http://serialsjournals.com/serialjournalmanager/pdf/1483683074.pdf
