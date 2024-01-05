# Smart_Lock_Authentication_Protocol_based_on_the_DGC_Architecture
The advent of smart locks in the field of the Internet of Things (IoT) marks a significant
progress, but also raises security challenges. In particular, authentication protocols based on the
DGC (Device Gateway Cloud) architecture for these locks are faced with critical security
issues, especially when the lock is in offline mode and the user acts as a gateway between the
lock and the cloud.
Our research focused on the development of an authentication protocol for smart locks using
Zero-Knowledge Proof (ZKP), specifically in its non-interactive form and easily integrable
with the Boneh-Boyen weak signature. This method aims to improve security and
confidentiality without increasing the number of requests in the protocol. The security analysis
of our protocol, including verifying its completeness and validity, has proven its effectiveness
against all known security attacks in communications.
To assess the effectiveness of our proposed protocol, we implemented applications for the smart
lock and for the user (owner) using the Python Kivy framework, and the authentication server
with FastAPI. This implementation allowed for precise evaluation of the resource consumption
of the key function of our protocol, thus providing a concrete measure of its performance and
efficiency.

