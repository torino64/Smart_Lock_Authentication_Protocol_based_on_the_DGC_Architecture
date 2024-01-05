# Smart_Lock_Authentication_Protocol_based_on_the_DGC_Architecture

![smart_lock](https://github.com/torino64/Smart_Lock_Authentication_Protocol_based_on_the_DGC_Architecture/assets/47543092/4aabf8de-8759-4956-80d2-8632883bd84e)

The advent of smart locks in  the field of the Internet of Things (IoT) marks a significant progress, but also raises security challenges. In particular, authentication protocols based on the DGC (Device Gateway Cloud) architecture for these locks are faced with critical security issues, especially when the lock is in offline mode and the user acts as a gateway between the lock and the cloud. Our research focused on the development of an authentication protocol for smart locks using
Zero-Knowledge Proof (ZKP), specifically in its non-interactive form and easily integrable with the Boneh-Boyen weak signature. This method aims to improve security and
confidentiality without increasing the number of requests in the protocol. The security analysis of our protocol, including verifying its completeness and validity, has proven its effectiveness against all known security attacks in communications. To assess the effectiveness of our proposed protocol, we implemented applications for the smart
lock and for the user (owner) using the Python Kivy framework, and the authentication server with FastAPI. This implementation allowed for precise evaluation of the resource consumption of the key function of our protocol, thus providing a concrete measure of its performance and efficiency.

# Installation
# Linux:
```
sudo apt-get update
sudo apt-get install git
// Note: Install also MongoDB.
sudo apt install python3.8
sudo apt-get install pip
pip install --upgrade pip setuptools
git clone https://github.com/torino64/Smart_Lock_Authentication_Protocol_based_on_the_DGC_Architecture
ls
cd Smart_Lock_Authentication_Protocol_based_on_the_DGC_Architecture
pip install -r requirements.txt
```
Before launching the server application and the client applications, you should first update the server's IP address in the client apps' settings. Then, launch the FastAPI server followed by initiating the smart lock app and the master app.
```
sudo systemctl start mongod
uvicorn app:app --host 0.0.0.0
```
Open two additional terminals, and in each one, launch the respective applications: one for the smart lock and the other for the master app
```
python3.8 smart_lock_app.py
python3.8 master_app.py
```

