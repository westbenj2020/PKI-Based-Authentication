# PKI-Based-Authentication
Public Key Infrastructure (PKI) is a technology for authenticating users and devices in the digital world. The basic idea is to have one or more trusted parties digitally sign documents certifying that a particular cryptographic key belongs to a particular user or device.

This message flow of the protocol implemented within this project can be conceptualized as a three-phase process; this process involves the registration of an application server and client as well as a service request by the client to obtain application data from the application server.

![image](https://user-images.githubusercontent.com/38194972/120053692-b2a74280-bff9-11eb-9312-f38b56e97d35.png)

The first phase, which consists of the application server sending concatenated data to the centralized certificate authority, is meant to request a public/private key pair and certificate; these tools will equip the application server with the ability to register future clients. 

In the second phase, the introduced client(s) will attempt to register with the application server to obtain a session key for further communication; this phase is obviously contingent upon the success of the application servers prior registration. 

In the third and final phase, the client(s) will utilize a previously allocated session key to request service from the application server.

Hardcoded values, which are known to each entity prior to cooperative communication, consist of identification strings and service request data.

This project integrates classroom knowledge of socket programming, basic network structure, and asymmetric cryptography techniques and principles; the advanced encryption standard is used in tandem with an RSA (Rivest-Shamir-Adleman) cryptosystem via the importation of external libraries - namely, pycryptodome.

Note: When running three separated command lines for each source file, make sure to run applicationServer.py and then centralizedCertificateAuthority.py. After receiving errors, a successful execution can be performed by running centralizedCertificateAuthority.py, then applicationServer.py, and finally client1.py. This sequence-of-execution inhibition can be remedied through the utilization of effective timing mechanisms, such as sleep(). If further development is pursued for this project, it is recommended to implement the aforementioned solution.

