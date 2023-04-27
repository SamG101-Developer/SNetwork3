### Establishing end-to-end encryption for UDP control connections [CCP]
In this scenario, A will perform a handshake with B to initiate a secure UDP connection. The following steps are taken:
- A owns a static asymmetric key pair: `[sPKa, sSKa]`
- A generates an ephemeral asymmetric key pair: `[ePKa, eSKa]`
- A signs the ephemeral public key with its static secret key: `S(ePKa, sSKa)`
- A sends a `CON_REQ` to B, with the signed ephemeral public key as metadata


- B receives a `CON_REQ` from A, with the A's signed ephemeral public key as metadata
- B verifies A's ephemeral public key with A's static public key: `V(S(ePKa, sSKa), ePKa, sPKa)`
- B generates a random symmetric connection master key: `CMK` (control master key)
- B derives a symmetric encryption key from the CMK: `CMK_EK` (encryption key)
- B signs the CMK with its static secret key: `S(CMK, sSKb)`
- B KEMs the CMK and signature with A's ephemeral public key: `KEM(S(CMK, sSKb), ePKa)`
- B sends a `CON_ACC` to A, with the KEMed signed CMK as metadata


- A receives a `CON_ACC` from B, with the KEMed signed CMK as metadata
- A decrypts the KEMed signed CMK using its own ephemeral private key: `UNKEM(KEM(S(CMK, sSKb), ePKa), eSKa) => S(CMK, sSKb)`
- A verifies the signature using B's static public key: `V(S(CMK, sSKb), CMK, sPKb) => CMK`
- A derives a symmetric encryption key from the CMK: `CMK_EK` (encryption key)


Note
- Asymmetric signing is quantum safe
- Asymmetric kem is quantum safe
- Symmetric encryption is authenticated => no need for MAC
- Signatures have a [random value, timestamp, recipient public key] attached to them
- Every fixed time point, keys are updated using a symmetric key wrap


### Establishing end-to-end encryption for packet data connections [PDCP]
This is slightly more complicated than the control-connection, because the client only connects to the 1st relay 
node, and passes information through it to the other relay nodes. Due to the security of the control-connection, it 
can be modeled that the 1st relay node is a malicious actor between the client and the other relay nodes. However, 
the only difference is that the other relay nodes cannot know who the client is. Therefore, bilateral authentication 
is not an option, because the other relay nodes would be able to identify the client. Instead, unilateral 
authentication is used, where the client sends non-authenticated data to relay nodes, and they send the same data 
back, but signed -- this way, the client can verify the relay nodes, but the relay nodes cannot verify the client. 
If the signed data is different to the data the client sent, then it has been tampered with by an intermediary relay 
node. Further to this, the relay nodes cannot create the symmetric keys for the packet encryption, as they have to 
way to KEM them back to the client node -- they don't know the client node's public key. Therefore, the client node
must create the symmetric keys, and KEM them to the relay nodes. The following steps are taken:
- A -> N, via (N - 1) relay nodes
- All communications from A go through other relay nodes in the chain to N (auto-forward)
- All communications from N go through other relay nodes in the chain to A (auto-forward)


- A chooses a node N from the DHT, using a predefined algorithm
- A generates a random symmetric packet master key: `PMK` (packet master key)
- A derives a symmetric encryption key from the PMK: `PMK_EK` (encryption key)
- A knows the ephemeral public key of N: `ePKn` (forwarded back from the control-connection-handshake)
- A KEMs the PMK with N's ephemeral public key: `KEM(PMK, ePKn)`
- A sends a `PKT_REQ` to N, with the KEMed PMK as metadata (via the relay nodes)


- N receives a `PKT_REQ` from A, with the KEMed PMK as metadata (via the relay nodes)
- N decrypts the KEMed PMK using its own ephemeral private key: `UNKEM(KEM(PMK, ePKn), eSKn) => PMK`
- N derives a symmetric encryption key from the PMK: `PMK_EK` (encryption key)
- N signs the hash of the PMK with its static secret key: `S(H(PMK), sSKn)`
- N sends a `PKT_ACC` to A, with the signed hash of the PMK as metadata (via the relay nodes)


- A receives a `PKT_ACC` from N, with the signed hash of the PMK as metadata (via the relay nodes)
- A verifies the signature using N's static public key: `V(S(H(PMK), sSKn), H(PMK), sPKn) => H(PMK)`
- A checks the hash of the PMK matches the hash of the PMK it sent: `H(PMK) == H(PMK)`


Note
- Asymmetric signing is quantum safe
- Asymmetric kem is quantum safe
- Symmetric encryption is authenticated => no need for MAC
- Signatures have a [random value, timestamp, recipient public key] attached to them
- Every packet manipulated -> counter incremented
- Every fixed time point (n milliseconds), iv is updated
- Every random time time point (n seconds), keys are updated using a symmetric key wrap
