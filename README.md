# We _Really_ Need to Talk About Session Tickets

Session tickets improve the TLS protocol performance and are therefore widely used. For this, the server encrypts secret state and the client stores the ciphertext and state. Anyone able to decrypt this ciphertext can passively decrypt the traffic or actively impersonate the TLS Server on resumption. To estimate the dangers associated with session tickets, we perform the first systematic large-scale analysis of the cryptographic pitfalls of session ticket implementations.

We found significant differences in session ticket implementations and critical security issues in the analyzed servers. Vulnerable servers used weak keys or repeating keystreams in the used tickets. Among others, our analysis revealed a widespread implementation flaw within the Amazon AWS ecosystem that allowed for passive traffic decryption for at least 1.9% of all servers in the Tranco Top 100k servers.


## Full Technical Paper

[*We Really Need to Talk About Session Tickets: A Large-Scale Analysis of Cryptographic Dangers with TLS Session Tickets*](https://www.usenix.org/conference/usenixsecurity23/presentation/hebrok);
Sven Hebrok, Simon Nachtigall, Marcel Maehren, Nurullah Erinola, Robert Merget, Juraj Somorovsky, Jörg Schwenk;
Usenix Security 2023

## Blog Posts

[We Really Need to Talk About Session Tickets](https://upb-syssec.github.io/blog/2023/session-tickets/);
Sven Hebrok;
2023

## Presentations

- RuhrSec 2023 (video and slides TBA)

## Am I Affected? / Using this Artefact

_This Artefact will be merged into [TLS-Scanner] and [TLS-Anvil] in the future. For now, use the [sessionticket-ae branch](https://github.com/tls-attacker/TLS-Scanner/tree/sessionticket-ae). The submodule in this repository already links to a stable version of this branch._

To check whether you are affected, the best thing to do is to actually check the keys used on your server.
The second-best thing is to use our scanner.
We extended [TLS-Scanner] to include tests for the vulnerabilities presented in our paper.
You first need to build the scanner (or get its docker image) and then run it against your server.
Then there are two parameters you might want to pass to the scanner:
- `-connect [host]` This is required and specifies which host (including port) to scan
- `-scanDetail NORMAL` This specifies in which depth the tests should be performed. A higher detail takes more time, but might reveal more issues. We used `DETAILED` for our experiments, but `NORMAL` should be sufficient for most cases.

### Running with Docker

To run the scanner using docker, you have two options:
Build the docker image locally, or use the prebuilt image from [dockerhub](https://hub.docker.com/r/snhebrok/tls-scanner-ae).
- To build the docker image yourself, use `docker build` from within TLS-Scanner.
- To use the prebuilt image, simply use `docker run` which will download the image.

```sh
# only if you want to build the image yourself
cd TLS-Scanner && docker build -t snhebrok/tls-scanner-ae .
# run the scanner (also pulls the image if it does not exist)
docker run --rm -it snhebrok/tls-scanner-ae -connect [host] -scanDetail NORMAL
```

**NB:** When using docker, `127.0.0.1` is not the localhost of your host machine. That is, you do not reach servers you have running on your PC this way. You have to use `172.17.0.1` (or any other IP address of your host machine) instead.

### Running from Source

To run the scanner from source, you need to have Java 11 and maven installed.
For more details about the TLS-Attacker projects, we recommend looking at the [TLS-Attacker-Description] repository.
To compile the scanner use maven:

```sh
cd TLS-Scanner
mvn clean package -DskipTests=true
java -jar apps/TLS-Server-Scanner.jar -connect [host] -scanDetail NORMAL
```

**If you encounter errors, check that you are using Java 11.**
`java --version` should return something like `openjdk 11.0.19`.

### Interpreting the Output Summary

![Sample output of a server not showing immediate flaws](img/normal_output.png)

The scanner summarizes the most relevant information under `SessionTicketEval`>`Summary`.
If your server does not support session tickets, that server is safe.
If it does support session tickets, the following properties should be `false`:
- `Ticket contains plain secret`
    - If `true`, the scanner found a sensitive session secret in a ticket sent by the server. In TLS 1.2 this means, that any network adversary can read this secret directly.
- `Ticket use default STEK (enc)`
    - If `true`, the scanner found the key and format to decrypt a ticket. The key (STEK) should always be chosen randomly. Again, a network adversary can recover the secret.
- `Ticket use default STEK (MAC)`
    - If `true`, the scanner found the key and format compute the mac for a ticket. The key (STEK) should always be chosen randomly. This might allow an attacker to mount different attacks like a padding oracle attack. In any case this signals an underlying issue.
- `No (full) MAC check`
    - If `true`, the scanner determined, that the server does not fully ensure the authenticity of the ticket. This might lead to a padding oracle attack. In any case this signals an underlying issue.
- `Vulnerable to Padding Oracle`
    - If `true`, the scanner was able to determine the last two plaintext bytes of the ticket by abusing a padding oracle attack. This means an attacker could use this to decrypt tickets, and again recover the contained secret.

The scanner also outputs further information about the tested and discovered issues.
We show two examples in the artefact evaulation experiments below.

## Artefact Evaluation Experiments

For the Artefact Evaluation we propose two experiments to show that we can detect default key material, as well as ticket authentication issues including padding oracle vulnerabilities.
To run the experiments, you need to have a server running.
Our experiments are designed to be used with the testserver in this repository.

### Test Server setup

To run the test server, you can either run it from source, or use docker.

#### Running from Source

To build the test server, we refer you to the [BUILDING.md](testserver/BUILDING.md) contained in the testserver directory.

#### Running with Docker

To run the test server using docker, you have two options:
Build the docker image locally, or use the prebuilt image from [dockerhub](https://hub.docker.com/r/snhebrok/vulnerable-bssl/tags).
- To build the docker image yourself, use `docker build` from within TLS-Scanner.
- To use the prebuilt image, simply use `docker run` which will download the image.

```sh
# only if you want to build the image yourself
cd testserver && docker build -t snhebrok/vulnerable-bssl:sessionticket-ae .
# run the server (also pulls the image if it does not exist)
# additional parameters as per experiment
docker run --rm  -it -p8000:8000 snhebrok/vulnerable-bssl:sessionticket-ae s_server -accept 8000 -loop -www <additional-parameters>
```

**NB:** When using docker, `-p8000:8000` maps the port 8000 of the container to the port 8000 of the host. This way, the server is reachable at `localhost:8000`.

**NB:** When using docker, Control+C does not work; you'll have to kill the container using `docker kill [container-id]`.


### E: Basic Experiment Structure

For all experiments you need to run the scanner against the TLS server.
Depending on the experiment, the server needs to be configured differently.
We'll provide a complete command to run the server for each experiment (using docker).
When the server is running, start the scanner:

```sh
# from source
java -jar apps/TLS-Server-Scanner.jar -connect [host] -scanDetail NORMAL
# with docker
docker run --rm -it snhebrok/tls-scanner-ae -connect [host] -scanDetail NORMAL
```


### E1: Detecting default keys (5+5 minutes)

**Setup** Run the test server with the following parameters:
```
docker run --rm  -it -p8000:8000 snhebrok/vulnerable-bssl:sessionticket-ae s_server -accept 8000 -loop -www \
    -ticketEnc AES-256-CBC -ticketHMac None
```

**Expected Result** The scanner should report the following:
```
Ticket use default STEK (enc)	 : true
Ticket use default STEK (MAC)	 : true
```
Further down, you'll find details about the discovered STEK, contained secret, algorithm, and format.

![Details about the used default STEK for encryption and MAC](img/default_stek.png)

**Manual Attack using OpenSSL**
You can also perform this attack manually using OpenSSL to validate the result of the scanner.
For this you have to perform three steps:


1. Connect to the server and store the session state
    - `openssl s_client -connect [host] -sess_out /tmp/session.cache`
    - You can connect via TLS 1.2 by passing `-tls1_2`.
    - For TLS 1.3 you might need to send `GET / HTTP/1.1` to the server before getting a ticket.
2. Inspect the stored session and take note of the associated secret.
    - `Resumption PSK` (TLS 1.3)/`Master-Key` (TLS1.2)
    - `openssl sess_id -noout -text -in /tmp/session.cache`
3. Decrypt the session ticket.
```sh
openssl sess_id -noout -text -in /tmp/session.cache | grep '[[:space:]]00' | \
    cut -f 7-21 -d" " | sed 's/[^a-f0-9]//g' | tr -d '\r\n' | cut -c1- | \
    xxd -r -p | openssl aes-128-cbc -d -K '00' -iv  '00' -nopad -v -nosalt | xxd -p
```
This command extracts the session ticket from the session cache and decrypts it using openssl AES-128-CBC with a all zero key (and IV).
The decryption is then formatted as a hexdump.
This hexdump, should contain the secret from step 2.

### E2: Detecting missing authentication and padding oracles (5+10 minutes)

**Setup** Run the test server with the following parameters:
```
docker run --rm  -it -p8000:8000 snhebrok/vulnerable-bssl:sessionticket-ae s_server -accept 8000 -loop -www \
    -ticketEnc AES-128-CBC -ticketEncKey 00 \
    -ticketHMac SHA256 -ticketHMacKey 00 -ticketHMacKeyLen 32
```

**Expected Result** The scanner should report the following:
```
No (full) MAC check		 : true
Vulnerable to Padding Oracle	 : true
```

Further down, you'll find details about the server's behavior when modifying the ticket and when trying to run a padding oracle attack.

The section *Manipulation* covers the behaviour when indusing bitflips into the ticket.
Several behaviors are pre-classified:

- `A`: The ticket was accepted.
- `\#`: The ticket was accepted, but keymaterial unknown to the scanner was used. That is, the server recovered some corrupted key material from the ticket.
- `_`: The ticket was rejected and a normal handshake was performed. **This is the expected good behavior.** This should be the case if the authenticity of the ticket is properly ensured.
- All other charachters are explained in the output.

Further down is a subsection *Padding Oracle* which contains details stating at which position the oracle was found.
This also includes the recovered plaintext, as well as what value was XOR-ed at which position to recover this value.
Further down is a summary of the observed behavior difference per offset (when modifying the last byte).
Note that multiple offsets might show different behavior, but not all are necessarily a valid padding oracle vulnerability.
This is internally verified by trying to recover the second byte. As the overall result is `TRUE`, this second byte was found.

![Details about missing authentication and padding oracle vulnerability](img/padding_oracle.png)



[TLS-Attacker-Description]: https://github.com/tls-attacker/TLS-Attacker-Description
[TLS-Scanner]: https://github.com/tls-attacker/TLS-Scanner
[TLS-Anvil]: https://github.com/tls-attacker/TLS-Anvil
