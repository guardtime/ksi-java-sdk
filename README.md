# KSI Java SDK #
Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more,
see [https://guardtime.com](https://guardtime.com).

The KSI Java SDK is a software development kit for developers who want to integrate KSI with their Java based applications
and systems. It provides an API for all KSI functionality, including the core functions - signing of data, extending
and verifying the signatures.

## Installation ##

The latest stable binary releases are available at [http://search.maven.org](http://search.maven.org). Just include the
dependencies in your pom.xml:

```xml
<dependency>
    <groupId>com.guardtime</groupId>
    <artifactId>ksi-api</artifactId>
    <version>4.x.x</version>
</dependency>

<dependency>
    <groupId>com.guardtime</groupId>
    <artifactId>ksi-service-client-simple-http</artifactId>
    <version>4.x.x</version>
</dependency>
```
If you need the latest version, download the source and build using Maven.

## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

A simple example how to obtain a signature:
```java
CredentialsAwareHttpSettings settings = new CredentialsAwareHttpSettings("signing-service-url", KSIServiceCredentials);
SimpleHttpSigningClient signingClient = new SimpleHttpSigningClient(settings);

Signer signer = new SignerBuilder().setSigningService(new KSISigningClientServiceAdapter(signingClient)).build();

KSISignature signature = signer.sign(new File("file.txt"));
```
The API full reference is available at [http://guardtime.github.io/ksi-java-sdk/](http://guardtime.github.io/ksi-java-sdk/).
Sample codes for signing, extending and verification are available at
[https://github.com/guardtime/ksi-sdk-samples](https://github.com/guardtime/ksi-sdk-samples).


## Compiling the Code ##
To compile the code you need JDK 1.7 (or later) and [Maven](https://maven.apache.org/).
The project can be built via the command line by executing the following maven command:
```
mvn clean install
```
This command tells Maven to build all the modules, and to install it in the local repository. This command also runs all
integration and unit tests. In order to run the integration tests successfully you need to have access to KSI
service, the simplest is to request a trial account here [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).
Add the KSI configuration to the file "ksi-api/src/test/resources/integrationtest.properties" (see file
"ksi-api/src/test/resources/integrationtest.properties.sample" for more information).

You can also skip the integration tests by executing the following command:
```
mvn clean install -DskipITs
```

You can skip unit and integration tests by executing the following command:
```
mvn clean install -DskipTests -DskipITs
```

## Dependencies ##

See Maven pom.xml files or use the following Maven command
```
mvn dependency:tree
```

## Compatibility ##

Java 1.7 or newer.

## Contributing ##

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

## License ##

See LICENSE file.
