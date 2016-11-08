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
    <version>4.5.70</version>
</dependency>

<dependency>
    <groupId>com.guardtime</groupId>
    <artifactId>ksi-service-client-simple-http</artifactId>
    <version>4.5.70</version>
</dependency>
```
If you need the latest version, download the source and build using Maven.

## Usage ##

In order to get trial access to the KSI platform, go to [https://guardtime.com/blockchain-developers](https://guardtime.com/blockchain-developers).

A simple example how to obtain a signature:
```java
HttpClientSettings clientSettings = new HttpClientSettings(
                "signing-service-url",
                "extending-service-url",
                "publications-file-url",
                KSIServiceCredentials,
                PduVersion);

SimpleHttpClient simpleHttpClient = new SimpleHttpClient(clientSettings);

KSI ksi = new KSIBuilder()
    .setKsiProtocolSignerClient(simpleHttpClient)
    .setKsiProtocolExtenderClient(simpleHttpClient)
    .setKsiProtocolPublicationsFileClient(simpleHttpClient)
    .setPublicationsFileTrustedCertSelector(new X509CertificateSubjectRdnSelector("E=test@test.com"))
    .build();

// synchronous signing
KSISignature sig1 = ksi.sign(new File("file.txt"));
// asynchronous signing
Future<KSISignature> future = ksi.asyncSign(new File("asyncFile.txt"));
KSISignature sig2 = future.getResult();
```
The API full reference is available here [http://guardtime.github.io/ksi-java-sdk/](http://guardtime.github.io/ksi-java-sdk/).

## Dependencies ##

See Maven pom.xml files or use the following Maven command
```
mvn dependency:tree
```

## Compatibility ##

Java 1.5 or newer.

## Contributing ##

See [CONTRIBUTING.md](CONTRIBUTING.md) file.

## License ##

See LICENSE file.
