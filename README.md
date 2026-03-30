# aap-protocol — Java SDK

**Agent Accountability Protocol · Java 11+ · Bouncy Castle Ed25519**

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![tests](https://img.shields.io/badge/tests-22%2F22-brightgreen)](https://github.com/halyndev/aap-java)

```xml
<dependency>
  <groupId>dev.aap</groupId>
  <artifactId>aap-protocol</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
import dev.aap.crypto.KeyPair;
import dev.aap.identity.Identity;
import dev.aap.authorization.Authorization;
import dev.aap.authorization.Level;
import dev.aap.audit.AuditChain;
import dev.aap.audit.AuditResult;
import dev.aap.provenance.Provenance;
import dev.aap.errors.PhysicalWorldViolation;

KeyPair supervisor = KeyPair.generate();
KeyPair agent      = KeyPair.generate();

Identity identity = Identity.create(
    "aap://acme/worker/bot@1.0.0",
    List.of("write:files"),
    agent, supervisor, "did:key:z6Mk"
);

Authorization auth = Authorization.create(
    identity.id, Level.SUPERVISED,
    List.of("write:files"),
    false, supervisor, "did:key:z6Mk"
);

// Physical World Rule
try {
    Authorization.create("aap://factory/robot/arm@1.0.0",
        Level.AUTONOMOUS, List.of("move:arm"),
        true, supervisor, "did:key:z6Mk");
} catch (PhysicalWorldViolation e) {
    // AAP-003: Level 4 forbidden for physical nodes. Not configurable.
}

Provenance prov = Provenance.create(identity.id, "write:file",
    "input".getBytes(), "output".getBytes(), auth.sessionId, agent);

AuditChain chain = new AuditChain();
chain.append(identity.id, "write:file", AuditResult.SUCCESS,
    prov.artifactId, agent, auth.level, false);

AuditChain.VerifyResult v = chain.verify();
System.out.println("valid=" + v.valid + " entries=" + v.count);
```

```bash
mvn test    # 22/22 tests passing
mvn exec:java -Dexec.mainClass=dev.aap.Quickstart
```

**[AAP Spec](https://aap-protocol.dev) · [NRP](https://nrprotocol.dev) · [Halyn](https://halyn.dev)**

License: MIT
