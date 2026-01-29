package at.asitplus.signum.supreme.sign

import de.infix.testBalloon.framework.core.testSuite
import at.asitplus.signum.indispensable.*
import at.asitplus.testballoon.*
import kotlin.random.Random
import at.asitplus.signum.supreme.*
import io.kotest.matchers.shouldBe

val SignerMLDSATest by testSuite {
    "MLDSA sign/verify roundtrip" {

        // Random message
        var message = Random.nextBytes(256)

        // Create ephemeral key
        val key = EphemeralKey { ml { variant = MLDSAVariant.MLDSA65 } }.getOrThrow()

        // Create signer from that key
        val signer = key.signer { ml { } } .getOrThrow()

        // Sign message
        val sig = signer.sign(message).signature

        // Verify message
        val verifier = SignatureAlgorithm.MLDSA(null, MLDSAVariant.MLDSA65).verifierFor(key.publicKey).getOrThrow()
        val success = verifier.verify(message, sig)
        success.isSuccess shouldBe true
    }

//    "Pre-Hash MLDSA sign/verify roundtrip" {
//
//        // Random message
//        var message = Random.nextBytes(256)
//
//        // Create ephemeral key
//        val key = EphemeralKey { ml { variant = MLDSAVariant.MLDSA44} }.getOrThrow()
//
//        // Create signer from that key
//        val signer = key.signer { ml {} } .getOrThrow()
//
//        // Sign message
//        val sig = signer.sign(message).signature
//
//        // Verify message
//        val verifier = SignatureAlgorithm.MLDSA(null, MLDSAVariant.MLDSA87).verifierFor(key.publicKey).getOrThrow()
//        val success = verifier.verify(message, sig)
//        println(success)
//    }

}
