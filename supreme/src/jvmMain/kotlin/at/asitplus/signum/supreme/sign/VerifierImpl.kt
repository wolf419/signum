package at.asitplus.signum.supreme.sign

import at.asitplus.catchingUnwrappedAs
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.indispensable.jcaAlgorithmComponent
import at.asitplus.signum.indispensable.jcaPSSParams
import at.asitplus.signum.indispensable.jcaSignatureBytes
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.Digest
import iaik.security.pq.mldsa.MLDSAPublicKey
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import kotlin.Throws
import kotlin.sequences.forEach

/**
 * Configures JVM-specific properties.
 * @see provider
 */
actual class PlatformVerifierConfiguration internal actual constructor() : DSL.Data() {
    /** The JCA provider to use, or none. */
    var provider: String? = null
}

private fun getSigInstance(alg: String, p: String?) =
    when (p) {
        null -> Signature.getInstance(alg)
        else -> Signature.getInstance(alg, p)
    }

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByMLDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.MLDSA, publicKey: CryptoPublicKey.ML,
             config: PlatformVerifierConfiguration) {
            }

internal actual fun verifyMLDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.MLDSA, publicKey: CryptoPublicKey.ML,
             data: SignatureInput, signature: CryptoSignature.ML,
             config: PlatformVerifierConfiguration) {
                if (publicKey.variant != signatureAlgorithm.variant)
                    throw InvalidKeyException("Specified variant does not match key")

                getSigInstance("ML-DSA", config.provider).run {
                    initVerify(publicKey.toJcaPublicKey().getOrThrow())
                    data.data.forEach(this::update)
                    val success = verify(signature.rawByteArray)
                    if (!success)
                        throw InvalidSignature("Signature is cryptographically invalid")
                }
            }

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByECDSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             config: PlatformVerifierConfiguration)
{
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        getSigInstance("${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA", config.provider)
            .initVerify(publicKey.toJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyECDSAImpl
            (signatureAlgorithm: SignatureAlgorithm.ECDSA, publicKey: CryptoPublicKey.EC,
             data: SignatureInput, signature: CryptoSignature.EC,
             config: PlatformVerifierConfiguration)
{
    val (input, alg) = when {
        (data.format == null) -> /* input data is not hashed, let JCA do hashing */
            Pair(data, "${signatureAlgorithm.digest.jcaAlgorithmComponent}withECDSA")
        else -> /* input data is already hashed, request raw sig from JCA */
            Pair(data.convertTo(signatureAlgorithm.digest).getOrThrow(), "NONEwithECDSA")
    }
    getSigInstance(alg, config.provider).run {
        initVerify(publicKey.toJcaPublicKey().getOrThrow())
        input.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}

private fun getRSAInstance(alg: SignatureAlgorithm.RSA, config: PlatformVerifierConfiguration) =
    when (alg.padding) {
        RSAPadding.PKCS1 -> getSigInstance(
            "${alg.digest.jcaAlgorithmComponent}withRSA", config.provider)
        RSAPadding.PSS -> getSigInstance("RSASSA-PSS", config.provider).apply {
            setParameter(alg.digest.jcaPSSParams)
        }
    }

@Throws(UnsupportedCryptoException::class)
internal actual fun checkAlgorithmKeyCombinationSupportedByRSAPlatformVerifier
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             config: PlatformVerifierConfiguration) {
    catchingUnwrappedAs(a=::UnsupportedCryptoException) {
        getRSAInstance(signatureAlgorithm, config)
            .initVerify(publicKey.toJcaPublicKey().getOrThrow())
    }.getOrThrow()
}

@JvmSynthetic
internal actual fun verifyRSAImpl
            (signatureAlgorithm: SignatureAlgorithm.RSA, publicKey: CryptoPublicKey.RSA,
             data: SignatureInput, signature: CryptoSignature.RSA,
             config: PlatformVerifierConfiguration)
{
    getRSAInstance(signatureAlgorithm, config).run {
        initVerify(publicKey.toJcaPublicKey().getOrThrow())
        data.data.forEach(this::update)
        val success = verify(signature.jcaSignatureBytes)
        if (!success)
            throw InvalidSignature("Signature is cryptographically invalid")
    }
}
