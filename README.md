> WARNING: This software is a proof of concept only and is not secure. Do not
> use this software! Attempting to use it WILL cause loss of your passwords
> and worse. I'm not joking. Don't use it.

# Kerberos PAKE
##### What is PAKE?
PAKE stands for Password Authenticated Key Exchange. It is essentially a
method to parlay a cryptographically strong session key between two entities
from a password. PAKE algorithms are usually a varient of a Diffie-Hellman Key
Exchange which in some way incorporates password material.

##### Why is PAKE interesting to Kerberos?
1. In the default Kerberos setup, offline dictionary attacks are possible
   (but difficult). PAKE mitigates this.
2. PAKE does not depend on clock synchronization such as is used in the
   default encrypted timestamp preauthentication mechanism.
3. Like existing methods, PAKE never sends passwords over the wire.
4. PAKE can be used to establish an encrypted channel for sending other
   sensitive material, like second factors.

##### What PAKE algorithms does Kerberos PAKE support?
* [SPAKE]
* [JPAKE]

##### What elliptic curves/hashes does Kerberos PAKE support?
Whatever is supported by your distribution of OpenSSL. This is likely to be
narrowed in the future. However, most distributions of OpenSSL include
support for the standard NIST curves.

##### What other features does Kerberos PAKE implement?
Currently: none. Just basic authentication is working. As a proof of concept,
we are focusing on the bare minimum. However, encrypted second factor support
is highly desired and will likely be implemented soon.

##### What client features does Kerberos PAKE require?
1. The client must respect PA-FX-COOKIE and properly return it to the KDC.
2. The client must be able to properly handle the
   [KDC_ERR_MORE_PREAUTH_REQUIRED] error code.

##### How does Kerberos PAKE work?
1. The client sends an AS-REQ to the server, including its supported
   encryption types. This is standard client behavior.

2. The KDC sends a PAKEInfo PA data parameter. This contains information on
   supported parameters for the exchange derived from the client-supported
   encryption types. This includes both hash algorithms and supported elliptic
   curves.

3. The client chooses an encryption type from the KDC returned
   PA-ENCTYPE-INFO2. This is standard client behavior. Then the client selects
   a matching PAKE configuration. Finally, the client begins the exchange
   process using the selected configuration by sending a message to the KDC.

4. At this point the KDC and client begin a series of roundtrips which are
   dependent on the PAKE algorithm selected. The KDC indicates to the client
   to continue the conversation by sending more PAKEData PA data in a
   KDC_ERR_MORE_PREAUTH_REQUIRED KrbError message.

5. Once the client has completed the PAKE exchange, it sends a PAKEVerifier PA
   data in a final AS-REQ. The KDC validates the client's authentication and
   issues a TGT encrypted in the exchanged session key.

6. The exchanged session key is not just the naked ellpitic curve point
   exchanged throughout the algorithm. This is derived with other data,
   including:
     * The client principal.
     * The TGS principal.
     * A hash of all the PA data sent over the wire. This prevents any
       downgrade attacks and ensures that all public keydata is incorporated
       into the final key.

For more details, see the Kerberos PAKE [ASN1] module. An internet draft is
hopefully coming soon.

##### What outstanding questions remain?
1. We currently enable MD5, but this is generally a bad idea. This is enabled
   because currently the code requires hash algorithms to produce the same
   length as the keys. Unfortunately, only MD5 and MDC2 produce 128-bit hashes.
   Without one of these (MD5 or MDC2) enabled, only 256-bit keys will be usable
   with Kerberos PAKE. Using 256-bit keys also forces Kerberos PAKE to use
   large curves (usually NIST P521) that are more computationally expensive.

2. Currently, we don't derive distinct keys for verifiers, session key and
   (future) encrypted second factors. I just haven't gotten around to it.

3. SPAKE support currently uses a different set of constants than those defined
   in [SPAKE]. In particular, we use OIDs in generating the constants rather
   than elliptic curve names. This is because many curves have multiple names,
   leading to ambiguity.

4. Support for encrypted second factors is a high priority.




[SPAKE]: https://tools.ietf.org/html/draft-irtf-cfrg-spake2-00
[JPAKE]: http://en.wikipedia.org/wiki/Password_Authenticated_Key_Exchange_by_Juggling
[ASN1]: https://github.com/npmccallum/krb5-pake/blob/master/KerberosPAKE.asn1
[KDC_ERR_MORE_PREAUTH_REQUIRED]: https://github.com/krb5/krb5/pull/245
