
//this function signs an vc with the private key that is associated to his did, this makes it possible to link an atomic vc to the subject

import {Resolver} from 'did-resolver'
import { EthrDID } from 'ethr-did'
//import wallet from 'ethereumjs-wallet'
import { Signer, ES256KSigner, createJWS, verifyJWS } from 'did-jwt';
//handle the creation of VC with atomic method for selective disclosure
import * as Atomic from '../atomic/Atomic';


/**
 * 
 * it basically does something like this:
 * {
    "originalJWT": "eyJhbGciOiJFUzI1NksifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZToxMjM0NTY3ODkiLCJ2YyI6InRlc3QifQ.nDlJqhZWF9mcZyT7o78eFz8F_4",
    "additionalSignatures": [
        {
        "header": {
            "alg": "ES256K",
            "kid": "did:example:123456789abcdef#keys-1"
        },
        "signature": "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        }
      ]
    }
 */
export async function signJWTsWithSubjectKey(
    vcResult: string[],
    subjectPrivateKey: string,
    subjectDID: EthrDID
    ): Promise<string[]> {
    
    const signedJWTs: string[] = [];
    
    // subjectDID.signer ? can i get from here?
    // Create a signer using the subject's private key  do i need this?
    let signerSub = ES256KSigner(Buffer.from(subjectPrivateKey.slice(2), 'hex'),false);

    for (const vcJwt of vcResult) {
        //console.log("\x1b[42m","verified credential:");
        //console.log(vcJwt,'\x1b[0m')
        //let decoded = didJWT.decodeJWT(vcJwt)
        //console.log(decoded)

        // Parse the JWT header and payload (leave the original signature intact)
        const [header, payload, signature] = vcJwt.split('.');
        
        // Create a new signature for the payload-signature combo (protects integrity of issuer signature, just for safety) 
        const newSignature = await createJWS(`${header}${payload}${signature}`, signerSub); //if you use "." i think it messes with the decoding in the verifier 
        //console.log("\x1b[44m","payload:"+payload,'\x1b[0m');
        // Wrap the original JWT and additional signature in a new structure
        const multiSigJWT = JSON.stringify({
            originalJWT: vcJwt,
            additionalSignatures: [
            {
                header: { kid: `${subjectDID.did}#keys-1` }, // Ensure kid is included
                signature: newSignature,
            },
            ],
        });
    
        signedJWTs.push(multiSigJWT);
        }
    
    return signedJWTs;
    }

export async function verifyMultiSigJWT(
    multiSigJWT: string,
    didResolver: Resolver
    ): Promise<boolean> {
    try {
        // Parse the multi-signature structure
        const parsedJWT = JSON.parse(multiSigJWT);
        const { originalJWT, additionalSignatures } = parsedJWT;

        if (!originalJWT || typeof originalJWT !== 'string') {
            throw new Error('Invalid or missing originalJWT');
            }

        if (!additionalSignatures || additionalSignatures.length === 0) {
            throw new Error('No additional signatures found');
        }

        // 1. Verify the original JWT
        const isOriginalValid = await Atomic.verifysingleVC(originalJWT, didResolver);
        if (!isOriginalValid) {
            throw new Error('Issuer signature is invalid');
        }
            
        // Split the original JWT
        const [header, payload, signature] = originalJWT.split('.');
        // Decode and parse the payload to get the subject DID
        const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());

        for (const { header: additionalHeader, signature: additionalSignature } of additionalSignatures) {
            const additionalKid : string = additionalHeader.kid;
            //do i take tht subject id from the additional header or the sub field in the payload? maybe check with "internal sub"

            if (!additionalKid) {
                throw new Error('Missing kid in additional signature header');
                }
            
            // Resolve the DID in the kid field
            const additionalDid = additionalKid.split('#')[0];
            // console.log(payload.sub)
            const didResult = await didResolver.resolve(additionalDid);
            const didDocument = didResult.didDocument;

            if (!didDocument) {
                throw new Error(`DID Document not found for ${additionalDid}`);
            }

            // Find the public key in the DID Document
            const publicKey = didDocument.verificationMethod?.find(
                (method) => method.id === additionalDid+"#controllerKey"
            );

            if (!publicKey) {
                throw new Error(`Public key not found for kid: ${additionalKid}`);
            }


            // Verify the additional signature
            const isAdditionalValid = verifyJWS(
                `${additionalSignature}`, //additional signature is basically another jwt: header.payload.signature
                publicKey
            );

            //Verifies given JWS. If the JWS is valid, returns the public key that was used to sign the JWS, or throws an Error if none of the pubKeys match.
            if (!isAdditionalValid) {
                throw new Error(`Additional signature for ${additionalKid} is invalid`);
            }
            console.log("\x1b[44m","verification of Issuer and Subject signature succeded!",'\x1b[0m');
            console.log(isAdditionalValid);
        }

    // If all checks pass, the multi-signature JWT is valid
    return true;
    } catch (error: any) {
    console.error('Verification failed:', error.message);
    return false;
    }
}
