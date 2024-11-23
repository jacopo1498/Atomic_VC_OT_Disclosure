
//this function signs an vc with the private key that is associated to his did, this makes it possible to link an atomic vc to the subject

import {Resolver} from 'did-resolver'
import { EthrDID } from 'ethr-did'
//import wallet from 'ethereumjs-wallet'
import { ES256KSigner, createJWS, verifyJWS } from 'did-jwt';
//handle the creation of VC with atomic method for selective disclosure
import * as Atomic from '../atomic/Atomic';
import {verifyContext, verifyExpiration, verifyIssuedAt, verifyUniqueID } from "./utilis" 
import { jwtDecode , JwtPayload} from "jwt-decode";
//for decoding jws payload
import { v4 as uuidv4 } from 'uuid'; // For generating unique IDs

const usedIDs = new Set<string>(); // Replace with a persistent storage in real sceanario


/**
 * 
 * it basically does something like this:
 * {
        "original jwt (with no dots)": "eyJhbGciOiJFUzI1NksifQ.eyJzdWIiOiJkaWQ6ZXhhbXBsZToxMjM0NTY3ODkiLCJ2YyI6InRlc3QifQ.nDlJqhZWF9mcZyT7o78eFz8F_4",
        "jti": 1
        "iat": 1699999999,       // Timestamp (issued at time)
        "exp": 1700000999,       // Expiry time
        "context": "transaction-id-456"  // Context-specific data

        "signature": "AbCdEfGhIjKlMnOpQrStUvWxYz123456"  (JWS)
    }
    JWS contains heade.payload.signature the payload and the header is protected by the singature
       

    so inside the JWS there is the encoded data that is protected by the DS

    standard:  RFC 7519 (JSON Web Token) and RFC 7515 (JSON Web Signature).
    the singature includes not only the original jwt but also the iat, exp and context to prevent reuse
    try to change iat and exp to re-send old signature -> detected
    try to change context to reuse the signature for a different sender -> detected

    base64url -> the '+' and '/' characters of standard Base64 are respectively replaced by '-' and '_'
 */



export async function signJWTsWithSubjectKey(
{ VC, subjectPrivateKey, subDID, audience }: { VC: string[]; subjectPrivateKey: string; subDID: EthrDID; audience: string},
): Promise<string[]> {
    
    //TODO check if you have everithing you need
    const signedJWTs: string[] = [];
    
    // subjectDID.signer ? can i get from here?
    // Create a signer using the subject's private key  do i need this?
    let signerSub = ES256KSigner(Buffer.from(subjectPrivateKey.slice(2), 'hex'),false);

    for (const vcJwt of VC) {
        //console.log("\x1b[42m","verified credential:");
        //console.log(vcJwt,'\x1b[0m')
        //let decoded = didJWT.decodeJWT(vcJwt)
        //console.log(decoded)

        // Parse the JWT header and payload (leave the original signature intact)
        //const [header, payload, signature] = vcJwt.split('.');
        // Define the header
        const header = {
            alg: 'ES256K', // Algorithm
            type: 'JWT',    // Type
        };

        const uniqueid = uuidv4();
        const issued = Math.floor(Date.now() / 1000);
        const expiration = issued + (60 * 5);
        const  additionalPayload = { jti: uniqueid, iat: issued, exp: expiration, context: audience }; //prepare the ds data to be retrived from jwt
        // Replace dots in the original JWT (. messes up with the jws)
        const originalJWTWithoutDots = vcJwt.replace(/\./g, '|');
        // Prepare the payload
        const payload = {
            originalJWT: originalJWTWithoutDots,
            ...additionalPayload, // Add the `jti`, `iat`, `exp`, and `context` fields
        };


        // Create a new signature for the payload-signature combo (protects integrity of issuer signature, just for safety) 
        const newSignature = await createJWS(payload, signerSub, header); //if you use "." i think it messes with the decoding in the verifier 
        //console.log("\x1b[44m","payload:"+payload,'\x1b[0m');

        // sign the original JWT and add a header, contails algoritm used 
        const multiSigJWT = JSON.stringify({
            additionalSignatures: [
            {
                header: { 
                    alg: "ES256K",
                    type: "JsonWebSignature"
                },
                signature: newSignature,
            },
            ],
        });
    
        signedJWTs.push(multiSigJWT);
        }
    
    return signedJWTs;
}





export async function verifyMultiSigJWT(
{ multiSigJWT, didResolver, expectedContext }: { multiSigJWT: string; didResolver: Resolver; expectedContext: string;}   
): Promise<boolean> {

    interface MySign {
        jti: string;
        iat: number;
        exp: number;
        context: string;
        originalJWT: string;
    }
      

    try {
        // Parse the multi-signature structure
        const parsedJWT = JSON.parse(multiSigJWT);
        const { additionalSignatures } = parsedJWT;

        if (!additionalSignatures || additionalSignatures.length === 0) {
            throw new Error('No additional signatures found');
        }

      

        for (const { header: additionalHeader, signature: additionalSignature } of additionalSignatures) {
           
            const decodedJWSPayload = jwtDecode<MySign>(additionalSignature);
            console.log("\x1b[42m",'Payload of the JWS:','\x1b[0m');
            console.log(decodedJWSPayload);

            const originalJWTencoded = (decodedJWSPayload.originalJWT as string).replace(/\|/g, '.');
            const originalJWT = jwtDecode(originalJWTencoded);
            const subject = originalJWT.sub;

            if (!subject) {
                throw new Error("subject not extracted");
            }

            const didResult = await didResolver.resolve(subject);
            const didDocument = didResult.didDocument; //get the did document 

            if (!didDocument) {
                throw new Error(`DID Document not found for ${subject}`);
            }

            // Find the public key in the DID Document
            const publicKey = didDocument.verificationMethod?.find(
                (method) => method.id === subject+"#controllerKey"
            );

            if (!publicKey) {
                throw new Error(`Public key not found for kid: ${subject}`);
            }

            // ---Verify the additional signature
            const isAdditionalValid = verifyJWS(
                `${additionalSignature}`, //additional signature is basically another jwt: header.payload.signature
                publicKey
            );
            //Verifies given JWS. If the JWS is valid, returns the public key that was used to sign the JWS, or throws an Error if none of the pubKeys match.
            if (!isAdditionalValid) {
                throw new Error(`Additional signature for ${subject} is invalid`);
            }
            //check everything
            if (!verifyExpiration(decodedJWSPayload.exp)) {
                throw new Error("The JWS has expired.");
            }
            if (!verifyIssuedAt(decodedJWSPayload.iat)) {
            throw new Error("The JWS issue time is invalid or outside the allowed skew.");
            }
            if (!verifyContext(decodedJWSPayload.context, expectedContext)) {
            throw new Error("The context does not match the expected value.");
            }  
            if (!verifyUniqueID(decodedJWSPayload.jti, usedIDs)) {//add the nonce to the set of used nonces
                throw new Error("The unique NONCE (jti) has been reused. Possible replay attack.");
            }
            console.log("\x1b[44m","Subject singature valid and verified",'\x1b[0m');
            console.log(isAdditionalValid);


            //  Verify the original JWT
            const isOriginalValid = await Atomic.verifysingleVC(originalJWTencoded, didResolver);
            if (!isOriginalValid) {
                throw new Error('Issuer signature is invalid');
            }
            console.log("\x1b[44m","original Vc jwt singature verified",'\x1b[0m');


            console.log("\x1b[44m","\nverification of Issuer and Subject signature succeded!\n",'\x1b[0m');
        }

    // If all checks pass, the multi-signature JWT is valid
    return true;
    } catch (error: any) {
    console.error('Verification failed:', error.message);
    return false;
    }
}
