import { computePublicKey } from "@ethersproject/signing-key";
import { ES256KSigner } from "did-jwt";
import { JsonRpcSigner } from "ethers";
import { EthrDID } from "ethr-did";
import { provider } from "./createAtomicVC";
import { getPrivateKeyHardhat } from "./getPrivateKeyHardhat";

//function to create and return the object used to manage a DID
export const createDid = async (RegAddress: string, accountAddress: JsonRpcSigner, index: number, chainId = '0x7a69') => {

    //TODO make something that obtains key from accountaddress
    const privateKey = await getPrivateKeyHardhat(index);
    if (!privateKey) {
        console.error("error PrivateKey retrival.");
        return;
    }
    const publicKey = computePublicKey(privateKey, true);
    console.log("Public Key: " + publicKey);
    console.log("Private Key: " + privateKey);
    const identifier = `did:ethr:${chainId}:${publicKey}`;
    const signer = await provider.getSigner(index);
    let signJ = ES256KSigner(Buffer.from(privateKey.slice(2), 'hex'), false);

    const ethrDid = new EthrDID({
        txSigner: signer,
        //privateKey : privateKey,
        signer: signJ,
        identifier: identifier,
        registry: RegAddress,
        chainNameOrId: chainId,
        alg: 'ES256K',
        provider
    });

    console.log("DID created:", ethrDid.did);

    return ethrDid;
};
