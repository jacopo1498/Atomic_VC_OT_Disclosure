import { Resolver } from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { JsonRpcSigner } from 'ethers' 
//import wallet from 'ethereumjs-wallet'
const didJWT = require('did-jwt');
//this is necessary to retrive the privatekeys from hardhat accounts
//handle the creation of VC with atomic method for sleective disclosure
import * as Atomic from './atomic/Atomic';
//handle multigignature
import { listVCDetails, signJWTsWithSubjectKey, verifyMultiSigJWT } from './multiplesgn/multipleSgn';
import { getPrivateKeyHardhat } from './getPrivateKeyHardhat'
import { createDid } from './createDid'

const { ethers } = require("hardhat");
//this is necessary for ot... basically simulates communication with a dummy socket curtesy of wyatt-howe
var IO = require('./OT/io-example.js');
const ascii = require('./OT/ascii.ts');


function getDisclosedClaimsNumber(fract:number,claimsTot:number){
    if (fract==1){
        return claimsTot;
    }else{
        if(claimsTot<=3){
            return 1;
        }else{
            return Math.round(claimsTot*fract);
        }
    }
}

//setup the provider 
console.log('Connecting to provider...');
 
export const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
console.log('Connected to the provider');
//contract address of the registry
const RegAddress = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const chainId = 31337;

// Set up DID resolver
const ethrDidResolver = getResolver.getResolver(
    {
        rpcUrl: "http://127.0.0.1:8545",
        registry: RegAddress,
        chainId: chainId,
        provider
    }
);
const didResolver = new Resolver(ethrDidResolver)

//i only want this to generate atomic VC, timing stuff later
const test = async (accounts : JsonRpcSigner[]) => {
	let issuerAddress=accounts[0];
	let subjectAddress=accounts[1];
	let verifierAddress=accounts[2];

	console.log("Issuer EOA:"+issuerAddress.toString());
	console.log("Subject EOA:"+subjectAddress.toString());
	console.log("Verifier EOA:"+verifierAddress.toString());

	let issuerDID = await createDid(RegAddress, issuerAddress, 0);
	let subjectDID = await createDid(RegAddress, subjectAddress, 1);
	let verifierDID = await createDid(RegAddress, verifierAddress, 2);
    if (!issuerDID) {
        console.error("error creating Issuer DID");
        return;
    }if (!subjectDID) {
        console.error("error creating subject DID");
        return;
    }if (!verifierDID) {
        console.error("error creating verifier DID");
        return;
    }
    
 
    /** compared to a verifiable presentation with this solution we accept that the vc may come from different issuer but since we want only a claim ,
     * to gather data for some task, we only need the claim in question to be validated the recipient of each credential, 
     * i.e., the subject’s DID in the credential, matches the DID of the subject who sent the presentation; ->use somebody else vc? 
     * ideally there should be a way to identify subject before doing OT, or signing the VC before 
     * 
     * solution: signature with my PrK
     * */
    //also it would be nice if k-out of-n is possible, idea for the future for now 1-out of-n
	
    const maxClaims = 5;
    const disclosedClaimsPercent = 0.6; //from 0 to 1 (ex. 0.5 = 50%)
    const OT = require('1-out-of-n')(IO);
    const op_id = 'ot_atomic_vc'; 
    const rec_choise = 1;
    const receiver = "transaction_receiver-did"; //context for the digital signature, here the dids of the sender and receiver should be used to uniquely bind it to this session
    //receiver also knows the context, because i expect the incoming transaction to be for me...

    //Issuer Create VC
    console.log("\x1b[43m","---issuing new VC---",'\x1b[0m');
    let vcResult= await Atomic.issueVC(issuerDID,subjectDID,maxClaims); //returns an array of jwt

    //show a VC 
    console.log("\x1b[43m","Example:",'\x1b[0m');
    const decodedVC = didJWT.decodeJWT(vcResult[0]);
    console.log(decodedVC );
    const credentialSubject = decodedVC.payload.vc.credentialSubject;
    console.log("credentialSubject:");
    console.log(credentialSubject );
    console.log("\n");

    //Subject verify the VC
    console.log("\x1b[43m","---verifing all VC---",'\x1b[0m');
    await Atomic.verifyVC(vcResult,didResolver);

    //select a subset of vc's (jwt) 
    const disclosedClaimsn = getDisclosedClaimsNumber(disclosedClaimsPercent, maxClaims); //n. of claims to disclose,based on percenteage and n. of claims of this iteration
    const disclosedClaimstoSign = Atomic.getMultipleRandom(vcResult , disclosedClaimsn); //claims that i choose to disclose through ot

    //sign each vc with the private key associated to your did
    const subjectPrivateKey = await getPrivateKeyHardhat(1); //the owner of the did knows his private key
    const disclosedClaims = await signJWTsWithSubjectKey({ VC: disclosedClaimstoSign, subjectPrivateKey: subjectPrivateKey!, subDID: subjectDID, audience: receiver });

/*
    //check all VC
    for (let i = 0; i < signedJWTs.length; i++) {
        console.log("\x1b[42m",'Signed JWT by subject:','\x1b[0m');
        console.log(signedJWTs[i]);
        if(! await verifyMultiSigJWT({multiSigJWT: signedJWTs[i],didResolver: didResolver,expectedContext: receiver})){
            console.error("error in signature verification");
        }
    }
*/
    
    
    //start OT protocol
    console.log("\n \n");
    console.log("\x1b[31m","---start OT protocol---",'\x1b[0m');
    console.log("\n \n");

    OT.then(function (OT: { send: (arg0: Uint8Array[], arg1: number, arg2: string) => void; receive: (arg0: number, arg1: number, arg2: string) => Promise<Uint8Array> }) {
        /*
        *  The sender (vc holder) calls:
        */
        console.log ("\x1b[36m","sender shows avaliable VC to choose to Receiver",'\x1b[0m');
        listVCDetails(disclosedClaims);
        console.log("\n");
        console.log ("\x1b[36m","sender sends all VC through OT...",'\x1b[0m');
        OT.send(disclosedClaims.map(ascii.to_array) , disclosedClaimsn, op_id);
        console.log ("\x1b[36m","done!",'\x1b[0m');
        console.log("\n");

        /*
        *  The receiver calls:
        */
        OT.receive(rec_choise, disclosedClaimsn, op_id).then(async function (array: Uint8Array) {
            const received_vc : string = ascii.to_ascii(array);
            console.log("\x1b[35m","receiver obtains only one verified credential with ot, choise="+rec_choise,'\x1b[0m');
            console.log("\x1b[35m",'The received secret is:','\x1b[0m', received_vc);
            if(! await verifyMultiSigJWT({multiSigJWT: received_vc,didResolver: didResolver, audience: receiver })){
                console.error("error in signature verification");
            }else{
                console.log("\n");
                console.log("\x1b[31m",'---AtomicVC successfully received---','\x1b[0m');
            }
        });
    });

 
}

provider.listAccounts().then((accounts: JsonRpcSigner[]) => {
	test(accounts);
}).catch(console.error);

