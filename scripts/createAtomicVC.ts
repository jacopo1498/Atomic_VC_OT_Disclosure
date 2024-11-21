import { Resolver } from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { JsonRpcSigner } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
//import wallet from 'ethereumjs-wallet'
const didJWT = require('did-jwt');
import { ES256KSigner } from 'did-jwt';
//this is necessary to retrive the privatekeys from hardhat accounts
import { config } from "hardhat";
//handle the creation of VC with atomic method for sleective disclosure
import * as Atomic from './atomic/Atomic';
//handle multigignature
import { signJWTsWithSubjectKey, verifyMultiSigJWT } from './multiplesgn/multipleSgn';

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
 
const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
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

//this function retrives the private key of an account given an index
async function getPrivateKeyHardhat(index: number) {
    const accounts = config.networks?.localhost?.accounts as string[];
    if (!accounts) {
        console.error("No accounts found in the configuration.");
        return;
    }

    const privateKey = accounts[index];
     console.log("Private Key:", privateKey);
    return privateKey;
}


//function to create and return the object used to manage a DID
const createDid = async (RegAddress:string, accountAddress:JsonRpcSigner, index:number, chainId = '0x7a69') => {
   
    //TODO make something that obtains key from accountaddress
    const privateKey = await getPrivateKeyHardhat (index);
    if (!privateKey) {
        console.error("error PrivateKey retrival.");
        return;
    }
    const publicKey = computePublicKey(privateKey, true);
    console.log("Public Key: "+publicKey);
    console.log("Private Key: "+privateKey);
    const identifier = `did:ethr:${chainId}:${publicKey}`;
    const signer = await provider.getSigner(index);
    let signJ= ES256KSigner(Buffer.from(privateKey.slice(2), 'hex'),false);

    const ethrDid = new EthrDID({ 
        txSigner: signer,
        //privateKey : privateKey,
        signer: signJ,
        identifier: identifier,
        registry: RegAddress,
        chainNameOrId: chainId,
        alg: 'ES256K',
        provider});

    console.log("DID created:", ethrDid.did);

	return ethrDid;
}
 

//i only want this to generate atomic VC, timing stuff later
const test = async (accounts : JsonRpcSigner[]) => {
	let issuerAddress=accounts[0];
	let subjectAddress=accounts[1];
	let verifierAddress=accounts[2];

	console.log("Issuer EOA:"+issuerAddress);
	console.log("Subject EOA:"+subjectAddress);
	console.log("Verifier EOA:"+verifierAddress);

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
    
    const maxClaims = 5;
    const disclosedClaimsPercent = 0.75;


    //ok all good but now we want to apply ot, no v presentation 
    /** compared to a verifiable presentation with this solution we accept that the vc may come from different issuer but since we want only a claim ,
     * to gather data for some task, we only need the claim in question to be validated the recipient of each credential, 
     * i.e., the subject’s DID in the credential, matches the DID of the subject who sent the presentation; ->use somebody else vc? 
     * ideally there should be a way to identify subject before doing OT, or signing the VC before 
     * 
     * solution: signature with my PrK
     * */
    //print on a file? maybe? if i will test the performance difference...
    //also it would be nice if k-out of-n is possible, for now 1-out of-n
    const OT = require('1-out-of-n')(IO);
    const op_id = 'ot_atomic_vc'; 
    const rec_choise = 1;
    
    //Issuer Create VC
    console.log("---issuing new VC---");
    let vcResult= await Atomic.issueVC(issuerDID,subjectDID,maxClaims); //returns an array of jwt
    //Subject verify the VC
    console.log("---verifing all VC---");
    await Atomic.verifyVC(vcResult,didResolver);


    //sign each vc with the private key associated to your did
    const subjectPrivateKey = await getPrivateKeyHardhat(1); //the owner of the did knows his private key
    const signedJWTs = await signJWTsWithSubjectKey(vcResult, subjectPrivateKey!, subjectDID);
	/*
    for (let i = 0; i < signedJWTs.length; i++) {
        console.log("\x1b[42m",'Signed JWT by subject:','\x1b[0m');
        console.log(signedJWTs[i]);
        if(! await verifyMultiSigJWT(signedJWTs[i],didResolver)){
            console.error("error in signature verification");
        }
    }
    */


    //select a subset of vc's (jwt) 
    const disclosedClaimsn = getDisclosedClaimsNumber(disclosedClaimsPercent, maxClaims); //n. of claims to disclose,based on percenteage and n. of claims of this iteration
    const disclosedClaims = Atomic.getMultipleRandom(signedJWTs , disclosedClaimsn); //claims that i choose to disclose through ot
    
 
    //start OT protocol
    console.log("---start OT protocol---");
    OT.then(function (OT: { send: (arg0: Uint8Array[], arg1: number, arg2: string) => void; receive: (arg0: number, arg1: number, arg2: string) => Promise<Uint8Array> }) {
        /*
        *  The sender (vc holder) calls:
        */
        console.log ("\x1b[36m","sender sends all VC...",'\x1b[0m')
        OT.send(disclosedClaims.map(ascii.to_array) , disclosedClaimsn, op_id);
        console.log ("\x1b[36m","done!",'\x1b[0m')
        /*
        *  The receiver calls:
        */
        OT.receive(rec_choise, disclosedClaimsn, op_id).then(function (array: Uint8Array) {
            const rec_vc : string = ascii.to_ascii(array);
            console.log("\x1b[31m","obtained verified credential with ot, choise="+rec_choise,'\x1b[0m');
            console.log("\x1b[31m",'The chosen secret is:','\x1b[0m', rec_vc);
            //Atomic.verifysingleVC(rec_vc,didResolver); //this needs to be reworked! two proofs now!
            if(! verifyMultiSigJWT(rec_vc,didResolver)){
                console.error("error in signature verification");
            }
        });
    });
 
}

provider.listAccounts().then((accounts: JsonRpcSigner[]) => {
	test(accounts);
}).catch(console.error);

