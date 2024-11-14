import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { JsonRpcSigner } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
//import wallet from 'ethereumjs-wallet'
const didJWT = require('did-jwt');
//this is necessary to retrive the privatekeys from hardhat accounts
import { config } from "hardhat";
//handle the creation of VC with atomic method for sleective disclosure
import * as Atomic from './atomic/Atomic';
const { ethers } = require("hardhat");
//this is necessary for ot... basically simulates communication with a dummy socket curtesy of wyatt-howe
var IO = require('./OT/io-example.js');


const maxClaims = 4;
const Runs = 1;
const disclosedClaimsPercent = 0.75;

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
    let signJ=didJWT.ES256KSigner(Buffer.from(privateKey.slice(2), 'hex'),false);

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
    

/*
    //disclosedClaimsPercent is a percenteage 0.75 -> 75%
	for (let i = 1; i < maxClaims; i++) {
		//Subject create the VP
		const disclosedClaims=getDisclosedClaimsNumber(disclosedClaimsPercent, Math.pow(2, i));
		for (let j = 0; j < Runs; j++) {
			//Issuer Create VC
            console.log("---issuing new vc---");
			let vcResult= await Atomic.issueVC(issuerDID,subjectDID,i);
			//Subject verify the VC
            console.log("---verifing vc---");
			await Atomic.verifyVC(vcResult,didResolver);
            //Subject creates VP
            console.log("---issuing new vp---");
			let vpResult= await Atomic.issueVP(vcResult,disclosedClaims,subjectDID);
			//Verifier verify the VP
            console.log("---verifing vp---");
			await Atomic.verifyVP(vpResult,didResolver);
		}
		
	}
*/       

    //ok all good but now we want to apply ot, no v presentation 
    //print on a file? maybe? if i will test the performance difference...
    //also it would be nice if k-out of-n is possible, for now 1-out of-n
    const OT = require('1-out-of-n')(IO);
    const op_id = 'ot_atomic_vc'; 
    
    for (let i = 1; i < maxClaims; i++) {
        //Issuer Create VC
        console.log("---issuing new vc---");
        let vcResult= await Atomic.issueVC(issuerDID,subjectDID,i);
        //Subject verify the VC
        console.log("---verifing vc---");
        await Atomic.verifyVC(vcResult,didResolver);
    }

    OT.send()
    OT.receive()
    

}

provider.listAccounts().then((accounts: JsonRpcSigner[]) => {
	test(accounts);
}).catch(console.error);

