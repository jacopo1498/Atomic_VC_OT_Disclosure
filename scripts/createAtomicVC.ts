import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers, isAddress, JsonRpcProvider, JsonRpcSigner } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
//import { ES256KSigner } from 'did-jwt'
// import pkg, { verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
// const { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation } = pkg;
import bip39 from 'bip39'
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const hdkey = require('ethereumjs-wallet/hdkey')
//import wallet from 'ethereumjs-wallet'
const didJWT = require('did-jwt');
const config = require("./config.json");
//habdle the creation of VC with atomic method for sleective disclosure
import * as atomic from './atomic/main.js'

  
function getDisclosedClaimsNumber(fract,claimsTot){
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
  


const output_file_name="MPTC1-C.csv";
const mnemonic = config.mnemonic;

//setup the provider 
console.log('Connecting to provider...');
const Web3HttpProvider = require('web3-providers-http')
// ...
 
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



//function to create and return the object used to manage a DID
const createDid = async (RegAddress:string, accountAddress:JsonRpcSigner, index:number, chainId = '0x7a69') => {
   
    //TODO make something that obtains key from accountaddress
    const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; //Account 0

    const publicKey = computePublicKey(privateKey, true);
    console.log("Public Key: "+publicKey);
    console.log("Private Key: "+privateKey);
    const identifier = `did:ethr:${chainId}:${publicKey}`;
    const signer = provider.getSigner(index);
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


	for (let i = 1; i < config.maxClaims; i++) {
		//Subject create the VP
		const disclosedClaims=getDisclosedClaimsNumber(config.disclosedClaims, Math.pow(2, i));
		for (let j = 0; j <config.runs; j++) {
			//Issuer Create VC
			let vcResult=await atomic.issueVC(issuerDID,subjectDID,i);
			//Subject verify the VC
			let timeVerifyVC=await atomic.verifyVC(vcResult.jwt,didResolver);
			let vpResult= await atomic.issueCompressedVP(vcResult.jwt, disclosedClaims,subjectDID);
			//Verifier verify the VP
			let timeverifyVP=await atomic.verifyCompressedVP(vpResult.jwtVP,didResolver);
		}
		
	}
}

provider.listAccounts().then((accounts) => {
	test(accounts);
}).catch(console.error);

