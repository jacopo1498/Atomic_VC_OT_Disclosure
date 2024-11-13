import {Resolver} from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers } from 'ethers' 
import { computePublicKey } from '@ethersproject/signing-key'
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { performance } = require('perf_hooks'); // performance suite for time measurement
const didJWT = require('did-jwt');

const options = {		
		header: {
			"typ": "JWT",
			"alg": "ES256K"
		},
	};

export async function issueVC(issuer,subject,nClaims){
	let start = performance.now();
	let jwt=[];
	const atomicVCPayloads = await createVCPayload(subject,Math.pow(2, nClaims));
	for (let c = 0; c <atomicVCPayloads.length; c++) {
		const jwtVC = await createVerifiableCredentialJwt(atomicVCPayloads[c], issuer, options);
		jwt.push(jwtVC);
	}
	let end = performance.now();
	const time = (end-start);
	return {jwt,time};
}

export async function verifyVC(jwtSet,didResolver){
	let start = performance.now();
	for (let c = 0; c <jwtSet.length; c++) {
		const verifiedCredential= await verifyCredential(jwtSet[c], didResolver,{});
	}
	let end = performance.now();
	const time = (end-start);
	return time;
}

function getMultipleRandom(arr, num) {
  const shuffled = [...arr].sort(() => 0.5 - Math.random());

  return shuffled.slice(0, num);
}

export async function issueVP(jwtSet,disclosedClaims, subject){
	let disclosedJWTset=getMultipleRandom(jwtSet, disclosedClaims);
	let start = performance.now();
	//console.log(disclosedJWTset);
	const VPPayload=createVPPayload(disclosedJWTset);
	let jwtVP=await createVerifiablePresentationJwt(VPPayload,subject,options);
	let end = performance.now();
	const time = (end-start);
	return {jwtVP,time};
}

export async function verifyVP(jwtVP,didResolver){
	let start = performance.now();
	const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});	
	let end = performance.now();
	const time = (end-start);
	return time;
}

async function createVCPayload(user,nClaims) {
	let atomicVC=[];
	for (let i = 0; i < nClaims; i++) {
   		var attrName="attrName"+i;
		var attrValue="attrValue"+i;
		const VCPayload={};
		//VCPayload['sub']=user.did;
    	//VCPayload['nbf']=626105238;
    	VCPayload['vc']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiableCredential'],
			id: "http://namespace.org/credentials/credID/"+attrName,
			credentialSubject: {}
		};
  		VCPayload['vc']['credentialSubject'][attrName] = attrValue;
  		atomicVC.push(VCPayload);
	}
	return atomicVC;
}


function createVPPayload(vc) {
	const VCPayload={};
	//VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vp']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiablePresentation'],
			verifiableCredential: vc
		};
	return VCPayload;
}

