
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, normalizeCredential, validateCredentialPayload, JwtCredentialPayload, Issuer, VerifiedCredential, JwtPresentationPayload } from 'did-jwt-vc';
import { Resolver } from 'did-resolver';
import { EthrDID } from 'ethr-did';

const options = {		
		header: {
			"typ": "JWT",
			"alg": "ES256K"
		},
	};

export async function issueVC(issuer:EthrDID,subject: EthrDID,nClaims: number){
	let jwt=[];
    console.log("creating verifiable credentials (jwt)...");
	//const atomicVCPayloads = await createVCPayload(subject,Math.pow(2, nClaims));
	const atomicVCPayloads = await createVCPayload(subject,nClaims);
	for (let c = 0; c <atomicVCPayloads.length; c++) {
		const jwtVC = await createVerifiableCredentialJwt(atomicVCPayloads[c], issuer as Issuer, options as {});
        //console.log(jwtVC);
		jwt.push(jwtVC);
	}
    console.log("\x1b[43m","verifiable credential issued:",'\x1b[0m');
    console.log(jwt)
	return jwt;
}

export async function verifyVC(jwtSet: string[],didResolver: Resolver){
	console.log("verifing VC's...(single claims)");
    for (let c = 0; c <jwtSet.length; c++) {
		const verifiedCredential= await verifyCredential(jwtSet[c], didResolver,{});
        console.log("\x1b[44m","verified credential:",'\x1b[0m');
        console.log(verifiedCredential)
	}
    return;
}

export async function verifysingleVC(jwt: string,didResolver: Resolver){
	console.log("verifing VC's...(single claims)");
	const verifiedCredential= await verifyCredential(jwt, didResolver,{});
	console.log("\x1b[44m","verified credential:",'\x1b[0m');
	console.log(verifiedCredential)

    return;
}


export function getMultipleRandom(arr: string[], num: number) {
  const shuffled = [...arr].sort(() => 0.5 - Math.random());

  return shuffled.slice(0, num);
}

export async function issueVP(jwtSet: string[],disclosedClaims: number, subject: EthrDID){
	let disclosedJWTset = getMultipleRandom(jwtSet, disclosedClaims);
    console.log("\x1b[43m","the number of claims (vc) disclosed is :"+disclosedClaims,'\x1b[0m');
	console.log(disclosedJWTset);
	const VPPayload = createVPPayload(disclosedJWTset);
	let jwtVP = await createVerifiablePresentationJwt(VPPayload,subject as Issuer ,options as {});
    console.log("\x1b[43m","verifiable presentation issued:",'\x1b[0m');
    console.log(jwtVP)
	return jwtVP;
}

export async function verifyVP(jwtVP: string,didResolver: Resolver){
	const verifiedPresentation= await verifyPresentation(jwtVP, didResolver,{});	
    console.log("\x1b[44m","verified presentation:",'\x1b[0m');
    console.log(verifiedPresentation)
	return;
}

//qui riempiamo le VC di attributi
async function createVCPayload(user: EthrDID,nClaims: number) {
	let atomicVC=[];
	for (let i = 0; i < nClaims; i++) {
   		var attrName="attrName"+i;
		var attrValue="attrValue"+i;
		const VCPayload={} as JwtCredentialPayload;
		VCPayload['sub']=user.did; //perchè era commentato?
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


function createVPPayload(vc: string[]) {
	const VPPayload={} as JwtPresentationPayload;
    VPPayload['vp']= {
			'@context': ['https://www.w3.org/2018/credentials/v1'],
			type: ['VerifiablePresentation'],
			verifiableP: vc
		};
	return VPPayload;
}

