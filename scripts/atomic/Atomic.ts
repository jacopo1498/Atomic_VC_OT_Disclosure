
import { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation,  verifyCredential, JwtCredentialPayload, Issuer, VerifiedCredential, JwtPresentationPayload } from 'did-jwt-vc';
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
        console.log(verifiedCredential.verified)
	}
    return;
}

export async function verifysingleVC(jwt: string,didResolver: Resolver) : Promise<Boolean>{
	console.log("verifing VC's...(single claims)");
	const verifiedCredential= await verifyCredential(jwt, didResolver,{});
	if (!verifiedCredential){
		console.error("error in the verificaton of the vc");
		return false;
	}
	console.log("\x1b[44m","verified credential:",'\x1b[0m');
	console.log(verifiedCredential)

    return true;
}


export function getMultipleRandom(arr: string[], num: number) {
  const shuffled = [...arr].sort(() => 0.5 - Math.random());

  return shuffled.slice(0, num);
}

//qui riempiamo le VC di attributi
async function createVCPayload(user: EthrDID,nClaims: number) {
	let atomicVC=[];
	for (let i = 0; i < nClaims; i++) {
   		var attrName="attrName"+i;
		var attrValue="attrValue"+i;
		const VCPayload={} as JwtCredentialPayload;
		VCPayload['sub']=user.did;
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




