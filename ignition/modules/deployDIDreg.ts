import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
//deploy DID registry contract to the hardhat network, 
const LockModule = buildModule("deployDIDreg", (m) => {

  const DIDr = m.contract("DIDRegistry");

  return { DIDr };
});

