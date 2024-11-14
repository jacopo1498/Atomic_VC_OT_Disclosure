import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
//deploy DID registry contract to the hardhat network, 
const didReg = buildModule("EthereumDIDRegistry", (m) => {

  const DIDr = m.contract("EthereumDIDRegistry");

  return { DIDr };
});

export default didReg;