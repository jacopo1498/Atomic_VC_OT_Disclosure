import { config } from "hardhat";

//this function retrives the private key of an account given an index
export async function getPrivateKeyHardhat(index: number) {
    const accounts = config.networks?.localhost?.accounts as string[];
    if (!accounts) {
        console.error("No accounts found in the configuration.");
        return;
    }

    const privateKey = accounts[index];
    console.log("Signing Private Key:", privateKey);
    return privateKey;
}
