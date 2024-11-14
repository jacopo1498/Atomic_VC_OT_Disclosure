// This assumes Hardhat is configured to expose accounts
import { config } from "hardhat";

async function getPrivateKey(index: number) {
    const accounts = config.networks?.localhost?.accounts as string[];
    if (!accounts) {
        console.error("No accounts found in the configuration.");
        return;
    }

    const privateKey = accounts[index];
    console.log("Private Key:", privateKey);
    return privateKey;
}

getPrivateKey(1);