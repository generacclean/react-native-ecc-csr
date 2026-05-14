import CSRModule, { CSRParams } from "react-native-ecc-csr";

/**
 * SECURE Example: Generate CSR with hardware-backed key storage
 * For Android: The private key NEVER leaves the Android Keystore hardware
 * For iOS: If you use "secp256r1" curve, then private key never leaves hardware. For others, it is stored in secure enclave backed by software
 */
async function generateSecureCSR() {
    try {
        // IMPORTANT: Generate a unique alias for this device/certificate
        const privateKeyAlias = `pwrview_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const params: CSRParams = {
            country: "US",
            state: "Texas",
            locality: "Austin",
            organization: "MyOrganization",
            organizationalUnit: "IT Team",
            commonName: "5dab25dd-7d0a-4a03-94c3-39f935c0a48a",
            serialNumber: "APCBPGN2202-AF250300028",
            ipAddress: "10.10.10.10",
            curve: "secp384r1",
            privateKeyAlias: privateKeyAlias,  // REQUIRED for secure storage
            phoneInfo: "ABCDEFG1898901",
        };

        const result = await CSRModule.generateCSR(params);

        console.log("✅ CSR Generated Securely!");
        console.log("CSR:", result.csr);
        console.log("Private Key Alias:", result.privateKeyAlias);
        console.log("Public Key:", result.publicKey);
        console.log("Hardware-Backed:", result.isHardwareBacked);

        return result;
    } catch (error) {
        console.error("Error generating secure CSR:", error);
        throw error;
    }
}

/**
 * Using device-specific alias
 */
async function generateCSRForDevice(deviceId: string, serialNumber: string) {
    try {
        // Use device-specific alias
        const privateKeyAlias = `device_${deviceId}_cert`;

        const params: CSRParams = {
            country: "US",
            state: "Nevada",
            locality: "Reno",
            organization: "Generac",
            organizationalUnit: "PWRview",
            commonName: deviceId,
            serialNumber: serialNumber,
            ipAddress: "10.10.10.10",
            curve: "secp384r1",
            privateKeyAlias: privateKeyAlias
        };

        const result = await CSRModule.generateCSR(params);

        console.log("✅ Secure CSR generated for device:", deviceId);
        console.log("Hardware-backed:", result.isHardwareBacked);

        return result;
    } catch (error) {
        console.error("Error generating CSR for device:", error);
        throw error;
    }
}

/**
 * Check if key exists before generating
 */
async function checkAndGenerateCSR(alias: string) {
    try {
        const exists = await CSRModule.keyExists(alias);

        if (exists) {
            console.log("✅ Key already exists. Retrieving public key...");
            const publicKey = await CSRModule.getPublicKey(alias);
            return { exists: true, publicKey };
        }

        console.log("Key doesn't exist. Generating new CSR...");
        const result = await CSRModule.generateCSR({
            commonName: "new-device",
            privateKeyAlias: alias
        });

        return { exists: false, result };
    } catch (error) {
        console.error("Error:", error);
        throw error;
    }
}

/**
 * Delete a key when device is decommissioned or certificate expires
 */
async function deleteDeviceKey(deviceId: string) {
    try {
        const privateKeyAlias = `device_${deviceId}_cert`;

        const exists = await CSRModule.keyExists(privateKeyAlias);
        if (!exists) {
            console.log("Key doesn't exist");
            return false;
        }

        await CSRModule.deleteKey(privateKeyAlias);
        console.log("✅ Key deleted successfully");
        return true;
    } catch (error) {
        console.error("Error deleting key:", error);
        throw error;
    }
}

/**
 * Retrieve public key for an existing key pair
 */
async function getExistingPublicKey(deviceId: string) {
    try {
        const privateKeyAlias = `device_${deviceId}_cert`;

        const exists = await CSRModule.keyExists(privateKeyAlias);
        if (!exists) {
            throw new Error("Key not found");
        }

        const publicKey = await CSRModule.getPublicKey(privateKeyAlias);
        console.log("✅ Public key retrieved");
        return publicKey;
    } catch (error) {
        console.error("Error retrieving public key:", error);
        throw error;
    }
}

/**
 * List all stored key aliases (you'll need to implement storage)
 */
async function listStoredKeyAliases() {
    // e.g., encrypted shared preferences or secure storage library
    const aliases = await getStoredAliases();

    for (const alias of aliases) {
        const exists = await CSRModule.keyExists(alias);
        console.log(`${alias}: ${exists ? '✅ exists' : '❌ missing'}`);
    }

    return aliases;
}
async function getStoredAliases(): Promise<string[]> {
    // Retrieve list of aliases from your secure storage
    return [];
}

export {
    generateSecureCSR,
    generateCSRForDevice,
    checkAndGenerateCSR,
    deleteDeviceKey,
    getExistingPublicKey,
    listStoredKeyAliases
};