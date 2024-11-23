
export function verifyExpiration(exp: number): boolean {
    const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
    return exp > currentTime;
}

export function verifyIssuedAt(iat: number): boolean {
    const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
    const maxSkew = 120; // Allowable clock skew in seconds (2 minutes)
    return iat <= currentTime && iat >= currentTime - maxSkew;
}

export function verifyContext(context: string, expectedContext: string): boolean {
    return context === expectedContext;
}

export function verifyUniqueID(jti: string, usedIDs: Set<string>): boolean {
    if (usedIDs.has(jti)) {
        return false; // Reused ID
    }
    usedIDs.add(jti); // Mark ID as used
    return true;
}

