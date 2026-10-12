export function canReadRecord(role, ownerId, actorId) {
    if (role === "ADMIN" || role === "AUDITOR")
        return true;
    return actorId !== null && actorId === ownerId;
}
export function canWriteRecord(role, ownerId, actorId, isShared = false) {
    if (role === "ADMIN")
        return true;
    return role === "USER" && actorId !== null && (actorId === ownerId || isShared);
}
export function normalizeUserName(input) {
    const hasControl = (value) => [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
    if (typeof input !== "string" || hasControl(input))
        return null;
    const displayName = input.normalize("NFKC").trim().replace(/\s+/gu, " ");
    const length = [...displayName].length;
    if (length < 2 || length > 40 || hasControl(displayName))
        return null;
    return { displayName, normalizedName: displayName.toLocaleLowerCase("en-US") };
}
export function safeSecretEqual(provided, expected) {
    const encoder = new TextEncoder();
    const providedBytes = encoder.encode(provided);
    const expectedBytes = encoder.encode(expected);
    let difference = providedBytes.length ^ expectedBytes.length;
    const maxLength = Math.max(providedBytes.length, expectedBytes.length);
    for (let index = 0; index < maxLength; index += 1) {
        difference |= (providedBytes[index] ?? 0) ^ (expectedBytes[index] ?? 0);
    }
    return difference === 0 && expectedBytes.length > 0;
}
