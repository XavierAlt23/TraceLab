export const MAX_BODY_BYTES = 8192;
export function isLocalRequest(request) {
    const host = new URL(request.url).hostname.replace(/^\[|\]$/gu, "");
    return ["localhost", "127.0.0.1", "::1"].includes(host);
}
export function makeSessionCookie(request, token, maxAge) {
    const local = isLocalRequest(request);
    return `${local ? "tracelab_session" : "__Host-tracelab_session"}=${token}; Path=/; HttpOnly;${local ? "" : " Secure;"} SameSite=Lax; Max-Age=${maxAge}`;
}
export function crossSiteMutation(request) {
    if (["GET", "HEAD", "OPTIONS"].includes(request.method))
        return false;
    const origin = request.headers.get("origin");
    return (origin !== null && origin !== new URL(request.url).origin)
        || request.headers.get("sec-fetch-site") === "cross-site";
}
export async function boundedJson(request) {
    if (request.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json")
        return null;
    const declared = request.headers.get("content-length");
    if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_BODY_BYTES))
        return null;
    if (!request.body)
        return null;
    const reader = request.body.getReader();
    const chunks = [];
    let length = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            length += value.length;
            if (length > MAX_BODY_BYTES) {
                await reader.cancel();
                return null;
            }
            chunks.push(value);
        }
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) {
            bytes.set(chunk, offset);
            offset += chunk.length;
        }
        const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        return typeof value === "object" && value !== null && !Array.isArray(value) ? value : null;
    }
    catch {
        return null;
    }
    finally {
        reader.releaseLock();
    }
}
export function secureResponse(request, response) {
    const headers = new Headers(response.headers);
    headers.set("x-content-type-options", "nosniff");
    headers.set("referrer-policy", "no-referrer");
    headers.set("x-frame-options", "DENY");
    headers.set("permissions-policy", "camera=(), microphone=(), geolocation=()");
    const local = isLocalRequest(request);
    headers.set("content-security-policy", `default-src 'self'; script-src 'self'${local ? " 'unsafe-inline'" : ""}; style-src 'self'${local ? " 'unsafe-inline'" : ""}; connect-src 'self'${local ? " ws://localhost:* ws://127.0.0.1:*" : ""}; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`);
    if (!local && new URL(request.url).protocol === "https:")
        headers.set("strict-transport-security", "max-age=31536000");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
