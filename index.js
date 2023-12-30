const bufferEncode = (value) =>
    btoa(String.fromCharCode(...new Uint8Array(value)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

const attestation = async () => {
    event.preventDefault();

    const result = await fetch("http://localhost:8080/attestatoin", {
        method: "GET",
        credentials: "include",
        headers: {
            "Content-Type": "application/x-msgpack"
        },
    })

    const buf = await result.arrayBuffer();

    const publicKey = msgpack.decode(new Uint8Array(buf.slice()));

    console.info(publicKey);

    console.log(document.cookie)

    const credential = await navigator.credentials.create({
        publicKey: publicKey,
    })

    // NOTE: msgpack.encode を使いたかったけどサーバーにうまくリクエストできなかったので挫折 ... 

    // NOTE: 2023/12/30 https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/toJSON
    // まだ credential.toJSON() が実装されていないため、自前で実装する

    const response = await fetch("http://localhost:8080/attestatoin", {
        method: "POST",
        credentials: "include",
        headers: {
            "Content-Type": "text/plain"
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: bufferEncode(credential.rawId),
            type: credential.type,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                attestationObject: bufferEncode(credential.response.attestationObject),
                clientDataJSON: bufferEncode(credential.response.clientDataJSON),
            },
        }),
    });

    if (response.status !== 200) {
        alert("Failed to attestation")
    }
};

document
    .getElementById("attestation")
    .addEventListener("submit", attestation);
