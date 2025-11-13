async function fileToArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

async function calculateSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function signWithPrivateKey(privateKeyPem, dataBuffer) {
  const keyData = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const binaryDer = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, dataBuffer);
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

document.getElementById("signButton").addEventListener("click", async () => {
  const fileInput = document.getElementById("pdfUploader");
  const privateKey = document.getElementById("privateKey").value.trim();
  const loader = document.getElementById("loader");
  const results = document.getElementById("results");
  const hashResult = document.getElementById("hashResult");
  const sigResult = document.getElementById("sigResult");

  if (!fileInput.files.length || !privateKey) {
    alert("Silakan pilih PDF dan masukkan private key!");
    return;
  }

  loader.style.display = "block";
  results.style.display = "none";

  try {
    const file = fileInput.files[0];
    const arrayBuffer = await fileToArrayBuffer(file);
    const hashHex = await calculateSHA256(arrayBuffer);

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(hashHex);
    const signatureB64 = await signWithPrivateKey(privateKey, dataBuffer);

    hashResult.textContent = hashHex;
    sigResult.textContent = signatureB64;
    results.style.display = "block";

    // Embed ke PDF
    const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    const { width } = lastPage.getSize();

    const text = `Digital Signature:
Hash (SHA-256): ${hashHex}
Signature: ${signatureB64.substring(0, 80)}...
Date: ${new Date().toLocaleString()}`;

    lastPage.drawText(text, {
      x: 50,
      y: 80,
      size: 10,
      maxWidth: width - 100,
      lineHeight: 12,
    });

    const signedPdfBytes = await pdfDoc.save();
    const blob = new Blob([signedPdfBytes], { type: "application/pdf" });

    const downloadBtn = document.getElementById("downloadBtn");
    downloadBtn.onclick = () => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `signed_${file.name}`;
      a.click();
      URL.revokeObjectURL(url);
    };
  } catch (err) {
    alert("Error: " + err.message);
    console.error(err);
  } finally {
    loader.style.display = "none";
  }
});
