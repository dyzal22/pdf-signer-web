// ========== UTILITAS ==========
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

// ========== DIGITAL SIGNATURE ==========
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

    // tampilkan hasil
    hashResult.textContent = hashHex;
    sigResult.textContent = signatureB64;
    results.style.display = "block";

    // tambahkan ke PDF
    const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    const { width } = lastPage.getSize();

    const text = `Digital Signature:
Hash (SHA-256): ${hashHex}
Signature (Base64): ${signatureB64.substring(0, 80)}...
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

// ========== VERIFIKASI SIGNATURE ==========
async function importPublicKey(pem) {
  const keyData = pem
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const binaryDer = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

document.getElementById("verifyButton").addEventListener("click", async () => {
  const fileInput = document.getElementById("verifyPdf");
  const publicKeyPem = document.getElementById("publicKey").value.trim();
  const signatureB64 = document.getElementById("signatureInput").value.trim();
  const verifyResultDiv = document.getElementById("verifyResult");

  if (!fileInput.files.length || !publicKeyPem || !signatureB64) {
    alert("Lengkapi semua data: PDF, public key, dan signature.");
    return;
  }

  verifyResultDiv.style.display = "none";
  verifyResultDiv.textContent = "";

  try {
    const file = fileInput.files[0];
    const arrayBuffer = await fileToArrayBuffer(file);
    const hashHex = await calculateSHA256(arrayBuffer);

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(hashHex);
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

    const publicKey = await importPublicKey(publicKeyPem);
    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBytes,
      dataBuffer
    );

    verifyResultDiv.style.display = "block";
    if (isValid) {
      verifyResultDiv.textContent = "✅ Signature VALID — file belum diubah dan kunci cocok.";
      verifyResultDiv.style.background = "#c8f7c5";
    } else {
      verifyResultDiv.textContent = "❌ Signature TIDAK VALID — file diubah atau kunci tidak cocok.";
      verifyResultDiv.style.background = "#f7c5c5";
    }
  } catch (err) {
    alert("Error saat verifikasi: " + err.message);
    console.error(err);
  }
});

// ========== TAB SWITCH ==========
document.getElementById("tab-sign").addEventListener("click", () => {
  document.getElementById("tab-sign").classList.add("active");
  document.getElementById("tab-verify").classList.remove("active");
  document.getElementById("content-sign").classList.add("active");
  document.getElementById("content-verify").classList.remove("active");
});

document.getElementById("tab-verify").addEventListener("click", () => {
  document.getElementById("tab-verify").classList.add("active");
  document.getElementById("tab-sign").classList.remove("active");
  document.getElementById("content-verify").classList.add("active");
  document.getElementById("content-sign").classList.remove("active");
});
