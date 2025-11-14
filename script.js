// =============================================================
// ===============  PDF DIGITAL SIGNATURE TOOL  =================
// Fitur: Signing PDF, Verifikasi Signature, dan Verifikasi PDF Signed
// =============================================================
//
// Catatan Konsep:
// -------------------------------------------------------------
// • Algoritma RSA: RSASSA-PKCS1-v1_5 (RSA Probabilistic Signature Scheme)
// • Hash yang digunakan: SHA-256
// • Signature: private key → sign(hash)
// • Verifikasi: public key → verify(hash, signature)
// • Model implementasi: "Detached Signature" (hash & signature disimpan terbuka)
// =============================================================


// =============================================================
// ========== BAGIAN 1. UTILITAS (fungsi umum pendukung) =========
// =============================================================

// Fungsi untuk membaca file menjadi ArrayBuffer (bentuk biner).
// Digunakan oleh WebCrypto API untuk proses hashing dan signing.
async function fileToArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// Fungsi untuk menghitung hash SHA-256 dari file PDF.
// Hash menjamin **integritas** dokumen — setiap perubahan 1 byte pun mengubah hash.
async function calculateSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Fungsi untuk melakukan digital signing dengan private key dalam format PEM (PKCS#8).
// Langkah:
// 1. Hapus header/footer PEM → base64
// 2. Konversi base64 → binary DER
// 3. Import ke WebCrypto API
// 4. sign(data) → hasil base64
async function signWithPrivateKey(privateKeyPem, dataBuffer) {
  const keyData = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");

  const binaryDer = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));

  // Import kunci privat ke WebCrypto (RSASSA-PKCS1-v1_5 + SHA-256)
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Proses signing
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, dataBuffer);

  // Encode signature → base64
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}



// =============================================================
// ========== BAGIAN 2. DIGITAL SIGNATURE (Tab 1) ===============
// =============================================================
// Fungsi utama: melakukan digital signature pada PDF dan menyisipkan
// hash & signature ke dalam halaman terakhir PDF.

document.getElementById("signButton").addEventListener("click", async () => {
  const fileInput = document.getElementById("pdfUploader");
  const privateKey = document.getElementById("privateKey").value.trim();
  const loader = document.getElementById("loader");
  const results = document.getElementById("results");
  const hashResult = document.getElementById("hashResult");
  const sigResult = document.getElementById("sigResult");

  // Validasi input
  if (!fileInput.files.length || !privateKey) {
    alert("Silakan pilih PDF dan masukkan private key!");
    return;
  }

  loader.style.display = "block";
  results.style.display = "none";

  try {
    const file = fileInput.files[0];

    // 1️⃣ Baca PDF sebagai ArrayBuffer
    const arrayBuffer = await fileToArrayBuffer(file);

    // 2️⃣ Hitung hash SHA-256 (integrity)
    const hashHex = await calculateSHA256(arrayBuffer);

    // 3️⃣ Encode hash → sign menggunakan private key
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(hashHex);
    const signatureB64 = await signWithPrivateKey(privateKey, dataBuffer);

    // 4️⃣ Tampilkan hash + signature
    hashResult.textContent = hashHex;
    sigResult.textContent = signatureB64;
    results.style.display = "block";

    // 5️⃣ Sisipkan hash + signature ke PDF menggunakan PDFLib
    const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    const { width } = lastPage.getSize();

    // Catatan: menaruh signature sebagai teks biasa → model "PDF annotation".
    const text = `Digital Signature (RSA-PKCS1v1.5 + SHA-256):
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

    // 6️⃣ Export PDF hasil signed → allow download
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



// =============================================================
// ========== BAGIAN 3. VERIFIKASI SIGNATURE (Tab 2) ============
// =============================================================
// Verifikasi signature PDF original (belum signed), hanya hash+signature eksternal.

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

    // 1️⃣ Hitung ulang hash file PDF
    const hashHex = await calculateSHA256(arrayBuffer);

    // 2️⃣ Siapkan data dan signature
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(hashHex);
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

    // 3️⃣ Verifikasi signature (RSA verify)
    const publicKey = await importPublicKey(publicKeyPem);
    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBytes,
      dataBuffer
    );

    // 4️⃣ Output hasil verifikasi
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



// =============================================================
// ========== BAGIAN 4. SWITCH TAB (Navigasi antar menu) ========
// =============================================================
// Mengatur UI tab agar aktif/non-aktif.

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



// =============================================================
// ========== BAGIAN 5. VERIFIKASI SIGNED PDF (Tab 3) ===========
// =============================================================
// Memverifikasi PDF yang sudah disisipkan hash+signature di dalam file.

document.getElementById("tab-verify-signed").addEventListener("click", () => {
  document.querySelectorAll(".tab, .content").forEach(el => el.classList.remove("active"));
  document.getElementById("tab-verify-signed").classList.add("active");
  document.getElementById("content-verify-signed").classList.add("active");
});

// Fungsi untuk ekstrak teks dari PDF (mengambil hash & signature tertanam)
async function extractTextFromPDF(arrayBuffer) {
  const pdfjsLib = window['pdfjs-dist/build/pdf'];
  pdfjsLib.GlobalWorkerOptions.workerSrc =
    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.16.105/pdf.worker.min.js";

  const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  let textContent = "";

  for (let i = 1; i <= pdf.numPages; i++) {
    const page = await pdf.getPage(i);
    const text = await page.getTextContent();
    text.items.forEach((item) => {
      textContent += item.str + "\n";
    });
  }
  return textContent;
}

document.getElementById("verifySignedButton").addEventListener("click", async () => {
  const fileInput = document.getElementById("verifySignedPdf");
  const publicKeyPem = document.getElementById("publicKey2").value.trim();
  const signatureB64 = document.getElementById("signatureInput2").value.trim();
  const resultDiv = document.getElementById("verifySignedResult");

  if (!fileInput.files.length || !publicKeyPem || !signatureB64) {
    alert("Lengkapi semua kolom terlebih dahulu!");
    return;
  }

  resultDiv.style.display = "none";
  resultDiv.textContent = "";

  try {
    const file = fileInput.files[0];
    const arrayBuffer = await fileToArrayBuffer(file);

    // 1️⃣ Ambil text dari PDF
    const pdfText = await extractTextFromPDF(arrayBuffer);

    // 2️⃣ Ambil hash dari teks PDF
    const match = pdfText.match(/Hash \(SHA-256\): ([A-Fa-f0-9]+)/);
    if (!match) throw new Error("Hash tidak ditemukan di dalam PDF signed.");

    const embeddedHash = match[1];

    // 3️⃣ Import public key
    const publicKey = await importPublicKey(publicKeyPem);

    // 4️⃣ Decode signature
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

    // 5️⃣ Verifikasi signature ↔ hash tertanam
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(embeddedHash);
    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBytes,
      dataBuffer
    );

    // 6️⃣ Output hasil
    resultDiv.style.display = "block";
    if (isValid) {
      resultDiv.textContent = "✅ Signed PDF VALID — hash cocok dengan signature dan public key.";
      resultDiv.style.background = "#c8f7c5";
    } else {
      resultDiv.textContent = "❌ Signed PDF TIDAK VALID — signature atau hash tidak sesuai.";
      resultDiv.style.background = "#f7c5c5";
    }
  } catch (err) {
    alert("Error: " + err.message);
    console.error(err);
  }
});
