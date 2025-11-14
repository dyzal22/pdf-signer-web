// =============================================================
// ===============  PDF DIGITAL SIGNATURE TOOL  =================
// Fitur: Signing PDF, Verifikasi Signature, dan Verifikasi PDF Signed
// =============================================================


// =============================================================
// ========== BAGIAN 1. UTILITAS (fungsi umum pendukung) =========
// =============================================================

// Fungsi untuk membaca file menjadi ArrayBuffer
// Digunakan agar PDF bisa diproses secara biner oleh WebCrypto API.
async function fileToArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

// Fungsi untuk menghitung hash SHA-256 dari file PDF.
// Hash digunakan untuk menjamin **integrity** (tidak ada perubahan isi file).
async function calculateSHA256(buffer) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

// Fungsi untuk menandatangani data dengan private key pengguna.
// Private key diinput dalam format PEM (PKCS#8), diubah ke format biner DER,
// lalu digunakan untuk menghasilkan signature base64.
async function signWithPrivateKey(privateKeyPem, dataBuffer) {
  const keyData = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const binaryDer = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));

  // Import private key ke WebCrypto API
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Lakukan proses signing
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, dataBuffer);

  // Kembalikan hasil signature dalam format base64
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}


// =============================================================
// ========== BAGIAN 2. DIGITAL SIGNATURE (Tab 1) ===============
// =============================================================
// Tujuan: Menghasilkan tanda tangan digital PDF + menyisipkan hasil signature ke dalam dokumen PDF.

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

    // 1️⃣ Baca file PDF sebagai ArrayBuffer
    const arrayBuffer = await fileToArrayBuffer(file);

    // 2️⃣ Hitung hash SHA-256 (integrity check)
    const hashHex = await calculateSHA256(arrayBuffer);

    // 3️⃣ Encode hash dan tanda tangani dengan private key
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(hashHex);
    const signatureB64 = await signWithPrivateKey(privateKey, dataBuffer);

    // 4️⃣ Tampilkan hasil hash dan signature
    hashResult.textContent = hashHex;
    sigResult.textContent = signatureB64;
    results.style.display = "block";

    // 5️⃣ Sisipkan hasil tanda tangan ke dalam PDF (menggunakan PDFLib)
    const pdfDoc = await PDFLib.PDFDocument.load(arrayBuffer);
    const pages = pdfDoc.getPages();
    const lastPage = pages[pages.length - 1];
    const { width } = lastPage.getSize();

    // Tambahkan teks signature ke halaman terakhir
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

    // 6️⃣ Simpan PDF yang sudah disigned dan siapkan tombol download
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
// Tujuan: Mengecek apakah signature cocok dengan file PDF asli (tanpa modifikasi).

async function importPublicKey(pem) {
  // Konversi public key PEM menjadi format DER untuk WebCrypto API
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

    // 1️⃣ Hitung ulang hash SHA-256 dari file PDF yang diupload
    const hashHex = await calculateSHA256(arrayBuffer);

    // 2️⃣ Encode hash untuk diverifikasi dengan public key
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(hashHex);
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

    // 3️⃣ Verifikasi signature (menggunakan public key)
    const publicKey = await importPublicKey(publicKeyPem);
    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBytes,
      dataBuffer
    );

    // 4️⃣ Tampilkan hasil verifikasi
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
// Logika terpusat untuk mengelola perpindahan tab di UI.

function switchTab(tabId) {
  // Sembunyikan semua konten dan hapus status aktif dari semua tab
  document.querySelectorAll(".tab, .content").forEach(el => {
    el.classList.remove("active");
  });

  // Tampilkan tab dan konten yang dipilih
  document.getElementById(`tab-${tabId}`).classList.add("active");
  document.getElementById(`content-${tabId}`).classList.add("active");
}

// Tambahkan event listener ke setiap tab
document.getElementById("tab-sign").addEventListener("click", () => switchTab("sign"));
document.getElementById("tab-verify").addEventListener("click", () => switchTab("verify"));
document.getElementById("tab-verify-signed").addEventListener("click", () => switchTab("verify-signed"));


// =============================================================
// ========== BAGIAN 5. VERIFIKASI SIGNED PDF (Tab 3) ===========
// =============================================================
// Tujuan: Mengecek keaslian file PDF yang sudah disigned dan memiliki hash & signature tertanam di dalamnya.

// Fungsi untuk mengekstrak teks dari file PDF agar bisa membaca hash & signature yang tertanam
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

    // 1️⃣ Ekstrak teks dari PDF
    const pdfText = await extractTextFromPDF(arrayBuffer);

    // 2️⃣ Temukan hash yang tertanam di PDF
    const match = pdfText.match(/Hash \(SHA-256\): ([A-Fa-f0-9]+)/);
    if (!match) throw new Error("Hash tidak ditemukan di dalam PDF signed.");

    const embeddedHash = match[1];
    console.log("Embedded hash:", embeddedHash);

    // 3️⃣ Import public key dan 4️⃣ Decode signature base64
    const publicKey = await importPublicKey(publicKeyPem);
    const signatureBytes = Uint8Array.from(atob(signatureB64), c => c.charCodeAt(0));

    // 5️⃣ Verifikasi signature terhadap hash tertanam
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(embeddedHash);
    const isValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signatureBytes,
      dataBuffer
    );

    // 6️⃣ Tampilkan hasil verifikasi signed PDF
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
