// script.js (client-side signing with PEM keys)

document.getElementById('signButton').addEventListener('click', async () => {
  const fileInput = document.getElementById('pdfUploader');
  const loader = document.getElementById('loader');
  const resultsDiv = document.getElementById('results');
  const hashResult = document.getElementById('hashResult');
  const sigResult = document.getElementById('sigResult');

  const privatePem = document.getElementById('privateKey')?.value.trim();
  const publicPem  = document.getElementById('publicKey')?.value.trim(); // optional verify

  if (fileInput.files.length === 0) {
    alert("Silakan pilih file PDF terlebih dahulu.");
    return;
  }
  if (!privatePem) {
    const ok = confirm("Private key belum diisi. Melanjutkan tanpa private key akan menghentikan proses. Isi private key sekarang?");
    if (!ok) return;
  }

  const file = fileInput.files[0];
  loader.style.display = 'block';
  resultsDiv.style.display = 'none';

  try {
    // --- baca file sebagai ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();

    // --- 1) hitung SHA-256 hash (hex) dari file
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashHex = bufferToHex(hashBuffer);

    // --- 2) import private key (PEM PKCS#8) ke CryptoKey
    const privateKey = await importPrivateKeyFromPem(privatePem);

    // --- 3) sign data (kita akan sign seluruh file ArrayBuffer)
    // algorithm: RSASSA-PKCS1-v1_5 with SHA-256
    const signatureBuffer = await crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      privateKey,
      arrayBuffer
    );
    const signatureBase64 = arrayBufferToBase64(signatureBuffer);

    // --- 4) (optional) verify with public key provided
    let verifyOk = null;
    if (publicPem) {
      const pubKey = await importPublicKeyFromPem(publicPem);
      verifyOk = await crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        pubKey,
        signatureBuffer,
        arrayBuffer
      );
    }

    // --- tampilkan hasil
    hashResult.textContent = hashHex;
    sigResult.textContent = signatureBase64;
    if (verifyOk !== null) {
      sigResult.textContent += `\n\n(Verifikasi dengan public key: ${verifyOk ? 'OK' : 'GAGAL'})`;
    }
    resultsDiv.style.display = 'block';
  } catch (err) {
    alert('Error: ' + err.message);
    console.error(err);
  } finally {
    loader.style.display = 'none';
  }
});

/* ----------------- util functions ----------------- */

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.prototype.map.call(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function pemToBinary(pem) {
  // remove header/footer and newlines
  const b64 = pem.replace(/-----BEGIN [^-]+-----/g, '')
                 .replace(/-----END [^-]+-----/g, '')
                 .replace(/\s+/g, '');
  return base64ToArrayBuffer(b64);
}

async function importPrivateKeyFromPem(pem) {
  if (!pem) throw new Error('Private key PEM kosong');
  // expect PKCS#8 PEM (-----BEGIN PRIVATE KEY-----)
  const binary = pemToBinary(pem);
  return await crypto.subtle.importKey(
    'pkcs8',
    binary,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, // not extractable
    ['sign']
  );
}

async function importPublicKeyFromPem(pem) {
  if (!pem) throw new Error('Public key PEM kosong');
  // expect SPKI PEM (-----BEGIN PUBLIC KEY-----)
  const binary = pemToBinary(pem);
  return await crypto.subtle.importKey(
    'spki',
    binary,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify']
  );
}
