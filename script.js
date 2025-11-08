document.getElementById('signButton').addEventListener('click', async () => {
    const fileInput = document.getElementById('pdfUploader');
    const loader = document.getElementById('loader');
    const resultsDiv = document.getElementById('results');
    const hashResult = document.getElementById('hashResult');
    const sigResult = document.getElementById('sigResult');

    if (fileInput.files.length === 0) {
        alert("Silakan pilih file PDF terlebih dahulu.");
        return;
    }

    const file = fileInput.files[0];

    // Tampilkan loader dan sembunyikan hasil sebelumnya
    loader.style.display = 'block';
    resultsDiv.style.display = 'none';

    try {
        // 1. Baca file PDF sebagai Base64
        // Kita mengirim Base64 dalam JSON, ini lebih mudah daripada 'multipart/form-data'
        const pdfBase64 = await fileToBase64(file);

        // 2. Kirim data Base64 ke API backend kita
        const response = await fetch('/api/sign_pdf', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ pdf_data: pdfBase64 }),
        });

        const result = await response.json();

        // 3. Tampilkan hasil atau error
        if (response.ok) {
            hashResult.textContent = result.hash_b64;
            sigResult.textContent = result.signature_b64;
            resultsDiv.style.display = 'block';
        } else {
            throw new Error(result.error || 'Terjadi kesalahan di server.');
        }

    } catch (error) {
        alert(`Error: ${error.message}`);
    } finally {
        // Sembunyikan loader
        loader.style.display = 'none';
    }
});

/**
 * Fungsi utilitas untuk mengubah objek File menjadi string Base64.
 */
function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => resolve(reader.result);
        reader.onerror = error => reject(error);
    });
}