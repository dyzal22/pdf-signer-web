import os
import json
import base64
    from http.server import BaseHTTPRequestHandler
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# -- - FUNGSI KRIPTOGRAFI(Sama seperti sebelumnya)-- -

    def sign_data(data_bytes, private_key_pem):
"""Menandatangani data byte dengan private key PEM."""
try:
        # 1. Muat Private Key dari string PEM(dari Environment Variable)
private_key = serialization.load_pem_private_key(
    private_key_pem.encode('utf-8'),
    password = None,  # Asumsi kunci tidak terproteksi password
            backend = default_backend()
)

        # 2. Buat hash dari data(PDF)
digest = hashes.Hash(hashes.SHA256(), backend = default_backend())
digest.update(data_bytes)
hash_data = digest.finalize()

        # 3. Tanda tangani hash
signature = private_key.sign(
    hash_data,
    asym_padding.PSS(
        mgf = asym_padding.MGF1(hashes.SHA256()),
        salt_length = asym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
        
        # 4. Kembalikan hash dan signature dalam format Base64 agar aman di JSON
return {
    "hash_b64": base64.b64encode(hash_data).decode('utf-8'),
    "signature_b64": base64.b64encode(signature).decode('utf-8')
}
        
    except Exception as e:
return { "error": f"Gagal menandatangani: {str(e)}"}

# -- - HANDLER SERVERLESS VERCEL-- -

    class handler(BaseHTTPRequestHandler):

    def do_POST(self):
try:
            # 1. Baca Private Key dari Vercel Environment Variable
            # INI ADALAH CARA AMAN MENYIMPAN KUNCI
private_key_pem = os.environ.get('PRIVATE_KEY')

if not private_key_pem:
    self.send_response(500)
self.send_header('Content-type', 'application/json')
self.end_headers()
self.wfile.write(json.dumps({ "error": "PRIVATE_KEY tidak diatur di server." }).encode('utf-8'))
return

            # 2. Baca data JSON yang dikirim dari frontend
content_length = int(self.headers['Content-Length'])
post_data = self.rfile.read(content_length)
data = json.loads(post_data)

            # 3. Ambil data PDF(yang dikirim sebagai Base64) dan decode
pdf_b64 = data.get('pdf_data')
if not pdf_b64:
                raise ValueError("Tidak ada 'pdf_data' dalam request.")
                
            # Hapus header data URL jika ada(cth: "data:application/pdf;base64,")
if ',' in pdf_b64:
    pdf_b64 = pdf_b64.split(',', 1)[1]

pdf_bytes = base64.b64decode(pdf_b64)

            # 4. Panggil fungsi signing
result = sign_data(pdf_bytes, private_key_pem)

            # 5. Kirim hasil(hash + signature) kembali ke frontend
self.send_response(200)
self.send_header('Content-type', 'application/json')
self.end_headers()
self.wfile.write(json.dumps(result).encode('utf-8'))

        except Exception as e:
            # Tangani error
self.send_response(400)
self.send_header('Content-type', 'application/json')
self.end_headers()
self.wfile.write(json.dumps({ "error": str(e) }).encode('utf-8'))