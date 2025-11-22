"""
Ed25519 Digital Signature Web Service - Flask Backend
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
import hashlib
import io
from datetime import datetime

# Import Ed25519 modules
from Ed25519.Ed25519_KeyGen import generate_keypair, Ed25519PrivateKey, Ed25519PublicKey
from Ed25519.Ed25519_Sign import sign
from Ed25519.Ed25519_Verify import verify
from Ed25519.Ed25519_FileSigning import sign_file, verify_file, hash_file
from Ed25519.Ed25519_EmbeddedSignature import embed_signature, verify_embedded_signature, extract_original_file
from Ed25519.Ed25519_MultiSignature import MultiSignatureDocument, Signer

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'json', 'bin'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE


# ============== Utility Functions ==============

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file):
    """Save uploaded file and return path"""
    if not file or file.filename == '':
        return None

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filepath


# ============== 1. Key Generation API ==============

@app.route('/api/keygen', methods=['POST'])
def keygen():
    """
    Generate new keypair
    Returns: {private_key: hex, public_key: hex, timestamp: iso}
    """
    try:
        private_key, public_key = generate_keypair()

        response_data = {
            'status': 'success',
            'private_key': private_key.to_bytes().hex(),
            'public_key': public_key.to_bytes().hex(),
            'timestamp': datetime.now().isoformat(),
            'message': 'Keypair generated successfully'
        }

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400


@app.route('/api/keygen/download', methods=['POST'])
def keygen_download():
    """
    Generate keypair and return as downloadable file
    """
    try:
        private_key, public_key = generate_keypair()

        keydata = {
            'private_key': private_key.to_bytes().hex(),
            'public_key': public_key.to_bytes().hex(),
            'created_at': datetime.now().isoformat(),
            'version': '1.0'
        }

        # Create JSON file
        json_data = json.dumps(keydata, indent=2).encode('utf-8')

        return send_file(
            io.BytesIO(json_data),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'ed25519_keypair_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        )

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400


# ============== 2. Sign Message API ==============

@app.route('/api/sign/message', methods=['POST'])
def sign_message():
    """
    Sign a short message
    Input: {message: string, private_key: hex OR generate: bool}
    Output: {signature: hex, public_key: hex, message_hash: hex}
    """
    try:
        data = request.get_json()
        message = data.get('message', '').encode('utf-8')
        private_key_hex = data.get('private_key')
        generate_new = data.get('generate', False)

        # Get or generate private key
        if generate_new or not private_key_hex:
            private_key, _ = generate_keypair()
            should_return_private = True
        else:
            private_key = Ed25519PrivateKey.from_bytes(bytes.fromhex(private_key_hex))
            should_return_private = False

        # Sign message
        signature = sign(message, private_key)
        signature_bytes = signature.to_bytes()

        # Get public key
        public_key = private_key.get_public_key()
        public_key_bytes = public_key.to_bytes()

        # Compute message hash
        message_hash = hashlib.sha256(message).digest()

        response_data = {
            'status': 'success',
            'signature': signature_bytes.hex(),
            'public_key': public_key_bytes.hex(),
            'message_hash': message_hash.hex(),
            'timestamp': datetime.now().isoformat()
        }

        if should_return_private:
            response_data['private_key'] = private_key.to_bytes().hex()
            response_data['message'] = 'New keypair generated. Save the private key!'

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400


@app.route('/api/verify/message', methods=['POST'])
def verify_message():
    """
    Verify message signature
    Input: {message: string, signature: hex, public_key: hex}
    Output: {valid: bool, message: string}
    """
    try:
        data = request.get_json()
        message = data.get('message', '').encode('utf-8')
        signature_hex = data.get('signature', '')
        public_key_hex = data.get('public_key', '')

        signature_bytes = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)

        is_valid = verify(signature_bytes, message, public_key_bytes)

        return jsonify({
            'status': 'success',
            'valid': is_valid,
            'message': 'Signature valid!' if is_valid else 'Signature invalid!',
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'valid': False,
            'message': str(e)
        }), 400


# ============== 3. Sign File API ==============

@app.route('/api/sign/file', methods=['POST'])
def sign_file_endpoint():
    """
    Sign a file (detached signature)
    Input: file, private_key (optional)
    Output: signature file (.sig)
    """
    try:
        # Get file
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'status': 'error', 'message': 'No file selected'}), 400

        # Save file
        filepath = save_uploaded_file(file)

        # Get private key
        private_key_hex = request.form.get('private_key')
        generate_new = request.form.get('generate') == 'true'

        if generate_new or not private_key_hex:
            private_key, _ = generate_keypair()
            should_return_private = True
        else:
            private_key = Ed25519PrivateKey.from_bytes(bytes.fromhex(private_key_hex))
            should_return_private = False

        # Get metadata
        metadata = {}
        if request.form.get('author'):
            metadata['author'] = request.form.get('author')
        if request.form.get('description'):
            metadata['description'] = request.form.get('description')

        # Sign file
        sig_path = filepath + '.sig'
        file_sig = sign_file(filepath, private_key, sig_path, metadata)

        # Read signature file
        with open(sig_path, 'rb') as f:
            sig_data = f.read()

        # Prepare response
        response = {
            'status': 'success',
            'filename': file.filename,
            'signature_filename': os.path.basename(sig_path),
            'file_hash': file_sig.file_hash.hex(),
            'timestamp': datetime.now().isoformat()
        }

        if should_return_private:
            response['private_key'] = private_key.to_bytes().hex()
            response['message'] = 'New keypair generated. Save the private key!'

        # Return signature file
        return send_file(
            io.BytesIO(sig_data),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=os.path.basename(sig_path)
        )

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

    finally:
        # Cleanup
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)


@app.route('/api/verify/file', methods=['POST'])
def verify_file_endpoint():
    """
    Verify file signature
    Input: file, signature_file
    Output: {valid: bool, ...}
    """
    try:
        if 'file' not in request.files or 'signature' not in request.files:
            return jsonify({'status': 'error', 'message': 'File and signature required'}), 400

        file = request.files['file']
        sig_file = request.files['signature']

        filepath = save_uploaded_file(file)
        sig_path = save_uploaded_file(sig_file)

        result = verify_file(filepath, sig_path)

        return jsonify({
            'status': 'success',
            **result,
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

    finally:
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)
        if 'sig_path' in locals() and os.path.exists(sig_path):
            os.remove(sig_path)


# ============== 4. Embedded Signature API ==============

@app.route('/api/sign/embedded', methods=['POST'])
def sign_embedded():
    """
    Sign and embed signature in PDF
    Input: pdf_file, private_key (optional)
    Output: signed PDF file
    """
    filepath = None
    output_path = None

    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No PDF file provided'}), 400

        file = request.files['file']

        # Check if PDF
        if not file.filename.lower().endswith('.pdf'):
            return jsonify({'status': 'error', 'message': 'Only PDF files supported'}), 400

        filepath = save_uploaded_file(file)

        # Get private key
        private_key_hex = request.form.get('private_key')
        generate_new = request.form.get('generate') == 'true'

        if generate_new or not private_key_hex:
            private_key, _ = generate_keypair()
            should_return_private = True
        else:
            private_key = Ed25519PrivateKey.from_bytes(bytes.fromhex(private_key_hex))
            should_return_private = False

        # Get metadata
        metadata = {}
        if request.form.get('author'):
            metadata['author'] = request.form.get('author')

        # Sign and embed
        output_path = filepath.replace('.pdf', '_signed.pdf')
        embed_signature(filepath, private_key, output_path, metadata)

        # Read signed PDF into memory BEFORE cleanup
        with open(output_path, 'rb') as f:
            pdf_data = f.read()

        # Cleanup files NOW (before sending response)
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        if output_path and os.path.exists(output_path):
            os.remove(output_path)

        # Prepare response headers
        response_headers = {}
        if should_return_private:
            response_headers['X-Private-Key'] = private_key.to_bytes().hex()

        # Return the in-memory PDF data
        return send_file(
            io.BytesIO(pdf_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=os.path.basename(output_path),
            **({'headers': response_headers} if response_headers else {})
        )

    except Exception as e:
        # Cleanup on error
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
        if output_path and os.path.exists(output_path):
            os.remove(output_path)

        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

@app.route('/api/verify/embedded', methods=['POST'])
def verify_embedded():
    """
    Verify embedded signature in PDF
    """
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No PDF file provided'}), 400

        file = request.files['file']
        filepath = save_uploaded_file(file)

        result = verify_embedded_signature(filepath)

        return jsonify({
            'status': 'success',
            **result,
            'timestamp': datetime.now().isoformat()
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

    finally:
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)


# ============== 5. Multi-Signature API ==============

@app.route('/api/multisig/create', methods=['POST'])
def multisig_create():
    """
    Create multi-signature document
    Input: {file, signers: [{name, email, public_key}, ...], threshold}
    """
    try:
        if 'file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No file provided'}), 400

        file = request.files['file']
        filepath = save_uploaded_file(file)

        data = request.get_json()
        signers_info = data.get('signers', [])
        threshold = data.get('threshold')

        # Convert signers
        signers = []
        for signer_info in signers_info:
            signer = Signer(
                name=signer_info['name'],
                email=signer_info['email'],
                public_key=bytes.fromhex(signer_info['public_key']),
                role=signer_info.get('role')
            )
            signers.append(signer)

        # Create document
        doc = MultiSignatureDocument(
            file_path=filepath,
            required_signers=signers,
            threshold=threshold,
            metadata=data.get('metadata')
        )

        # Save document
        doc_path = filepath + '.msig'
        doc.save(doc_path)

        # Read file
        with open(doc_path, 'rb') as f:
            doc_data = f.read()

        return send_file(
            io.BytesIO(doc_data),
            mimetype='application/json',
            as_attachment=True,
            download_name=f'{os.path.basename(filepath)}.msig'
        )

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

    finally:
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)


@app.route('/api/multisig/sign', methods=['POST'])
def multisig_sign():
    """
    Add signature to multi-signature document
    Input: multisig_file, private_key, comment (optional)
    """
    try:
        if 'msig_file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No msig file provided'}), 400

        msig_file = request.files['msig_file']
        private_key_hex = request.form.get('private_key')
        comment = request.form.get('comment')

        # Save files
        msig_path = save_uploaded_file(msig_file)

        # Parse private key
        private_key = Ed25519PrivateKey.from_bytes(bytes.fromhex(private_key_hex))
        public_key = private_key.get_public_key()
        public_key_bytes = public_key.to_bytes()

        # Load document
        original_file = request.form.get('original_file')
        doc = MultiSignatureDocument.load(msig_path, original_file)

        # Find signer info
        signer_info = None
        for required_signer in doc.required_signers:
            if required_signer.public_key.to_bytes() == public_key_bytes:
                signer_info = required_signer
                break

        if not signer_info:
            return jsonify({'status': 'error', 'message': 'Public key not in signers list'}), 400

        # Add signature
        doc.add_signature(private_key, signer_info, comment)

        # Save updated document
        doc.save(msig_path)

        # Return updated document
        with open(msig_path, 'rb') as f:
            doc_data = f.read()

        return send_file(
            io.BytesIO(doc_data),
            mimetype='application/json',
            as_attachment=True,
            download_name=os.path.basename(msig_path)
        )

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

    finally:
        if 'msig_path' in locals() and os.path.exists(msig_path):
            os.remove(msig_path)


@app.route('/api/multisig/status', methods=['POST'])
def multisig_status():
    """
    Get status of multi-signature document
    """
    try:
        if 'msig_file' not in request.files:
            return jsonify({'status': 'error', 'message': 'No msig file provided'}), 400

        msig_file = request.files['msig_file']
        msig_path = save_uploaded_file(msig_file)

        original_file = request.form.get('original_file', 'original_file')
        doc = MultiSignatureDocument.load(msig_path, original_file)

        status_info = doc.get_status()

        return jsonify({
            'status': 'success',
            'document_status': status_info,
            'signers': [
                {
                    'name': sig.signer.name,
                    'email': sig.signer.email,
                    'role': sig.signer.role,
                    'timestamp': sig.timestamp,
                    'comment': sig.comment,
                    'valid': doc.verify_signature(sig.signer.email)
                }
                for sig in doc.get_signature_chain()
            ]
        }), 200

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

    finally:
        if 'msig_path' in locals() and os.path.exists(msig_path):
            os.remove(msig_path)


# ============== Health Check ==============

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'service': 'Ed25519 Digital Signature Service',
        'timestamp': datetime.now().isoformat()
    }), 200


# ============== Error Handlers ==============

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'status': 'error',
        'message': 'File too large. Maximum size is 50MB'
    }), 413


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'message': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)