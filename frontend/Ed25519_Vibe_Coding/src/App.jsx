import React, { useState } from 'react'
import axios from 'axios'
import './App.css'
import {
  Key,
  FileText,
  File,
  Users,
  Zap,
  Download,
  Upload,
  AlertCircle,
  CheckCircle,
  Copy,
  Loader
} from 'lucide-react'

// API Service
const API_BASE = 'http://localhost:5000/api'

const apiService = {
  generateKeypair: async () => {
    const response = await axios.post(`${API_BASE}/keygen`)
    return response.data
  },

  signMessage: async (message, privateKey = null, generate = false, metadata = {}) => {
    const response = await axios.post(`${API_BASE}/sign/message`, {
      message,
      private_key: privateKey,
      generate,
      metadata
    })
    return response.data
  },

  verifyMessage: async (message, signature, publicKey) => {
    const response = await axios.post(`${API_BASE}/verify/message`, {
      message,
      signature,
      public_key: publicKey
    })
    return response.data
  },

  signFile: async (file, privateKey = null, generate = false, author = '', description = '') => {
    const formData = new FormData()
    formData.append('file', file)
    if (privateKey) formData.append('private_key', privateKey)
    if (generate) formData.append('generate', 'true')
    if (author) formData.append('author', author)
    if (description) formData.append('description', description)

    const response = await axios.post(`${API_BASE}/sign/file`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      responseType: 'blob'
    })
    return response
  },

  signEmbedded: async (file, privateKey = null, generate = false, metadata = {}) => {
    const formData = new FormData()
    formData.append('file', file)
    if (privateKey) formData.append('private_key', privateKey)
    if (generate) formData.append('generate', 'true')

    // Thêm tất cả metadata vào formData
    Object.entries(metadata).forEach(([key, value]) => {
      if (value) {
        formData.append(key, value)
      }
    })

    // Thêm custom fields riêng
    if (metadata.customFields && Array.isArray(metadata.customFields)) {
      metadata.customFields.forEach((field, index) => {
        if (field.key && field.value) {
          formData.append(`custom_field_${index}_key`, field.key)
          formData.append(`custom_field_${index}_value`, field.value)
        }
      })
    }

    const response = await axios.post(`${API_BASE}/sign/embedded`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
      responseType: 'blob'
    })
    return response
  },

  verifyEmbedded: async (file) => {
    const formData = new FormData()
    formData.append('file', file)

    const response = await axios.post(`${API_BASE}/verify/embedded`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    return response.data
  }
}

const readKeypairFile = (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target.result)
        if (json.private_key) {
          resolve(json.private_key)
        } else {
          reject(new Error('Invalid keypair file format'))
        }
      } catch (error) {
        reject(new Error('Failed to parse keypair file'))
      }
    }
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.readAsText(file)
  })
}

const downloadSignatureResult = (signatureData, message, onSuccess) => {
  if (message.length > 1000) {
    if (!confirm('Message is very long. Continue downloading?')) {
      return
    }
  }

  const json = JSON.stringify({
    message: message,
    signature: signatureData.signature,
    public_key: signatureData.public_key,
    message_hash: signatureData.message_hash,
    timestamp: signatureData.timestamp,
    metadata: signatureData.metadata || {},
    algorithm: "Ed25519",
    version: "1.0"
  }, null, 2)

  const blob = new Blob([json], { type: 'application/json' })
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `signature_${new Date().toISOString().split('T')[0]}.json`
  a.click()
  onSuccess('Signature file downloaded!')
}

// ============== Main App Component ==============

function App() {
  const [activeTab, setActiveTab] = useState('keygen')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [messageType, setMessageType] = useState('') // 'success', 'error'

  const showMessage = (text, type = 'success') => {
    setMessage(text)
    setMessageType(type)
    setTimeout(() => setMessage(''), 5000)
  }

  return (
    <div className="app">
      <header className="header">
        <div className="container">
          <div className="logo">
            <Zap className="logo-icon" />
            <h1>Ed25519 Digital Signature Service</h1>
          </div>
          <p className="subtitle">Secure digital signing and verification</p>
        </div>
      </header>

      {message && (
        <div className={`message message-${messageType}`}>
          {messageType === 'success' ? <CheckCircle size={20} /> : <AlertCircle size={20} />}
          <span>{message}</span>
        </div>
      )}

      <div className="container">
        <nav className="tabs">
          <button
            className={`tab ${activeTab === 'keygen' ? 'active' : ''}`}
            onClick={() => setActiveTab('keygen')}
          >
            <Key size={18} /> Create Key
          </button>
          <button
            className={`tab ${activeTab === 'message' ? 'active' : ''}`}
            onClick={() => setActiveTab('message')}
          >
            <FileText size={18} /> Sign Message
          </button>
          <button
            className={`tab ${activeTab === 'file' ? 'active' : ''}`}
            onClick={() => setActiveTab('file')}
          >
            <File size={18} /> Sign File
          </button>
          <button
            className={`tab ${activeTab === 'multisig' ? 'active' : ''}`}
            onClick={() => setActiveTab('multisig')}
          >
            <Users size={18} /> Multi-Signature
          </button>
        </nav>

        <main className="content">
          {activeTab === 'keygen' && (
            <KeyGenTab onSuccess={showMessage} onError={(e) => showMessage(e, 'error')} />
          )}
          {activeTab === 'message' && (
            <MessageTab onSuccess={showMessage} onError={(e) => showMessage(e, 'error')} />
          )}
          {activeTab === 'file' && (
            <FileTab onSuccess={showMessage} onError={(e) => showMessage(e, 'error')} />
          )}
          {activeTab === 'multisig' && (
            <MultiSigTab onSuccess={showMessage} onError={(e) => showMessage(e, 'error')} />
          )}
        </main>
      </div>
    </div>
  )
}

// ============== Tab Components ==============

function KeyGenTab({ onSuccess, onError }) {
  const [loading, setLoading] = useState(false)
  const [keypair, setKeypair] = useState(null)

  const generateKeypair = async () => {
    try {
      setLoading(true)
      const data = await apiService.generateKeypair()
      setKeypair(data)
      onSuccess('Keypair generated successfully!')
    } catch (error) {
      onError(error.response?.data?.message || 'Error generating keypair')
    } finally {
      setLoading(false)
    }
  }

  const downloadKeypair = async () => {
    try {
      const jsonString = JSON.stringify({
        private_key: keypair.private_key,
        public_key: keypair.public_key,
        created_at: keypair.timestamp
      }, null, 2)

      const blob = new Blob([jsonString], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ed25519_keypair_${new Date().toISOString().split('T')[0]}.json`
      a.click()
      onSuccess('Keypair downloaded!')
    } catch (error) {
      onError('Error downloading keypair')
    }
  }

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text)
    onSuccess(`${label} copied to clipboard!`)
  }

  return (
    <div className="tab-content">
      <div className="card">
        <h2>Generate New Keypair</h2>
        <p className="description">Create a new Ed25519 keypair for signing and verification</p>

        <button className="btn btn-primary" onClick={generateKeypair} disabled={loading}>
          {loading ? <Loader className="spinner" /> : <Key size={18} />}
          Generate Keypair
        </button>

        {keypair && (
          <div className="keypair-display">
            <div className="key-item">
              <h3>Public Key (32 bytes)</h3>
              <div className="key-box">
                <code>{keypair.public_key.substring(0, 64)}...</code>
                <button
                  className="copy-btn"
                  onClick={() => copyToClipboard(keypair.public_key, 'Public key')}
                  title="Copy"
                >
                  <Copy size={16} />
                </button>
              </div>
            </div>

            <div className="key-item">
              <h3>Private Key (32 bytes)</h3>
              <div className="key-box warning">
                <code>{keypair.private_key.substring(0, 64)}...</code>
                <button
                  className="copy-btn"
                  onClick={() => copyToClipboard(keypair.private_key, 'Private key')}
                  title="Copy"
                >
                  <Copy size={16} />
                </button>
              </div>
              <p className="warning-text">⚠️ Keep your private key safe!</p>
            </div>

            <button className="btn btn-success" onClick={downloadKeypair}>
              <Download size={18} />
              Download Keypair
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

function MessageTab({ onSuccess, onError }) {
  const [activeMode, setActiveMode] = useState('sign') // 'sign' or 'verify'
  const [loading, setLoading] = useState(false)

  return (
    <div className="tab-content">
      <div className="mode-toggle">
        <button
          className={`mode-btn ${activeMode === 'sign' ? 'active' : ''}`}
          onClick={() => setActiveMode('sign')}
        >
          Sign
        </button>
        <button
          className={`mode-btn ${activeMode === 'verify' ? 'active' : ''}`}
          onClick={() => setActiveMode('verify')}
        >
          Verify
        </button>
      </div>

      {activeMode === 'sign' ? (
        <SignMessageForm onSuccess={onSuccess} onError={onError} />
      ) : (
        <VerifyMessageForm onSuccess={onSuccess} onError={onError} />
      )}
    </div>
  )
}

function SignMessageForm({ onSuccess, onError }) {
  const [message, setMessage] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [generateNew, setGenerateNew] = useState(true)
  const [loading, setLoading] = useState(false)
  const [signature, setSignature] = useState(null)
  const [showDownloadOption, setShowDownloadOption] = useState(false) // MỚI

  const [signerName, setSignerName] = useState('')
  const [signerEmail, setSignerEmail] = useState('')
  const [customFields, setCustomFields] = useState([])

  const handleSign = async () => {
    if (!message.trim()) {
      onError('Please enter a message')
      return
    }

    try {
      setLoading(true)

      const metadata = {}
      if (signerName) metadata.signer_name = signerName
      if (signerEmail) metadata.signer_email = signerEmail

      // Thêm custom fields
      customFields.forEach(field => {
        if (field.key && field.value) {
          metadata[field.key] = field.value
        }
      })

      const data = await apiService.signMessage(message, privateKey || null, generateNew, metadata)
      setSignature(data)
      onSuccess('Message signed successfully!')

      if (data.private_key) {
        setPrivateKey(data.private_key)
        setShowDownloadOption(true) // MỚI: Hiện tùy chọn download
      }
    } catch (error) {
      onError(error.response?.data?.message || 'Error signing message')
    } finally {
      setLoading(false)
    }
  }

  // MỚI: Hàm download private key
  const downloadPrivateKey = () => {
    const json = JSON.stringify({
      private_key: privateKey,
      public_key: signature.public_key,
      created_at: new Date().toISOString()
    }, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `private_key_${new Date().toISOString().split('T')[0]}.json`
    a.click()
    onSuccess('Private key downloaded!')
    setShowDownloadOption(false)
  }

  // MỚI: Thêm custom field
  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '' }])
  }

  // MỚI: Xóa custom field
  const removeCustomField = (index) => {
    setCustomFields(customFields.filter((_, i) => i !== index))
  }

  // MỚI: Cập nhật custom field
  const updateCustomField = (index, field, value) => {
    const updated = [...customFields]
    updated[index][field] = value
    setCustomFields(updated)
  }

  return (
    <div className="card">
      <h2>Sign Message</h2>

      <div className="form-group">
        <label>Message to sign</label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter your message..."
          rows={4}
        />
      </div>

      {/* MỚI: Signer Information Section */}
      <div className="metadata-section">
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', color: '#555' }}>
          Signer Information (Optional)
        </h3>

        <div className="form-group">
          <label>Your Name</label>
          <input
            type="text"
            value={signerName}
            onChange={(e) => setSignerName(e.target.value)}
            placeholder="John Doe"
          />
        </div>

        <div className="form-group">
          <label>Your Email</label>
          <input
            type="email"
            value={signerEmail}
            onChange={(e) => setSignerEmail(e.target.value)}
            placeholder="john@example.com"
          />
        </div>

        {/* MỚI: Custom Metadata Fields */}
        <div className="custom-fields-section">
          <div className="custom-fields-header">
            <label>Custom Fields</label>
            <button
              type="button"
              className="btn-add-field"
              onClick={addCustomField}
            >
              + Add Field
            </button>
          </div>

          {customFields.length > 0 && (
            <div className="custom-fields-list">
              {customFields.map((field, index) => (
                <div key={index} className="custom-field-row">
                  <input
                    type="text"
                    value={field.key}
                    onChange={(e) => updateCustomField(index, 'key', e.target.value)}
                    placeholder="Field name (e.g., department)"
                    className="custom-field-input"
                  />
                  <input
                    type="text"
                    value={field.value}
                    onChange={(e) => updateCustomField(index, 'value', e.target.value)}
                    placeholder="Value"
                    className="custom-field-input"
                  />
                  <button
                    type="button"
                    onClick={() => removeCustomField(index)}
                    className="btn-remove-field"
                    title="Remove field"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="form-group">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={generateNew}
            onChange={(e) => setGenerateNew(e.target.checked)}
          />
          Generate new keypair
        </label>
      </div>

      {!generateNew && (
        <div className="form-group">
          <label>Private Key</label>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => document.getElementById('keypair-upload-msg').click()}
              style={{ flex: 1 }}
            >
              <Upload size={18} />
              Upload Keypair File
            </button>
            <input
              id="keypair-upload-msg"
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={async (e) => {
                const file = e.target.files?.[0]
                if (file) {
                  try {
                    const key = await readKeypairFile(file)
                    setPrivateKey(key)
                    onSuccess('Keypair file loaded!')
                  } catch (error) {
                    onError(error.message)
                  }
                }
              }}
            />
          </div>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Paste private key or upload keypair file..."
            rows={3}
          />
        </div>
      )}

      <button className="btn btn-primary" onClick={handleSign} disabled={loading}>
        {loading ? <Loader className="spinner" /> : <Zap size={18} />}
        Sign Message
      </button>

      {/* MỚI: Popup download private key */}
      {showDownloadOption && (
        <div className="download-option-popup">
          <div className="popup-content">
            <h3>⚠️ Save Your Private Key</h3>
            <p>A new keypair was generated. Do you want to download the private key?</p>
            <p className="warning-text">You won't be able to download it again!</p>
            <div style={{ display: 'flex', gap: '10px', marginTop: '1rem' }}>
              <button className="btn btn-success" onClick={downloadPrivateKey}>
                <Download size={18} />
                Download Private Key
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => setShowDownloadOption(false)}
              >
                Skip
              </button>
            </div>
          </div>
        </div>
      )}

      {signature && (
        <div className="result-box">
          <h3>Signature Result</h3>

          {signature.metadata && Object.keys(signature.metadata).length > 0 && (
            <div className="metadata-display">
              <h4>Signer Information:</h4>
              {Object.entries(signature.metadata).map(([key, value]) => (
                <p key={key}>
                  <strong>{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</strong> {value}
                </p>
              ))}
            </div>
          )}

          <ResultDisplay
            data={signature}
            onDownload={() => downloadSignatureResult(signature, message, onSuccess)}
          />
        </div>
      )}
    </div>
  )
}

function VerifyMessageForm({ onSuccess, onError }) {
  const [message, setMessage] = useState('')
  const [signature, setSignature] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [metadata, setMetadata] = useState(null)

  // MỚI: Hàm đọc file chữ ký
  const readSignatureFile = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = (e) => {
        try {
          const json = JSON.parse(e.target.result)
          // Validate required fields
          if (!json.signature || !json.public_key) {
            reject(new Error('Invalid signature file: missing signature or public_key'))
            return
          }

          resolve({
            signature: json.signature,
            publicKey: json.public_key,
            message: json.message || '', // MỚI: Lấy message nếu có
            messageHash: json.message_hash || '',
            metadata: json.metadata || {}
          })
        } catch (error) {
          reject(new Error('Failed to parse signature file'))
        }
      }
      reader.onerror = () => reject(new Error('Failed to read file'))
      reader.readAsText(file)
    })
  }

  const handleVerify = async () => {
    if (!message.trim() || !signature.trim() || !publicKey.trim()) {
      onError('Please fill all fields')
      return
    }

    try {
      setLoading(true)
      const data = await apiService.verifyMessage(message, signature, publicKey)
      setResult(data)
      onSuccess(data.message)
    } catch (error) {
      onError(error.response?.data?.message || 'Error verifying message')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <h2>Verify Message</h2>

      <div className="form-group">
        <label>Message</label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Original message..."
          rows={3}
        />
      </div>

      {/* MỚI: Nút upload signature file */}
      <div className="form-group">
        <label>Signature</label>
        <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => document.getElementById('signature-file-upload').click()}
            style={{ flex: 1 }}
          >
            <Upload size={18} />
            Upload Signature File
          </button>
          <input
            id="signature-file-upload"
            type="file"
            accept=".json"
            style={{ display: 'none' }}
            onChange={async (e) => {
              const file = e.target.files?.[0]
              if (file) {
                try {
                  const data = await readSignatureFile(file)
                  setSignature(data.signature)
                  setPublicKey(data.publicKey)
                  if (data.message) {
                    setMessage(data.message) // MỚI: Auto-fill message
                  }
                  if (data.metadata) {
                    setMetadata(data.metadata)  // MỚI: Lưu metadata
                  }
                  onSuccess('Signature file loaded!' + (data.message ? ' Message auto-filled.' : ''))
                } catch (error) {
                  onError(error.message)
                }
              }
            }}
          />
        </div>
        <textarea
          value={signature}
          onChange={(e) => setSignature(e.target.value)}
          placeholder="Signature hex string or upload signature file..."
          rows={3}
        />
      </div>

      <div className="form-group">
        <label>Public Key (hex)</label>
        <textarea
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
          placeholder="Public key hex string (auto-filled from signature file)..."
          rows={2}
        />
      </div>

      {metadata && Object.keys(metadata).length > 0 && (
        <div className="metadata-display" style={{ marginBottom: '1rem' }}>
          <h4>Signer Information from File:</h4>
          {Object.entries(metadata).map(([key, value]) => (
            <p key={key}>
              <strong>{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</strong> {value}
            </p>
          ))}
        </div>
      )}

      <button className="btn btn-primary" onClick={handleVerify} disabled={loading}>
        {loading ? <Loader className="spinner" /> : <CheckCircle size={18} />}
        Verify Message
      </button>

      {result && (
        <div className={`result-box ${result.valid ? 'success' : 'error'}`}>
          <h3>{result.valid ? '✓ Valid' : '✗ Invalid'}</h3>
          <p>{result.message}</p>

          {metadata && Object.keys(metadata).length > 0 && (
            <div className="metadata-display" style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid rgba(0,0,0,0.1)' }}>
              <h4 style={{ marginBottom: '0.75rem' }}>Signer Information:</h4>
              {Object.entries(metadata).map(([key, value]) => (
                <p key={key} style={{ marginBottom: '0.5rem' }}>
                  <strong>{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:</strong> {value}
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function FileTab({ onSuccess, onError }) {
  const [activeMode, setActiveMode] = useState('detached') // 'detached', 'embedded', 'verify'

  return (
    <div className="tab-content">
      <div className="mode-toggle" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0' }}>
        <button
          className={`mode-btn ${activeMode === 'detached' ? 'active' : ''}`}
          onClick={() => setActiveMode('detached')}
        >
          Sign (Detached)
        </button>
        <button
          className={`mode-btn ${activeMode === 'embedded' ? 'active' : ''}`}
          onClick={() => setActiveMode('embedded')}
        >
          Sign (Embedded PDF)
        </button>
        <button
          className={`mode-btn ${activeMode === 'verify' ? 'active' : ''}`}
          onClick={() => setActiveMode('verify')}
        >
          Verify
        </button>
      </div>

      {activeMode === 'detached' && (
        <SignFileDetachedForm onSuccess={onSuccess} onError={onError} />
      )}
      {activeMode === 'embedded' && (
        <SignFileEmbeddedForm onSuccess={onSuccess} onError={onError} />
      )}
      {activeMode === 'verify' && (
        <VerifyFileForm onSuccess={onSuccess} onError={onError} />
      )}
    </div>
  )
}

function SignFileDetachedForm({ onSuccess, onError }) {
  const [file, setFile] = useState(null)
  const [privateKey, setPrivateKey] = useState('')
  const [generateNew, setGenerateNew] = useState(true)
  const [author, setAuthor] = useState('')
  const [signerEmail, setSignerEmail] = useState('')
  const [customFields, setCustomFields] = useState([])
  const [loading, setLoading] = useState(false)
  const [showDownloadOption, setShowDownloadOption] = useState(false)

  const handleSign = async () => {
    if (!file) {
      onError('Please select a file')
      return
    }

    try {
      setLoading(true)

      const metadata = {}
      if (author) metadata.author = author
      if (signerEmail) metadata.signer_email = signerEmail

      // Thêm custom fields
      customFields.forEach(field => {
        if (field.key && field.value) {
          metadata[field.key] = field.value
        }
      })

      // Thêm metadata vào form data
      const formData = new FormData()
      formData.append('file', file)
      if (privateKey) formData.append('private_key', privateKey)
      if (generateNew) formData.append('generate', 'true')
      if (author) formData.append('author', author)
      if (signerEmail) formData.append('signer_email', signerEmail)

      // Thêm custom fields vào form data
      customFields.forEach((field, index) => {
        if (field.key && field.value) {
          formData.append(`custom_field_${index}_key`, field.key)
          formData.append(`custom_field_${index}_value`, field.value)
        }
      })

      const response = await apiService.signFile(file, privateKey || null, generateNew, author)

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = `${file.name}.sig`
      a.click()

      onSuccess(`Signature file downloaded!`)

      if (response.headers['x-private-key']) {
        promptSavePrivateKey(response.headers['x-private-key'], onSuccess)
      }
    } catch (error) {
      onError(error.response?.data?.message || 'Error signing file')
    } finally {
      setLoading(false)
    }
  }

  // Thêm custom field
  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '' }])
  }

  // Xóa custom field
  const removeCustomField = (index) => {
    setCustomFields(customFields.filter((_, i) => i !== index))
  }

  // Cập nhật custom field
  const updateCustomField = (index, field, value) => {
    const updated = [...customFields]
    updated[index][field] = value
    setCustomFields(updated)
  }

  return (
    <div className="card">
      <h2>Sign File (Detached Signature)</h2>
      <p className="description">Create a separate .sig file for any file type</p>

      <div className="form-group">
        <label>Select File</label>
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
          className="file-input"
        />
        {file && <p className="file-info">📄 {file.name}</p>}
      </div>

      <div className="form-group">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={generateNew}
            onChange={(e) => setGenerateNew(e.target.checked)}
          />
          Generate new keypair
        </label>
      </div>

      {!generateNew && (
        <div className="form-group">
          <label>Private Key</label>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => document.getElementById('keypair-upload-detached').click()}
              style={{ flex: 1 }}
            >
              <Upload size={18} />
              Upload Keypair File
            </button>
            <input
              id="keypair-upload-detached"
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={async (e) => {
                const file = e.target.files?.[0]
                if (file) {
                  try {
                    const key = await readKeypairFile(file)
                    setPrivateKey(key)
                    onSuccess('Keypair file loaded!')
                  } catch (error) {
                    onError(error.message)
                  }
                }
              }}
            />
          </div>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Paste private key or upload keypair file..."
            rows={2}
          />
        </div>
      )}

      {/* PHẦN THÔNG TIN NGƯỜI KÝ - MỚI */}
      <div className="metadata-section">
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', color: '#555' }}>
          Signer Information (Optional)
        </h3>

        <div className="form-group">
          <label>Your Name</label>
          <input
            type="text"
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            placeholder="John Doe"
          />
        </div>

        <div className="form-group">
          <label>Your Email</label>
          <input
            type="email"
            value={signerEmail}
            onChange={(e) => setSignerEmail(e.target.value)}
            placeholder="john@example.com"
          />
        </div>

        {/* PHẦN CUSTOM FIELDS - MỚI */}
        <div className="custom-fields-section">
          <div className="custom-fields-header">
            <label>Custom Fields</label>
            <button
              type="button"
              className="btn-add-field"
              onClick={addCustomField}
            >
              + Add Field
            </button>
          </div>

          {customFields.length > 0 && (
            <div className="custom-fields-list">
              {customFields.map((field, index) => (
                <div key={index} className="custom-field-row">
                  <input
                    type="text"
                    value={field.key}
                    onChange={(e) => updateCustomField(index, 'key', e.target.value)}
                    placeholder="Field name (e.g., department)"
                    className="custom-field-input"
                  />
                  <input
                    type="text"
                    value={field.value}
                    onChange={(e) => updateCustomField(index, 'value', e.target.value)}
                    placeholder="Value"
                    className="custom-field-input"
                  />
                  <button
                    type="button"
                    onClick={() => removeCustomField(index)}
                    className="btn-remove-field"
                    title="Remove field"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <button className="btn btn-primary" onClick={handleSign} disabled={loading || !file}>
        {loading ? <Loader className="spinner" /> : <Zap size={18} />}
        Sign File
      </button>
    </div>
  )
}

function SignFileEmbeddedForm({ onSuccess, onError }) {
  const [file, setFile] = useState(null)
  const [privateKey, setPrivateKey] = useState('')
  const [generateNew, setGenerateNew] = useState(true)
  const [author, setAuthor] = useState('')
  const [signerEmail, setSignerEmail] = useState('')
  const [customFields, setCustomFields] = useState([])
  const [loading, setLoading] = useState(false)

  const handleSign = async () => {
    if (!file) {
      onError('Please select a PDF file')
      return
    }

    if (!file.name.toLowerCase().endsWith('.pdf')) {
      onError('Only PDF files are supported for embedded signatures')
      return
    }

    try {
      setLoading(true)

      const metadata = {
        author: author,
        signer_email: signerEmail,
        customFields: customFields.filter(f => f.key && f.value) // chỉ gửi fields có giá trị
      }

      const response = await apiService.signEmbedded(
        file,
        privateKey || null,
        generateNew,
        metadata
      )

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = file.name.replace('.pdf', '_signed.pdf')
      a.click()

      onSuccess('Signed PDF downloaded!')

      if (response.headers['x-private-key']) {
        promptSavePrivateKey(response.headers['x-private-key'], onSuccess)
      }
    } catch (error) {
      onError(error.response?.data?.message || 'Error signing PDF')
    } finally {
      setLoading(false)
    }
  }

  // Thêm custom field
  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '' }])
  }

  // Xóa custom field
  const removeCustomField = (index) => {
    setCustomFields(customFields.filter((_, i) => i !== index))
  }

  // Cập nhật custom field
  const updateCustomField = (index, field, value) => {
    const updated = [...customFields]
    updated[index][field] = value
    setCustomFields(updated)
  }

  return (
    <div className="card">
      <h2>Sign PDF (Embedded Signature)</h2>
      <p className="description">Embed signature directly into PDF file</p>

      <div className="form-group">
        <label>Select PDF File</label>
        <input
          type="file"
          accept=".pdf"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
          className="file-input"
        />
        {file && <p className="file-info">📄 {file.name}</p>}
      </div>

      <div className="form-group">
        <label className="checkbox">
          <input
            type="checkbox"
            checked={generateNew}
            onChange={(e) => setGenerateNew(e.target.checked)}
          />
          Generate new keypair
        </label>
      </div>

      {!generateNew && (
        <div className="form-group">
          <label>Private Key</label>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => document.getElementById('keypair-upload-embedded').click()}
              style={{ flex: 1 }}
            >
              <Upload size={18} />
              Upload Keypair File
            </button>
            <input
              id="keypair-upload-embedded"
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={async (e) => {
                const file = e.target.files?.[0]
                if (file) {
                  try {
                    const key = await readKeypairFile(file)
                    setPrivateKey(key)
                    onSuccess('Keypair file loaded!')
                  } catch (error) {
                    onError(error.message)
                  }
                }
              }}
            />
          </div>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Paste private key or upload keypair file..."
            rows={2}
          />
        </div>
      )}

      <div className="metadata-section">
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', color: '#555' }}>
          Signer Information (Optional)
        </h3>

        <div className="form-group">
          <label>Your Name</label>
          <input
            type="text"
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            placeholder="John Doe"
          />
        </div>

        <div className="form-group">
          <label>Your Email</label>
          <input
            type="email"
            value={signerEmail}
            onChange={(e) => setSignerEmail(e.target.value)}
            placeholder="john@example.com"
          />
        </div>

        {/* PHẦN CUSTOM FIELDS - MỚI */}
        <div className="custom-fields-section">
          <div className="custom-fields-header">
            <label>Custom Fields</label>
            <button
              type="button"
              className="btn-add-field"
              onClick={addCustomField}
            >
              + Add Field
            </button>
          </div>

          {customFields.length > 0 && (
            <div className="custom-fields-list">
              {customFields.map((field, index) => (
                <div key={index} className="custom-field-row">
                  <input
                    type="text"
                    value={field.key}
                    onChange={(e) => updateCustomField(index, 'key', e.target.value)}
                    placeholder="Field name (e.g., department)"
                    className="custom-field-input"
                  />
                  <input
                    type="text"
                    value={field.value}
                    onChange={(e) => updateCustomField(index, 'value', e.target.value)}
                    placeholder="Value"
                    className="custom-field-input"
                  />
                  <button
                    type="button"
                    onClick={() => removeCustomField(index)}
                    className="btn-remove-field"
                    title="Remove field"
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <button className="btn btn-primary" onClick={handleSign} disabled={loading || !file}>
        {loading ? <Loader className="spinner" /> : <Zap size={18} />}
        Sign PDF
      </button>
    </div>
  )
}

function VerifyFileForm({ onSuccess, onError }) {
  const [verifyType, setVerifyType] = useState('detached') // 'detached' or 'embedded'
  const [file, setFile] = useState(null)
  const [signatureFile, setSignatureFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [metadata, setMetadata] = useState(null)

  const handleVerifyDetached = async () => {
    if (!file || !signatureFile) {
      onError('Please select both file and signature')
      return
    }

    try {
      setLoading(true)
      const formData = new FormData()
      formData.append('file', file)
      formData.append('signature', signatureFile)

      const response = await axios.post(`${API_BASE}/verify/file`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })

      setResult(response.data)
      if (response.data.metadata) {
        setMetadata(response.data.metadata)
      }
      onSuccess(response.data.message)
    } catch (error) {
      onError(error.response?.data?.message || 'Error verifying file')
    } finally {
      setLoading(false)
    }
  }

  const handleVerifyEmbedded = async () => {
    if (!file) {
      onError('Please select a signed PDF file')
      return
    }

    try {
      setLoading(true)
      const data = await apiService.verifyEmbedded(file)
      setResult(data)
      if (data.metadata) {
        setMetadata(data.metadata)
      }
      onSuccess(data.message)
    } catch (error) {
      onError(error.response?.data?.message || 'Error verifying embedded signature')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <h2>Verify File Signature</h2>

      <div className="form-group">
        <label>Signature Type</label>
        <div className="radio-group">
          <label className="radio">
            <input
              type="radio"
              checked={verifyType === 'detached'}
              onChange={() => {
                setVerifyType('detached')
                setResult(null)
              }}
            />
            Detached (.sig file)
          </label>
          <label className="radio">
            <input
              type="radio"
              checked={verifyType === 'embedded'}
              onChange={() => {
                setVerifyType('embedded')
                setResult(null)
              }}
            />
            Embedded (signed PDF)
          </label>
        </div>
      </div>

      {verifyType === 'detached' ? (
        <>
          <div className="form-group">
            <label>Original File</label>
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="file-input"
            />
            {file && <p className="file-info">📄 {file.name}</p>}
          </div>

          <div className="form-group">
            <label>Signature File (.sig)</label>
            <input
              type="file"
              accept=".sig"
              onChange={(e) => setSignatureFile(e.target.files?.[0] || null)}
              className="file-input"
            />
            {signatureFile && <p className="file-info">📄 {signatureFile.name}</p>}
          </div>

          <button
            className="btn btn-primary"
            onClick={handleVerifyDetached}
            disabled={loading || !file || !signatureFile}
          >
            {loading ? <Loader className="spinner" /> : <CheckCircle size={18} />}
            Verify Signature
          </button>
        </>
      ) : (
        <>
          <div className="form-group">
            <label>Signed PDF File</label>
            <input
              type="file"
              accept=".pdf"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="file-input"
            />
            {file && <p className="file-info">📄 {file.name}</p>}
          </div>

          <button
            className="btn btn-primary"
            onClick={handleVerifyEmbedded}
            disabled={loading || !file}
          >
            {loading ? <Loader className="spinner" /> : <CheckCircle size={18} />}
            Verify Embedded Signature
          </button>
        </>
      )}

      {result && (
        <div className={`result-box ${result.valid ? 'success' : 'error'}`}>
          <h3>{result.valid ? '✓ Valid' : '✗ Invalid'}</h3>
          <p>{result.message}</p>
          {result.file_hash && (
            <p>
              <strong>Hash:</strong> {result.file_hash.substring(0, 32)}...
            </p>
          )}
          {result.signer && (
            <p>
              <strong>Signer:</strong> {result.signer}
            </p>
          )}
          {result.timestamp && (
            <p>
              <strong>Signed:</strong> {new Date(result.timestamp).toLocaleString()}
            </p>
          )}

          {metadata && Object.keys(metadata).length > 0 && (
            <div className="metadata-display" style={{
              marginTop: '1rem',
              paddingTop: '1rem',
              borderTop: '1px solid rgba(0,0,0,0.1)'
            }}>
              <h4>Signer Information:</h4>
              {Object.entries(metadata).map(([key, value]) => (
                <p key={key}>
                  <strong>
                    {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:
                  </strong> {value}
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function MultiSigTab({ onSuccess, onError }) {
  return (
    <div className="card">
      <h2>Multi-Signature</h2>
      <p className="description">Multiple parties signing the same document</p>
      <p style={{ marginTop: '1rem', padding: '1rem', backgroundColor: '#e3f2fd', borderRadius: '8px' }}>
        This feature requires uploading and managing multiple signature files. It will be fully implemented in the next phase with dedicated UI for managing signers and tracking signature status.
      </p>
    </div>
  )
}

// ============== Utility Components ==============

function ResultDisplay({ data, onDownload }) {
  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text)
    alert(`${label} copied!`)
  }

  return (
    <div className="result-items">
      {/* MỚI: Nút download signature - CHỈ hiện khi có onDownload */}
      {data.signature && data.public_key && onDownload && (
        <button
          className="btn btn-secondary"
          onClick={onDownload}
          style={{ marginBottom: '1rem', width: '100%' }}
        >
          <Download size={18} />
          Download Signature File
        </button>
      )}

      {data.signature && (
        <div className="result-item">
          <strong>Signature:</strong>
          <code>{data.signature.substring(0, 64)}...</code>
          <button onClick={() => copyToClipboard(data.signature, 'Signature')} className="copy-btn">
            <Copy size={16} />
          </button>
        </div>
      )}
      {data.public_key && (
        <div className="result-item">
          <strong>Public Key:</strong>
          <code>{data.public_key.substring(0, 64)}...</code>
          <button onClick={() => copyToClipboard(data.public_key, 'Public Key')} className="copy-btn">
            <Copy size={16} />
          </button>
        </div>
      )}
      {data.private_key && (
        <div className="result-item warning">
          <strong>Private Key (NEW):</strong>
          <code>{data.private_key.substring(0, 64)}...</code>
          <button onClick={() => copyToClipboard(data.private_key, 'Private Key')} className="copy-btn">
            <Copy size={16} />
          </button>
          <p className="warning-text">⚠️ Save this key safely!</p>
        </div>
      )}
    </div>
  )
}

function promptSavePrivateKey(privateKey, onSuccess) {
  const json = JSON.stringify({ private_key: privateKey }, null, 2)
  const blob = new Blob([json], { type: 'application/json' })
  const url = window.URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `private_key_${new Date().toISOString().split('T')[0]}.json`
  a.click()
  onSuccess('Private key file downloaded!')
}

export default App