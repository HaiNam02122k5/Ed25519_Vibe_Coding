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

  signMessage: async (message, privateKey = null, generate = false) => {
    const response = await axios.post(`${API_BASE}/sign/message`, {
      message,
      private_key: privateKey,
      generate
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

  signEmbedded: async (file, privateKey = null, generate = false, author = '') => {
    const formData = new FormData()
    formData.append('file', file)
    if (privateKey) formData.append('private_key', privateKey)
    if (generate) formData.append('generate', 'true')
    if (author) formData.append('author', author)

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

  const handleSign = async () => {
    if (!message.trim()) {
      onError('Please enter a message')
      return
    }

    try {
      setLoading(true)
      const data = await apiService.signMessage(message, privateKey || null, generateNew)
      setSignature(data)
      onSuccess('Message signed successfully!')

      if (data.private_key) {
        setPrivateKey(data.private_key)
        promptSavePrivateKey(data.private_key, onSuccess)
      }
    } catch (error) {
      onError(error.response?.data?.message || 'Error signing message')
    } finally {
      setLoading(false)
    }
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
          <label>Private Key (hex)</label>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Paste your private key..."
            rows={3}
          />
        </div>
      )}

      <button className="btn btn-primary" onClick={handleSign} disabled={loading}>
        {loading ? <Loader className="spinner" /> : <Zap size={18} />}
        Sign Message
      </button>

      {signature && (
        <div className="result-box">
          <h3>Signature Result</h3>
          <ResultDisplay data={signature} />
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

      <div className="form-group">
        <label>Signature (hex)</label>
        <textarea
          value={signature}
          onChange={(e) => setSignature(e.target.value)}
          placeholder="Signature hex string..."
          rows={3}
        />
      </div>

      <div className="form-group">
        <label>Public Key (hex)</label>
        <textarea
          value={publicKey}
          onChange={(e) => setPublicKey(e.target.value)}
          placeholder="Public key hex string..."
          rows={2}
        />
      </div>

      <button className="btn btn-primary" onClick={handleVerify} disabled={loading}>
        {loading ? <Loader className="spinner" /> : <CheckCircle size={18} />}
        Verify Message
      </button>

      {result && (
        <div className={`result-box ${result.valid ? 'success' : 'error'}`}>
          <h3>{result.valid ? '✓ Valid' : '✗ Invalid'}</h3>
          <p>{result.message}</p>
        </div>
      )}
    </div>
  )
}

function FileTab({ onSuccess, onError }) {
  const [activeMode, setActiveMode] = useState('sign') // 'sign' or 'verify'

  return (
    <div className="tab-content">
      <div className="mode-toggle">
        <button
          className={`mode-btn ${activeMode === 'sign' ? 'active' : ''}`}
          onClick={() => setActiveMode('sign')}
        >
          Sign File
        </button>
        <button
          className={`mode-btn ${activeMode === 'verify' ? 'active' : ''}`}
          onClick={() => setActiveMode('verify')}
        >
          Verify File
        </button>
      </div>

      {activeMode === 'sign' ? (
        <SignFileForm onSuccess={onSuccess} onError={onError} />
      ) : (
        <VerifyFileForm onSuccess={onSuccess} onError={onError} />
      )}
    </div>
  )
}

function SignFileForm({ onSuccess, onError }) {
  const [file, setFile] = useState(null)
  const [signType, setSignType] = useState('detached') // 'detached' or 'embedded'
  const [privateKey, setPrivateKey] = useState('')
  const [generateNew, setGenerateNew] = useState(true)
  const [author, setAuthor] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSign = async () => {
    if (!file) {
      onError('Please select a file')
      return
    }

    if (signType === 'embedded' && !file.name.toLowerCase().endsWith('.pdf')) {
      onError('Embedded signature only works with PDF files')
      return
    }

    try {
      setLoading(true)
      let response

      if (signType === 'embedded') {
        response = await apiService.signEmbedded(file, privateKey || null, generateNew, author)
      } else {
        response = await apiService.signFile(file, privateKey || null, generateNew, author)
      }

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const a = document.createElement('a')
      a.href = url
      a.download = signType === 'embedded' ? file.name.replace('.pdf', '_signed.pdf') : `${file.name}.sig`
      a.click()

      onSuccess(`File signed and downloaded! ${response.headers['x-private-key'] ? '(New keypair created - check your downloads)' : ''}`)

      if (response.headers['x-private-key']) {
        promptSavePrivateKey(response.headers['x-private-key'], onSuccess)
      }
    } catch (error) {
      onError(error.response?.data?.message || 'Error signing file')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <h2>Sign File</h2>

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
        <label>Signature Type</label>
        <div className="radio-group">
          <label className="radio">
            <input
              type="radio"
              checked={signType === 'detached'}
              onChange={() => setSignType('detached')}
            />
            Detached (separate .sig file)
          </label>
          <label className="radio">
            <input
              type="radio"
              checked={signType === 'embedded'}
              onChange={() => setSignType('embedded')}
            />
            Embedded (in PDF only)
          </label>
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
          <label>Private Key (hex)</label>
          <textarea
            value={privateKey}
            onChange={(e) => setPrivateKey(e.target.value)}
            placeholder="Paste your private key..."
            rows={2}
          />
        </div>
      )}

      <div className="form-group">
        <label>Author (optional)</label>
        <input
          type="text"
          value={author}
          onChange={(e) => setAuthor(e.target.value)}
          placeholder="Your name"
        />
      </div>

      <button className="btn btn-primary" onClick={handleSign} disabled={loading || !file}>
        {loading ? <Loader className="spinner" /> : <Zap size={18} />}
        Sign File
      </button>
    </div>
  )
}

function VerifyFileForm({ onSuccess, onError }) {
  const [file, setFile] = useState(null)
  const [signatureFile, setSignatureFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)

  const handleVerify = async () => {
    if (!file) {
      onError('Please select file to verify')
      return
    }

    if (!signatureFile) {
      onError('Please select signature file')
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
      onSuccess(response.data.message)
    } catch (error) {
      onError(error.response?.data?.message || 'Error verifying file')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <h2>Verify File</h2>

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
          onChange={(e) => setSignatureFile(e.target.files?.[0] || null)}
          className="file-input"
        />
        {signatureFile && <p className="file-info">📄 {signatureFile.name}</p>}
      </div>

      <button
        className="btn btn-primary"
        onClick={handleVerify}
        disabled={loading || !file || !signatureFile}
      >
        {loading ? <Loader className="spinner" /> : <CheckCircle size={18} />}
        Verify File
      </button>

      {result && (
        <div className={`result-box ${result.valid ? 'success' : 'error'}`}>
          <h3>{result.valid ? '✓ Valid' : '✗ Invalid'}</h3>
          <p>{result.message}</p>
          {result.file_hash && (
            <p>
              <strong>Hash:</strong> {result.file_hash.substring(0, 32)}...
            </p>
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

function ResultDisplay({ data }) {
  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text)
    alert(`${label} copied!`)
  }

  return (
    <div className="result-items">
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