import React, { useState, useEffect, ChangeEvent, FormEvent } from 'react';
import axios, { AxiosError } from 'axios';
import './App.css';

interface Document {
  id: string;
  name: string;
  userId?: string;
  category?: string; // Added category
}

interface User {
  id: string;
  username: string;
}

const API_URL = '/api';

function App() {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [message, setMessage] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string>(''); // For auth errors
  const [searchTerm, setSearchTerm] = useState<string>('');

  // Auth state
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [currentUser, setCurrentUser] = useState<User | null>(JSON.parse(localStorage.getItem('user') || 'null'));
  const [isLoginView, setIsLoginView] = useState<boolean>(true); // Toggle between login and register
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');

  // Category state
  const [categories, setCategories] = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState<string>(''); // Empty string means all categories
  const [uploadCategory, setUploadCategory] = useState<string>('');


  useEffect(() => {
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      fetchDocuments(); // This will now also depend on selectedCategory implicitly through its params
      fetchCategories();
    } else {
      delete axios.defaults.headers.common['Authorization'];
      setCategories([]); // Clear categories on logout
      setSelectedCategory('');
    }
  }, [token, searchTerm, selectedCategory]); // Re-fetch when token, searchTerm, or selectedCategory changes

  const clearMessages = () => {
    setMessage('');
    setErrorMessage('');
  };

  const fetchDocuments = async () => {
    if (!token) return; // Don't fetch if not logged in
    clearMessages();
    try {
      const params = new URLSearchParams();
      if (searchTerm) {
        params.append('q', searchTerm);
      }
      if (selectedCategory) { // Add category to params if selected
        params.append('category', selectedCategory);
      }
      const response = await axios.get<Document[]>(`${API_URL}/documents`, { params });
      setDocuments(response.data || []);
    } catch (error) {
      console.error('Error fetching documents:', error);
      setErrorMessage('Error fetching documents.');
      setDocuments([]);
    }
  };

  const fetchCategories = async () => {
    if (!token) return;
    try {
      const response = await axios.get<string[]>(`${API_URL}/categories`);
      setCategories(response.data || []);
    } catch (error) {
      console.error('Error fetching categories:', error);
      // Not setting error message here to avoid overriding document fetch errors
      // Potentially have a separate error state for categories if needed
      setCategories([]);
    }
  };

  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (event.target.files) {
      setSelectedFile(event.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setMessage('Please select a file to upload.');
      return;
    }
    clearMessages();
    const formData = new FormData();
    formData.append('file', selectedFile);
    if (uploadCategory.trim() !== '') { // Add category if provided
      formData.append('category', uploadCategory.trim());
    }

    try {
      const response = await axios.post<Document>(`${API_URL}/documents`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setMessage(`Document '${response.data.name}' uploaded successfully!`);
      setSelectedFile(null);
      setUploadCategory(''); // Clear category input
      const fileInput = document.getElementById('fileInput') as HTMLInputElement;
      if (fileInput) fileInput.value = '';
      fetchDocuments();
      fetchCategories(); // Re-fetch categories as a new one might have been implicitly added
    } catch (error) {
      console.error('Error uploading document:', error);
      const axiosError = error as AxiosError<{ message?: string, error?: string }>;
      setErrorMessage(axiosError.response?.data?.error || axiosError.response?.data?.message || 'Error uploading document.');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    clearMessages();
    if (window.confirm(`Are you sure you want to delete ${name}?`)) {
      try {
        await axios.delete(`${API_URL}/documents/${id}`);
        setMessage(`Document '${name}' deleted successfully!`);
        fetchDocuments();
      } catch (error) {
        console.error('Error deleting document:', error);
        const axiosError = error as AxiosError<{ message?: string, error?: string }>;
        setErrorMessage(axiosError.response?.data?.error || axiosError.response?.data?.message || 'Error deleting document.');
      }
    }
  };

  const handleView = async (id: string, name: string) => {
    clearMessages(); // Clear previous general messages
    try {
      const response = await axios.get(`${API_URL}/documents/${id}`, {
        responseType: 'blob',
      });

      if (!(response.data instanceof Blob)) {
        // This specific error should be displayed, not affect auth
        setErrorMessage('Received invalid data type when trying to view the document.');
        console.error('View error: response.data is not a Blob', response.data);
        return;
      }

      const file = response.data;
      const fileURL = URL.createObjectURL(file);

      // Attempt to open in a new tab
      // For PDFs, most browsers will display them. For other types, behavior varies.
      window.open(fileURL, '_blank');

      // Revoke the object URL after a short delay to allow the new tab to load it.
      // If revoked too soon, the new tab might not be able to access the blob.
      setTimeout(() => URL.revokeObjectURL(fileURL), 1000); // 1 second delay

    } catch (error) {
      console.error('Error viewing document:', error);
      const axiosError = error as AxiosError<{ message?: string, error?: string }>;
      let specificErrorMessage = 'Error viewing document.';
      if (axiosError.response && axiosError.response.data instanceof Blob &&
          axiosError.response.data.type && axiosError.response.data.type.toLowerCase().includes('application/json')) {
        try {
          const errorJson = JSON.parse(await axiosError.response.data.text());
          specificErrorMessage = errorJson.error || errorJson.message || specificErrorMessage;
        } catch (parseError) { /* Keep default specificErrorMessage */ }
      } else if (axiosError.response?.data?.error || axiosError.response?.data?.message) {
        specificErrorMessage = axiosError.response.data.error || axiosError.response.data.message;
      }
      setErrorMessage(specificErrorMessage); // Set the specific error message
      // CRITICAL: Ensure this error handling does NOT clear the auth token or user state.
      // The current setErrorMessage should not do that by itself.
    }
  };

  const handleAuthSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    clearMessages();
    const url = isLoginView ? `${API_URL}/auth/login` : `${API_URL}/auth/register`;
    try {
      const response = await axios.post<{ token?: string; id?: string; userId?: string; username?: string }>(url, { username, password });
      if (isLoginView && response.data.token) {
        const { token: receivedToken, userId, username: receivedUsername } = response.data;
        if (receivedToken && userId && receivedUsername) {
            setToken(receivedToken);
            const userToStore: User = { id: userId, username: receivedUsername };
            setCurrentUser(userToStore);
            localStorage.setItem('token', receivedToken);
            localStorage.setItem('user', JSON.stringify(userToStore));
            setUsername('');
            setPassword('');
            setMessage('Login successful!');
        } else {
            setErrorMessage("Login failed: Incomplete data from server.")
        }
      } else if (!isLoginView) {
        setMessage('Registration successful! Please log in.');
        setIsLoginView(true); // Switch to login view
        setUsername(''); // Clear username for login
        setPassword('');
      }
    } catch (error) {
      console.error(`Error during ${isLoginView ? 'login' : 'registration'}:`, error);
      const axiosError = error as AxiosError<{ message?: string, error?: string }>;
      setErrorMessage(axiosError.response?.data?.error || axiosError.response?.data?.message || `Error during ${isLoginView ? 'login' : 'registration'}`);
    }
  };

  const handleLogout = () => {
    clearMessages();
    setToken(null);
    setCurrentUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setDocuments([]); // Clear documents
    setMessage('Logged out successfully.');
  };


  if (!token || !currentUser) {
    return (
      <div className="App auth-container">
        <header className="App-header">
          <h1>{isLoginView ? 'Login' : 'Register'}</h1>
        </header>
        <main>
          <form onSubmit={handleAuthSubmit} className="auth-form">
            <div>
              <label htmlFor="username">Username:</label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div>
              <label htmlFor="password">Password:</label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit">{isLoginView ? 'Login' : 'Register'}</button>
            {errorMessage && <p className="message error-message">{errorMessage}</p>}
            {message && !errorMessage && <p className="message success-message">{message}</p>} {/* Only show success if no error */}
          </form>
          <button onClick={() => { setIsLoginView(!isLoginView); clearMessages(); setUsername(''); setPassword(''); }} className="toggle-auth-button">
            {isLoginView ? 'Need to register?' : 'Already have an account? Login'}
          </button>
        </main>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>Home Document Management</h1>
        <div className="user-info">
          <span>Welcome, {currentUser.username}!</span>
          <button onClick={handleLogout} className="logout-button">Logout</button>
        </div>
      </header>
      <main>
        {message && <p className="message success-message">{message}</p>}
        {errorMessage && <p className="message error-message">{errorMessage}</p>}

        <div className="upload-section">
          <h2>Upload New Document</h2>
          <div>
            <input type="file" id="fileInput" onChange={handleFileChange} accept="application/pdf" />
          </div>
          <div>
            <input
              type="text"
              placeholder="Category (optional)"
              value={uploadCategory}
              onChange={(e) => setUploadCategory(e.target.value)}
              className="category-input"
            />
          </div>
          <button onClick={handleUpload} disabled={!selectedFile}>
            Upload
          </button>
        </div>

        <div className="document-list-section">
          <h2>My Documents</h2>

          <div className="filter-controls">
            <div className="search-bar-container">
              <input
                type="text"
                placeholder="Search documents by name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="search-input"
              />
            </div>
            <div className="category-filter-container">
              <button
                onClick={() => setSelectedCategory('')}
                className={selectedCategory === '' ? 'active-category' : ''}
              >
                All Categories
              </button>
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={selectedCategory === cat ? 'active-category' : ''}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {documents.length === 0 && searchTerm === '' && selectedCategory === '' ? (
            <p>No documents found. Upload some!</p>
          ) : documents.length === 0 ? (
            <p>No documents match your current filters (Category: {selectedCategory || 'All'}, Search: "{searchTerm}").</p>
          ) : (
            <ul>
              {documents.map((doc) => (
                <li key={doc.id}>
                  <div className="doc-info">
                    <span className="doc-name">{doc.name}</span>
                    {doc.category && <span className="doc-category">Category: {doc.category}</span>}
                  </div>
                  <div className="doc-actions">
                    <button onClick={() => handleView(doc.id, doc.name)}>View</button>
                    <button className="delete-button" onClick={() => handleDelete(doc.id, doc.name)}>Delete</button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
