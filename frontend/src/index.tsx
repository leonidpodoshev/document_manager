import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css'; // Keep this for global styles if any
import App from './App';
// reportWebVitals is not typically used with Vite in the same way as CRA
// You can set up analytics differently if needed.

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
