import { useEffect, useState } from "react";
import { useGoogleIdentity } from "./hooks/useGoogleIdentity";
import { sanitizeUserData } from "./utils/sanitize";

const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

function App() {
  const googleReady = useGoogleIdentity();
  const [user, setUser] = useState(null);
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!googleReady) return;

    const handleCredentialResponse = async (response) => {
      try {
        const token = response.credential;

        const res = await fetch(`${API_BASE_URL}/login`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (res.ok) {
          const data = await res.json();
          
          // Security: Use DOMPurify-based sanitization for comprehensive XSS protection
          const sanitizedUser = sanitizeUserData(data);
          
          if (sanitizedUser && sanitizedUser.name && sanitizedUser.email) {
            setUser(sanitizedUser);
            setMessage(`Welcome back, ${sanitizedUser.name}!`);
          } else {
            setMessage('Invalid user data received. Please try again.');
          }
        } else {
          setMessage('Login failed. Please try again.');
        }
      } catch (error) {
        console.error('Login error:', error);
        setMessage('An error occurred during login.');
      }
    };

    window.google.accounts.id.initialize({
      client_id: CLIENT_ID,
      callback: handleCredentialResponse,
    });

    window.google.accounts.id.renderButton(
      document.getElementById("google-signin"),
      { theme: "outline", size: "large" }
    );

    // Optional: Uncomment to show the One Tap prompt automatically
    // window.google.accounts.id.prompt();

  }, [googleReady]);

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>Login with Google</h1>
      
      {/* Security: Safe message display */}
      {message && (
        <div style={{ 
          padding: '10px', 
          marginBottom: '20px',
          backgroundColor: user ? '#d4edda' : '#f8d7da',
          border: `1px solid ${user ? '#c3e6cb' : '#f5c6cb'}`,
          borderRadius: '4px',
          color: user ? '#155724' : '#721c24'
        }}>
          {message}
        </div>
      )}
      
      {user ? (
        <div style={{ marginTop: '20px' }}>
          <h2>Welcome!</h2>
          <p><strong>Name:</strong> {user.name}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <button 
            onClick={() => {
              setUser(null);
              setMessage('');
            }}
            style={{
              padding: '8px 16px',
              backgroundColor: '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Logout
          </button>
        </div>
      ) : (
        <div id="google-signin"></div>
      )}
    </div>
  );
}

export default App;
