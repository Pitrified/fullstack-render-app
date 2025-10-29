import { useEffect, useState } from "react";
import { useGoogleIdentity } from "./hooks/useGoogleIdentity";
import { useAuth } from "./hooks/useAuth";
import { sanitizeUserData } from "./utils/sanitize";

const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;

function App() {
  const googleReady = useGoogleIdentity();
  const { user, loading, error, login, logout, isAuthenticated } = useAuth();
  const [message, setMessage] = useState('');

  useEffect(() => {
    if (!googleReady || loading || isAuthenticated) return;

    const handleCredentialResponse = async (response) => {
      try {
        const token = response.credential;
        
        // Use the new session-based login
        const result = await login(token);
        
        if (result.success) {
          // Security: Use DOMPurify-based sanitization for comprehensive XSS protection
          const sanitizedUser = sanitizeUserData(result.user);
          
          if (sanitizedUser && sanitizedUser.name && sanitizedUser.email) {
            setMessage(`Welcome back, ${sanitizedUser.name}!`);
          } else {
            setMessage('Invalid user data received. Please try again.');
          }
        } else {
          setMessage(result.error || 'Login failed. Please try again.');
        }
      } catch (error) {
        console.error('Login error:', error);
        setMessage('An error occurred during login.');
      }
    };

    // Wait for the DOM element to be available
    const initializeGoogleSignIn = () => {
      const buttonContainer = document.getElementById("google-signin");
      if (!buttonContainer) {
        // If element doesn't exist yet, try again in next tick
        setTimeout(initializeGoogleSignIn, 100);
        return;
      }

      window.google.accounts.id.initialize({
        client_id: CLIENT_ID,
        callback: handleCredentialResponse,
      });

      window.google.accounts.id.renderButton(
        buttonContainer,
        { theme: "outline", size: "large" }
      );
    };

    initializeGoogleSignIn();

  }, [googleReady, loading, isAuthenticated]);

  // Handle logout with session invalidation
  const handleLogout = async () => {
    const result = await logout();
    if (result.success) {
      setMessage('');
    }
  };

  // Show loading state during authentication check
  if (loading && !user) {
    return (
      <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
        <h1>Login with Google</h1>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>Login with Google</h1>
      
      {/* Security: Safe message display */}
      {(message || error) && (
        <div style={{ 
          padding: '10px', 
          marginBottom: '20px',
          backgroundColor: (user && !error) ? '#d4edda' : '#f8d7da',
          border: `1px solid ${(user && !error) ? '#c3e6cb' : '#f5c6cb'}`,
          borderRadius: '4px',
          color: (user && !error) ? '#155724' : '#721c24'
        }}>
          {error || message}
        </div>
      )}
      
      {isAuthenticated && user ? (
        <div style={{ marginTop: '20px' }}>
          <h2>Welcome!</h2>
          <p><strong>Name:</strong> {user.name}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <button 
            onClick={handleLogout}
            disabled={loading}
            style={{
              padding: '8px 16px',
              backgroundColor: loading ? '#6c757d' : '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: loading ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Logging out...' : 'Logout'}
          </button>
        </div>
      ) : (
        <div id="google-signin"></div>
      )}
    </div>
  );
}

export default App;
