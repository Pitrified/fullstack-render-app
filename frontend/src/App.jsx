import { useEffect } from "react";
import { useGoogleIdentity } from "./hooks/useGoogleIdentity";
import { useSecureAuth } from "./hooks/useSecureAuth";
import { sanitizeUserData } from "./utils/sanitize";

const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;

function App() {
  const googleReady = useGoogleIdentity();
  const { 
    user, 
    loading, 
    error, 
    login, 
    logout, 
    clearError, 
    isAuthenticated 
  } = useSecureAuth();

  useEffect(() => {
    if (!googleReady) return;

    // If Google client id is not set, show setup instructions and skip init
    if (!CLIENT_ID) {
      console.warn('VITE_GOOGLE_CLIENT_ID is not set. Google Sign-In will not render.');
      return;
    }

    const handleCredentialResponse = async (response) => {
      try {
        clearError(); // Clear any previous errors
        
        const token = response.credential;
        const result = await login(token);
        
        if (!result.success) {
          console.error('Secure login failed:', result.error);
        }
      } catch (error) {
        console.error('Login error:', error);
      }
    };

    try {
      window.google.accounts.id.initialize({
        client_id: CLIENT_ID,
        callback: handleCredentialResponse,
      });

      // Only render sign-in button if user is not authenticated
      if (!isAuthenticated) {
        const el = document.getElementById("google-signin");
        if (el) {
          window.google.accounts.id.renderButton(el, { theme: "outline", size: "large" });
        } else {
          console.warn('Google sign-in element not found: #google-signin');
        }
      }
    } catch (err) {
      console.error('Failed to initialize Google Identity Services:', err);
    }

    // Optional: Uncomment to show the One Tap prompt automatically
    // if (!isAuthenticated) {
    //   window.google.accounts.id.prompt();
    // }

  }, [googleReady, isAuthenticated, login, clearError]);

  const handleLogout = async () => {
    const result = await logout();
    if (result.success) {
      // Force page reload to reset Google One Tap state
      window.location.reload();
    }
  };

  // Loading state
  if (loading) {
    return (
      <div style={{ 
        padding: '20px', 
        fontFamily: 'Arial, sans-serif',
        textAlign: 'center' 
      }}>
        <h1>Secure OAuth App</h1>
        <div style={{ marginTop: '20px' }}>
          <div style={{ 
            display: 'inline-block',
            width: '20px',
            height: '20px',
            border: '2px solid #f3f3f3',
            borderTop: '2px solid #007bff',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite'
          }}></div>
          <p style={{ marginTop: '10px' }}>Loading...</p>
        </div>
        <style>{`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>🔒 Secure Google OAuth App</h1>
      <p style={{ color: '#666', marginBottom: '20px' }}>
        Powered by httpOnly cookies and CSRF protection
      </p>
      
      {/* Error display */}
      {error && (
        <div style={{ 
          padding: '12px', 
          marginBottom: '20px',
          backgroundColor: '#f8d7da',
          border: '1px solid #f5c6cb',
          borderRadius: '4px',
          color: '#721c24'
        }}>
          <strong>⚠️ Error:</strong> {error}
          <button 
            onClick={clearError}
            style={{
              marginLeft: '10px',
              padding: '2px 8px',
              backgroundColor: 'transparent',
              border: '1px solid #721c24',
              borderRadius: '3px',
              color: '#721c24',
              cursor: 'pointer',
              fontSize: '12px'
            }}
          >
            Dismiss
          </button>
        </div>
      )}
      
      {isAuthenticated ? (
        <div>
          {/* Success message */}
          <div style={{ 
            padding: '12px', 
            marginBottom: '20px',
            backgroundColor: '#d4edda',
            border: '1px solid #c3e6cb',
            borderRadius: '4px',
            color: '#155724'
          }}>
            <strong>✅ Secure Login Successful</strong>
            <br />
            <small>Your session is protected with httpOnly cookies</small>
          </div>

          {/* User information */}
          <div style={{ 
            marginBottom: '20px',
            padding: '20px',
            backgroundColor: '#f8f9fa',
            borderRadius: '8px',
            border: '1px solid #dee2e6'
          }}>
            <h2 style={{ marginTop: 0, color: '#495057' }}>👋 Welcome!</h2>
            
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '15px' }}>
              {user.picture && (
                <img 
                  src={user.picture} 
                  alt="Profile"
                  style={{
                    width: '50px',
                    height: '50px',
                    borderRadius: '50%',
                    marginRight: '15px',
                    border: '2px solid #007bff'
                  }}
                />
              )}
              <div>
                <p style={{ margin: '0 0 5px 0', fontSize: '18px', fontWeight: 'bold' }}>
                  {user.name}
                </p>
                <p style={{ margin: 0, color: '#666' }}>
                  {user.email}
                </p>
              </div>
            </div>

            <div style={{ 
              padding: '10px',
              backgroundColor: '#e3f2fd',
              borderRadius: '4px',
              fontSize: '14px',
              color: '#1565c0'
            }}>
              <strong>🔐 Security Features Active:</strong>
              <ul style={{ margin: '5px 0', paddingLeft: '20px' }}>
                <li>httpOnly session cookies (XSS protection)</li>
                <li>CSRF token validation</li>
                <li>Secure SameSite cookie policy</li>
                <li>Automatic session refresh</li>
              </ul>
            </div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button 
              onClick={handleLogout}
              style={{
                padding: '10px 20px',
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '16px',
                fontWeight: '500'
              }}
            >
              🚪 Secure Logout
            </button>
            
            <button 
              onClick={() => window.location.reload()}
              style={{
                padding: '10px 20px',
                backgroundColor: '#28a745',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontSize: '16px',
                fontWeight: '500'
              }}
            >
              🔄 Test Session Persistence
            </button>
          </div>
        </div>
      ) : (
        <div>
          <div style={{ 
            padding: '20px',
            backgroundColor: '#f8f9fa',
            borderRadius: '8px',
            border: '1px solid #dee2e6',
            textAlign: 'center',
            marginBottom: '20px'
          }}>
            <h2 style={{ color: '#495057', marginTop: 0 }}>🔐 Secure Login Required</h2>
            <p style={{ color: '#666', marginBottom: '20px' }}>
              This application uses enterprise-grade security with httpOnly cookies and CSRF protection.
              <br />
              Your tokens are never exposed to JavaScript, preventing XSS attacks.
            </p>
            
            {CLIENT_ID ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginTop: '15px' }}>
                <div id="google-signin" style={{ display: 'flex', justifyContent: 'center' }}></div>
                <button
                  onClick={() => {
                    // Manual fallback: try to show One Tap prompt or render button
                    if (window.google && window.google.accounts && window.google.accounts.id) {
                      try {
                        // Show One Tap prompt which will present sign-in options
                        window.google.accounts.id.prompt();
                      } catch (err) {
                        console.error('Failed to prompt Google Identity Services:', err);
                      }
                    } else {
                      console.warn('Google Identity Services not loaded yet.');
                    }
                  }}
                  style={{
                    marginTop: '12px',
                    padding: '10px 18px',
                    backgroundColor: '#4285F4',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '14px'
                  }}
                >
                  Sign in with Google
                </button>
              </div>
            ) : (
              <div style={{ marginTop: '15px', color: '#555' }}>
                <p><strong>Google client ID not configured.</strong></p>
                <p>To enable sign-in, add `VITE_GOOGLE_CLIENT_ID` to `frontend/.env.local`:</p>
                <pre style={{ background: '#f1f1f1', padding: '8px', borderRadius: '4px' }}>
{`VITE_GOOGLE_CLIENT_ID=your_google_client_id_here`}
                </pre>
              </div>
            )}
          </div>
          
          <div style={{ 
            fontSize: '14px',
            color: '#666',
            backgroundColor: '#fff3cd',
            padding: '15px',
            borderRadius: '4px',
            border: '1px solid #ffeaa7'
          }}>
            <strong>🛡️ Security Notice:</strong>
            <ul style={{ margin: '10px 0', paddingLeft: '20px' }}>
              <li>Tokens are stored in secure httpOnly cookies</li>
              <li>CSRF protection prevents cross-site attacks</li>
              <li>Sessions automatically expire for security</li>
              <li>All communication uses TLS encryption</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
