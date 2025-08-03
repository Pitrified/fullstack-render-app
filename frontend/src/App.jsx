import { useEffect } from "react";
import { useGoogleIdentity } from "./hooks/useGoogleIdentity";

const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL 

function App() {
  const googleReady = useGoogleIdentity();

  useEffect(() => {
    if (!googleReady) return;

    const handleCredentialResponse = async (response) => {
      const token = response.credential;

      const res = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await res.json();
      alert(`Hello ${data.name} (${data.email})`);
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
    <div>
      <h1>Login with Google</h1>
      <div id="google-signin"></div>
    </div>
  );
}

export default App;
