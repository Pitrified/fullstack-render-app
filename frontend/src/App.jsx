import { useEffect } from "react";

const CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID;

function App() {
  useEffect(() => {
    window.google.accounts.id.initialize({
      client_id: CLIENT_ID,
      callback: handleCredentialResponse,
    });
    window.google.accounts.id.renderButton(
      document.getElementById("google-signin"),
      { theme: "outline", size: "large" }
    );
  }, []);

  const handleCredentialResponse = async (response) => {
    const token = response.credential;

    const res = await fetch("http://localhost:8000/login", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await res.json();
    alert(`Hello ${data.name} (${data.email})`);
  };

  return (
    <div>
      <h1>Login with Google</h1>
      <div id="google-signin"></div>
    </div>
  );
}

export default App;
