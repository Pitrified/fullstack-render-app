import { useEffect, useState } from "react";

export function useGoogleIdentity() {
  const [googleReady, setGoogleReady] = useState(false);

  useEffect(() => {
    if (window.google && window.google.accounts) {
      setGoogleReady(true);
      return;
    }

    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;

    script.onload = () => setGoogleReady(true);

    document.body.appendChild(script);

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  return googleReady;
}
