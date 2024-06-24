import { useEffect, useState } from 'react';

export function NightModeButton() {
  const [darkMode, setDarkMode] = useState(false);

  // On mount, check if dark mode is already enabled (e.g., persisted in local storage)
  useEffect(() => {
    setDarkMode(document.body.classList.contains('dark'));
  }, []);

  const toggleDarkMode = () => {
    document.body.classList.toggle('dark');
    setDarkMode(!darkMode);
  };

  return (
    <button onClick={toggleDarkMode}>
      {darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
    </button>
  );
}