export function LoadingScreen() {
  return (
    <div className="app">
      <div className="background-pattern" />
      <div className="loading-container">
        <div className="loading-spinner" />
        <p>Initializing cryptographic primitives...</p>
      </div>
    </div>
  );
}

