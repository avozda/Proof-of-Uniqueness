import { useState, useEffect } from "react";
import { generateDID, toHex, initCrypto, publicKeyFromPrivateKey } from "./lib/did";
import type { DIDKeyPair } from "./lib/did";
import { createVerifiableCredential } from "./lib/vc";
import { generatePersonId } from "./lib/vc";
import type { VerifiableCredential, FormData } from "./lib/vc";
import {
  buildHolderBindingMessage,
  generateHolderKeyPair,
  signMessageWithHolderKey,
  type HolderKeyPair,
} from "./lib/holderKey";
import {
  LoadingScreen,
  DIDSection,
  IdentityForm,
  CredentialDisplay,
  ZKProofSection,
} from "./components";
import "./App.css";

const DID_STORAGE_KEY = "issuer-did-eddsa";

interface StoredDID {
  did: string;
  publicKeyX: string;
  publicKeyY: string;
  privateKey: string;
  verificationMethod: string;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function loadDIDFromStorage(): DIDKeyPair | null {
  try {
    const stored = localStorage.getItem(DID_STORAGE_KEY);
    if (stored) {
      const parsed: StoredDID = JSON.parse(stored);
      const loaded: DIDKeyPair = {
        did: parsed.did,
        publicKey: {
          x: BigInt(parsed.publicKeyX),
          y: BigInt(parsed.publicKeyY),
        },
        privateKey: hexToBytes(parsed.privateKey),
        verificationMethod: parsed.verificationMethod,
      };

      const derivedPub = publicKeyFromPrivateKey(loaded.privateKey);
      if (
        derivedPub.x !== loaded.publicKey.x ||
        derivedPub.y !== loaded.publicKey.y
      ) {
        console.warn(
          "Stored issuer DID keypair is inconsistent with private key; regenerating.",
        );
        localStorage.removeItem(DID_STORAGE_KEY);
        return null;
      }

      return loaded;
    }
  } catch (e) {
    console.error("Failed to load DID from storage:", e);
  }
  return null;
}

function saveDID(did: DIDKeyPair): void {
  const toStore: StoredDID = {
    did: did.did,
    publicKeyX: did.publicKey.x.toString(),
    publicKeyY: did.publicKey.y.toString(),
    privateKey: toHex(did.privateKey),
    verificationMethod: did.verificationMethod,
  };
  localStorage.setItem(DID_STORAGE_KEY, JSON.stringify(toStore));
}

function App() {
  const [formData, setFormData] = useState<FormData>({
    name: "Jan Novak",
    dateOfBirth: "1990-06-15",
    placeOfBirth: "Prague",
    permanentAddress: "Main St 123, Prague",
    nationality: "Czech",
    sex: "male",
  });

  const [credential, setCredential] = useState<VerifiableCredential | null>(
    null,
  );
  const [holderKeyPair, setHolderKeyPair] = useState<HolderKeyPair | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [cryptoReady, setCryptoReady] = useState(false);
  const [issuerDID, setIssuerDID] = useState<DIDKeyPair | null>(null);

  // Initialize crypto and load/create DID
  useEffect(() => {
    async function init() {
      await initCrypto();
      setCryptoReady(true);

      const existingDID = loadDIDFromStorage();
      if (existingDID) {
        setIssuerDID(existingDID);
      } else {
        const newDID = generateDID();
        saveDID(newDID);
        setIssuerDID(newDID);
      }
    }
    init();
  }, []);

  const handleRegenerateDID = () => {
    if (!cryptoReady) return;
    const newDID = generateDID();
    saveDID(newDID);
    setIssuerDID(newDID);
  };

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>,
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!issuerDID) return;

    setIsGenerating(true);

    await new Promise((resolve) => setTimeout(resolve, 500));

    try {
      const generatedHolderKey = generateHolderKeyPair();

      const subjectId = generatePersonId();
      const holderBindingMessage = buildHolderBindingMessage(subjectId);
      const holderBindingSignature = signMessageWithHolderKey(
        generatedHolderKey.privateKey,
        holderBindingMessage,
      );

      setHolderKeyPair(generatedHolderKey);

      const vc = createVerifiableCredential(
        formData,
        issuerDID,
        "Example Authority",
        generatedHolderKey.publicKey,
        {
          r8x: holderBindingSignature.R8[0],
          r8y: holderBindingSignature.R8[1],
          s: holderBindingSignature.S,
        },
        subjectId,
      );
      setCredential(vc);
    } catch (error) {
      console.error("Error generating credential:", error);
    } finally {
      setIsGenerating(false);
    }
  };

  if (!cryptoReady || !issuerDID) {
    return <LoadingScreen />;
  }

  return (
    <div className="app">
      <div className="background-pattern" />

      <header className="header">
        <div className="header-badge">
          <span className="badge-icon">◈</span>
          <span>Proof of Uniqueness</span>
        </div>
        <h1>Biometric Identity Credential</h1>
        <p className="subtitle">
          W3C Verifiable Credentials 2.0 with EdDSA Poseidon Signatures
        </p>
      </header>

      <DIDSection issuerDID={issuerDID} onRegenerate={handleRegenerateDID} />

      <main className="main-content">
        <IdentityForm
          formData={formData}
          isGenerating={isGenerating}
          onInputChange={handleInputChange}
          onSubmit={handleSubmit}
        />

        {credential && holderKeyPair && (
          <section className="result-section">
            <div className="section-header">
              <h2>Generated Credential</h2>
              <p>W3C Verifiable Credential 2.0</p>
            </div>

            <CredentialDisplay credential={credential} />
            <ZKProofSection
              credential={credential}
              issuerPublicKey={issuerDID.publicKey}
              holderKeyPair={holderKeyPair}
            />
          </section>
        )}
      </main>

      <footer className="footer">
        <p>Built with EdDSA Poseidon signatures</p>
      </footer>
    </div>
  );
}

export default App;
