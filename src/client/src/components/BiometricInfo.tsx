import { toHex } from "../lib/did";
import { BIOMETRIC_CONFIG } from "../lib/biometrics";
import type { MockBiometricData } from "../lib/biometrics";

interface BiometricInfoProps {
  biometricData: MockBiometricData;
}

export function BiometricInfo({ biometricData }: BiometricInfoProps) {
  return (
    <div className="biometric-info">
      <h3>
        <span className="bio-icon">🧬</span>
        Mock Biometric Data
      </h3>

      <div className="bio-config">
        <div className="config-item">
          <span className="config-value">{BIOMETRIC_CONFIG.dataLength}</span>
          <span className="config-label">Data Length (bytes)</span>
        </div>
        <div className="config-item">
          <span className="config-value">{BIOMETRIC_CONFIG.blockSize}</span>
          <span className="config-label">Block Size (bytes)</span>
        </div>
        <div className="config-item">
          <span className="config-value">{BIOMETRIC_CONFIG.errorThreshold}</span>
          <span className="config-label">Hamming Distance (bits/block)</span>
        </div>
        <div className="config-item">
          <span className="config-value">{BIOMETRIC_CONFIG.repetitions}</span>
          <span className="config-label">Repetitions</span>
        </div>
      </div>

      <div className="bio-grid">
        <div className="bio-item">
          <span className="bio-label">
            Raw Biometric ({BIOMETRIC_CONFIG.dataLength} bytes)
          </span>
          <code>{toHex(biometricData.rawBiometric)}</code>
        </div>
        <div className="bio-item">
          <span className="bio-label">Fuzzy Sketch</span>
          <code>{toHex(biometricData.sketch).slice(0, 64)}...</code>
        </div>
        <div className="bio-item">
          <span className="bio-label">Verification Key</span>
          <code>{toHex(biometricData.verificationKey)}</code>
        </div>
      </div>
    </div>
  );
}

