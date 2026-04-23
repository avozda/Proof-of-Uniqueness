import type { FormData } from "../lib/vc";

interface IdentityFormProps {
  formData: FormData;
  isGenerating: boolean;
  onInputChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => void;
  onSubmit: (e: React.FormEvent) => void;
}

export function IdentityForm({
  formData,
  isGenerating,
  onInputChange,
  onSubmit,
}: IdentityFormProps) {
  const isFormValid =
    formData.name &&
    formData.dateOfBirth &&
    formData.placeOfBirth &&
    formData.nationality &&
    formData.sex;

  return (
    <section className="form-section">
      <div className="section-header">
        <h2>Identity Information</h2>
        <p>Enter the credential subject details</p>
      </div>

      <form onSubmit={onSubmit} className="credential-form">
        <div className="form-group">
          <label htmlFor="name">Full Name</label>
          <input
            type="text"
            id="name"
            name="name"
            value={formData.name}
            onChange={onInputChange}
            placeholder="Jan Novak"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="dateOfBirth">Date of Birth</label>
          <input
            type="date"
            id="dateOfBirth"
            name="dateOfBirth"
            value={formData.dateOfBirth}
            onChange={onInputChange}
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="nationality">Nationality</label>
          <input
            type="text"
            id="nationality"
            name="nationality"
            value={formData.nationality}
            onChange={onInputChange}
            placeholder="Czech"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="placeOfBirth">Place of Birth</label>
          <input
            type="text"
            id="placeOfBirth"
            name="placeOfBirth"
            value={formData.placeOfBirth}
            onChange={onInputChange}
            placeholder="Prague"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="sex">Sex</label>
          <select
            id="sex"
            name="sex"
            value={formData.sex}
            onChange={onInputChange}
            required
          >
            <option value="">Select...</option>
            <option value="male">Male</option>
            <option value="female">Female</option>
            <option value="other">Other</option>
          </select>
        </div>

        <button
          type="submit"
          className="submit-button"
          disabled={!isFormValid || isGenerating}
        >
          {isGenerating ? (
            <>
              <span className="spinner" />
              Generating...
            </>
          ) : (
            <>
              Generate Verifiable Credential
            </>
          )}
        </button>
      </form>
    </section>
  );
}
