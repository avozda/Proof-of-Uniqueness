import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { useState } from "react";
import * as z from "zod";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Card } from "@/components/ui/card";
import { CredentialProcessor } from "../utils/credentialProcessor";
import { useAccount, useConnect, useDisconnect, useChainId } from "wagmi";
import type {
  ProcessingResult,
  ProcessingSteps,
} from "../utils/credentialProcessor";

// List of countries for nationality selection
const countries = [
  "Afghanistan",
  "Albania",
  "Algeria",
  "Argentina",
  "Armenia",
  "Australia",
  "Austria",
  "Azerbaijan",
  "Bangladesh",
  "Belarus",
  "Belgium",
  "Brazil",
  "Bulgaria",
  "Canada",
  "Chile",
  "China",
  "Colombia",
  "Croatia",
  "Cyprus",
  "Czech Republic",
  "Denmark",
  "Egypt",
  "Estonia",
  "Finland",
  "France",
  "Georgia",
  "Germany",
  "Ghana",
  "Greece",
  "Hungary",
  "Iceland",
  "India",
  "Indonesia",
  "Ireland",
  "Israel",
  "Italy",
  "Japan",
  "Kazakhstan",
  "Kenya",
  "Latvia",
  "Lebanon",
  "Lithuania",
  "Luxembourg",
  "Malaysia",
  "Mexico",
  "Netherlands",
  "New Zealand",
  "Nigeria",
  "Norway",
  "Pakistan",
  "Peru",
  "Philippines",
  "Poland",
  "Portugal",
  "Romania",
  "Russia",
  "Saudi Arabia",
  "Singapore",
  "Slovakia",
  "Slovenia",
  "South Africa",
  "South Korea",
  "Spain",
  "Sweden",
  "Switzerland",
  "Thailand",
  "Turkey",
  "Ukraine",
  "United Kingdom",
  "United States",
  "Venezuela",
  "Vietnam",
];

// Form validation schema
const formSchema = z.object({
  firstName: z
    .string()
    .min(1, "First name is required")
    .min(2, "First name must be at least 2 characters"),
  secondName: z
    .string()
    .min(1, "Second name is required")
    .min(2, "Second name must be at least 2 characters"),
  dateOfBirth: z.string().min(1, "Date of birth is required"),
  nationality: z.string().min(1, "Nationality is required"),
});

type FormData = z.infer<typeof formSchema>;

export function IdentityForm() {
  const [isProcessing, setIsProcessing] = useState(false);
  const [processingSteps, setProcessingSteps] = useState<ProcessingSteps[]>([]);
  const [result, setResult] = useState<ProcessingResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitToContract, setSubmitToContract] = useState(false);

  // Wagmi hooks
  const { address, isConnected } = useAccount();
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();
  const chainId = useChainId();

  const form = useForm<FormData>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      firstName: "",
      secondName: "",
      dateOfBirth: "",
      nationality: "",
    },
  });

  const onSubmit = async (data: FormData) => {
    console.log("Form submitted with data:", data);
    setIsProcessing(true);
    setError(null);
    setResult(null);

    try {
      const processor = new CredentialProcessor((steps) => {
        setProcessingSteps(steps);
      });

      const credentialData = {
        givenName: data.firstName,
        familyName: data.secondName,
        dateOfBirth: data.dateOfBirth,
        nationality: data.nationality,
      };

      const processingResult = await processor.processCredential(
        credentialData,
        undefined, // privateKeyHex
        submitToContract,
        chainId
      );
      setResult(processingResult);
      console.log("Processing completed successfully!", processingResult);
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : "An unknown error occurred";
      setError(errorMessage);
      console.error("Processing failed:", err);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownloadAll = () => {
    if (result) {
      const processor = new CredentialProcessor();
      processor.downloadAll(result);
    }
  };

  const handleReset = () => {
    setResult(null);
    setError(null);
    setProcessingSteps([]);
    form.reset();
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-2xl w-full space-y-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-gray-900 mb-2">
            Proof-of-Uniqueness
          </h2>
        </div>

        <div className="grid gap-8 md:grid-cols-2">
          {/* Form Section */}
          <div className="bg-white p-8 rounded-lg shadow-md">
            <h3 className="text-xl font-semibold mb-6">Identity Information</h3>
            <Form {...form}>
              <form
                onSubmit={form.handleSubmit(onSubmit)}
                className="space-y-6"
              >
                <FormField
                  control={form.control}
                  name="firstName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>First Name</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="Enter your first name"
                          {...field}
                          disabled={isProcessing}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="secondName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Second Name</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="Enter your second name"
                          {...field}
                          disabled={isProcessing}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="dateOfBirth"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Date of Birth</FormLabel>
                      <FormControl>
                        <Input type="date" {...field} disabled={isProcessing} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="nationality"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Nationality</FormLabel>
                      <Select
                        onValueChange={field.onChange}
                        defaultValue={field.value}
                        disabled={isProcessing}
                      >
                        <FormControl>
                          <SelectTrigger className="w-full">
                            <SelectValue placeholder="Select your nationality" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {countries.map((country) => (
                            <SelectItem key={country} value={country}>
                              {country}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Blockchain submission option */}
                <div className="border-t pt-4 space-y-4">
                  <div className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id="submitToContract"
                      checked={submitToContract}
                      onChange={(e) => setSubmitToContract(e.target.checked)}
                      disabled={isProcessing}
                      className="rounded"
                    />
                    <label
                      htmlFor="submitToContract"
                      className="text-sm text-gray-700"
                    >
                      Submit proof to blockchain
                    </label>
                  </div>

                  {submitToContract && (
                    <div className="space-y-2">
                      {!isConnected ? (
                        <div className="space-y-2">
                          <p className="text-sm text-gray-600">
                            Connect your wallet to submit to blockchain:
                          </p>
                          {connectors.map((connector) => (
                            <Button
                              key={connector.uid}
                              type="button"
                              variant="outline"
                              size="sm"
                              onClick={() => connect({ connector })}
                              disabled={isProcessing}
                              className="w-full"
                            >
                              Connect {connector.name}
                            </Button>
                          ))}
                        </div>
                      ) : (
                        <div className="space-y-1">
                          <p className="text-sm text-green-600">
                            ✓ Connected: {address?.slice(0, 6)}...
                            {address?.slice(-4)}
                          </p>
                          <p className="text-xs text-gray-500">
                            Chain ID: {chainId}
                          </p>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => disconnect()}
                            disabled={isProcessing}
                          >
                            Disconnect
                          </Button>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <Button
                    type="submit"
                    className="w-full"
                    disabled={
                      isProcessing || (submitToContract && !isConnected)
                    }
                  >
                    {isProcessing
                      ? "Processing..."
                      : submitToContract
                      ? "Generate & Submit Proof"
                      : "Generate Proof"}
                  </Button>

                  {result && (
                    <div className="space-y-2">
                      <Button
                        type="button"
                        variant="outline"
                        className="w-full"
                        onClick={handleDownloadAll}
                      >
                        Download All Files
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        className="w-full"
                        onClick={handleReset}
                      >
                        Reset
                      </Button>
                    </div>
                  )}
                </div>
              </form>
            </Form>
          </div>

          {/* Status Section */}
          <div className="bg-white p-8 rounded-lg shadow-md">
            <h3 className="text-xl font-semibold mb-6">Processing Status</h3>

            {error && (
              <Card className="p-4 mb-4 bg-red-50 border-red-200">
                <p className="text-red-800 text-sm">
                  <strong>Error:</strong> {error}
                </p>
              </Card>
            )}

            {processingSteps.length > 0 && (
              <div className="space-y-3">
                {processingSteps.map((step, index) => (
                  <div key={index} className="flex items-center space-x-3">
                    <div
                      className={`w-4 h-4 rounded-full flex items-center justify-center ${
                        step.completed
                          ? "bg-green-500"
                          : isProcessing &&
                            index ===
                              processingSteps.findIndex((s) => !s.completed)
                          ? "bg-blue-500 animate-pulse"
                          : "bg-gray-300"
                      }`}
                    >
                      {step.completed && (
                        <svg
                          className="w-2 h-2 text-white"
                          fill="currentColor"
                          viewBox="0 0 20 20"
                        >
                          <path
                            fillRule="evenodd"
                            d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
                            clipRule="evenodd"
                          />
                        </svg>
                      )}
                    </div>
                    <span
                      className={`text-sm ${
                        step.completed ? "text-green-700" : "text-gray-600"
                      }`}
                    >
                      {step.step}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {result && (
              <Card className="p-4 mt-4 bg-green-50 border-green-200">
                <p className="text-green-800 text-sm">
                  <strong>Success!</strong> ZK proof generated successfully.
                  {result.contractSubmission && (
                    <span> Proof submitted to blockchain!</span>
                  )}
                </p>
                <div className="mt-3 text-xs text-green-600 space-y-1">
                  <div>
                    • Signed Credential: Contains your verified identity
                  </div>
                  <div>• Circuit Inputs: Data prepared for ZK circuit</div>
                  <div>• ZK Proof: Zero-knowledge proof of your identity</div>
                  {result.contractSubmission && (
                    <>
                      <div>
                        • Transaction Hash:{" "}
                        {result.contractSubmission.hash.slice(0, 10)}...
                      </div>
                      <div>
                        • Block: #
                        {result.contractSubmission.receipt?.blockNumber}
                      </div>
                    </>
                  )}
                </div>
                {result.contractSubmission && (
                  <div className="mt-2">
                    {chainId === 31337 ? (
                      <span className="text-xs text-gray-600">
                        Transaction Hash: {result.contractSubmission.hash}
                      </span>
                    ) : (
                      <a
                        href={
                          chainId === 11155111
                            ? `https://sepolia.etherscan.io/tx/${result.contractSubmission.hash}`
                            : `https://etherscan.io/tx/${result.contractSubmission.hash}`
                        }
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-blue-600 hover:text-blue-800"
                      >
                        View on {chainId === 11155111 ? "Sepolia " : ""}
                        Etherscan →
                      </a>
                    )}
                  </div>
                )}
              </Card>
            )}

            {!isProcessing &&
              !result &&
              !error &&
              processingSteps.length === 0 && (
                <p className="text-gray-500 text-sm">
                  Fill in your identity information and click "Generate Proof"
                  to start the process.
                </p>
              )}
          </div>
        </div>
      </div>
    </div>
  );
}
