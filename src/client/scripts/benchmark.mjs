import { performance } from "perf_hooks";

async function runBenchmark() {
    console.log("Benchmarking Biometric Fuzzy Extractor Operations...");
    try {
        // Import local compiled fuzzy signature package
        const fuzzyExtractor = await import("../../EdDSA-fuzzy-signature/dist/index.js");
        const BIOMETRIC_LENGTH = 32;
        
        // Helper to simulate raw biometric sensor array
        const generateMockBiometric = () => {
            const arr = new Uint8Array(BIOMETRIC_LENGTH);
            for(let i=0; i<BIOMETRIC_LENGTH; i++) arr[i] = Math.floor(Math.random() * 256);
            return arr;
        };
        
        let totalEnroll = 0;
        let totalRecover = 0;
        const iterations = 100;
        
        // Warm up the JIT compiler to avoid cold-start bias
        const warmup = generateMockBiometric();
        const { sketch: ws } = fuzzyExtractor.enroll(warmup);
        fuzzyExtractor.fuzzyRep(warmup, ws);

        for (let i = 0; i < iterations; i++) {
            const rawBio = generateMockBiometric();
            
            // 1. Benchmark Enrollment (Sketch generation)
            const t0 = performance.now();
            const { vk, sketch } = fuzzyExtractor.enroll(rawBio);
            const t1 = performance.now();
            totalEnroll += (t1 - t0);
            
            // 2. Benchmark Reconstruction (Zero noise ideal path)
            const t2 = performance.now();
            const key = fuzzyExtractor.fuzzyRep(rawBio, sketch);
            if (key) {
                const privateKey = fuzzyExtractor.derivePrivateKey(key);
            }
            const t3 = performance.now();
            totalRecover += (t3 - t2);
        }
        
        console.log(`\nResults over ${iterations} iterations:`);
        console.log(`- Avg Fuzzy Enrollment (Sketch Gen): ${(totalEnroll/iterations).toFixed(2)} ms`);
        console.log(`- Avg Fuzzy Recovery (Key Derivation): ${(totalRecover/iterations).toFixed(2)} ms`);
        
    } catch (e) {
        console.error("Error running benchmark:", e);
    }
}
runBenchmark();
