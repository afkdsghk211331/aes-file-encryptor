import { createContext, useContext, useState, useCallback, useRef, useEffect } from "react";
import { encryptFile, decryptFile, type EncryptionMode } from "aes-file-encryptor";

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
type ThemeMode = "light" | "dark" | "system";

const ThemeCtx = createContext<{ theme: ThemeMode; setTheme: (t: ThemeMode) => void }>(null!);

function useTheme() {
  return useContext(ThemeCtx);
}

function applyTheme(mode: ThemeMode) {
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const dark = mode === "system" ? prefersDark : mode === "dark";
  if (dark) {
    document.documentElement.classList.add("dark");
  } else {
    document.documentElement.classList.remove("dark");
  }
}

function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    const stored = localStorage.getItem("theme-mode");
    return (stored as ThemeMode) || "system";
  });

  useEffect(() => {
    localStorage.setItem("theme-mode", theme);
    applyTheme(theme);
  }, [theme]);

  // Listen for OS theme changes when in "system" mode
  useEffect(() => {
    if (theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => applyTheme("system");
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, [theme]);

  return <ThemeCtx.Provider value={{ theme, setTheme }}>{children}</ThemeCtx.Provider>;
}

function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const options: ThemeMode[] = ["light", "system", "dark"];
  const labels: Record<ThemeMode, string> = { light: "Light", system: "Auto", dark: "Dark" };

  return (
    <div className="flex items-center gap-1 bg-gray-200 dark:bg-gray-800 rounded-lg p-1">
      {options.map((opt) => (
        <button
          key={opt}
          className={`px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
            theme === opt
              ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
              : "text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
          }`}
          onClick={() => setTheme(opt)}
        >
          {labels[opt]}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
type Action = "encrypt" | "decrypt";

interface BenchResult {
  mode: EncryptionMode;
  duration: number;
  blob: Blob;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 2 : 0) + " " + units[i];
}

function formatMs(ms: number): string {
  if (ms < 1000) return ms.toFixed(0) + " ms";
  return (ms / 1000).toFixed(2) + " s";
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function FileSelector({
  file,
  onFile,
  label,
}: {
  file: File | null;
  onFile: (f: File) => void;
  label: string;
}) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (e.dataTransfer.files.length > 0) onFile(e.dataTransfer.files[0]);
    },
    [onFile],
  );

  return (
    <div
      className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-colors cursor-pointer
        ${dragging
          ? "border-cyan-400 bg-cyan-400/10"
          : "border-gray-300 hover:border-gray-500 dark:border-gray-700 dark:hover:border-gray-500"
        }`}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
    >
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])}
      />
      {file ? (
        <div className="space-y-1">
          <div className="text-3xl text-gray-400 dark:text-gray-500">
            <FileIcon />
          </div>
          <div className="font-medium text-cyan-600 dark:text-cyan-300">{file.name}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400">{formatBytes(file.size)}</div>
        </div>
      ) : (
        <div className="space-y-1">
          <div className="text-3xl text-gray-400 dark:text-gray-500">
            <FolderIcon />
          </div>
          <div className="text-gray-500 dark:text-gray-400">{label}</div>
        </div>
      )}
    </div>
  );
}

function ModeSelector({
  mode,
  onChange,
}: {
  mode: EncryptionMode;
  onChange: (m: EncryptionMode) => void;
}) {
  return (
    <div className="flex gap-2">
      {(["CBC", "CTR", "CFB"] as EncryptionMode[]).map((m) => (
        <button
          key={m}
          className={`flex-1 py-2 px-4 rounded-lg font-semibold transition-colors ${
            mode === m
              ? "bg-cyan-500 text-white"
              : "bg-gray-200 text-gray-600 hover:bg-gray-300 dark:bg-gray-800 dark:text-gray-400 dark:hover:bg-gray-700"
          }`}
          onClick={() => onChange(m)}
        >
          AES-{m}
        </button>
      ))}
    </div>
  );
}

function ResultDisplay({
  action,
  blob,
  duration,
  mode,
  fileName,
  onDownload,
}: {
  action: Action;
  blob: Blob;
  duration: number;
  mode: EncryptionMode;
  fileName: string;
  onDownload: () => void;
}) {
  const verb = action === "encrypt" ? "Encrypted" : "Decrypted";
  const dlName = action === "encrypt"
    ? fileName + ".encrypted"
    : fileName.replace(/\.encrypted$/, "");

  return (
    <div className="bg-gray-100 dark:bg-gray-800/60 rounded-xl p-6 space-y-3">
      <div className="flex items-center gap-2 text-green-600 dark:text-green-400 font-semibold text-lg">
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
        {verb} successfully
      </div>
      <div className="grid grid-cols-2 gap-2 text-sm text-gray-600 dark:text-gray-300">
        <span>Mode:</span>
        <span className="font-mono">AES-{mode}</span>
        <span>Time:</span>
        <span className="font-mono text-cyan-600 dark:text-cyan-300">{formatMs(duration)}</span>
        <span>Output size:</span>
        <span className="font-mono">{formatBytes(blob.size)}</span>
      </div>
      <button
        className="w-full py-3 bg-cyan-500 hover:bg-cyan-400 text-white font-semibold rounded-lg transition-colors"
        onClick={() => onDownload()}
      >
        Download {dlName}
      </button>
    </div>
  );
}

function BenchCard({
  result,
  action,
  fileName,
}: {
  result: BenchResult;
  action: Action;
  fileName: string;
}) {
  const suffix = action === "encrypt" ? ".encrypted" : "";
  const dlName = action === "encrypt"
    ? fileName + suffix
    : fileName.replace(/\.encrypted$/, "");
  return (
    <div className="bg-gray-100 dark:bg-gray-800/60 rounded-xl p-4 space-y-2">
      <div className="font-bold text-cyan-600 dark:text-cyan-300">AES-{result.mode}</div>
      <div className="text-sm text-gray-600 dark:text-gray-300">
        Time: <span className="font-mono font-semibold">{formatMs(result.duration)}</span>
      </div>
      <div className="text-sm text-gray-600 dark:text-gray-300">
        Size: <span className="font-mono">{formatBytes(result.blob.size)}</span>
      </div>
      <button
        className="w-full py-2 bg-gray-300 hover:bg-gray-400 dark:bg-gray-700 dark:hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors"
        onClick={() => downloadBlob(result.blob, dlName)}
      >
        Download ({result.mode})
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SVG icons
// ---------------------------------------------------------------------------
function FileIcon() {
  return (
    <svg className="w-10 h-10 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
    </svg>
  );
}

function FolderIcon() {
  return (
    <svg className="w-10 h-10 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------
export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [action, setAction] = useState<Action>("encrypt");
  const [mode, setMode] = useState<EncryptionMode>("CBC");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{
    blob: Blob;
    duration: number;
    action: Action;
    mode: EncryptionMode;
    fileName: string;
  } | null>(null);
  const [benchResults, setBenchResults] = useState<{
    cbc: BenchResult;
    ctr: BenchResult;
    cfb: BenchResult;
    action: Action;
    fileName: string;
  } | null>(null);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState<number | null>(null);

  const handleProcess = async () => {
    if (!file || !key) return;
    setBusy(true);
    setProgress(0);
    setError("");
    setResult(null);
    try {
      const fn = action === "encrypt" ? encryptFile : decryptFile;
      const t0 = performance.now();
      const blob = await fn(file, key, mode, { onProgress: setProgress });
      const elapsed = performance.now() - t0;
      setResult({ blob, duration: elapsed, action, mode, fileName: file.name });
      setProgress(1);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const handleBenchmark = async () => {
    if (!file || !key) return;
    setBusy(true);
    setProgress(0);
    setError("");
    setBenchResults(null);
    try {
      const fn = action === "encrypt" ? encryptFile : decryptFile;
      const modes: EncryptionMode[] = ["CBC", "CTR", "CFB"];
      const results: Record<EncryptionMode, BenchResult> = {} as Record<EncryptionMode, BenchResult>;
      for (let i = 0; i < modes.length; i++) {
        const m = modes[i];
        const t0 = performance.now();
        const blob = await fn(file, key, m, { onProgress: (p: number) => setProgress((i + p) / modes.length) });
        results[m] = { mode: m, duration: performance.now() - t0, blob };
      }
      setBenchResults({
        cbc: results.CBC,
        ctr: results.CTR,
        cfb: results.CFB,
        action,
        fileName: file.name,
      });
      setProgress(1);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const canRun = file !== null && key.length > 0 && !busy;
  const fastest =
    benchResults &&
    (["CBC", "CTR", "CFB"] as EncryptionMode[]).reduce((a, b) =>
      benchResults[a.toLowerCase() as keyof Omit<typeof benchResults, "action" | "fileName">].duration <
      benchResults[b.toLowerCase() as keyof Omit<typeof benchResults, "action" | "fileName">].duration
        ? a : b,
    );

  const lockIcon = (
    <svg className="w-4 h-4 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );

  const unlockIcon = (
    <svg className="w-4 h-4 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 10.5V6.75a4.5 4.5 0 119 0v3.75M3.75 21.75h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H3.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );

  return (
    <ThemeProvider>
      <div className="min-h-screen py-12 px-4
        bg-gradient-to-b from-gray-100 to-white
        dark:from-gray-950 dark:to-gray-900">
        <div className="max-w-xl mx-auto space-y-8">
          {/* Header + Theme Toggle */}
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-600 to-blue-500 dark:from-cyan-400 dark:to-blue-500 bg-clip-text text-transparent">
                AES File Encryptor
              </h1>
              <p className="text-gray-500 dark:text-gray-400">
                Encrypt and decrypt files in your browser with AES-CBC, AES-CTR and AES-CFB
              </p>
            </div>
            <ThemeToggle />
          </div>

          {/* Action toggle */}
          <div className="flex gap-2 bg-gray-200 dark:bg-gray-900 p-1 rounded-lg">
            {(["encrypt", "decrypt"] as Action[]).map((a) => (
              <button
                key={a}
                className={`flex-1 py-2 rounded-md font-semibold capitalize transition-colors ${
                  action === a
                    ? "bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow"
                    : "text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
                }`}
                onClick={() => {
                  setAction(a);
                  setResult(null);
                  setBenchResults(null);
                  setError("");
                }}
              >
                {a === "encrypt"
                  ? <>{lockIcon} Encrypt</>
                  : <>{unlockIcon} Decrypt</>
                }
              </button>
            ))}
          </div>

          {/* File selector */}
          <FileSelector
            file={file}
            onFile={(f) => {
              setFile(f);
              setResult(null);
              setBenchResults(null);
            }}
            label={
              action === "encrypt"
                ? "Drop a file to encrypt, or click to browse"
                : "Drop the encrypted file to decrypt, or click to browse"
            }
          />

          {/* Key input */}
          <div className="space-y-2">
            <label className="text-sm font-medium text-gray-600 dark:text-gray-300">Key / Passphrase</label>
            <input
              type="password"
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="Enter your secret passphrase"
              className="w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent font-mono
                dark:bg-gray-800 dark:border-gray-700 dark:text-white dark:placeholder-gray-500"
            />
          </div>

          {/* Mode selector */}
          <ModeSelector mode={mode} onChange={(m) => setMode(m)} />

          {/* Action buttons */}
          <div className="grid grid-cols-2 gap-3">
            <button
              disabled={!canRun}
              className={`py-3 rounded-lg font-semibold transition-colors ${
                canRun
                  ? "bg-cyan-500 hover:bg-cyan-400 text-white"
                  : "bg-gray-200 text-gray-400 cursor-not-allowed dark:bg-gray-800 dark:text-gray-600"
              }`}
              onClick={handleProcess}
            >
              {busy ? "Processing..." : `${action === "encrypt" ? "Encrypt" : "Decrypt"} (${mode})`}
            </button>
            <button
              disabled={!canRun || action === "decrypt"}
              title={action === "decrypt" ? "Comparison is only available for encryption" : ""}
              className={`py-3 rounded-lg font-semibold transition-colors ${
                canRun && action !== "decrypt"
                  ? "bg-violet-500 hover:bg-violet-400 text-white"
                  : "bg-gray-200 text-gray-400 cursor-not-allowed dark:bg-gray-800 dark:text-gray-600"
              }`}
              onClick={handleBenchmark}
            >
              {busy ? "Running..." : "Compare All 3 Modes"}
            </button>
          </div>

          {/* Progress bar */}
          {progress !== null && (
            <div className="space-y-1">
              <div className="flex justify-between text-sm text-gray-500 dark:text-gray-400">
                <span>{busy ? (action === "encrypt" ? "Encrypting..." : "Decrypting...") : "Done"}</span>
                <span className="font-mono">{Math.round(progress * 100)}%</span>
              </div>
              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-cyan-500 rounded-full transition-all duration-200"
                  style={{ width: `${progress * 100}%` }}
                />
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="bg-red-100 dark:bg-red-900/40 border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 rounded-xl p-4">
              Error: {error}
            </div>
          )}

          {/* Single result */}
          {result && (
            <ResultDisplay
              action={result.action}
              blob={result.blob}
              duration={result.duration}
              mode={result.mode}
              fileName={result.fileName}
              onDownload={() => {
                const dlName = result.action === "encrypt"
                  ? result.fileName + ".encrypted"
                  : result.fileName.replace(/\.encrypted$/, "");
                downloadBlob(result.blob, dlName);
              }}
            />
          )}

          {/* Benchmark results */}
          {benchResults && (
            <div className="space-y-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white">Performance Comparison</h2>
              <div className="grid grid-cols-3 gap-3">
                <BenchCard
                  result={benchResults.cbc}
                  action={benchResults.action}
                  fileName={benchResults.fileName}
                />
                <BenchCard
                  result={benchResults.ctr}
                  action={benchResults.action}
                  fileName={benchResults.fileName}
                />
                <BenchCard
                  result={benchResults.cfb}
                  action={benchResults.action}
                  fileName={benchResults.fileName}
                />
              </div>
              <div className="bg-gray-100 dark:bg-gray-800/60 rounded-xl p-4 text-center">
                <span className="text-gray-500 dark:text-gray-400">Fastest: </span>
                <span className="font-bold text-green-600 dark:text-green-400">AES-{fastest}</span>
              </div>
              <div className="bg-gray-100 dark:bg-gray-800/60 rounded-xl p-4">
                <h3 className="font-semibold text-gray-700 dark:text-gray-300 mb-2">Speed breakdown</h3>
                {[benchResults.cbc, benchResults.ctr, benchResults.cfb].map((r) => {
                  const max = Math.max(benchResults.cbc.duration, benchResults.ctr.duration, benchResults.cfb.duration);
                  const pct = (r.duration / max) * 100;
                  const barColor = r.mode === "CBC" ? "bg-cyan-500" : r.mode === "CTR" ? "bg-violet-500" : "bg-amber-500";
                  return (
                    <div key={r.mode} className="mb-2 last:mb-0">
                      <div className="flex justify-between text-sm text-gray-500 dark:text-gray-400 mb-1">
                        <span>AES-{r.mode}</span>
                        <span className="font-mono">{formatMs(r.duration)}</span>
                      </div>
                      <div className="h-2 bg-gray-300 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${barColor}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </ThemeProvider>
  );
}
