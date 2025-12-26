/* global BigInt */

import React, { useState } from "react";
import axios from "axios";
import "./App.css";

// API URL - kosong berarti sama dengan origin (untuk production)
// Di development, bisa set REACT_APP_API_URL=http://localhost:3001
const API_URL = process.env.REACT_APP_API_URL || "";

// ========================================
// Schnorr Protocol - Crypto Functions
// Berdasarkan Notasi Bab 2 (Tabel 2.1):
//   p = Bilangan prima besar (modulus)
//   g = Generator grup
//   x = Nilai rahasia (private key)
//   y = g^x mod p (public key)
//   r = Nonce acak
//   t = g^r mod p (commitment)
//   c = Challenge
//   z = r + cx mod p (response)
// ========================================
const schnorr = {
  // p: Bilangan prima besar (modulus) - sesuai Tabel 2.1
  p: BigInt(
    "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"
  ),
  // g: Generator grup - sesuai Tabel 2.1
  g: BigInt(2),

  // Generate random BigInt dalam rentang [0, max)
  randomBigInt: (max) => {
    const str = max.toString();
    let result = "";
    for (let i = 0; i < str.length; i++) {
      result += Math.floor(Math.random() * 10);
    }
    return BigInt(result) % max;
  },

  // Fungsi modular exponentiation: base^exp mod mod
  modPow: (base, exp, mod) => {
    let result = BigInt(1);
    base = base % mod;
    while (exp > 0) {
      if (exp % BigInt(2) === BigInt(1)) {
        result = (result * base) % mod;
      }
      exp = exp >> BigInt(1);
      base = (base * base) % mod;
    }
    return result;
  },

  // Hash password menjadi private key (x)
  // Dalam praktik nyata gunakan fungsi hash kriptografis yang lebih kuat
  hashToPrivateKey: (password) => {
    let hash = 0;
    for (let i = 0; i < password.length; i++) {
      hash = (hash << 5) - hash + password.charCodeAt(i);
      hash = hash & hash;
    }
    return BigInt(Math.abs(hash)) + BigInt(1000000);
  },
};

function App() {
  const [step, setStep] = useState("menu");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [qrCode, setQrCode] = useState("");
  const [totpSecret, setTotpSecret] = useState("");
  const [logs, setLogs] = useState([]);

  const addLog = (message, isClient = true) => {
    const prefix = isClient ? "CLIENT:" : "SERVER:";
    setLogs((prev) => [...prev, `${prefix} ${message}`]);
    console.log(`${prefix} ${message}`);
  };

  // ========================================
  // PROSES REGISTRASI
  // Sesuai Flowchart Gambar 3.2
  // ========================================
  const handleRegister = async () => {
    try {
      addLog("=== REGISTRASI DIMULAI ===");
      addLog(`Username: ${username}`);

      // ========================================
      // Langkah 1: Generate key pair dari password
      // x = private key (dari hash password)
      // y = g^x mod p (public key) - Persamaan 2.1
      // ========================================
      const x = schnorr.hashToPrivateKey(password); // x = private key
      const y = schnorr.modPow(schnorr.g, x, schnorr.p); // y = g^x mod p

      addLog("Private key (x) di-generate dari password");
      addLog(`x = ${x.toString().substring(0, 20)}...`);
      addLog("Public key (y = g^x mod p) dihitung - Persamaan 2.1");
      addLog(`y = ${y.toString().substring(0, 20)}...`);
      addLog("Private key (x) TIDAK PERNAH keluar dari browser!");

      // ========================================
      // Langkah 2: Kirim HANYA public key (y) ke server
      // ========================================
      addLog("Mengirim public key (y) ke server...", true);
      const response = await axios.post(`${API_URL}/api/register`, {
        username,
        publicKey: y.toString(), // Hanya y yang dikirim, x tetap di client
      });

      addLog("Server merespons dengan TOTP secret", false);
      setQrCode(response.data.qrCode);
      setTotpSecret(response.data.totpSecret);
      setStep("qr");
    } catch (error) {
      addLog(`Error: ${error.response?.data?.error || error.message}`);
    }
  };

  // ========================================
  // PROSES LOGIN
  // Sesuai Flowchart Gambar 3.3 dan Tabel 3.3
  // ========================================
  const handleLogin = async () => {
    try {
      addLog("=== LOGIN DIMULAI ===");

      // ========================================
      // FASE 1: Persiapan - Generate private key dari password
      // x = private key (TIDAK dikirim ke server)
      // ========================================
      const x = schnorr.hashToPrivateKey(password);
      addLog("Private key (x) di-generate dari password (lokal)");
      addLog(`x = ${x.toString().substring(0, 20)}...`);
      addLog("Password/Private key (x) TIDAK dikirim!");

      // ========================================
      // FASE 1: Challenge Request (Client → Server)
      // Sesuai Tabel 3.3 Fase 1
      // ========================================
      addLog("Meminta challenge dari server...");
      const challengeRes = await axios.post(`${API_URL}/api/challenge`, {
        username,
      });

      // ========================================
      // FASE 2: Challenge Generation (Server)
      // c = challenge (dari server) - Persamaan 2.3
      // ========================================
      const c = BigInt(challengeRes.data.challenge); // c = challenge
      const sessionId = challengeRes.data.sessionId;

      addLog(
        `Challenge (c) diterima: ${c
          .toString()
          .substring(0, 20)}... - Persamaan 2.3`,
        false
      );

      // ========================================
      // FASE 3: Proof Generation (Client)
      // Sesuai Tabel 3.3 Fase 3
      // ========================================
      addLog("--- Membuat Zero Knowledge Proof ---");

      // r = random nonce - sesuai Tabel 2.1
      const r = schnorr.randomBigInt(schnorr.p - BigInt(1)) + BigInt(1);
      addLog("Random nonce (r) di-generate");

      // t = g^r mod p (commitment) - Persamaan 2.2
      const t = schnorr.modPow(schnorr.g, r, schnorr.p);
      addLog(
        `Commitment (t = g^r mod p): ${t
          .toString()
          .substring(0, 20)}... - Persamaan 2.2`
      );

      // z = r + c*x mod (p-1) (response) - Persamaan 2.4
      const z = (r + c * x) % (schnorr.p - BigInt(1));
      addLog(
        `Response (z = r + c×x mod p): ${z
          .toString()
          .substring(0, 20)}... - Persamaan 2.4`
      );

      addLog("Mengirim commitment (t) & response (z) ke server");
      addLog("Yang dikirim adalah PROOF, bukan PASSWORD!");

      // ========================================
      // FASE 4: Verification (Server)
      // Server akan memverifikasi: g^z ≡ t × y^c (mod p) - Persamaan 2.5
      // ========================================
      const verifyRes = await axios.post(`${API_URL}/api/verify`, {
        username,
        commitment: t.toString(), // t = commitment
        response: z.toString(), // z = response
        sessionId,
        totpCode,
      });

      if (verifyRes.data.success) {
        addLog("ZKP Verification: VALID ✓", false);
        addLog(
          "Server memverifikasi: g^z ≡ t × y^c (mod p) - Persamaan 2.5",
          false
        );
        addLog("TOTP Verification: VALID ✓", false);
        addLog("LOGIN BERHASIL!", false);
        setStep("success");
      } else {
        addLog(
          `Verifikasi gagal: ${verifyRes.data.error || "Unknown error"}`,
          false
        );
      }
    } catch (error) {
      addLog(`Error: ${error.response?.data?.error || error.message}`);
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🔐 Zero Knowledge Proof + TOTP</h1>
        <p>Protokol Schnorr - Demo Skripsi</p>
      </header>

      <div className="container">
        <div className="main-panel">
          {step === "menu" && (
            <div>
              <h2>Pilih Aksi</h2>
              <button onClick={() => setStep("register")}>Registrasi</button>
              <button onClick={() => setStep("login")}>Login</button>
            </div>
          )}

          {step === "register" && (
            <div>
              <h2>Registrasi</h2>
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button onClick={handleRegister}>Daftar</button>
              <button onClick={() => setStep("menu")}>Kembali</button>
            </div>
          )}

          {step === "qr" && (
            <div>
              <h2>Setup Google Authenticator</h2>
              {qrCode && <img src={qrCode} alt="QR Code" />}
              <p>
                TOTP Secret: <code>{totpSecret}</code>
              </p>
              <ol style={{ textAlign: "left" }}>
                <li>Buka Google Authenticator</li>
                <li>Scan QR code atau masukkan secret manual</li>
                <li>Klik tombol di bawah setelah selesai</li>
              </ol>
              <button onClick={() => setStep("menu")}>Selesai</button>
            </div>
          )}

          {step === "login" && (
            <div>
              <h2>Login</h2>
              <input
                type="text"
                placeholder="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <input
                type="text"
                placeholder="Google Authenticator Code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                maxLength={6}
              />
              <button onClick={handleLogin}>Login</button>
              <button onClick={() => setStep("menu")}>Kembali</button>
            </div>
          )}

          {step === "success" && (
            <div>
              <h2>✅ Login Berhasil!</h2>
              <p>Autentikasi ZKP + TOTP berhasil</p>
              <button
                onClick={() => {
                  setStep("menu");
                  setLogs([]);
                }}
              >
                Kembali
              </button>
            </div>
          )}
        </div>

        <div className="logs-panel">
          <h3>📋 Network Logs</h3>
          <div className="logs">
            {logs.map((log, i) => (
              <div key={i} className="log-entry">
                {log}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
