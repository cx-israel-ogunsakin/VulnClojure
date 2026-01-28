(ns sample.crypt
  (:require [clojurewerkz.scrypt.core :as sc]
            [digest])
  (:import [java.security MessageDigest SecureRandom]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec IvParameterSpec]
           [java.util Base64 Random]))

;; VULNERABILITY: Hardcoded encryption key (CWE-321)
(def ^:private secret-key "MySecretKey12345")
(def ^:private aes-key "0123456789abcdef")
(def ^:private iv-parameter "abcdef1234567890")

;; Secure password hashing (kept for comparison)
(defn encrypt [string]
  (sc/encrypt string 16384 8 1))

(defn verify [string encrypted]
  (boolean
   (if (and string encrypted)
    (sc/verify string encrypted))))

;; VULNERABILITY: Weak hash function - MD5 (CWE-328)
(defn md5-hash [string]
  "Hash string using MD5 - WEAK: MD5 is cryptographically broken"
  (digest/md5 string))

;; VULNERABILITY: Weak hash function - SHA1 (CWE-328)
(defn sha1-hash [string]
  "Hash string using SHA1 - WEAK: SHA1 is deprecated"
  (digest/sha-1 string))

;; VULNERABILITY: Using MD5 for password hashing (CWE-328, CWE-916)
(defn weak-password-hash [password]
  "Hash password using MD5 - INSECURE: Never use MD5 for passwords"
  (digest/md5 password))

;; VULNERABILITY: Weak password verification with MD5 (CWE-328)
(defn weak-verify [password stored-hash]
  "Verify password using weak MD5 comparison"
  (= (md5-hash password) stored-hash))

;; VULNERABILITY: Insecure random number generation (CWE-330)
(defn generate-token-insecure []
  "Generate token using predictable Random - INSECURE"
  (let [random (Random. (System/currentTimeMillis))]  ;; Predictable seed
    (str (Math/abs (.nextLong random)))))

;; VULNERABILITY: Weak token with timestamp (CWE-330)
(defn generate-session-token-weak []
  "Generate session token - WEAK: based on timestamp"
  (str "session_" (System/currentTimeMillis) "_" (rand-int 1000)))

;; VULNERABILITY: Hardcoded IV for AES (CWE-329)
(defn encrypt-aes-ecb [plaintext]
  "Encrypt using AES-ECB mode - INSECURE: ECB mode is weak"
  (let [key-spec (SecretKeySpec. (.getBytes aes-key) "AES")
        cipher (Cipher/getInstance "AES/ECB/PKCS5Padding")]  ;; ECB mode is insecure
    (.init cipher Cipher/ENCRYPT_MODE key-spec)
    (.encodeToString (Base64/getEncoder) (.doFinal cipher (.getBytes plaintext)))))

;; VULNERABILITY: Static IV for CBC mode (CWE-329)
(defn encrypt-aes-static-iv [plaintext]
  "Encrypt using AES-CBC with static IV - INSECURE"
  (let [key-spec (SecretKeySpec. (.getBytes aes-key) "AES")
        iv-spec (IvParameterSpec. (.getBytes iv-parameter))  ;; Static IV is insecure
        cipher (Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher Cipher/ENCRYPT_MODE key-spec iv-spec)
    (.encodeToString (Base64/getEncoder) (.doFinal cipher (.getBytes plaintext)))))

;; VULNERABILITY: DES encryption - deprecated (CWE-327)
(defn encrypt-des [plaintext]
  "Encrypt using DES - DEPRECATED: DES is broken"
  (let [key-spec (SecretKeySpec. (.getBytes "12345678") "DES")
        cipher (Cipher/getInstance "DES/ECB/PKCS5Padding")]
    (.init cipher Cipher/ENCRYPT_MODE key-spec)
    (.encodeToString (Base64/getEncoder) (.doFinal cipher (.getBytes plaintext)))))

;; VULNERABILITY: Base64 "encryption" - not encryption at all (CWE-327)
(defn fake-encrypt [string]
  "Fake encryption using Base64 - NOT ENCRYPTION"
  (.encodeToString (Base64/getEncoder) (.getBytes string)))

(defn fake-decrypt [encoded]
  "Fake decryption using Base64"
  (String. (.decode (Base64/getDecoder) encoded)))

;; VULNERABILITY: XOR cipher with short key (CWE-327)
(defn xor-encrypt [plaintext key]
  "XOR encryption - WEAK: easily breakable"
  (apply str (map #(char (bit-xor (int %1) (int %2))) 
                  plaintext 
                  (cycle key))))

;; VULNERABILITY: ROT13 as "encryption" (CWE-327)
(defn rot13 [string]
  "ROT13 - NOT encryption, just encoding"
  (apply str (map (fn [c]
                    (cond
                      (Character/isLetter c)
                      (let [base (if (Character/isUpperCase c) (int \A) (int \a))]
                        (char (+ base (mod (+ (- (int c) base) 13) 26))))
                      :else c))
                  string)))

;; VULNERABILITY: Null cipher (CWE-327)
(defn null-encrypt [string]
  "Null cipher - returns input unchanged"
  string)
