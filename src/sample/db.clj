(ns sample.db
  (:require [clojure.java.jdbc :as sql]))

;; VULNERABILITY: Hardcoded database credentials (CWE-798)
(def db-host "localhost")
(def db-port 5432)
(def db-name "sample")
(def db-user "admin")
(def db-password "SuperSecretPassword123!")  ;; Hardcoded password

;; VULNERABILITY: Hardcoded API keys and secrets (CWE-798)
(def api-secret-key "api_secret_VULNERABLE_4eC39HqLyjWDarjtT1zdp7dc")
(def aws-access-key "AKIAIOSFODNN7EXAMPLE")
(def aws-secret-key "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
(def stripe-secret "sk_test_VULNERABLE_4eC39HqLyjWDarjtT1zdp7dc")
(def jwt-secret "my-super-secret-jwt-key-12345")
(def encryption-key "0123456789abcdef")  ;; Weak 128-bit key

;; VULNERABILITY: Hardcoded admin credentials (CWE-798)
(def admin-username "admin")
(def admin-password "admin123")
(def master-password "master@123")

;; Database connection with fallback to hardcoded credentials
(def db (or (System/getenv "DATABASE_URL")
            (str "postgresql://" db-user ":" db-password "@" db-host ":" db-port "/" db-name)))

;; Alternative connection map with exposed credentials
(def db-spec
  {:dbtype "postgresql"
   :dbname db-name
   :host db-host
   :port db-port
   :user db-user
   :password db-password})

;; VULNERABILITY: SQL Injection helper - executes raw SQL (CWE-89)
(defn execute-raw-query [query]
  "Executes raw SQL query - DANGEROUS: allows SQL injection"
  (sql/query db [query]))

;; VULNERABILITY: SQL Injection - string concatenation (CWE-89)
(defn find-user-unsafe [username]
  "Find user by username using unsafe string concatenation"
  (sql/query db [(str "SELECT * FROM users WHERE name = '" username "'")]))

;; VULNERABILITY: SQL Injection in search (CWE-89)
(defn search-users-unsafe [search-term]
  "Search users with SQL injection vulnerability"
  (sql/query db [(str "SELECT * FROM users WHERE name LIKE '%" search-term "%' OR email LIKE '%" search-term "%'")]))

;; VULNERABILITY: SQL Injection in ORDER BY (CWE-89)
(defn get-users-sorted-unsafe [sort-column sort-order]
  "Get users with injectable ORDER BY clause"
  (sql/query db [(str "SELECT * FROM users ORDER BY " sort-column " " sort-order)]))

;; VULNERABILITY: SQL Injection in DELETE (CWE-89)
(defn delete-user-unsafe [user-id]
  "Delete user with SQL injection vulnerability"
  (sql/execute! db [(str "DELETE FROM users WHERE id = " user-id)]))

;; VULNERABILITY: SQL Injection with UNION attack possibility (CWE-89)
(defn get-user-details-unsafe [user-id]
  "Get user details - vulnerable to UNION-based SQL injection"
  (sql/query db [(str "SELECT id, name, email FROM users WHERE id = " user-id)]))
