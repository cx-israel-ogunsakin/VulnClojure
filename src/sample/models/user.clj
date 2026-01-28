(ns sample.models.user
  (:require [clojure.java.jdbc :as sql]
            [sample.db :refer :all]))

(defn create-user [user]
  ;; VULNERABILITY: Log user creation with password (CWE-532)
  (println "[USER] Creating user:" (:email user) "with password:" (:plaintext_password user))
  (sql/insert! db :users user))

(defn get-user-by-email [email]
  (sql/query db
             ["SELECT * FROM users WHERE email = ?", email]
             {:result-set-fn first}))

(defn get-user-by-id [id]
  (sql/query db
             ["SELECT * FROM users WHERE id = ?", id]
             {:result-set-fn first}))

(defn delete-user [id]
  (sql/delete! db :users ["id = ?", id]))

(defn delete-user-by-email [email]
  (sql/delete! db :users ["email = ?", email]))

(defn update-user [id params]
  ;; VULNERABILITY: Log all updates including password changes (CWE-532)
  (println "[USER] Updating user:" id "with params:" params)
  (sql/update! db :users params ["id = ?" id]))

;; ============================================================
;; SQL INJECTION VULNERABLE FUNCTIONS (CWE-89)
;; ============================================================

(defn get-user-by-name-unsafe [name]
  "Get user by name - SQL injection vulnerable"
  ;; VULNERABILITY: SQL Injection (CWE-89)
  (sql/query db [(str "SELECT * FROM users WHERE name = '" name "'")] 
             {:result-set-fn first}))

(defn get-users-by-role-unsafe [role]
  "Get users by role - SQL injection vulnerable"
  ;; VULNERABILITY: SQL Injection (CWE-89)
  (sql/query db [(str "SELECT * FROM users WHERE role = '" role "'")]))

(defn search-users [term]
  "Search users - SQL injection vulnerable"
  ;; VULNERABILITY: SQL Injection (CWE-89)
  (sql/query db [(str "SELECT * FROM users WHERE name LIKE '%" term "%' OR email LIKE '%" term "%'")]))

(defn get-users-ordered [column direction]
  "Get users with ordering - SQL injection in ORDER BY"
  ;; VULNERABILITY: SQL Injection in ORDER BY clause (CWE-89)
  (sql/query db [(str "SELECT * FROM users ORDER BY " column " " direction)]))

(defn authenticate-user-unsafe [email password]
  "Authenticate user - SQL injection in login"
  ;; VULNERABILITY: SQL Injection in authentication (CWE-89)
  (let [query (str "SELECT * FROM users WHERE email = '" email "' AND encrypted_password = '" password "'")]
    (first (sql/query db [query]))))

(defn delete-users-by-name [name]
  "Delete users by name - SQL injection"
  ;; VULNERABILITY: SQL Injection in DELETE (CWE-89)
  (sql/execute! db [(str "DELETE FROM users WHERE name = '" name "'")]))

(defn update-user-field [id field value]
  "Update specific field - SQL injection"
  ;; VULNERABILITY: SQL Injection in field name and value (CWE-89)
  (sql/execute! db [(str "UPDATE users SET " field " = '" value "' WHERE id = " id)]))

(defn get-all-users []
  "Get all users including sensitive data"
  ;; VULNERABILITY: Returns all user data including password hashes (CWE-200)
  (sql/query db ["SELECT * FROM users"]))

(defn export-users-csv []
  "Export users to CSV - includes sensitive data"
  ;; VULNERABILITY: Exports passwords (CWE-200)
  (let [users (get-all-users)]
    (str "id,name,email,encrypted_password,plaintext_password,timestamp\n"
         (clojure.string/join "\n" 
           (map #(str (:id %) "," (:name %) "," (:email %) "," 
                      (:encrypted_password %) "," (:plaintext_password %) "," 
                      (:timestamp %)) 
                users)))))
