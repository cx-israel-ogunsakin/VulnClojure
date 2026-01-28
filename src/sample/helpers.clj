(ns sample.helpers
  (:require [compojure.core :refer :all]
            [clojure.java.shell :refer [sh]]
            [sample.models.user :as user-db]
            [ring.util.codec :refer [url-encode]]
            [struct.core :as st]
            [hiccup.form :refer :all]
            [hiccup.element :refer :all])
  (:import [javax.naming.directory InitialDirContext SearchControls]
           [javax.naming Context]
           [java.util Hashtable]))

(defn get-user [id]
  (if id
    (user-db/get-user-by-id id)))

(defn error-item [error]
  [:div.text-danger error])

(defn input-control [type id name & [value required error]]
  [:div.form-group
   (list
     (label id name)
     (if error (error-item error))
     (type {:class "form-control" :required required} id value))])

(defn avatar-uri [file-name]
  (str "/files/avatars/" (url-encode file-name)))

;; ============================================================
;; LDAP INJECTION (CWE-90)
;; ============================================================

(defn ldap-authenticate [username password]
  "Authenticate user via LDAP - vulnerable to LDAP injection"
  ;; VULNERABILITY: LDAP Injection (CWE-90)
  (try
    (let [env (doto (Hashtable.)
                (.put Context/INITIAL_CONTEXT_FACTORY "com.sun.jndi.ldap.LdapCtxFactory")
                (.put Context/PROVIDER_URL "ldap://localhost:389")
                (.put Context/SECURITY_AUTHENTICATION "simple")
                ;; VULNERABILITY: User input directly in LDAP bind (CWE-90)
                (.put Context/SECURITY_PRINCIPAL (str "cn=" username ",dc=example,dc=com"))
                (.put Context/SECURITY_CREDENTIALS password))
          ctx (InitialDirContext. env)]
      (.close ctx)
      true)
    (catch Exception e
      (println "[LDAP] Authentication failed:" (.getMessage e))
      false)))

(defn ldap-search [filter-string]
  "Search LDAP directory - vulnerable to LDAP injection"
  ;; VULNERABILITY: LDAP Injection in search filter (CWE-90)
  (try
    (let [env (doto (Hashtable.)
                (.put Context/INITIAL_CONTEXT_FACTORY "com.sun.jndi.ldap.LdapCtxFactory")
                (.put Context/PROVIDER_URL "ldap://localhost:389"))
          ctx (InitialDirContext. env)
          controls (doto (SearchControls.)
                     (.setSearchScope SearchControls/SUBTREE_SCOPE))
          ;; VULNERABILITY: Filter string from user input (CWE-90)
          results (.search ctx "dc=example,dc=com" filter-string controls)]
      (loop [entries []]
        (if (.hasMore results)
          (recur (conj entries (.next results)))
          entries)))
    (catch Exception e
      (println "[LDAP] Search failed:" (.getMessage e))
      [])))

(defn ldap-find-user [username]
  "Find user in LDAP - vulnerable"
  ;; VULNERABILITY: LDAP Injection (CWE-90)
  (ldap-search (str "(uid=" username ")")))

;; ============================================================
;; XPATH INJECTION (CWE-643)
;; ============================================================

(defn xpath-query [xml-doc xpath-expression]
  "Execute XPath query - vulnerable to XPath injection"
  ;; VULNERABILITY: XPath Injection (CWE-643)
  (try
    (let [factory (javax.xml.xpath.XPathFactory/newInstance)
          xpath (.newXPath factory)]
      ;; User input directly in XPath expression
      (.evaluate xpath xpath-expression xml-doc))
    (catch Exception e
      (str "XPath error: " (.getMessage e)))))

;; ============================================================
;; REGEX DOS (CWE-1333)
;; ============================================================

(defn validate-email-regex [email]
  "Validate email with vulnerable regex - ReDoS"
  ;; VULNERABILITY: ReDoS - evil regex (CWE-1333)
  (re-matches #"^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$" email))

(defn validate-password-regex [password]
  "Validate password with vulnerable regex"
  ;; VULNERABILITY: ReDoS (CWE-1333)
  (re-matches #"^(([a-z])+)+([A-Z])+([0-9])+$" password))

;; ============================================================
;; SHELL HELPERS (CWE-78)
;; ============================================================

(defn run-command [cmd]
  "Run shell command - command injection helper"
  ;; VULNERABILITY: Direct command execution (CWE-78)
  (let [result (sh "sh" "-c" cmd)]
    {:exit (:exit result)
     :output (:out result)
     :error (:err result)}))

(defn process-file [filename operation]
  "Process file with shell operation - command injection"
  ;; VULNERABILITY: Command injection (CWE-78)
  (run-command (str operation " " filename)))

;; ============================================================
;; FORMAT STRING (CWE-134)
;; ============================================================

(defn format-log-message [template & args]
  "Format log message - format string vulnerability"
  ;; VULNERABILITY: Format string with user input (CWE-134)
  (apply format template args))

(defn log-user-action [user action details]
  "Log user action with format string"
  ;; VULNERABILITY: User-controlled format string (CWE-134)
  (println (format-log-message details user action)))
