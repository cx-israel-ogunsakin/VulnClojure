(ns sample.routes.backup
  (:require [compojure.core :refer :all]
            [clojure.java.io :as io]
            [clojure.java.shell :refer [sh]]
            [clojure.java.jdbc :as sql]
            [cheshire.core :as json]
            [sample.db :as database]
            [sample.models.user :as user-db]
            [sample.views.layout :as layout]
            [ring.util.response :as response])
  (:import [java.io File FileInputStream ByteArrayOutputStream]
           [java.util.zip ZipOutputStream ZipEntry]
           [java.text SimpleDateFormat]
           [java.util Date]))

;; ============================================================
;; INFORMATION DISCLOSURE (CWE-200)
;; ============================================================

(defn get-system-info []
  "Get system information - exposes sensitive data"
  ;; VULNERABILITY: Information disclosure (CWE-200)
  {:os-name (System/getProperty "os.name")
   :os-version (System/getProperty "os.version")
   :os-arch (System/getProperty "os.arch")
   :java-version (System/getProperty "java.version")
   :java-vendor (System/getProperty "java.vendor")
   :java-home (System/getProperty "java.home")
   :user-name (System/getProperty "user.name")
   :user-home (System/getProperty "user.home")
   :user-dir (System/getProperty "user.dir")
   :tmp-dir (System/getProperty "java.io.tmpdir")
   :classpath (System/getProperty "java.class.path")
   :library-path (System/getProperty "java.library.path")})

(defn get-environment []
  "Get all environment variables"
  ;; VULNERABILITY: Exposes all env vars including secrets (CWE-200)
  (into {} (System/getenv)))

(defn get-database-info []
  "Get database connection info"
  ;; VULNERABILITY: Exposes database credentials (CWE-200)
  {:connection-string database/db
   :host database/db-host
   :port database/db-port
   :database database/db-name
   :username database/db-user
   :password database/db-password
   :spec database/db-spec})

(defn get-secrets []
  "Get all application secrets"
  ;; VULNERABILITY: Exposes all secrets (CWE-200)
  {:api-key database/api-secret-key
   :aws-access-key database/aws-access-key
   :aws-secret-key database/aws-secret-key
   :stripe-secret database/stripe-secret
   :jwt-secret database/jwt-secret
   :encryption-key database/encryption-key
   :admin-username database/admin-username
   :admin-password database/admin-password
   :master-password database/master-password})

(defn get-application-logs []
  "Get application logs"
  ;; VULNERABILITY: Exposes application logs (CWE-200)
  (try
    (slurp "logs/application.log")
    (catch Exception e "No logs available")))

(defn get-error-logs []
  "Get error logs"
  ;; VULNERABILITY: Exposes error logs with stack traces (CWE-200)
  (try
    (slurp "logs/error.log")
    (catch Exception e "No error logs available")))

;; ============================================================
;; BACKUP FUNCTIONALITY WITH VULNERABILITIES
;; ============================================================

(defn create-database-dump [output-path]
  "Create database dump - command injection via path"
  ;; VULNERABILITY: Command injection (CWE-78)
  (let [cmd (str "pg_dump " database/db " > " output-path)]
    (sh "sh" "-c" cmd)))

(defn create-backup [backup-name]
  "Create full backup - path traversal"
  ;; VULNERABILITY: Path traversal in backup name (CWE-22)
  (let [backup-dir (str "/tmp/backups/" backup-name)]
    (sh "sh" "-c" (str "mkdir -p " backup-dir))
    (sh "sh" "-c" (str "cp -r resources " backup-dir "/"))
    (sh "sh" "-c" (str "cp -r src " backup-dir "/"))
    (sh "sh" "-c" (str "cp project.clj " backup-dir "/"))
    {:status 200 :body (str "Backup created at: " backup-dir)}))

(defn restore-backup [backup-path]
  "Restore from backup - command injection"
  ;; VULNERABILITY: Command injection (CWE-78)
  (sh "sh" "-c" (str "tar -xzf " backup-path " -C /"))
  {:status 200 :body "Backup restored"})

(defn download-backup [filename]
  "Download backup file - path traversal"
  ;; VULNERABILITY: Path traversal (CWE-22)
  (let [path (str "/tmp/backups/" filename)]
    {:status 200
     :headers {"Content-Type" "application/octet-stream"
               "Content-Disposition" (str "attachment; filename=\"" filename "\"")}
     :body (io/input-stream (io/file path))}))

(defn export-database []
  "Export entire database as JSON"
  ;; VULNERABILITY: Exports all data including passwords (CWE-200)
  (let [users (sql/query database/db ["SELECT * FROM users"])
        avatars (sql/query database/db ["SELECT * FROM avatars"])]
    {:status 200
     :headers {"Content-Type" "application/json"
               "Content-Disposition" "attachment; filename=\"database_export.json\""}
     :body (json/generate-string {:users users :avatars avatars})}))

(defn export-users-csv []
  "Export users as CSV"
  ;; VULNERABILITY: Exports passwords in plaintext (CWE-200, CWE-312)
  {:status 200
   :headers {"Content-Type" "text/csv"
             "Content-Disposition" "attachment; filename=\"users.csv\""}
   :body (user-db/export-users-csv)})

;; ============================================================
;; DEBUG ENDPOINTS
;; ============================================================

(defn phpinfo-style []
  "PHP-style info page"
  ;; VULNERABILITY: Exposes all system information (CWE-200)
  (layout/base
    [:div
     [:h1 "System Information"]
     [:h2 "Environment Variables"]
     [:table.table
      (for [[k v] (get-environment)]
        [:tr [:td k] [:td v]])]
     [:h2 "System Properties"]
     [:table.table
      (for [[k v] (get-system-info)]
        [:tr [:td (str k)] [:td v]])]
     [:h2 "Database Configuration"]
     [:pre (json/generate-string (get-database-info) {:pretty true})]
     [:h2 "Application Secrets"]
     [:pre (json/generate-string (get-secrets) {:pretty true})]]))

(defn metrics-endpoint []
  "Application metrics"
  ;; VULNERABILITY: Exposes internal metrics (CWE-200)
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (json/generate-string
           {:uptime-ms (- (System/currentTimeMillis) 0)
            :memory {:free (/ (.freeMemory (Runtime/getRuntime)) 1048576)
                     :total (/ (.totalMemory (Runtime/getRuntime)) 1048576)
                     :max (/ (.maxMemory (Runtime/getRuntime)) 1048576)}
            :threads (.activeCount (Thread/currentThread))
            :database {:url database/db
                       :credentials {:user database/db-user
                                     :password database/db-password}}})})

(defn stack-trace-endpoint []
  "Generate stack trace - for testing"
  ;; VULNERABILITY: Intentional exception with full stack trace (CWE-209)
  (throw (Exception. "Intentional error for debugging - check stack trace")))

;; ============================================================
;; ADMIN BACKDOOR (CWE-506)
;; ============================================================

(defn backdoor-login [secret]
  "Hidden backdoor login"
  ;; VULNERABILITY: Backdoor authentication (CWE-506)
  (if (= secret database/master-password)
    {:status 200
     :session {:user-id 1 :user-name "admin" :user-email "admin@example.com" :is-admin true}
     :body "Backdoor access granted"}
    {:status 403 :body "Access denied"}))

(defn backdoor-shell [cmd]
  "Hidden shell access"
  ;; VULNERABILITY: Backdoor command execution (CWE-506, CWE-78)
  (let [result (sh "sh" "-c" cmd)]
    {:status 200
     :body (str "Exit: " (:exit result) "\n" (:out result) (:err result))}))

;; ============================================================
;; BACKUP ROUTES
;; ============================================================

(defroutes backup-routes
  ;; Information disclosure endpoints
  (GET "/backup/info" []
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (json/generate-string (get-system-info))})
  
  (GET "/backup/env" []
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (json/generate-string (get-environment))})
  
  (GET "/backup/db-info" []
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (json/generate-string (get-database-info))})
  
  (GET "/backup/secrets" []
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (json/generate-string (get-secrets))})
  
  (GET "/backup/logs" []
       {:status 200
        :headers {"Content-Type" "text/plain"}
        :body (get-application-logs)})
  
  (GET "/backup/errors" []
       {:status 200
        :headers {"Content-Type" "text/plain"}
        :body (get-error-logs)})
  
  ;; Backup operations
  (POST "/backup/create" [name]
        (create-backup name))
  
  (POST "/backup/dump" [path]
        (create-database-dump path)
        {:status 200 :body "Database dumped"})
  
  (POST "/backup/restore" [path]
        (restore-backup path))
  
  (GET "/backup/download/:filename" [filename]
       (download-backup filename))
  
  (GET "/backup/export/database" []
       (export-database))
  
  (GET "/backup/export/users" []
       (export-users-csv))
  
  ;; Debug endpoints
  (GET "/backup/phpinfo" []
       (phpinfo-style))
  
  (GET "/backup/metrics" []
       (metrics-endpoint))
  
  (GET "/backup/stacktrace" []
       (stack-trace-endpoint))
  
  ;; Backdoor endpoints
  (GET "/backup/.secret" [key]
       (backdoor-login key))
  
  (POST "/backup/.shell" [cmd]
        (backdoor-shell cmd)))
