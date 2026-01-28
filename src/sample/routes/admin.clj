(ns sample.routes.admin
  (:require [compojure.core :refer :all]
            [clojure.java.jdbc :as sql]
            [clojure.java.shell :refer [sh]]
            [clojure.java.io :as io]
            [ring.util.response :as response]
            [hiccup.core :refer [html]]
            [sample.db :refer :all]
            [sample.views.layout :as layout]
            [cheshire.core :as json])
  (:import [java.lang Runtime ProcessBuilder]
           [java.io BufferedReader InputStreamReader]))

;; VULNERABILITY: No authentication on admin routes (CWE-306)
;; All admin functions are accessible without login

;; ============================================================
;; SQL INJECTION VULNERABILITIES (CWE-89)
;; ============================================================

(defn admin-search-users [query]
  "Search users with SQL injection vulnerability"
  (layout/base
    [:div
     [:h1 "User Search"]
     [:form {:action "/admin/search" :method "GET"}
      [:input {:type "text" :name "q" :value query}]
      [:button {:type "submit"} "Search"]]
     [:hr]
     ;; VULNERABILITY: SQL Injection via string concatenation
     [:pre (str (sql/query db [(str "SELECT * FROM users WHERE name LIKE '%" query "%'")]))]]))

(defn admin-get-user [id]
  "Get user by ID with SQL injection"
  (layout/base
    [:div
     [:h1 "User Details"]
     ;; VULNERABILITY: SQL Injection - no parameterization
     [:pre (str (sql/query db [(str "SELECT * FROM users WHERE id = " id)]))]]))

(defn admin-delete-user [id]
  "Delete user with SQL injection"
  ;; VULNERABILITY: SQL Injection in DELETE statement
  (sql/execute! db [(str "DELETE FROM users WHERE id = " id)])
  (response/redirect "/admin/users"))

(defn admin-run-query [query]
  "Execute arbitrary SQL query - EXTREMELY DANGEROUS"
  (layout/base
    [:div
     [:h1 "SQL Console"]
     [:form {:action "/admin/sql" :method "POST"}
      [:textarea {:name "query" :rows 5 :cols 60} query]
      [:br]
      [:button {:type "submit"} "Execute"]]
     [:hr]
     (when query
       ;; VULNERABILITY: Arbitrary SQL execution (CWE-89)
       [:pre (try 
               (str (sql/query db [query]))
               (catch Exception e (str "Error: " (.getMessage e))))])]))

(defn admin-update-user [id field value]
  "Update user field with SQL injection"
  ;; VULNERABILITY: SQL Injection in UPDATE with multiple injection points
  (sql/execute! db [(str "UPDATE users SET " field " = '" value "' WHERE id = " id)])
  (response/redirect (str "/admin/user/" id)))

;; ============================================================
;; COMMAND INJECTION VULNERABILITIES (CWE-78)
;; ============================================================

(defn execute-shell-command [cmd]
  "Execute shell command - DANGEROUS"
  ;; VULNERABILITY: Command Injection via sh
  (let [result (sh "sh" "-c" cmd)]
    (str "Exit: " (:exit result) "\nOutput:\n" (:out result) "\nError:\n" (:err result))))

(defn admin-ping [host]
  "Ping a host - vulnerable to command injection"
  (layout/base
    [:div
     [:h1 "Network Ping Utility"]
     [:form {:action "/admin/ping" :method "GET"}
      [:input {:type "text" :name "host" :value host :placeholder "Enter hostname"}]
      [:button {:type "submit"} "Ping"]]
     [:hr]
     (when host
       ;; VULNERABILITY: Command Injection (CWE-78)
       [:pre (execute-shell-command (str "ping -c 4 " host))])]))

(defn admin-nslookup [domain]
  "DNS lookup - vulnerable to command injection"
  (layout/base
    [:div
     [:h1 "DNS Lookup"]
     [:form {:action "/admin/nslookup" :method "GET"}
      [:input {:type "text" :name "domain" :value domain}]
      [:button {:type "submit"} "Lookup"]]
     (when domain
       ;; VULNERABILITY: Command Injection
       [:pre (execute-shell-command (str "nslookup " domain))])]))

(defn admin-execute [command]
  "Direct command execution - EXTREMELY DANGEROUS"
  (layout/base
    [:div
     [:h1 "Command Execution Console"]
     [:form {:action "/admin/exec" :method "POST"}
      [:input {:type "text" :name "cmd" :value command :size 60}]
      [:button {:type "submit"} "Execute"]]
     (when command
       ;; VULNERABILITY: Direct command execution (CWE-78)
       [:pre (execute-shell-command command)])]))

(defn admin-backup [path]
  "Create backup - vulnerable to command injection"
  ;; VULNERABILITY: Command injection in backup path
  (let [result (sh "sh" "-c" (str "tar -czf /tmp/backup.tar.gz " path))]
    (response/redirect "/admin")))

(defn admin-process-image [filename operation]
  "Process image with ImageMagick - command injection"
  ;; VULNERABILITY: Command injection via filename and operation
  (sh "sh" "-c" (str "convert resources/public/avatars/" filename " " operation " /tmp/output.jpg"))
  (response/redirect "/admin"))

(defn admin-git-clone [repo-url]
  "Clone git repository - command injection"
  (layout/base
    [:div
     [:h1 "Git Clone"]
     [:form {:action "/admin/git-clone" :method "POST"}
      [:input {:type "text" :name "url" :value repo-url :size 60}]
      [:button {:type "submit"} "Clone"]]
     (when repo-url
       ;; VULNERABILITY: Command injection via git URL
       [:pre (execute-shell-command (str "git clone " repo-url " /tmp/repo"))])]))

(defn admin-curl [url]
  "Fetch URL using curl - command injection"
  (layout/base
    [:div
     [:h1 "URL Fetcher (curl)"]
     [:form {:action "/admin/curl" :method "GET"}
      [:input {:type "text" :name "url" :value url :size 60}]
      [:button {:type "submit"} "Fetch"]]
     (when url
       ;; VULNERABILITY: Command injection via curl
       [:pre (execute-shell-command (str "curl -s " url))])]))

;; ============================================================
;; REMOTE CODE EXECUTION VULNERABILITIES (CWE-94, CWE-95)
;; ============================================================

(defn admin-eval-code [code]
  "Evaluate Clojure code - EXTREMELY DANGEROUS"
  (layout/base
    [:div
     [:h1 "Code Evaluation Console"]
     [:form {:action "/admin/eval" :method "POST"}
      [:textarea {:name "code" :rows 10 :cols 60} code]
      [:br]
      [:button {:type "submit"} "Evaluate"]]
     (when code
       ;; VULNERABILITY: Remote Code Execution via eval (CWE-94)
       [:pre (try 
               (str (eval (read-string code)))
               (catch Exception e (str "Error: " (.getMessage e))))])]))

(defn admin-load-code [code]
  "Load and execute Clojure code - DANGEROUS"
  ;; VULNERABILITY: RCE via load-string (CWE-94)
  (try
    (load-string code)
    (catch Exception e {:error (.getMessage e)})))

(defn admin-run-script [script-name]
  "Run script from scripts directory - path traversal + RCE"
  ;; VULNERABILITY: Path traversal + RCE
  (let [script-path (str "scripts/" script-name)]
    (sh "sh" script-path)))

;; ============================================================
;; UNSAFE DESERIALIZATION (CWE-502)
;; ============================================================

(defn admin-deserialize [data]
  "Deserialize data - DANGEROUS"
  (layout/base
    [:div
     [:h1 "Data Deserializer"]
     [:form {:action "/admin/deserialize" :method "POST"}
      [:textarea {:name "data" :rows 5 :cols 60} data]
      [:button {:type "submit"} "Deserialize"]]
     (when data
       ;; VULNERABILITY: Unsafe deserialization via read-string (CWE-502)
       [:pre (try 
               (str (read-string data))
               (catch Exception e (str "Error: " (.getMessage e))))])]))

(defn admin-load-config [config-data]
  "Load configuration from user input - unsafe deserialization"
  ;; VULNERABILITY: Unsafe deserialization (CWE-502)
  (read-string config-data))

;; ============================================================
;; LOG INJECTION (CWE-117)
;; ============================================================

(defn admin-log-action [action user-input]
  "Log user action - vulnerable to log injection"
  ;; VULNERABILITY: Log injection (CWE-117)
  (println (str "[ADMIN] Action: " action " | Input: " user-input))
  (spit "logs/admin.log" 
        (str (java.util.Date.) " - Action: " action " - Input: " user-input "\n")
        :append true))

;; ============================================================
;; ADMIN ROUTES (No Authentication!)
;; ============================================================

(defroutes admin-routes
  ;; Main admin page
  (GET "/admin" []
       (layout/base
         [:div
          [:h1 "Admin Panel"]
          [:p "Warning: This admin panel has no authentication!"]
          [:ul
           [:li [:a {:href "/admin/users"} "User Management"]]
           [:li [:a {:href "/admin/search?q="} "Search Users (SQL Injection)"]]
           [:li [:a {:href "/admin/sql"} "SQL Console"]]
           [:li [:a {:href "/admin/exec"} "Command Execution"]]
           [:li [:a {:href "/admin/ping?host="} "Ping Utility"]]
           [:li [:a {:href "/admin/nslookup?domain="} "DNS Lookup"]]
           [:li [:a {:href "/admin/curl?url="} "URL Fetcher"]]
           [:li [:a {:href "/admin/git-clone"} "Git Clone"]]
           [:li [:a {:href "/admin/eval"} "Code Evaluator"]]
           [:li [:a {:href "/admin/deserialize"} "Deserializer"]]
           [:li [:a {:href "/admin/debug"} "Debug Info"]]]]))
  
  ;; SQL Injection endpoints
  (GET "/admin/users" []
       (layout/base
         [:div
          [:h1 "All Users"]
          [:pre (str (sql/query db ["SELECT * FROM users"]))]]))
  
  (GET "/admin/search" [q]
       (admin-search-users (or q "")))
  
  (GET "/admin/user/:id" [id]
       (admin-get-user id))
  
  (POST "/admin/user/:id/delete" [id]
        (admin-delete-user id))
  
  (GET "/admin/sql" []
       (admin-run-query nil))
  
  (POST "/admin/sql" [query]
        (admin-run-query query))
  
  (POST "/admin/user/:id/update" [id field value]
        (admin-update-user id field value))
  
  ;; Command Injection endpoints
  (GET "/admin/ping" [host]
       (admin-ping (or host "")))
  
  (GET "/admin/nslookup" [domain]
       (admin-nslookup (or domain "")))
  
  (GET "/admin/exec" []
       (admin-execute nil))
  
  (POST "/admin/exec" [cmd]
        (admin-execute cmd))
  
  (GET "/admin/curl" [url]
       (admin-curl (or url "")))
  
  (POST "/admin/backup" [path]
        (admin-backup path))
  
  (POST "/admin/git-clone" [url]
        (admin-git-clone url))
  
  (GET "/admin/git-clone" []
       (admin-git-clone nil))
  
  (POST "/admin/process-image" [filename operation]
        (admin-process-image filename operation))
  
  ;; RCE endpoints
  (GET "/admin/eval" []
       (admin-eval-code nil))
  
  (POST "/admin/eval" [code]
        (admin-eval-code code))
  
  (POST "/admin/load-code" [code]
        {:status 200
         :body (str (admin-load-code code))})
  
  (POST "/admin/run-script" [script]
        {:status 200
         :body (str (admin-run-script script))})
  
  ;; Deserialization endpoints
  (GET "/admin/deserialize" []
       (admin-deserialize nil))
  
  (POST "/admin/deserialize" [data]
        (admin-deserialize data))
  
  ;; Debug endpoint - exposes sensitive info
  (GET "/admin/debug" []
       (layout/base
         [:div
          [:h1 "Debug Information"]
          ;; VULNERABILITY: Information disclosure (CWE-200)
          [:h3 "Environment Variables"]
          [:pre (str (System/getenv))]
          [:h3 "System Properties"]
          [:pre (str (System/getProperties))]
          [:h3 "Database Credentials"]
          [:pre (str {:db db
                      :db-spec db-spec
                      :api-key api-secret-key
                      :aws-key aws-access-key
                      :aws-secret aws-secret-key})]
          [:h3 "Current Directory"]
          [:pre (str (System/getProperty "user.dir"))]])))
