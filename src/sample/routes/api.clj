(ns sample.routes.api
  (:require [compojure.core :refer :all]
            [clojure.java.io :as io]
            [clojure.data.xml :as xml]
            [clj-http.client :as http]
            [cheshire.core :as json]
            [clj-yaml.core :as yaml]
            [ring.util.response :as response]
            [sample.db :refer :all]
            [sample.crypt :as crypt]
            [sample.models.user :as user-db])
  (:import [java.io StringReader ByteArrayInputStream]
           [javax.xml.parsers DocumentBuilderFactory SAXParserFactory]
           [org.xml.sax InputSource]
           [java.net URL URLConnection HttpURLConnection]
           [java.util Base64]))

;; ============================================================
;; SERVER-SIDE REQUEST FORGERY (SSRF) (CWE-918)
;; ============================================================

(defn fetch-url [url]
  "Fetch content from URL - vulnerable to SSRF"
  ;; VULNERABILITY: SSRF - no validation of URL (CWE-918)
  (try
    (slurp url)
    (catch Exception e
      (str "Error fetching URL: " (.getMessage e)))))

(defn fetch-url-advanced [url]
  "Fetch URL using clj-http - SSRF vulnerable"
  ;; VULNERABILITY: SSRF with full HTTP capabilities
  (try
    (:body (http/get url {:insecure? true
                          :socket-timeout 10000
                          :connection-timeout 10000}))
    (catch Exception e
      (str "Error: " (.getMessage e)))))

(defn api-proxy [target-url]
  "Proxy requests to internal services - SSRF"
  ;; VULNERABILITY: SSRF - can access internal services
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (fetch-url-advanced target-url)})

(defn api-webhook [webhook-url data]
  "Send webhook to URL - SSRF"
  ;; VULNERABILITY: SSRF via POST request
  (try
    (http/post webhook-url
               {:body (json/generate-string data)
                :headers {"Content-Type" "application/json"}
                :insecure? true})
    (catch Exception e
      {:error (.getMessage e)})))

(defn api-import-from-url [url]
  "Import data from URL - SSRF"
  ;; VULNERABILITY: SSRF - fetches and processes external data
  (let [content (fetch-url url)]
    (try
      (json/parse-string content true)
      (catch Exception e
        {:error "Invalid JSON" :raw content}))))

(defn api-check-url [url]
  "Check if URL is reachable - SSRF for port scanning"
  ;; VULNERABILITY: SSRF - can be used for internal port scanning
  (try
    (let [connection (.openConnection (URL. url))]
      (.setConnectTimeout connection 3000)
      (.connect connection)
      {:reachable true :url url})
    (catch Exception e
      {:reachable false :url url :error (.getMessage e)})))

(defn api-fetch-avatar [avatar-url]
  "Fetch avatar from external URL - SSRF"
  ;; VULNERABILITY: SSRF - fetches images from arbitrary URLs
  (try
    (let [response (http/get avatar-url {:as :byte-array :insecure? true})]
      {:status 200
       :headers {"Content-Type" (get-in response [:headers "Content-Type"] "image/png")}
       :body (:body response)})
    (catch Exception e
      {:status 500 :body (str "Error: " (.getMessage e))})))

;; ============================================================
;; XML EXTERNAL ENTITY (XXE) INJECTION (CWE-611)
;; ============================================================

(defn parse-xml-unsafe [xml-string]
  "Parse XML with XXE vulnerability"
  ;; VULNERABILITY: XXE - external entities enabled by default (CWE-611)
  (let [factory (DocumentBuilderFactory/newInstance)]
    ;; VULNERABILITY: Not disabling external entities
    ;; Missing: (.setFeature factory "http://apache.org/xml/features/disallow-doctype-decl" true)
    (let [builder (.newDocumentBuilder factory)
          input-source (InputSource. (StringReader. xml-string))]
      (.parse builder input-source))))

(defn api-parse-xml [xml-content]
  "Parse XML from user input - XXE vulnerable"
  ;; VULNERABILITY: XXE injection
  (try
    (let [doc (parse-xml-unsafe xml-content)]
      {:status 200
       :body (str "Parsed XML document: " (.getDocumentElement doc))})
    (catch Exception e
      {:status 400
       :body (str "XML parsing error: " (.getMessage e))})))

(defn api-import-xml [xml-data]
  "Import users from XML - XXE vulnerable"
  ;; VULNERABILITY: XXE in data import
  (try
    (let [parsed (xml/parse-str xml-data)]
      {:status 200
       :headers {"Content-Type" "application/json"}
       :body (json/generate-string {:parsed parsed})})
    (catch Exception e
      {:status 400
       :body (json/generate-string {:error (.getMessage e)})})))

(defn api-svg-upload [svg-content]
  "Process SVG file - XXE via SVG"
  ;; VULNERABILITY: XXE via SVG (CWE-611)
  (let [parsed (parse-xml-unsafe svg-content)]
    (spit "resources/public/uploads/image.svg" svg-content)
    {:status 200 :body "SVG uploaded"}))

;; ============================================================
;; UNSAFE DESERIALIZATION (CWE-502)
;; ============================================================

(defn api-deserialize-clojure [data]
  "Deserialize Clojure data - DANGEROUS"
  ;; VULNERABILITY: Unsafe deserialization via read-string (CWE-502)
  (try
    {:status 200
     :body (json/generate-string (read-string data))}
    (catch Exception e
      {:status 400
       :body (json/generate-string {:error (.getMessage e)})})))

(defn api-deserialize-yaml [yaml-data]
  "Deserialize YAML data - potentially dangerous"
  ;; VULNERABILITY: YAML deserialization (CWE-502)
  (try
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (json/generate-string (yaml/parse-string yaml-data))}
    (catch Exception e
      {:status 400
       :body (json/generate-string {:error (.getMessage e)})})))

(defn api-eval-template [template data]
  "Evaluate template with data - code injection"
  ;; VULNERABILITY: Template injection via eval (CWE-94)
  (try
    (let [data-map (read-string data)
          result (eval (read-string template))]
      {:status 200 :body (str result)})
    (catch Exception e
      {:status 400 :body (str "Error: " (.getMessage e))})))

;; ============================================================
;; SENSITIVE DATA EXPOSURE (CWE-200, CWE-312)
;; ============================================================

(defn api-get-users []
  "Get all users - exposes sensitive data"
  ;; VULNERABILITY: Exposes password hashes and all user data (CWE-200)
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (json/generate-string (clojure.java.jdbc/query db ["SELECT * FROM users"]))})

(defn api-get-user-full [id]
  "Get full user details including password"
  ;; VULNERABILITY: Exposes encrypted password (CWE-200)
  (let [user (user-db/get-user-by-id (Integer/parseInt id))]
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (json/generate-string user)}))

(defn api-debug []
  "Debug endpoint exposing system info"
  ;; VULNERABILITY: Information disclosure (CWE-200)
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (json/generate-string 
           {:environment (into {} (System/getenv))
            :system-properties (into {} (System/getProperties))
            :database-url db
            :api-key api-secret-key
            :aws-credentials {:access-key aws-access-key
                              :secret-key aws-secret-key}
            :stripe-key stripe-secret
            :jwt-secret jwt-secret})})

(defn api-logs []
  "Fetch application logs - information disclosure"
  ;; VULNERABILITY: Log file exposure (CWE-200)
  (try
    {:status 200
     :body (slurp "logs/application.log")}
    (catch Exception e
      {:status 200
       :body "No logs available"})))

(defn api-config []
  "Expose application configuration"
  ;; VULNERABILITY: Configuration exposure (CWE-200)
  {:status 200
   :headers {"Content-Type" "application/json"}
   :body (json/generate-string
           {:database {:host db-host
                       :port db-port
                       :name db-name
                       :user db-user
                       :password db-password}
            :secrets {:api-key api-secret-key
                      :encryption-key encryption-key
                      :admin-password admin-password
                      :master-password master-password}})})

;; ============================================================
;; INSECURE DIRECT OBJECT REFERENCES (IDOR) (CWE-639)
;; ============================================================

(defn api-get-user-data [user-id]
  "Get user data without authorization check"
  ;; VULNERABILITY: IDOR - no authorization (CWE-639)
  (let [user (user-db/get-user-by-id (Integer/parseInt user-id))]
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (json/generate-string user)}))

(defn api-update-user-data [user-id data]
  "Update user data without authorization"
  ;; VULNERABILITY: IDOR - can update any user (CWE-639)
  (let [parsed-data (json/parse-string data true)]
    (user-db/update-user (Integer/parseInt user-id) parsed-data)
    {:status 200 :body "User updated"}))

(defn api-delete-user [user-id]
  "Delete user without authorization"
  ;; VULNERABILITY: IDOR - can delete any user (CWE-639)
  (user-db/delete-user (Integer/parseInt user-id))
  {:status 200 :body "User deleted"})

(defn api-get-user-password-hash [user-id]
  "Get user password hash - extremely dangerous"
  ;; VULNERABILITY: Exposing password hash (CWE-200, CWE-639)
  (let [user (user-db/get-user-by-id (Integer/parseInt user-id))]
    {:status 200
     :body (:encrypted_password user)}))

;; ============================================================
;; BROKEN AUTHENTICATION (CWE-287, CWE-306)
;; ============================================================

(defn api-reset-password [email new-password]
  "Reset password without verification"
  ;; VULNERABILITY: Password reset without verification (CWE-640)
  (let [user (user-db/get-user-by-email email)]
    (when user
      (user-db/update-user (:id user) {:encrypted_password (crypt/weak-password-hash new-password)}))
    {:status 200 :body "Password reset"}))

(defn api-login-weak [email password]
  "Login with weak authentication"
  ;; VULNERABILITY: Using MD5 for password verification (CWE-328)
  (let [user (user-db/get-user-by-email email)]
    (if (and user (= (crypt/md5-hash password) (:encrypted_password user)))
      {:status 200 
       :body (json/generate-string {:token (crypt/generate-token-insecure)
                                    :user user})}
      {:status 401 :body "Invalid credentials"})))

(defn api-generate-token []
  "Generate authentication token - insecure"
  ;; VULNERABILITY: Weak token generation (CWE-330)
  {:status 200
   :body (json/generate-string {:token (crypt/generate-token-insecure)
                                :session-id (crypt/generate-session-token-weak)})})

;; ============================================================
;; API ROUTES
;; ============================================================

(defroutes api-routes
  ;; SSRF endpoints
  (GET "/api/fetch" [url]
       (response/response (fetch-url url)))
  
  (GET "/api/proxy" [url]
       (api-proxy url))
  
  (POST "/api/webhook" {body :body}
        (let [data (json/parse-string (slurp body) true)]
          (api-webhook (:url data) (:data data))))
  
  (GET "/api/import" [url]
       (response/response (json/generate-string (api-import-from-url url))))
  
  (GET "/api/check-url" [url]
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (json/generate-string (api-check-url url))})
  
  (GET "/api/fetch-avatar" [url]
       (api-fetch-avatar url))
  
  ;; XXE endpoints
  (POST "/api/parse-xml" {body :body}
        (api-parse-xml (slurp body)))
  
  (POST "/api/import-xml" {body :body}
        (api-import-xml (slurp body)))
  
  (POST "/api/upload-svg" {body :body}
        (api-svg-upload (slurp body)))
  
  ;; Deserialization endpoints
  (POST "/api/deserialize" [data]
        (api-deserialize-clojure data))
  
  (POST "/api/deserialize-yaml" {body :body}
        (api-deserialize-yaml (slurp body)))
  
  (POST "/api/eval-template" [template data]
        (api-eval-template template data))
  
  ;; Sensitive data exposure endpoints
  (GET "/api/users" []
       (api-get-users))
  
  (GET "/api/user/:id" [id]
       (api-get-user-full id))
  
  (GET "/api/user/:id/password" [id]
       (api-get-user-password-hash id))
  
  (GET "/api/debug" []
       (api-debug))
  
  (GET "/api/logs" []
       (api-logs))
  
  (GET "/api/config" []
       (api-config))
  
  ;; IDOR endpoints
  (GET "/api/data/:id" [id]
       (api-get-user-data id))
  
  (POST "/api/data/:id" [id data]
        (api-update-user-data id data))
  
  (DELETE "/api/data/:id" [id]
          (api-delete-user id))
  
  ;; Broken authentication
  (POST "/api/reset-password" [email password]
        (api-reset-password email password))
  
  (POST "/api/login" [email password]
        (api-login-weak email password))
  
  (GET "/api/token" []
       (api-generate-token)))
