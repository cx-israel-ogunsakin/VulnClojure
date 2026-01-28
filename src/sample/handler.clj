(ns sample.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [migratus.core :as migratus]
            [sample.routes.home :refer [home-routes]]
            [sample.routes.profile :refer [profile-routes]]
            [sample.routes.auth :refer [auth-routes]]
            [sample.routes.files :refer [files-routes]]
            [sample.routes.admin :refer [admin-routes]]
            [sample.routes.api :refer [api-routes]]
            [sample.routes.backup :refer [backup-routes]]
            [sample.views.layout :as layout]
            [sample.db :as database]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults api-defaults]]
            [ring.middleware.session :refer [wrap-session]]
            [ring.middleware.session.cookie :refer [cookie-store]])
  (:import [java.util Base64]))

;; VULNERABILITY: Hardcoded database credentials in config (CWE-798)
(def migratus-config
  {:store :database
   :migration-dir "migrations"
   :db (or (System/getenv "DATABASE_URL") "postgresql://admin:SuperSecretPassword123!@localhost:5432/sample")})

(defn init []
  ;; VULNERABILITY: Log database connection string with credentials (CWE-532)
  (println "[INIT] Connecting to database:" (:db migratus-config))
  (println "[INIT] Using credentials - User:" database/db-user "Password:" database/db-password)
  (migratus/migrate migratus-config))

;; VULNERABILITY: Verbose error page exposing stack traces (CWE-209)
(defn not-found []
  (layout/base
    [:center
     [:h1 "404. Page not found!"]
     [:p "Debug info:"]
     [:pre (str "Server time: " (java.util.Date.))]
     [:pre (str "Java version: " (System/getProperty "java.version"))]
     [:pre (str "OS: " (System/getProperty "os.name"))]
     [:pre (str "User dir: " (System/getProperty "user.dir"))]]))

;; VULNERABILITY: Detailed error handler exposing internals (CWE-209)
(defn error-handler [request exception]
  {:status 500
   :headers {"Content-Type" "text/html"}
   :body (str "<h1>Internal Server Error</h1>"
              "<h2>Exception:</h2>"
              "<pre>" (.getMessage exception) "</pre>"
              "<h2>Stack Trace:</h2>"
              "<pre>" (with-out-str (.printStackTrace exception)) "</pre>"
              "<h2>Request Details:</h2>"
              "<pre>" (pr-str request) "</pre>"
              "<h2>Environment:</h2>"
              "<pre>" (pr-str (System/getenv)) "</pre>")})

;; VULNERABILITY: Debug middleware that logs all requests with sensitive data (CWE-532)
(defn wrap-debug-logging [handler]
  (fn [request]
    ;; VULNERABILITY: Log all request data including passwords, tokens, etc.
    (println "[DEBUG] Request:" (:uri request))
    (println "[DEBUG] Method:" (:request-method request))
    (println "[DEBUG] Headers:" (:headers request))
    (println "[DEBUG] Params:" (:params request))
    (println "[DEBUG] Session:" (:session request))
    (println "[DEBUG] Body:" (when (:body request) (slurp (:body request))))
    (let [response (handler request)]
      ;; VULNERABILITY: Log response data
      (println "[DEBUG] Response status:" (:status response))
      (println "[DEBUG] Response headers:" (:headers response))
      response)))

;; VULNERABILITY: CORS middleware with wildcard origin (CWE-942)
(defn wrap-permissive-cors [handler]
  (fn [request]
    (let [response (handler request)]
      (-> response
          ;; VULNERABILITY: Allow all origins (CWE-942)
          (assoc-in [:headers "Access-Control-Allow-Origin"] "*")
          ;; VULNERABILITY: Allow credentials with wildcard origin
          (assoc-in [:headers "Access-Control-Allow-Credentials"] "true")
          (assoc-in [:headers "Access-Control-Allow-Methods"] "GET, POST, PUT, DELETE, OPTIONS")
          (assoc-in [:headers "Access-Control-Allow-Headers"] "*")))))

;; VULNERABILITY: Remove security headers (CWE-693)
(defn wrap-remove-security-headers [handler]
  (fn [request]
    (let [response (handler request)]
      (-> response
          ;; VULNERABILITY: Remove or weaken security headers
          (assoc-in [:headers "X-Frame-Options"] nil)  ;; Allows clickjacking
          (assoc-in [:headers "X-Content-Type-Options"] nil)
          (assoc-in [:headers "X-XSS-Protection"] "0")  ;; Disable XSS filter
          (assoc-in [:headers "Content-Security-Policy"] nil)))))

;; VULNERABILITY: Insecure session configuration (CWE-614)
(def insecure-session-config
  {:store (cookie-store {:key "1234567890abcdef"})  ;; VULNERABILITY: Weak/hardcoded key (CWE-321)
   :cookie-name "session"
   :cookie-attrs {:http-only false  ;; VULNERABILITY: Accessible via JavaScript (CWE-1004)
                  :secure false      ;; VULNERABILITY: Sent over HTTP (CWE-614)
                  :same-site :none   ;; VULNERABILITY: Allows cross-site requests
                  :max-age 86400000}})  ;; VULNERABILITY: Very long session (CWE-613)

(defroutes static-routes
  (route/resources "/")
  (route/not-found (not-found)))

;; Debug endpoint that exposes sensitive information
(defroutes debug-routes
  (GET "/debug/info" []
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (str {:environment (into {} (System/getenv))
                    :properties (into {} (System/getProperties))
                    :database database/db
                    :api-key database/api-secret-key
                    :aws-access-key database/aws-access-key
                    :aws-secret-key database/aws-secret-key
                    :stripe-key database/stripe-secret
                    :jwt-secret database/jwt-secret
                    :admin-password database/admin-password})})
  
  (GET "/debug/headers" request
       {:status 200
        :headers {"Content-Type" "text/plain"}
        :body (str (:headers request))})
  
  (GET "/debug/session" request
       {:status 200
        :headers {"Content-Type" "text/plain"}
        :body (str (:session request))})
  
  (GET "/debug/request" request
       {:status 200
        :headers {"Content-Type" "text/plain"}
        :body (pr-str request)})
  
  (GET "/health" []
       {:status 200
        :headers {"Content-Type" "application/json"}
        :body (str {:status "ok"
                    :database database/db
                    :version "1.0.0"
                    :server-time (str (java.util.Date.))})})
  
  ;; VULNERABILITY: phpinfo-style endpoint (CWE-200)
  (GET "/server-info" []
       {:status 200
        :headers {"Content-Type" "text/html"}
        :body (str "<html><head><title>Server Info</title></head><body>"
                   "<h1>Server Information</h1>"
                   "<h2>Environment Variables</h2><pre>" (System/getenv) "</pre>"
                   "<h2>System Properties</h2><pre>" (System/getProperties) "</pre>"
                   "<h2>Database Config</h2><pre>" database/db-spec "</pre>"
                   "<h2>Secrets</h2><pre>"
                   "API Key: " database/api-secret-key "<br>"
                   "AWS Access: " database/aws-access-key "<br>"
                   "AWS Secret: " database/aws-secret-key "<br>"
                   "Stripe: " database/stripe-secret "<br>"
                   "JWT: " database/jwt-secret "<br>"
                   "Admin Password: " database/admin-password
                   "</pre></body></html>")}))

(def app-routes
  (routes
    auth-routes
    home-routes
    profile-routes
    files-routes
    admin-routes      ;; Admin routes with no authentication
    api-routes        ;; API routes with vulnerabilities
    backup-routes     ;; Backup routes with information disclosure
    debug-routes      ;; Debug routes exposing sensitive info
    static-routes))

;; VULNERABILITY: Insecure defaults - CSRF disabled (CWE-352)
(def insecure-defaults
  (-> site-defaults
      (assoc-in [:security :anti-forgery] false)  ;; VULNERABILITY: CSRF disabled
      (assoc-in [:security :frame-options] nil)   ;; VULNERABILITY: Clickjacking enabled
      (assoc-in [:security :content-type-options] nil)
      (assoc-in [:security :xss-protection] false)
      (assoc-in [:session :cookie-attrs :http-only] false)
      (assoc-in [:session :cookie-attrs :secure] false)))

(def app
  (-> app-routes
      (wrap-defaults insecure-defaults)
      wrap-permissive-cors
      wrap-remove-security-headers
      wrap-debug-logging))  ;; Logs all sensitive data
