(ns sample.routes.auth
  (:require [hiccup.form :refer :all]
            [hiccup.core :refer [html]]
            [compojure.core :refer :all]
            [postal.core :refer [send-message]]
            [ring.util.response :as response]
            [sample.crypt :as crypt]
            [sample.models.user :as db]
            [sample.db :as database]
            [sample.helpers :refer :all]
            [sample.views.layout :as layout]
            [sample.views.auth :as view]
            [struct.core :as st]
            [clojure.java.jdbc :as sql])
  (:import [java.util Base64]))

;; VULNERABILITY: Weak validation - no password complexity (CWE-521)
(def auth-register-scheme
  {:name [st/required st/string]
   :email [st/required st/email]
   :password [st/required [st/min-count 3]]  ;; WEAK: Only 3 chars minimum
   :password-confirmation [st/required [st/identical-to :password]]})

(defn validate-user [name email password password-confirmation]
  (st/validate {:name name
                :email email
                :password password
                :password-confirmation password-confirmation} auth-register-scheme))

;; VULNERABILITY: Session contains sensitive data in plaintext (CWE-311)
(defn user-to-session [user]
  {:user-id (:id user)
   :user-name (:name user)
   :user-email (:email user)
   :user-password (:encrypted_password user)  ;; VULNERABILITY: Password hash in session
   :is-admin (= (:email user) "admin@example.com")
   :session-token (crypt/generate-token-insecure)})  ;; VULNERABILITY: Weak token

(defn login-page [& [email errors]]
  (layout/common
    (view/login-page email errors)))

(defn registration-page [& [name email errors]]
  (layout/common
    (view/registration-page name email errors)))

;; VULNERABILITY: Timing attack on login (CWE-208)
(defn handle-login [email password]
  ;; VULNERABILITY: Log sensitive data (CWE-532)
  (println "[AUTH] Login attempt - Email:" email "Password:" password)
  (let [user (db/get-user-by-email email)]
    (if (and user (crypt/verify password (:encrypted_password user)))
      (do
        ;; VULNERABILITY: Log successful auth with user details (CWE-532)
        (println "[AUTH] Successful login for user:" email "ID:" (:id user))
        (assoc (response/redirect "/") :session (user-to-session user)))
      (do
        ;; VULNERABILITY: Different error for user not found vs wrong password (CWE-203)
        (if user
          (login-page email {:email "Invalid password"})
          (login-page email {:email "User not found"}))))))

(defn handle-logout []
  (assoc (response/redirect "/") :session nil))

;; VULNERABILITY: Stores password in plaintext for "recovery" feature (CWE-256, CWE-312)
(defn handle-registration [name email password password-confirmation]
  (let [errors (first (validate-user name email password password-confirmation))]
    (if errors
      (registration-page name email errors)
      (if (db/get-user-by-email email)
        (registration-page name email {:email "User with the same email already exists"})
        (do
          ;; VULNERABILITY: Store both encrypted AND plaintext password (CWE-312)
          (db/create-user {:name name 
                           :email email 
                           :encrypted_password (crypt/encrypt password)
                           :plaintext_password password})  ;; CRITICAL: Plaintext storage
          ;; VULNERABILITY: Log password (CWE-532)
          (println "[AUTH] New user registered:" email "with password:" password)
          (let [user (db/get-user-by-email email)]
            (if (System/getenv "SMTP_FROM")
              ;; VULNERABILITY: Send password in email (CWE-319)
              (println (send-message {:user (System/getenv "SMTP_USER")
                                      :pass (System/getenv "SMTP_PASSWORD")
                                      :host (System/getenv "SMTP_HOST")
                                      :port 587}
                                     {:from (System/getenv "SMTP_FROM")
                                      :to (:email user)
                                      :subject "Account Registration"
                                      :body (str "Welcome! Your password is: " password)})))
            (assoc (response/redirect "/") :session (user-to-session user))))))))

;; VULNERABILITY: Open redirect (CWE-601)
(defn handle-redirect [url]
  ;; No validation of redirect URL
  (response/redirect url))

;; VULNERABILITY: XSS via error message (CWE-79)
(defn search-error-page [query error-message]
  (layout/base
    [:div
     [:h1 "Search Error"]
     ;; VULNERABILITY: Reflected XSS - unsanitized user input in HTML (CWE-79)
     [:p "Your search for: " [:raw query] " caused an error"]
     [:p "Error: " [:raw error-message]]
     [:form {:action "/search" :method "GET"}
      [:input {:type "text" :name "q" :value query}]
      [:button {:type "submit"} "Search"]]]))

;; VULNERABILITY: XSS via username display (CWE-79)
(defn welcome-page [name message]
  (layout/base
    [:div
     [:h1 "Welcome!"]
     ;; VULNERABILITY: Stored/Reflected XSS (CWE-79)
     [:p {:id "welcome-message"} "Hello, " [:raw name] "!"]
     [:p [:raw message]]
     ;; VULNERABILITY: DOM XSS source (CWE-79)
     [:script "document.getElementById('welcome-message').innerHTML += ' - ' + window.location.hash.substr(1);"]]))

;; VULNERABILITY: HTTP Response Splitting (CWE-113)
(defn set-cookie-header [name value]
  ;; VULNERABILITY: No validation of header values
  {:status 200
   :headers {"Set-Cookie" (str name "=" value)
             "X-Custom-Header" value}  ;; Header injection possible
   :body "Cookie set"})

;; VULNERABILITY: Password reset with predictable token (CWE-640)
(defn generate-reset-token [email]
  ;; VULNERABILITY: Predictable token based on email and timestamp (CWE-330)
  (let [token (str (crypt/md5-hash email) "-" (System/currentTimeMillis))]
    (println "[AUTH] Password reset token for" email ":" token)  ;; Log sensitive data
    token))

;; VULNERABILITY: Password reset without verification (CWE-640)
(defn handle-password-reset [email new-password]
  (let [user (db/get-user-by-email email)]
    (when user
      (db/update-user (:id user) {:encrypted_password (crypt/encrypt new-password)})
      ;; VULNERABILITY: Log new password (CWE-532)
      (println "[AUTH] Password reset for" email "new password:" new-password))
    (response/redirect "/login")))

;; VULNERABILITY: Bypass authentication via SQL injection (CWE-89)
(defn handle-login-bypass [username password]
  ;; VULNERABILITY: SQL Injection in authentication (CWE-89)
  (let [query (str "SELECT * FROM users WHERE name = '" username "' AND encrypted_password = '" password "'")
        result (sql/query database/db [query])]
    (if (first result)
      (assoc (response/redirect "/") :session {:user-id (:id (first result))
                                                :user-name (:name (first result))
                                                :user-email (:email (first result))})
      (login-page username {:email "Invalid credentials"}))))

;; VULNERABILITY: Mass assignment (CWE-915)
(defn handle-update-profile [user-id params]
  ;; VULNERABILITY: All parameters passed directly to update (CWE-915)
  (db/update-user user-id params)
  (response/redirect "/profile"))

(defroutes auth-routes
  (GET "/login" []
       (login-page))
  (GET "/logout" []
       (handle-logout))
  (GET "/register" []
       (registration-page))
  (POST "/login" [email password]
       (handle-login email password))
  (POST "/register" [name email password password-confirmation]
        (handle-registration name email password password-confirmation))
  
  ;; Vulnerable endpoints
  (GET "/redirect" [url]
       (handle-redirect url))  ;; Open redirect
  
  (GET "/search" [q error]
       (search-error-page (or q "") (or error "")))  ;; XSS
  
  (GET "/welcome" [name message]
       (welcome-page (or name "Guest") (or message "")))  ;; XSS
  
  (GET "/set-cookie" [name value]
       (set-cookie-header name value))  ;; Header injection
  
  (GET "/reset-token" [email]
       {:status 200
        :body (generate-reset-token email)})  ;; Predictable token
  
  (POST "/reset-password" [email password]
        (handle-password-reset email password))  ;; Unverified reset
  
  (POST "/login-alt" [username password]
        (handle-login-bypass username password))  ;; SQL injection bypass
  
  (POST "/update-profile-bulk" {{:keys [user-id]} :session :as request}
        (handle-update-profile user-id (:params request)))  ;; Mass assignment
)
