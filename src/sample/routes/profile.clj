(ns sample.routes.profile
  (:require [compojure.core :refer :all]
            [clojure.java.jdbc :as sql]
            [sample.crypt :as crypt]
            [ring.util.response :as response]
            [clojure.java.io :as io]
            [clojure.java.shell :refer [sh]]
            [sample.helpers :refer :all]
            [sample.models.user :as db]
            [sample.db :as database]
            [sample.models.avatar :as avatar-db]
            [sample.views.layout :as layout]
            [sample.views.profile :as view]
            [cheshire.core :as json])
  (:import [java.io File]))

(defn wrap-current-user-id [handler]
  (fn [request]
    (let [user-id (:user-id (:session request))]
      (handler (assoc request :user-id user-id)))))

(defn remove-user [id]
  (if (db/delete-user id)
    (assoc (response/redirect "/") :session nil)))

(defn profile-page [user]
  (layout/common (view/profile-page user) user))

(defn profile-edit-page [user]
  (layout/common (view/profile-edit-page user) user))

(defn password-page [user]
  (layout/common (view/password-page user) user))

;; VULNERABILITY: File upload without validation (CWE-434)
(defn update-profile [name user file]
  (do
    (db/update-user (:id user) {:name name})
    (when (seq (:filename file))
      ;; VULNERABILITY: No file type validation
      ;; VULNERABILITY: No file size limit
      ;; VULNERABILITY: Path traversal via filename (CWE-22)
      (avatar-db/create-avatar {:user_id (:id user)
                                :name (:filename file)})
      (io/copy (:tempfile file) (io/file "resources" "public" "avatars" (:filename file))))
    (response/redirect "/profile")))

;; VULNERABILITY: Weak password change - no rate limiting (CWE-307)
(defn update-password [current-password new-password confirm-password user]
  ;; VULNERABILITY: Log password change with passwords (CWE-532)
  (println "[PROFILE] Password change attempt for user:" (:id user) 
           "Current:" current-password "New:" new-password)
  (if (crypt/verify current-password (:encrypted_password user))
    (if (= new-password confirm-password)
      (do
        (db/update-user (:id user) {:encrypted_password (crypt/encrypt new-password)})
        (assoc (response/redirect "/login") :session nil))
      (layout/common
        (view/password-page user {:confirm-password "Confirmation password does not match"}) user))
    (layout/common
      (view/password-page user {:current-password "Incorrect current password"}) user)))

;; ============================================================
;; INSECURE DIRECT OBJECT REFERENCE (IDOR) (CWE-639)
;; ============================================================

(defn get-user-profile-idor [user-id]
  "Get any user's profile without authorization"
  ;; VULNERABILITY: IDOR - no authorization check (CWE-639)
  (let [user (get-user (Integer/parseInt user-id))]
    (if user
      (layout/base
        [:div
         [:h1 "User Profile"]
         [:p "ID: " (:id user)]
         [:p "Name: " (:name user)]
         [:p "Email: " (:email user)]
         [:p "Password Hash: " (:encrypted_password user)]  ;; VULNERABILITY: Exposes hash
         [:p "Created: " (:timestamp user)]])
      {:status 404 :body "User not found"})))

(defn update-user-idor [user-id params]
  "Update any user without authorization"
  ;; VULNERABILITY: IDOR - can update any user (CWE-639)
  (db/update-user (Integer/parseInt user-id) params)
  (response/redirect (str "/profile/view/" user-id)))

(defn delete-user-idor [user-id]
  "Delete any user without authorization"
  ;; VULNERABILITY: IDOR - can delete any user (CWE-639)
  (db/delete-user (Integer/parseInt user-id))
  {:status 200 :body "User deleted"})

(defn get-user-avatar-idor [user-id]
  "Get any user's avatar without authorization"
  ;; VULNERABILITY: IDOR - access any user's avatar (CWE-639)
  (if-let [avatar (avatar-db/get-avatar-by-user (Integer/parseInt user-id))]
    {:status 200
     :headers {"Content-Type" "application/json"}
     :body (json/generate-string avatar)}
    {:status 404 :body "Avatar not found"}))

(defn change-user-password-idor [user-id new-password]
  "Change any user's password without verification"
  ;; VULNERABILITY: IDOR + No current password required (CWE-639, CWE-620)
  (println "[PROFILE] Admin password change for user:" user-id "to:" new-password)
  (db/update-user (Integer/parseInt user-id) 
                  {:encrypted_password (crypt/encrypt new-password)})
  {:status 200 :body "Password changed"})

(defn export-user-data-idor [user-id]
  "Export user data including sensitive information"
  ;; VULNERABILITY: IDOR + Information disclosure (CWE-639, CWE-200)
  (let [user (get-user (Integer/parseInt user-id))
        avatars (avatar-db/get-avatar-by-user (Integer/parseInt user-id))]
    {:status 200
     :headers {"Content-Type" "application/json"
               "Content-Disposition" (str "attachment; filename=\"user_" user-id "_export.json\"")}
     :body (json/generate-string {:user user :avatars avatars})}))

;; ============================================================
;; PRIVILEGE ESCALATION (CWE-269)
;; ============================================================

(defn promote-to-admin [user-id]
  "Promote user to admin - no authorization"
  ;; VULNERABILITY: Privilege escalation (CWE-269)
  (db/update-user (Integer/parseInt user-id) {:role "admin" :is_admin true})
  {:status 200 :body "User promoted to admin"})

(defn set-user-role [user-id role]
  "Set user role without authorization"
  ;; VULNERABILITY: Arbitrary role assignment (CWE-269)
  (db/update-user (Integer/parseInt user-id) {:role role})
  {:status 200 :body (str "Role set to: " role)})

;; ============================================================
;; SQL INJECTION IN PROFILE (CWE-89)
;; ============================================================

(defn search-profiles [search-term]
  "Search user profiles - SQL injection"
  ;; VULNERABILITY: SQL Injection (CWE-89)
  (let [query (str "SELECT id, name, email FROM users WHERE name LIKE '%" search-term "%'")]
    (layout/base
      [:div
       [:h1 "Search Results"]
       [:form {:action "/profile/search" :method "GET"}
        [:input {:type "text" :name "q" :value search-term}]
        [:button {:type "submit"} "Search"]]
       [:pre (str (sql/query database/db [query]))]])))

(defn get-profile-by-email [email]
  "Get profile by email - SQL injection"
  ;; VULNERABILITY: SQL Injection via email (CWE-89)
  (let [query (str "SELECT * FROM users WHERE email = '" email "'")]
    (first (sql/query database/db [query]))))

;; ============================================================
;; COMMAND INJECTION (CWE-78)
;; ============================================================

(defn resize-avatar [user-id size]
  "Resize user avatar - command injection"
  ;; VULNERABILITY: Command injection via size parameter (CWE-78)
  (let [avatar (avatar-db/get-avatar-by-user (Integer/parseInt user-id))
        filename (:name avatar)
        cmd (str "convert resources/public/avatars/" filename " -resize " size " resources/public/avatars/resized_" filename)]
    (sh "sh" "-c" cmd)
    {:status 200 :body "Avatar resized"}))

(defn convert-avatar [user-id format]
  "Convert avatar format - command injection"
  ;; VULNERABILITY: Command injection via format parameter (CWE-78)
  (let [avatar (avatar-db/get-avatar-by-user (Integer/parseInt user-id))
        filename (:name avatar)
        cmd (str "convert resources/public/avatars/" filename " resources/public/avatars/" filename "." format)]
    (sh "sh" "-c" cmd)
    {:status 200 :body "Avatar converted"}))

;; ============================================================
;; PROFILE ROUTES
;; ============================================================

(defroutes profile-routes
  (wrap-current-user-id
    (context "/profile" {:keys [user-id]}
             (GET "/" []
                  (if user-id
                    (profile-page (get-user user-id))
                    (response/redirect "/login")))
             (GET "/edit" []
                  (if user-id
                    (profile-edit-page (get-user user-id))
                    (response/redirect "/login")))
             (POST "/update" [name file]
                   (if user-id
                     (update-profile name (get-user user-id) file)
                     (response/redirect "/login")))
             (GET "/password" []
                  (if user-id
                    (password-page (get-user user-id))
                    (response/redirect "/login")))
             (POST "/password/update" [current-password new-password confirm-password]
                   (if user-id
                     (update-password current-password new-password confirm-password (get-user user-id))
                     (response/redirect "/login")))
             (POST "/delete" []
                   (if user-id
                     (remove-user user-id)
                     (response/redirect "/login")))
             
             ;; IDOR Vulnerable Endpoints
             (GET "/view/:id" [id]
                  (get-user-profile-idor id))  ;; IDOR
             
             (POST "/update/:id" [id name email]
                   (update-user-idor id {:name name :email email}))  ;; IDOR
             
             (DELETE "/delete/:id" [id]
                     (delete-user-idor id))  ;; IDOR
             
             (GET "/avatar/:id" [id]
                  (get-user-avatar-idor id))  ;; IDOR
             
             (POST "/password/change/:id" [id password]
                   (change-user-password-idor id password))  ;; IDOR
             
             (GET "/export/:id" [id]
                  (export-user-data-idor id))  ;; IDOR + Info disclosure
             
             ;; Privilege Escalation
             (POST "/promote/:id" [id]
                   (promote-to-admin id))
             
             (POST "/role/:id" [id role]
                   (set-user-role id role))
             
             ;; SQL Injection
             (GET "/search" [q]
                  (search-profiles (or q "")))
             
             (GET "/by-email" [email]
                  {:status 200
                   :headers {"Content-Type" "application/json"}
                   :body (json/generate-string (get-profile-by-email email))})
             
             ;; Command Injection
             (POST "/resize-avatar/:id" [id size]
                   (resize-avatar id size))
             
             (POST "/convert-avatar/:id" [id format]
                   (convert-avatar id format)))))
