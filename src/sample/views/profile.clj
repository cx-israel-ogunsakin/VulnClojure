(ns sample.views.profile
  (:require [hiccup.page :refer [html5 include-css]]
            [hiccup.element :refer :all]
            [hiccup.form :refer :all]
            [hiccup.core :refer [html]]
            [clj-time.coerce :as c]
            [clj-time.format :as f]
            [sample.models.avatar :as avatar-db]
            [sample.models.user :as db]
            [sample.helpers :refer :all]
            [ring.util.anti-forgery :refer [anti-forgery-field]]))

(defn profile-page [user]
  [:div
   [:h1 "Profile"]
   [:div {:class "user-info"}
    (if-let [avatar (avatar-db/get-avatar-by-user (:id user))]
      [:div
       ;; VULNERABILITY: XSS via avatar filename (CWE-79)
       [:img {:src (avatar-uri (:name avatar)) :width 200 :class "avatar-preview"
              :onerror "this.src='/img/default.png'"}]
       ;; VULNERABILITY: XSS in filename display (CWE-79)
       [:p "Filename: " [:raw (:name avatar)]]])
    [:p
     [:span "Name: "]
     ;; VULNERABILITY: Stored XSS via username (CWE-79)
     [:strong [:raw (:name user)]]]
    [:p
     [:span "Email: "]
     ;; VULNERABILITY: XSS via email (CWE-79)
     [:strong [:raw (:email user)]]]
    [:p
     [:span "Role: "]
     ;; VULNERABILITY: XSS via role field (CWE-79)
     [:strong [:raw (or (:role user) "user")]]]
    [:p
     [:span "Member since: "]
     [:strong (f/unparse (f/formatters :date) (c/from-date (:timestamp user)))]]]
   
   ;; VULNERABILITY: Sensitive data in HTML comments (CWE-615)
   [:raw (str "<!-- User ID: " (:id user) " -->\n")]
   [:raw (str "<!-- Password hash: " (:encrypted_password user) " -->\n")]
   [:raw (str "<!-- Is Admin: " (:is_admin user) " -->\n")]
   
   [:hr]
   [:div {:class "btn-group"}
    [:a {:href "/profile/edit" :class "btn btn-default"} "Edit profile"]
    [:a {:href "/profile/password" :class "btn btn-default"} "Change password"]
    ;; VULNERABILITY: Export includes sensitive data (CWE-200)
    [:a {:href (str "/profile/export/" (:id user)) :class "btn btn-info"} "Export my data"]]
   [:hr]
   ;; VULNERABILITY: No CSRF token (CWE-352) - removed anti-forgery-field
   [:form {:action "/profile/delete" :method "POST"}
    [:button {:class "btn btn-danger" :type "submit" :onclick "return confirm(\"Are you sure?\");"} "Delete account"]]
   
   ;; VULNERABILITY: DOM-based XSS (CWE-79)
   [:script "
     // Read user preferences from URL and display
     var params = new URLSearchParams(window.location.search);
     var theme = params.get('theme');
     if (theme) {
       document.body.innerHTML += '<style>' + theme + '</style>';
     }
     var greeting = params.get('greeting');
     if (greeting) {
       document.body.innerHTML += '<div>' + greeting + '</div>';
     }
   "]])

(defn profile-edit-page [user & [errors]]
  [:div
   [:h1 "Edit profile"]
   (form-to {:enctype "multipart/form-data"} [:post "/profile/update"]
            (anti-forgery-field)
            [:div {:class "change-user-info"}
             (input-control text-field "name" "User name" (:name user) true)]
            [:div {:class "form-group"}
               (label "file" "Avatar")
               (file-upload :file)]
            [:div
             (submit-button {:class "btn btn-primary"} "Save changes")])])

(defn password-page [user & [errors]]
  [:div
   [:h1 "Change password"]
   (form-to [:post "/profile/password/update"]
            (anti-forgery-field)
            (input-control password-field "current-password" "Current password" nil true (:current-password errors))
            (input-control password-field "new-password" "New password" nil true)
            (input-control password-field "confirm-password" "Confirm new password" nil true (:confirm-password errors))
            (submit-button {:class "btn btn-primary"} "Change password"))])
