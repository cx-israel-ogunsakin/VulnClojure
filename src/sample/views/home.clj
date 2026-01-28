(ns sample.views.home
  (:require [hiccup.element :refer :all]
            [hiccup.core :refer [html]]))

(defn home [user]
  [:div
   ;; VULNERABILITY: XSS via user name - raw output (CWE-79)
   [:h1 "Hello " [:raw (:name user "Guest")] "!"]
   
   ;; VULNERABILITY: DOM-based XSS setup (CWE-79)
   [:div {:id "user-greeting"}]
   [:script "
     // VULNERABILITY: DOM XSS - reads from URL hash
     var hash = window.location.hash.substr(1);
     if (hash) {
       document.getElementById('user-greeting').innerHTML = 'Custom greeting: ' + decodeURIComponent(hash);
     }
     
     // VULNERABILITY: DOM XSS - reads from URL parameters
     var urlParams = new URLSearchParams(window.location.search);
     var msg = urlParams.get('msg');
     if (msg) {
       document.getElementById('user-greeting').innerHTML += '<br>Message: ' + msg;
     }
   "]
   
   ;; Display user info with potential XSS
   (when user
     [:div.user-info
      [:p "Welcome back, " [:raw (:name user)] "!"]
      [:p "Email: " [:raw (:email user)]]
      ;; VULNERABILITY: Exposed session/password info in HTML comment (CWE-615)
      [:raw (str "<!-- User ID: " (:id user) " -->")]
      [:raw (str "<!-- Session: " (pr-str user) " -->")]])])
