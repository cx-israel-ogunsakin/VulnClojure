(defproject sample "0.1.0-SNAPSHOT"
  :description "Vulnerable sample application for SAST testing"
  :url "http://example.com/FIXME"
  :min-lein-version "2.0.0"
  :dependencies [[org.clojure/clojure "1.12.0"]
                 [clojurewerkz/scrypt "1.2.0"]
                 [compojure "1.7.1"]
                 [funcool/struct "1.4.0"]
                 [hiccup "1.0.5"]
                 [org.postgresql/postgresql "42.4.4"]
                 [org.clojure/java.jdbc "0.7.12"]
                 [clj-time "0.15.2"]
                 [migratus "1.3.5"]
                 [prone "2021-04-23"]
                 [com.draines/postal "2.0.5"]
                 [ring/ring-anti-forgery "1.3.1"]
                 [ring/ring-defaults "0.3.4"]
                 ;; Additional dependencies for vulnerable features
                 [clj-http "3.12.3"]           ;; For SSRF vulnerabilities
                 [org.clojure/data.xml "0.0.8"] ;; For XXE vulnerabilities
                 [org.clojure/data.json "2.4.0"] ;; For JSON handling
                 [cheshire "5.11.0"]           ;; For JSON serialization
                 [digest "1.4.10"]             ;; For weak hash functions (MD5, SHA1)
                 [buddy/buddy-core "1.10.1"]   ;; For crypto operations
                 [clj-yaml "0.7.0"]]           ;; For YAML deserialization vulnerabilities
  :plugins [[lein-ring "0.12.5"]
            [migratus-lein "0.5.0"]]
  :migratus {:store :database
             :migration-dir "migrations"
             :db (or (System/getenv "DATABASE_URL") "postgresql://localhost:5432/sample")}
  :ring {:handler sample.handler/app
         :init sample.handler/init}
  :profiles
  {:dev {:dependencies [[javax.servlet/servlet-api "2.5"]
                        [kerodon "0.9.1"]
                        [ring/ring-mock "0.4.0"]]
         :plugins [[lein-kibit "0.1.5"]
                   [lein-ancient "0.6.15"]]
         :ring {:stacktrace-middleware prone.middleware/wrap-exceptions}}
   :test {:prep-tasks [["migratus", "migrate"]]}})
