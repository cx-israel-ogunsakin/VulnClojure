(ns sample.routes.files
  (:require [compojure.core :refer :all]
            [clojure.java.io :as io]
            [clojure.java.shell :refer [sh]]
            [sample.models.avatar :as avatar-db]
            [sample.db :as database]
            [ring.util.response :refer [file-response response content-type]]
            [ring.util.codec :refer [url-decode]]
            [hiccup.core :refer [html]]
            [sample.views.layout :as layout])
  (:import [java.io File FileInputStream ByteArrayOutputStream]
           [java.util.zip ZipOutputStream ZipEntry]
           [java.nio.file Files Paths]))

;; ============================================================
;; PATH TRAVERSAL VULNERABILITIES (CWE-22)
;; ============================================================

(defn avatar-file [avatar]
  ;; VULNERABILITY: Path traversal via URL-decoded filename (CWE-22)
  (file-response (str "resources/public/avatars/" (url-decode (:name avatar)))))

(defn read-file-unsafe [filename]
  "Read any file from filesystem - PATH TRAVERSAL"
  ;; VULNERABILITY: Path traversal - no validation (CWE-22)
  (try
    (slurp filename)
    (catch Exception e
      (str "Error reading file: " (.getMessage e)))))

(defn get-file-content [base-path filename]
  "Get file content with path traversal vulnerability"
  ;; VULNERABILITY: Path traversal via filename (CWE-22)
  (let [full-path (str base-path "/" filename)]
    (slurp full-path)))

(defn download-file [path]
  "Download file from path - path traversal"
  ;; VULNERABILITY: Arbitrary file download (CWE-22)
  (try
    (let [file (io/file path)
          content (slurp file)]
      {:status 200
       :headers {"Content-Type" "application/octet-stream"
                 "Content-Disposition" (str "attachment; filename=\"" (.getName file) "\"")}
       :body content})
    (catch Exception e
      {:status 404 :body (str "File not found: " (.getMessage e))})))

(defn serve-static-file [filename]
  "Serve static file - vulnerable to path traversal"
  ;; VULNERABILITY: No path validation, allows ../../../etc/passwd (CWE-22)
  (let [base-dir "resources/public/"
        ;; No sanitization of filename
        full-path (str base-dir filename)]
    (if (.exists (io/file full-path))
      (file-response full-path)
      {:status 404 :body "Not found"})))

(defn read-config-file [config-name]
  "Read configuration file - path traversal"
  ;; VULNERABILITY: Path traversal in config reading (CWE-22)
  (slurp (str "config/" config-name)))

(defn read-template [template-name]
  "Read template file"
  ;; VULNERABILITY: Template path traversal (CWE-22)
  (slurp (str "templates/" template-name)))

;; ============================================================
;; INSECURE FILE UPLOAD VULNERABILITIES (CWE-434)
;; ============================================================

(defn upload-file-unsafe [file]
  "Upload file without any validation"
  ;; VULNERABILITY: No file type validation (CWE-434)
  ;; VULNERABILITY: No file size limit
  ;; VULNERABILITY: Original filename used (allows overwrite)
  (let [filename (:filename file)
        temp-file (:tempfile file)
        dest-path (str "resources/public/uploads/" filename)]
    (io/copy temp-file (io/file dest-path))
    {:status 200 :body (str "File uploaded to: " dest-path)}))

(defn upload-avatar-unsafe [user-id file]
  "Upload avatar without validation - allows any file type"
  ;; VULNERABILITY: No validation - can upload .jsp, .php, .sh, etc. (CWE-434)
  (let [filename (:filename file)
        ;; VULNERABILITY: Path traversal in filename (CWE-22)
        dest-path (str "resources/public/avatars/" filename)]
    (io/copy (:tempfile file) (io/file dest-path))
    (avatar-db/create-avatar {:user_id user-id :name filename})
    filename))

(defn upload-document [file]
  "Upload document - weak validation"
  ;; VULNERABILITY: Blacklist-based validation (easily bypassed) (CWE-434)
  (let [filename (:filename file)
        banned-extensions #{"exe" "bat" "cmd"}
        ext (last (clojure.string/split filename #"\."))]
    (if (contains? banned-extensions (clojure.string/lower-case ext))
      {:status 400 :body "Invalid file type"}
      (do
        (io/copy (:tempfile file) (io/file (str "resources/public/documents/" filename)))
        {:status 200 :body "Uploaded"}))))

(defn upload-with-shell [file operation]
  "Upload and process file - command injection via operation"
  ;; VULNERABILITY: Command injection in file processing (CWE-78)
  (let [filename (:filename file)
        dest-path (str "/tmp/" filename)]
    (io/copy (:tempfile file) (io/file dest-path))
    ;; VULNERABILITY: Command injection
    (sh "sh" "-c" (str operation " " dest-path))
    {:status 200 :body "Processed"}))

(defn save-uploaded-file [file directory]
  "Save uploaded file to directory - path traversal"
  ;; VULNERABILITY: Path traversal in both filename AND directory (CWE-22)
  (let [dest-path (str directory "/" (:filename file))]
    (io/make-parents dest-path)
    (io/copy (:tempfile file) (io/file dest-path))
    dest-path))

;; ============================================================
;; ZIP SLIP / ARCHIVE VULNERABILITIES (CWE-22)
;; ============================================================

(defn extract-zip-unsafe [zip-file dest-dir]
  "Extract ZIP file - vulnerable to Zip Slip"
  ;; VULNERABILITY: Zip Slip - no validation of entry paths (CWE-22)
  (with-open [zip (java.util.zip.ZipInputStream. (io/input-stream zip-file))]
    (loop [entry (.getNextEntry zip)]
      (when entry
        ;; VULNERABILITY: Entry name used directly without validation
        (let [dest-file (io/file dest-dir (.getName entry))]
          (if (.isDirectory entry)
            (.mkdirs dest-file)
            (do
              (io/make-parents dest-file)
              (io/copy zip dest-file))))
        (recur (.getNextEntry zip))))))

;; ============================================================
;; INFORMATION DISCLOSURE (CWE-200)
;; ============================================================

(defn list-directory [path]
  "List directory contents - information disclosure"
  ;; VULNERABILITY: Directory listing (CWE-200)
  (let [dir (io/file path)]
    (if (.exists dir)
      {:status 200
       :body (html [:ul (for [f (.listFiles dir)]
                          [:li [:a {:href (str "/files/raw?path=" (.getAbsolutePath f))}
                                (.getName f)]])])}
      {:status 404 :body "Directory not found"})))

(defn get-file-metadata [path]
  "Get file metadata - information disclosure"
  ;; VULNERABILITY: File metadata exposure (CWE-200)
  (let [file (io/file path)]
    {:name (.getName file)
     :path (.getAbsolutePath file)
     :size (.length file)
     :readable (.canRead file)
     :writable (.canWrite file)
     :executable (.canExecute file)
     :last-modified (.lastModified file)}))

;; ============================================================
;; SYMLINK VULNERABILITIES (CWE-59)
;; ============================================================

(defn read-file-follow-symlinks [path]
  "Read file following symlinks - TOCTOU race condition"
  ;; VULNERABILITY: Following symlinks without validation (CWE-59)
  (slurp path))

(defn create-symlink [target link-name]
  "Create symbolic link - allows access bypass"
  ;; VULNERABILITY: Arbitrary symlink creation (CWE-59)
  (let [target-path (Paths/get target (into-array String []))
        link-path (Paths/get (str "resources/public/links/" link-name) (into-array String []))]
    (Files/createSymbolicLink link-path target-path (into-array java.nio.file.attribute.FileAttribute []))
    {:status 200 :body "Symlink created"}))

;; ============================================================
;; UNSAFE FILE OPERATIONS
;; ============================================================

(defn write-file-unsafe [path content]
  "Write file without validation - arbitrary file write"
  ;; VULNERABILITY: Arbitrary file write (CWE-22)
  (spit path content)
  {:status 200 :body "Written"})

(defn delete-file-unsafe [path]
  "Delete file without validation"
  ;; VULNERABILITY: Arbitrary file deletion (CWE-22)
  (io/delete-file path)
  {:status 200 :body "Deleted"})

(defn copy-file-unsafe [source dest]
  "Copy file - path traversal in both params"
  ;; VULNERABILITY: Path traversal in source and destination (CWE-22)
  (io/copy (io/file source) (io/file dest))
  {:status 200 :body "Copied"})

(defn move-file-unsafe [source dest]
  "Move file - path traversal"
  ;; VULNERABILITY: Path traversal (CWE-22)
  (.renameTo (io/file source) (io/file dest))
  {:status 200 :body "Moved"})

;; ============================================================
;; FILE ROUTES
;; ============================================================

(defroutes files-routes
  (context "/files" {}
           ;; Original avatar route with path traversal
           (GET "/avatars/:name" [name]
                (if-let [avatar (avatar-db/get-avatar-by-name name)]
                  (avatar-file avatar)))
           
           ;; Path traversal endpoints
           (GET "/read" [path]
                {:status 200
                 :headers {"Content-Type" "text/plain"}
                 :body (read-file-unsafe path)})
           
           (GET "/download" [path]
                (download-file path))
           
           (GET "/static/*" {{path :*} :route-params}
                (serve-static-file path))
           
           (GET "/config/:name" [name]
                {:status 200 :body (read-config-file name)})
           
           (GET "/template/:name" [name]
                {:status 200 :body (read-template name)})
           
           ;; File upload endpoints
           (POST "/upload" [file]
                 (upload-file-unsafe file))
           
           (POST "/upload-avatar" [file user-id]
                 {:status 200 :body (upload-avatar-unsafe user-id file)})
           
           (POST "/upload-doc" [file]
                 (upload-document file))
           
           (POST "/upload-process" [file operation]
                 (upload-with-shell file operation))
           
           (POST "/save" [file directory]
                 {:status 200 :body (save-uploaded-file file directory)})
           
           ;; Archive extraction
           (POST "/extract-zip" [file dest]
                 (extract-zip-unsafe (:tempfile file) dest)
                 {:status 200 :body "Extracted"})
           
           ;; Directory listing
           (GET "/list" [path]
                (list-directory (or path ".")))
           
           (GET "/metadata" [path]
                {:status 200
                 :headers {"Content-Type" "application/json"}
                 :body (str (get-file-metadata path))})
           
           ;; File operations
           (POST "/write" [path content]
                 (write-file-unsafe path content))
           
           (DELETE "/delete" [path]
                   (delete-file-unsafe path))
           
           (POST "/copy" [source dest]
                 (copy-file-unsafe source dest))
           
           (POST "/move" [source dest]
                 (move-file-unsafe source dest))
           
           ;; Symlink
           (POST "/symlink" [target name]
                 (create-symlink target name))
           
           ;; Raw file access
           (GET "/raw" [path]
                {:status 200 
                 :body (read-file-follow-symlinks path)})))
