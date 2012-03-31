(defpackage oauth2.test.google-user-email
  (:use cl oauth2))

(in-package oauth2.test.google-user-email)

(defparameter *client-id*  NIL
  "Google client ID.")

(defparameter *client-secret* NIL
  "Google client secret")

(defparameter *redirect-uri*
  NIL)

(defparameter *redirect*
  (request-code
   "https://accounts.google.com/o/oauth2/auth"
   *client-id*
   :scope "https://www.googleapis.com/auth/userinfo.profile"
   :redirect-uri *redirect-uri*))

(format t "Go to ~A and come back with the code: " *redirect*)
(defparameter *code* (read-line))

(defparameter *token*
  (request-token
   "https://accounts.google.com/o/oauth2/token"
   *code* 
   :redirect-uri *redirect-uri*
   :method :post
   :other `(("client_id" . ,*client-id*)
            ("client_secret" . ,*client-secret*))))

(format t "I got a token:~%~A~%" *token*)

(defparameter *info*
  (with-input-from-string (stream
                           (map 'string 'code-char
                                (request-resource "https://www.googleapis.com/oauth2/v1/userinfo"
                                                  *token*)))
    (json:decode-json stream)))

(format t "User info:~%~A" *info*)