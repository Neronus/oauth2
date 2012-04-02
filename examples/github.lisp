(defpackage oauth2.github-example
  (:use cl oauth2)
  (:documentation
   "This package demonstrate using oauth2 to access gitub data.
To use it, you have to set *username* to your username
and *password* to your password."))

(in-package oauth2.github-example)

(defparameter *username* nil "Your github username")
(defparameter *password* nil "Your github password")

(defun assert-login ()
  "Make sure login data has been set."
  (assert (and *username* *password*)))

(defun plist->json (plist)
  (json:encode-json-plist-to-string plist))
(defun json->plist (json)
  (alexandria:alist-plist
   (json:decode-json-from-string
    (map 'string 'code-char json))))

(defun convert-answer (body status headers uri stream to-be-closed? reason)
  "Take a drakma:http-request answer and turn it into two values:
A plist and a HTTP response code."
  (declare (ignore headers uri stream to-be-closed? reason))
  (values
   (when (not (zerop (length body))) (json->plist body))
   status))

(defun create-authorization (&optional (scopes :public_repo))
  "Create an authorization to access github data for the given account.
Returns githubs response as a plist."
  (assert-login)
  (multiple-value-call 'convert-answer
    (drakma:http-request "https://api.github.com/authorizations"
                         :basic-authorization (list *username* *password*)
                         :method :post
                         :content (json:encode-json-plist-to-string
                                   (list :scopes scopes)))))

(defun delete-authorization (id)
  "Delete authorization with the given ID. Returns githubs response."
  (assert-login)
  (multiple-value-call 'convert-answer
   (drakma:http-request (format nil "https://api.github.com/authorizations/~A" id)
                        :method :delete
                        :basic-authorization (list *username* *password*))))

(defun my-repos (token)
  "Return repos as plist for the given token. A token
can be obtained from CREATE-AUTHORIZATION."
  (multiple-value-call 'convert-answer
   (oauth2:request-resource "https://api.github.com/user/repos"
                            (oauth2:string->token token))))

(defun main ()
  (let* ((auth (create-authorization))
         (token (getf auth :token)))
    (when (null token)
      (error "Creating authorization failed. Github answered: ~A" auth))
    (format t "Your repositories:~%~A~%"
            (my-repos token))
    (delete-authorization (getf auth :id))))