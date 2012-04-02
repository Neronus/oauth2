 (defpackage oauth2
  (:use cl drakma)
  (:export :request-code :request-token :request-resource :refresh-token
           :authorization-error :error-code :error-body
           :token-string :token-type :token-expires-in
           :token-refresh-token :token-scope :token-from-string)
  (:documentation
   "This package contains a fairly low-level implementation of the OAUTH2 protocol.
It currently only supports \"Authorization Code Grant\" (section 4.1 if the draft)
for authorization. This is the method intended for webservers.

To use it, you first have to ask for an access code using REQUEST-CODE.
You redirect the user to the url returned by REQUEST-CODE.
You then have to provide the code you get from that to get a token via
REQUEST-TOKEN.
Once you have the token, you can request the actual resource using
REQUEST-RESOURCE.
See the specific functions for more information."))

(in-package oauth2)

(declaim (optimize debug))

(defmacro push-when (var name place)
  (alexandria:once-only (var)
    `(when ,var
       (push (cons ,name ,var) ,place))))

(define-condition authorization-error (error)
  ((code :reader error-code :initarg :code :type integer)
   (body :reader error-body :initarg :body :type string))
  (:report
   (lambda (c s)
     (format s "Server responded to authorization request with non-redirection code: ~A" (error-code c)))))

(defun parse-json (string)
  (with-input-from-string (in (map 'string 'code-char string))
    (json:decode-json in)))

(defun request-code
    (authorizer client-id &key redirect-uri scope state
     (method :get)
     other)
  "Send an authorization request to the server. Return the rediction URI
on success. Signals an AUTHORIZATION-ERROR otherwise.

This function will not tell you the actual code.
A user-agent has to go to the URI this function returns.
The authorizer will then ask the user to log in and grant
access to you.

After the user has done that, her browser will be send to the
REQUEST-URI you specify above. It will contain 
application/x-www-form-urlencoded data.
If the user granted access, then there will be two parameters:
  1. code - The access code you requested
  2. state - the STATE parameter you specify when calling REQUEST-CODE.
If not, then at least an error parameter will be urlencoded, and
it will be one of the following:
  invalid_request, unauhtorized_client, access_denied, unsupported_response_type,
  invalid_scope, server_error, temporarily_unavailable
  See section 4.1.2.1. of the OAuth 2.0 spec for more information.
"
  (declare (type string client-id))
  (let ((data other))
    (push '("response_type" . "code") data)
    (push `("client_id" . ,client-id) data)
    (push-when redirect-uri "redirect_uri" data)
    (push-when scope "scope" data)
    (push-when state "state" data)
    (multiple-value-bind (body code headers)
        (http-request authorizer
                      :method method
                      :parameters data
                      :redirect nil)
      (format t "~A~%" headers)
      (when (/= code 302)
        (error
         (make-instance 'authorization-error
                        :code code
                        :body body)))
      (cdr (assoc :location headers)))))

(define-condition request-token-error (error)
  ((type :initarg :type :reader error-type :type string)
   (description :initarg :description :reader error-description :type (or string null))
   (uri :initarg :uri :reader error-uri :type (or string null)))
  (:report
   (lambda (c s)
     (format s "Server responded with error type ~A" (error-type c))
     (when (error-description c)
       (format s "~%~%~A" (error-description c)))
     (when (error-uri c)
       (format s "For more information, see ~A" (error-uri c))))))

(defun assoc1 (key list)
  (cdr (assoc key list)))

(defstruct token
  (string nil :type string :read-only t)
  (type nil :type string :read-only t)
  (expires-in nil :type (or null integer) :read-only t)
  (refresh-token nil :type (or null string))
  (scope nil :type (or null string)))

(defun string->token (string &key expires-in refresh-token scope)
  "Construct a new token from a token-string"
  (make-token :string string :type "Bearer"
              :expires-in expires-in :refresh-token refresh-token :scope scope))

(defmacro with-handle-token (token)
  "Handle the return value you get from a request for a token. Used by request-token and refresh-token."
  `(multiple-value-bind (body code) ,token
     (case code
       (400
        (let ((data (parse-json body)))
          (error (make-instance 'request-token-error
                                :type (assoc1 :error data)
                                :uri (assoc1 :error--uri data)
                                :description (assoc1 :error--description data)))))
       (200
        (let ((data (parse-json body)))
          (make-token
           :string (assoc1 :access--token data)
           :type   (assoc1 :token--type data)
           :expires-in (assoc1 :expires--in data)
           :refresh-token (assoc1 :refresh--token data)
           :scope (assoc1 :scope data))))
       (t
        (error "Got an invalid response from server. Code: ~A" code)))))

(defun request-token (authorizer code &key redirect-uri (method :get) other)
  "Request a token from the authorizer.

CODE has to be authorization code. You can get it from calling REQUEST-CODE.

If you specified a REDIRECT-URI when calling REQUEST-CODE, then you have to
submit the identical REDIRECT-URI here.

METHOD is the HTTP method used to talk to the authorizer.

OTHER is an alist of additional parameters to send to the authorizer.

Returns a TOKEN."
  (declare (type string code))
  (let ((data other))
    (push `("code" . ,code) data)
    (push-when redirect-uri "redirect_uri" data)
    (push '("grant_type" . "authorization_code") data)
    (with-handle-token
        (http-request authorizer
                      :method method
                      :parameters data
                      :redirect nil))))

(defun plist-remove (key list)
  "Returns a copy of list with the key-value pair identified by KEY removed."
  (loop :for p :on list :by #'cddr
        :unless (eq key (car p))
        :nconc (list (car p) (cadr p))))

(defun refresh-token (url token &key scope other (method :get))
  "Refresh a TOKEN you got from REQUEST-TOKEN.

Assumes that (TOKEN-REQUEST-TOKEN TOKEN) is not NIL.

METHOD is the HTTP method used to talk to the authorizer.

OTHER is an alist of additional parameters to send to the authorizer.

Returns a new TOKEN.
"
  (assert (not (null (token-refresh-token token))))
  (let ((data other))
    (push `("refresh_token" . ,(token-refresh-token token)) data)
    (push '("grant_type" . "refresh_token") data)
    (push-when scope "scope" data)
    (with-handle-token
        (http-request url
                      :method method
                      :parameters data
                      :redirect nil))))

(defun request-resource (url token &rest rest)
  "Request a resource from URL using TOKEN as token.
Use REQUEST-TOKEN to get a token.
All other parameters are given to DRAKMA:HTTP-REQUEST as they are.
The return value is like the one of DRAKMA:HTTP-REQUEST."
  (declare (type string url)
           (type token token))
  (when (not (string= (token-type token) "Bearer"))
    (error "Only token-bearer authentication supported."))
  (let ((headers (getf rest :additional-headers))
        (other (plist-remove :additional-headers rest)))
   (apply
    'http-request url :additional-headers
    `(("Authorization" . ,(format nil "Bearer ~A" (token-string token))) ,@headers)
    other)))