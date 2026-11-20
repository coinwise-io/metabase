(ns metabase.sso.integrations.sso-oidc
  "HTTP flow of the generic OpenID Connect single sign-on provider.

   1. The login page sends the browser to GET /auth/oidc?redirect=<path>.
   2. Metabase stores state and nonce in an encrypted cookie and redirects to the identity provider.
   3. The user signs in at the identity provider (password, MFA, ...).
   4. The identity provider redirects to GET /auth/oidc/callback?code=...&state=...
   5. Metabase checks the state, exchanges the code, validates the ID token, finds or creates the user, synchronizes
      groups and sets the session cookie."
  (:require
   [java-time.api :as t]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.sso.core :as sso]
   [metabase.sso.settings :as sso.settings]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [ring.util.codec :as codec]
   [ring.util.response :as response]))

(set! *warn-on-reflection* true)

(def provider-key
  "Identifier of this provider in the OIDC state cookie."
  :sso-oidc)

(defn redirect-uri
  "The callback URL to register with the identity provider."
  []
  (str (system/site-url) "/auth/oidc/callback"))

(defn- check-enabled!
  []
  (when-not (sso.settings/sso-oidc-enabled)
    (throw (ex-info (tru "OpenID Connect single sign-on is not enabled.")
                    {:status-code 400}))))

(defn- login-error-redirect
  "Send the browser back to the login page with an error code instead of showing a raw error page. Only a code is
   passed, never a message, so nobody can craft a login-page link that shows text of their choosing."
  [error-code]
  (-> (response/redirect (str "/auth/login?sso_error=" (codec/url-encode (name (or error-code :unknown)))))
      (sso/clear-oidc-state-cookie)))

(defn sso-initiate
  "Start the sign-in: redirect to the identity provider's authorization endpoint."
  [request]
  (check-enabled!)
  (let [{:keys [redirect]} (:params request)
        ;; reject a bad redirect before contacting the identity provider
        final-redirect     (if redirect
                             (do (sso/validate-redirect-url! redirect)
                                 redirect)
                             "/")
        auth-result        (auth-identity/authenticate :provider/sso-oidc
                                                       (assoc request :redirect-uri (redirect-uri)))]
    (if (= :redirect (:success? auth-result))
      (sso/wrap-oidc-redirect auth-result request provider-key final-redirect
                              {:browser-id (:browser-id request)})
      (throw (ex-info (or (:message auth-result) (tru "Failed to start single sign-on."))
                      {:status-code 500})))))

(defn sso-callback
  "Finish the sign-in after the identity provider redirects back with an authorization code."
  [request]
  (check-enabled!)
  (let [{:keys [code state error error_description]} (:params request)]
    (if error
      (do (log/warnf "OIDC identity provider returned an error: %s %s" error error_description)
          (login-error-redirect (if (= error "access_denied") :access-denied :identity-provider-error)))
      (let [login-result (auth-identity/login! :provider/sso-oidc
                                               (assoc request
                                                      :code          code
                                                      :state         state
                                                      :oidc-provider provider-key
                                                      :redirect-uri  (redirect-uri)
                                                      :device-info   (request/device-info request)))]
        (if (and (true? (:success? login-result)) (:session login-result))
          (let [base-response (-> (response/redirect (or (:redirect-url login-result) "/"))
                                  (sso/clear-oidc-state-cookie))]
            (request/set-session-cookies request
                                         base-response
                                         (:session login-result)
                                         (t/zoned-date-time (t/zone-id "GMT"))))
          (let [message (or (:message login-result) (tru "Single sign-on failed."))]
            (log/warnf "OIDC sign-in failed: %s %s" (:error login-result) message)
            (login-error-redirect (if (keyword? (:error login-result)) (:error login-result) :unknown))))))))
