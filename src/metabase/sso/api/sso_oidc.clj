(ns metabase.sso.api.sso-oidc
  "`/api/sso-oidc` routes: admin endpoints of the generic OpenID Connect single sign-on provider."
  (:require
   [clojure.string :as str]
   [metabase.api.common :as api]
   [metabase.api.macros :as api.macros]
   [metabase.settings.core :as setting]
   [metabase.sso.core :as sso]
   [metabase.sso.integrations.sso-oidc :as sso-oidc]
   [metabase.sso.settings :as sso.settings]
   [toucan2.core :as t2]))

;;; ------------------------------------------------ /api/sso-oidc ------------------------------------------------

(api.macros/defendpoint :get "/redirect-uri" :- [:map [:redirect-uri :string]]
  "The callback URL to register in the identity provider. You must be a superuser to do this."
  []
  (api/check-superuser)
  {:redirect-uri (sso-oidc/redirect-uri)})

(api.macros/defendpoint :post "/check" :- [:map
                                           [:ok :boolean]
                                           [:discovery {:optional true} :map]
                                           [:credentials {:optional true} :map]]
  "Check an OpenID Connect configuration: fetch the issuer's discovery document and try the client credentials at its
   token endpoint. Values left out of the body fall back to the saved settings. You must be a superuser to do this."
  [_route-params
   _query-params
   {:keys [issuer-uri client-id client-secret scopes]}
   :- [:map {:closed true}
       [:issuer-uri    {:optional true} [:maybe :string]]
       [:client-id     {:optional true} [:maybe :string]]
       [:client-secret {:optional true} [:maybe :string]]
       [:scopes        {:optional true} [:maybe :string]]]]
  (api/check-superuser)
  (let [issuer-uri    (or (some-> issuer-uri str/trim not-empty (str/replace #"/+$" ""))
                          (sso.settings/sso-oidc-issuer-uri))
        client-id     (or (some-> client-id str/trim not-empty) (sso.settings/sso-oidc-client-id))
        ;; the form shows the masked secret; a masked or missing value means "use the saved one"
        client-secret (if (or (str/blank? client-secret)
                              (= client-secret (sso.settings/sso-oidc-client-secret)))
                        (sso.settings/unobfuscated-sso-oidc-client-secret)
                        client-secret)
        scopes        (-> (or (not-empty scopes) (sso.settings/sso-oidc-scopes) "openid email profile")
                          str/trim
                          (str/split #"\s+")
                          vec)]
    (api/check-400 (and issuer-uri client-id client-secret)
                   "Issuer URI, client ID and client secret are required.")
    (sso/check-oidc-configuration issuer-uri client-id client-secret scopes)))

(def ^:private settings-keys
  [:sso-oidc-issuer-uri
   :sso-oidc-client-id
   :sso-oidc-client-secret
   :sso-oidc-scopes
   :sso-oidc-login-button-label
   :sso-oidc-attribute-email
   :sso-oidc-attribute-firstname
   :sso-oidc-attribute-lastname
   :sso-oidc-attribute-groups
   :sso-oidc-user-provisioning-enabled
   :sso-oidc-password-login-admins-only])

(api.macros/defendpoint :put "/settings" :- :nil
  "Update the OpenID Connect single sign-on settings. The configuration is saved before `sso-oidc-enabled`, in one
   transaction, so a configuration can be saved and enabled in one request. You must be a superuser to do this."
  [_route-params
   _query-params
   body :- [:map {:closed true}
            [:sso-oidc-enabled                   {:optional true} [:maybe :boolean]]
            [:sso-oidc-issuer-uri                {:optional true} [:maybe :string]]
            [:sso-oidc-client-id                 {:optional true} [:maybe :string]]
            [:sso-oidc-client-secret             {:optional true} [:maybe :string]]
            [:sso-oidc-scopes                    {:optional true} [:maybe :string]]
            [:sso-oidc-login-button-label        {:optional true} [:maybe :string]]
            [:sso-oidc-attribute-email           {:optional true} [:maybe :string]]
            [:sso-oidc-attribute-firstname       {:optional true} [:maybe :string]]
            [:sso-oidc-attribute-lastname        {:optional true} [:maybe :string]]
            [:sso-oidc-attribute-groups          {:optional true} [:maybe :string]]
            [:sso-oidc-user-provisioning-enabled {:optional true} [:maybe :boolean]]
            [:sso-oidc-password-login-admins-only {:optional true} [:maybe :boolean]]]]
  (api/check-superuser)
  (t2/with-transaction [_conn]
    (setting/set-many! (select-keys body settings-keys))
    (when (contains? body :sso-oidc-enabled)
      (sso.settings/sso-oidc-enabled! (:sso-oidc-enabled body))))
  nil)

(def ^{:arglists '([request respond raise])} routes
  "`/api/sso-oidc` routes."
  (api.macros/ns-handler *ns*))
