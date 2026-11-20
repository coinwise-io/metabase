(ns metabase.sso.sso-oidc-password-login-test
  "With OIDC single sign-on enforced (`sso-oidc-password-login-admins-only`), only administrators — the break-glass
   accounts — may sign in with a password or reset one."
  (:require
   [clojure.test :refer :all]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.session.api :as api.session]
   [metabase.sso.settings :as sso.settings]
   [metabase.test :as mt]
   [metabase.util :as u]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(def ^:private password "Break-Glass-2026!")

(defmacro ^:private with-oidc!
  [enabled? admins-only? & body]
  `(mt/with-temporary-setting-values [sso-oidc-issuer-uri                 "https://idp.example.com"
                                      sso-oidc-client-id                  "client-id"
                                      sso-oidc-client-secret              "client-secret"
                                      sso-oidc-enabled                    ~enabled?
                                      sso-oidc-password-login-admins-only ~admins-only?]
     ~@body))

(defn- do-with-users!
  "Call `f` with `member` and `admin`, two users with [[password]]."
  [f]
  (mt/with-temp [:model/User member {:email "member@example.com"}
                 :model/User admin  {:email "breakglass@example.com" :is_superuser true}]
    (auth-identity/set-password! (u/the-id member) password)
    (auth-identity/set-password! (u/the-id admin) password)
    (f member admin)))

(defn- login [user status]
  (mt/client :post status "session" {:username (:email user) :password password}))

(deftest setting-test
  (testing "the rule is only in force while OIDC is enabled, so turning OIDC off never locks anyone out"
    (with-oidc! false true
      (is (false? (sso.settings/sso-oidc-password-login-admins-only)))
      (is (true? (sso.settings/password-login-allowed? false)))))
  (with-oidc! true true
    (is (false? (sso.settings/password-login-allowed? false)))
    (is (true? (sso.settings/password-login-allowed? true)))))

(deftest login-test
  (do-with-users!
   (fn [member admin]
     (testing "enforced: a non-admin is refused, an admin (break glass) gets in"
       (with-oidc! true true
         (is (re-find #"only available to administrators" (str (login member 401))))
         (is (some? (:id (login admin 200))))
         (testing "no session was created for the refused user"
           (is (not (t2/exists? :model/Session :user_id (u/the-id member)))))))
     (testing "not enforced: everybody may use a password"
       (with-oidc! true false
         (is (some? (:id (login member 200))))))
     (testing "OIDC off: the stored rule does nothing"
       (with-oidc! false true
         (is (some? (:id (login member 200)))))))))

(deftest reset-password-test
  (do-with-users!
   (fn [member admin]
     (with-oidc! true true
       (testing "a non-admin's reset token is refused before anything changes"
         (let [token (auth-identity/create-password-reset! (u/the-id member))]
           (is (re-find #"only available to administrators"
                        (str (mt/client :post 400 "session/reset_password" {:token token :password "New-Pass-2026!!"}))))
           (is (t2/exists? :model/AuthIdentity :user_id (u/the-id member) :provider "emailed-secret-password-reset")
               "the token was not consumed")))
       (testing "an admin can still reset"
         (let [token (auth-identity/create-password-reset! (u/the-id admin))]
           (is (=? {:success true}
                   (mt/client :post 200 "session/reset_password" {:token token :password "New-Pass-2026!!"})))))))))

(deftest forgot-password-test
  (mt/with-dynamic-fn-redefs [api.session/forgot-password-impl
                              (let [orig (mt/original-fn #'api.session/forgot-password-impl)]
                                (fn [& args] (u/deref-with-timeout (apply orig args) 1000)))]
    (do-with-users!
     (fn [member admin]
       (with-oidc! true true
         (mt/with-fake-inbox
           (testing "a non-admin gets no reset link"
             (mt/client :post 204 "session/forgot_password" {:email (:email member)})
             (is (mt/received-email-subject? (:email member) #"Password Reset"))
             (is (not (mt/received-email-body? (:email member) #"/auth/reset_password/")))
             (is (not (t2/exists? :model/AuthIdentity :user_id (u/the-id member)
                                  :provider "emailed-secret-password-reset"))))
           (testing "an admin gets one"
             (mt/client :post 204 "session/forgot_password" {:email (:email admin)})
             (is (mt/received-email-body? (:email admin) #"/auth/reset_password/")))))))))
