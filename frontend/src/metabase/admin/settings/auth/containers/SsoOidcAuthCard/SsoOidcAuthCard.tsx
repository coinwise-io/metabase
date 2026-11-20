import { t } from "ttag";

import { useUpdateSsoOidcSettingsMutation } from "metabase/admin/settings/api/sso-oidc";
import { LoadingAndErrorWrapper } from "metabase/common/components/LoadingAndErrorWrapper";
import { useAdminSetting } from "metabase/settings";

import { AuthCard } from "../../components/AuthCard";

export function SsoOidcAuthCard() {
  const {
    value: isConfigured,
    settingDetails,
    isLoading,
  } = useAdminSetting("sso-oidc-configured");
  const { value: isEnabled } = useAdminSetting("sso-oidc-enabled");
  const [updateSettings] = useUpdateSsoOidcSettingsMutation();

  const handleDeactivate = () =>
    updateSettings({
      "sso-oidc-enabled": false,
      "sso-oidc-issuer-uri": null,
      "sso-oidc-client-id": null,
      "sso-oidc-client-secret": null,
    }).unwrap();

  if (isLoading) {
    return <LoadingAndErrorWrapper loading />;
  }

  return (
    <AuthCard
      type="sso-oidc"
      name={t`OpenID Connect (SSO)`}
      description={t`Allows users to sign in through an OpenID Connect identity provider such as JumpCloud, with single sign-on, MFA and group mapping.`}
      isConfigured={!!isConfigured}
      isEnabled={!!isEnabled}
      onDeactivate={handleDeactivate}
      onChange={(newValue) =>
        updateSettings({ "sso-oidc-enabled": newValue }).unwrap()
      }
      setting={settingDetails}
    />
  );
}
