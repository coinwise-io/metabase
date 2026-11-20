import { SsoOidcButton } from "metabase/auth/components/SsoOidcButton";
import {
  PLUGIN_AUTH_PROVIDERS,
  PLUGIN_IS_PASSWORD_USER,
} from "metabase/plugins";
import MetabaseSettings from "metabase/utils/settings";

PLUGIN_AUTH_PROVIDERS.providers.push((providers) => {
  const ssoOidcProvider = {
    name: "sso-oidc",
    Button: SsoOidcButton,
  };

  return MetabaseSettings.get("sso-oidc-enabled")
    ? [ssoOidcProvider, ...providers]
    : providers;
});

PLUGIN_IS_PASSWORD_USER.push((user) => user.sso_source !== "sso-oidc");
