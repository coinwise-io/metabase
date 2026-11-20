import "metabase/auth/plugins";
import { screen } from "__support__/ui";

import { setup } from "../Login/tests/setup";

import { getSsoOidcErrorMessage, getSsoOidcLoginUrl } from "./SsoOidcButton";

describe("SsoOidcButton", () => {
  it("is not shown when OpenID Connect is disabled", () => {
    setup({ isSsoOidcEnabled: false });

    expect(screen.queryByText("Sign in with SSO")).not.toBeInTheDocument();
  });

  it("is shown next to password login when OpenID Connect is enabled", () => {
    setup({ isSsoOidcEnabled: true });

    expect(screen.getByText("Sign in with SSO")).toBeInTheDocument();
    expect(screen.getByText("Sign in with email")).toBeInTheDocument();
  });

  it("uses the label configured by the admin", () => {
    setup({
      isSsoOidcEnabled: true,
      ssoOidcLoginButtonLabel: "Entrar com JumpCloud",
    });

    expect(screen.getByText("Entrar com JumpCloud")).toBeInTheDocument();
  });

  it("starts sign-in on the backend and keeps the redirect", () => {
    setup({
      isSsoOidcEnabled: true,
      initialRoute: "/auth/login?redirect=%2Fdashboard%2F1",
    });

    expect(
      screen.getByRole("link", { name: "Sign in with SSO" }),
    ).toHaveAttribute("href", "/auth/oidc?redirect=%2Fdashboard%2F1");
  });

  it("shows the error the backend reported", () => {
    setup({
      isSsoOidcEnabled: true,
      initialRoute: "/auth/login?sso_error=account-creation-not-allowed",
    });

    expect(screen.getByRole("alert")).toHaveTextContent(
      "You'll need an administrator to create an account",
    );
  });
});

describe("getSsoOidcLoginUrl", () => {
  it("leaves out the redirect when there is none", () => {
    expect(getSsoOidcLoginUrl()).toBe("/auth/oidc");
  });
});

describe("getSsoOidcErrorMessage", () => {
  it("returns nothing without an error", () => {
    expect(getSsoOidcErrorMessage(null)).toBeNull();
  });

  it("never echoes an unknown code", () => {
    const message = getSsoOidcErrorMessage("<b>attacker text</b>");

    expect(message).not.toContain("attacker");
  });
});
