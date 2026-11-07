# Does Wazuh's GitHub module cover what the OmniAxis org webhook watches?

Checked 7 Nov 2026. **Short answer: not today, and only partly after a plan change.**

## 1. The module cannot run on this organisation's plan

- Wazuh 4.14.9's GitHub module (`src/wazuh_modules/wm_github.h`) reads exactly one endpoint:
  `GET https://api.github.com/orgs/{org}/audit-log?phrase=created:…&include=web|git|all`.
- GitHub documents that endpoint only for **GitHub Enterprise Cloud**. It is absent from the Free, Pro and Team REST reference.
- `omniaxis-labs` is on the **Team** plan (`gh api orgs/omniaxis-labs`: `plan.name = "team"`).
  A call to `/orgs/omniaxis-labs/audit-log` returns **HTTP 404**.
- Even on Enterprise Cloud, the token must belong to an organisation owner and carry `read:audit_log`. It is long-lived and powerful, and it would sit on the SCDC server.

So enabling `<github>` in `ossec.conf` today would only produce module errors. It is left out of the managed block on purpose.

## 2. What the OmniAxis webhook watches today

Source: `apps/app/lib/security-intake/github-events.ts` on `OmniAxis` `origin/main`. It reads code only; nothing was changed.

| GitHub webhook event | OmniAxis event | Audit-log equivalent (Enterprise Cloud only) | Covered by the Wazuh module? |
|---|---|---|---|
| `member`, `membership`, `organization` (member added, removed, invited, role) | `github.member_changed` | `org.add_member`, `org.remove_member`, `org.invite_member`, `org.update_member` | Yes, with Enterprise Cloud |
| `organization` (renamed, deleted) | `github.org_changed` | `org.rename`, `org.delete` (delete is moot) | Yes, with Enterprise Cloud |
| `repository` (publicized, created public, deleted, archived, transferred…) | `github.repository.publicized` / `repository_changed` | `repo.access`, `repo.create`, `repo.destroy`, `repo.archived`, `repo.transfer` | Yes, with Enterprise Cloud |
| `branch_protection_rule`, `branch_protection_configuration`, `repository_ruleset` | `github.branch_protection_changed` | `protected_branch.*`, `repository_ruleset.*` | Yes, with Enterprise Cloud |
| `deploy_key` | `github.deploy_key_changed` | `public_key.create` / `public_key.delete` (repo deploy keys) | Yes, with Enterprise Cloud |
| `installation`, `installation_repositories`, `github_app_authorization` | `github.app_changed` | `integration_installation.*`, `oauth_authorization.*` | Mostly, with Enterprise Cloud |
| `personal_access_token_request` | `github.token_request` | `personal_access_token.*` | Yes, with Enterprise Cloud |
| `security_and_analysis` | `github.security_analysis_changed` | `repo.*_enable`/`_disable` for security features | Partly |
| `dependabot_alert`, `repository_vulnerability_alert` | `github.dependabot_alert` | **Not in the audit log** (alerts are not audit events) | **No** |
| `meta` (webhook deleted) | `github.hook_deleted` | `hook.destroy` | Yes, with Enterprise Cloud |
| `ping` | `github.ping` | n/a | n/a |
| OmniAxis's poll (drift checks) | various | n/a | No |

Two more gaps remain even with Enterprise Cloud:
- **Latency.** The module polls (default every 10 minutes, with a 30-second delay). The webhook is near-real-time.
- **Dependabot and vulnerability alerts** never appear in the audit log.

## 3. Recommendation

Keep OmniAxis's GitHub webhook as the source of these signals. **Do not** buy Enterprise Cloud for this.

Move the webhook up to the SCDC as a product feed: OmniAxis sends its `github.*` events as signed SCDC contract events (`source: "omniaxis"`, `type: "github.branch_protection_changed"`, and so on), with the GitHub repository as `refs.resource`. The ruleset already gives `omniaxis` events their own group and severity bands. The webhook stays at organisation level, so Musterward's repository events arrive too. The product label is then decided by the repository name, not by who receives the webhook. That fixes today's mislabelling instead of hiding it.

If the organisation later moves to Enterprise Cloud for other reasons, enable the module as a cross-check. Use a dedicated owner token with `read:audit_log` only. Note that the module takes the token inline in `ossec.conf`, which the `wazuh` group can read. Set `event_type` to `all`. It would catch changes made while the webhook was down or deleted.
