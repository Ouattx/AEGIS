# Sales kit

| Document | Use it for |
|---|---|
| [PRODUCT_SHEET.md](PRODUCT_SHEET.md) / [PRODUCT_SHEET_FR.md](PRODUCT_SHEET_FR.md) | one-page leave-behind (English / French) |
| [SHADOW_PILOT_OFFER.md](SHADOW_PILOT_OFFER.md) | the paid pilot: scope, timeline, deliverables, success criteria, pricing placeholders |
| [PILOT_SOW_TEMPLATE.md](PILOT_SOW_TEMPLATE.md) | statement-of-work template (counsel review required) |
| [SECURITY_QUESTIONNAIRE.md](SECURITY_QUESTIONNAIRE.md) | pre-answers for the operator's vendor-security questionnaire |
| [DEMO_SCRIPT.md](DEMO_SCRIPT.md) | the 10-minute demo, click by click |
| [OBJECTION_HANDLING.md](OBJECTION_HANDLING.md) | answers to the objections ISPs raise |
| [CLAIMS_GUIDE.md](CLAIMS_GUIDE.md) | what we can and cannot claim; read before writing anything external |

For the DPO and counsel: [../compliance/](../compliance/). For the operator's engineers:
[../INSTALL.md](../INSTALL.md) and [../OPERATOR_INTEGRATION.md](../OPERATOR_INTEGRATION.md).

Before anything leaves the company: render the kit from the commercial configuration
(`python deploy/tools/render_sales_kit.py --config commercial.toml --out dist/sales`, starting from
[commercial.example.toml](commercial.example.toml)); the renderer refuses while any `FOUNDER TO SET` value is
missing, so only rendered copies are ever sent. The claims guide review must be done, and every legal template
must have been through counsel.
