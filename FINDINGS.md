# Uber Driver App - Reverse Engineering Findings

## Key Webview URLs (loaded in-app as webviews — no SSL pinning on these)

### Payment/Banking (most relevant)
- `https://payments.uber.com/` — Payment hub
- `https://payments.uber.com/edit/` — Edit payment method
- `https://payments.uber.com/payment-history` — Payment history
- `https://payments.uber.com/3ds-web-initialize` — 3DS verification
- `https://earner-payments.uber.com/repayments` — Earner repayments
- `https://finprod.uber.com/financing/` — Financial products
- `https://finprod.uber.com/pcp/management` — Card management
- `https://partners.uber.com/p3/payments/cartop` — Payments page
- `https://partners.uber.com/p3/payments/v2/trips/` — Trip payments
- `https://partners.uber.com/p3/tax-profile` — Tax profile
- `https://pay.hyperwallet.com/` — Third-party payout provider

### Earnings
- `https://drivers.uber.com/earnings/webview/` — Earnings webview
- `https://drivers.uber.com/earnings/trips/` — Trip earnings

### Auth
- `https://auth.uber.com/v2` — Authentication
- `https://auth.uber.com/oauth/client/social/authorize` — OAuth
- `https://login.uber.com` — Login
- `https://accounts.uber.com` — Account management

### Other Webviews
- `https://helix-go-webview.uber.com/go/home` — Driver home webview
- `https://drivers.uber.com/earner-profile/copilot` — Driver profile
- `https://bonjour.uber.com/work-hub` — Onboarding

## Critical API Endpoints (gRPC-style /rt/ routes)

### Cash Out / Instant Pay
- `/rt/payment/earner/ondemand_disbursement/cashout_data` — Get cashout info
- `/rt/payment/earner/ondemand-disbursement/makedisbursement` — Execute cashout

### Payment Profiles (Bank Accounts)
- `/rt/payment/v3/payment-profiles` — List payment profiles
- `/rt/payment/v3/payment-profiles/` — Get/modify profiles
- `/rt/payment/v3/payment-profiles/default` — Set default profile
- `/rt/payment/v3/payment-profiles/balance` — Get balance
- `/rt/payment/v3/payment-profile-finalize` — Finalize profile changes

### Earner Payments Management
- `/rt/payments/onboarding/get_earner_payments_management` — Get payment management UI
- `/rt/payments/onboarding/get_earner_first_payout_experience` — First payout setup
- `/rt/payments/onboarding/get-payment-onboarding-menu` — Payment onboarding
- `/rt/payments/onboarding/list_onboarding_flows` — List payment setup flows
- `/rt/payments/onboarding/perform_step` — Execute a step in payment setup

### Payment Selection
- `/rt/payments/selection/switcher` — Switch payment method
- `/rt/payments/selection/optionchanged` — Change payment option
- `/rt/payments/selection/bar` — Payment selection bar

### Earnings
- `/rt/earnings/get-balance-summary` — Balance summary
- `/rt/earnings/get-daily-earnings-view` — Daily earnings
- `/rt/earnings/get-weekly-earnings-view` — Weekly earnings

### Earner Debit Card
- `/rt/earnerdebit/updateAutoDisbursementPreference` — Change auto-disbursement
- `/rt/earnerdebit/getentrypointrouting` — Entry point routing
- `/rt/earnerdebit/getidentity` — Identity for debit card

### Wallet
- `/rt/payments/wallet/home` — Wallet home
- `/rt/payments/wallet/account-details` — Account details
- `/rt/payments/wallet/account-feed` — Account transactions

### Auth Cookie Bridge (webview ↔ native)
- `/rt/identity/auth/issue-web-auth-cookies` — Issue auth cookies for webviews
- `/rt/unused/non-production-endpoint/uber-payments-auth-bridge/from-web`
- `/rt/unused/non-production-endpoint/uber-payments-auth-bridge/to-web`
- `/rt/unused/non-production-endpoint/uber-payments-auth-bridge/request-redirect-url`

## WebView Bridge Architecture
- Uses `window.CarbonBridge.postMessage()` for native ↔ web communication
- Uses `window.presidio.bridge.postMessage()` for auth bridge
- Cookie-based auth: app issues web auth cookies via `/rt/identity/auth/issue-web-auth-cookies`
- `FinProdWebMessagesBridgeWorker` handles financial product webview messages
- `shared_cookie_jar_bridge_enabled` flag for cookie sharing

## Key Classes (from DEX analysis)
- `BankAccountAdd*` — Add bank account flow
- `BankAccountEdit*` — Edit bank account flow
- `CashOut*` / `CashoutAmount*` — Cash out flow
- `EarnerPayment*` — Earner payment management
- `FinProdWebView*` — Financial products webview
- `PaymentProfile*` — Payment profile management

## Attack Vectors for Automation

### 1. Web Portal (easiest)
- `drivers.uber.com` and `partners.uber.com` have webview versions
- Login at `auth.uber.com`, get cookies, access payment pages
- Automate with Playwright/Puppeteer

### 2. WebView Cookie Injection (medium)
- App uses `/rt/identity/auth/issue-web-auth-cookies` to auth webviews
- If we capture that cookie, we can load payment webviews in a browser
- The cookie jar bridge shares cookies between native and webview

### 3. Direct API Calls (hardest but most powerful)
- `/rt/payment/v3/payment-profiles` to list/modify bank accounts
- `/rt/payments/selection/switcher` to switch payment method
- `/rt/payment/earner/ondemand-disbursement/makedisbursement` for cashout
- Need: auth token, correct headers, protobuf/JSON format

### 4. UI Automation (guaranteed to work)
- ADB + uiautomator to tap through screens
- No API or SSL knowledge needed
- Slow but reliable
