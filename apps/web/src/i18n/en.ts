/**
 * English strings.
 *
 * Every user-facing string goes through here even though English is the only
 * language in the MVP. Adding Albanian later is then a new dictionary rather
 * than a hunt through JSX for hardcoded text -- which is the cheap-now,
 * expensive-later trade the spec calls out.
 */
export const en = {
  app: {
    name: "Cleave",
    tagline: "Cloud security posture, in plain language",
  },
  nav: {
    dashboard: "Dashboard",
    changes: "Changes",
    reports: "Reports",
    settings: "Settings",
    assets: "Assets",
    findings: "Findings",
    risks: "Risks",
    attackPaths: "Attack paths",
    remediation: "Remediation",
    scans: "Scans",
    rules: "Rules",
    connections: "Connections",
    compliance: "Compliance",
    signOut: "Sign out",
  },
  account: {
    menu: "Account menu",
    signedInAs: "Signed in as",
    organization: "Organization",
    switchTo: "Switch to",
    currentOrg: "Current organization",
    newOrganization: "Create organization",
    settings: "Environments",
    unknownUser: "Signed in",
    removeOrg: "Remove organization",
    removingOrg: "Removing\u2026",
    removeOrgTitle: "Remove",
    removeOrgDetail:
      "Its cloud connections, discovered accounts, assets, scan history, findings and risks are all deleted with it. This cannot be undone.",
    removeOrgOwnerOnly: "Only an owner can remove an organization.",
    keep: "Keep it",
  },
  auth: {
    signIn: "Sign in",
    signUp: "Create your account",
    email: "Email address",
    password: "Password",
    continue: "Continue",
    sendLink: "Send sign-in link",
    checkEmail: "Check your email",
    linkSentTo: "We sent a sign-in link to",
    confirmSentTo: "We sent a confirmation link to",
    resetSentTo: "We sent a password reset link to",
    openOnThisDevice: "Open it on this device to continue.",
    passwordNotice:
      "Your password goes from this browser straight to the identity provider. Cleave's API never receives it, and stores no cloud credential of yours at all.",
    continueWithMicrosoft: "Continue with Microsoft",
    orDivider: "or",
    forgotPassword: "Forgot password",
    magicLinkInstead: "Email me a one-time link instead",
    passwordInstead: "Use a password instead",
    noAccount: "Don't have an account?",
    haveAccount: "Already have an account?",
    createOne: "Create one",
    resetTitle: "Reset your password",
    resetIntro: "Enter your email and we'll send you a link to set a new one.",
    sendReset: "Send reset link",
    newPassword: "New password",
    setPassword: "Set new password",
    passwordUpdated: "Password updated",
    passwordTooShort: "Use at least 8 characters.",
    showPassword: "Show password",
    hidePassword: "Hide password",
    creatingAccount: "Creating account\u2026",
    signingIn: "Signing in\u2026",
    sending: "Sending\u2026",
    backToSignIn: "Back to sign in",
    useAnotherAddress: "Use a different address",
    microsoftHint:
      "Signing in with Microsoft does not give Cleave access to your Azure resources \u2014 that is a separate consent step.",
  },
  // The dashboard's getting-started checklist. Every step is read off state
  // the server already holds, so the list is right on any device and for any
  // teammate -- nothing here is remembered by the browser except a dismissal.
  demo: {
    explore: "Explore a demo environment",
    exploreDetail: "A recorded Azure estate, scanned by Cleave. Read-only, nothing to set up.",
    opening: "Opening the demo\u2026",
    unavailable: "The demo is not available right now.",
    badge: "Demo",
    bannerTitle: "You are exploring the Cleave demo",
    bannerDetail:
      "A recorded Azure estate, scanned by the real product. Everything here is read-only.",
    createOwn: "Create your organization",
    backTo: "Back to {name}",
    leave: "Leave the demo",
    readOnlyAction: "Read-only in the demo",
  },
  gettingStarted: {
    title: "Get Cleave working for you",
    intro: "Five steps from a connected cloud to a fix you can prove.",
    progress: "{done} of {total} done",
    dismiss: "Hide this checklist",
    connectTitle: "Connect your cloud environment",
    connectDetail: "Read-only access, granted by your administrator. About 3 minutes.",
    connectAction: "Connect a cloud",
    continueAction: "Continue setup",
    scanTitle: "Run your first scan",
    scanDetail: "Cleave reads the environment and scores what it finds.",
    scanAction: "Run a scan",
    fixTitle: "Fix your top risk and verify it",
    fixDetail: "Apply the fix, rescan, and watch Cleave confirm it is gone.",
    fixAction: "Open the top risk",
    fixActionFallback: "Open findings",
    scheduleTitle: "Turn on automatic scanning",
    scheduleDetail: "Keep the posture current without anyone remembering to scan.",
    scheduleAction: "Choose a schedule",
    contextTitle: "Say what each environment is for",
    contextDetail: "Criticality and data sensitivity sharpen every risk score.",
    contextAction: "Declare in Settings",
    waitingOnPrevious: "After the step before",
    next: "Next",
  },
  onboarding: {
    createOrg: "Create your organization",
    orgName: "Organization name",
    industry: "Industry",
    country: "Country",
    create: "Create organization",
    step: "Step",
    // The prototype says the first scan "runs on its own" after connecting. It
    // does not: the setup wizard ends on "Run the first scan".
    intro:
      "This takes about a minute. Next you connect your cloud, which takes about 3 more, and then run the first scan.",
    stepOrganization: "Name your organization",
    stepCloud: "Connect your cloud",
    orgNameHelp: "The name that appears on reports and exported evidence.",
    optional: "optional",
    countryHelp: "Two-letter code, used for compliance context.",
    demoTitle: "Look around a recorded estate first",
    demoDetail:
      "A real scan of a demo environment — real rules, real risk engine, nothing of yours connected.",
  },
  connection: {
    title: "Environments",
    intro: "Everything Cleave reads from. New subscriptions are picked up automatically.",
    connectCloud: "Connect environment",
    comingSoon: "Coming soon",
    noConnections: "No cloud environment connected yet.",
    noConnectionsHelp:
      "A few minutes and one deployment you run yourself. No credential is asked for.",
    step: "Step",
    of: "of",
    stepConsent: "Grant admin consent",
    stepDeploy: "Deploy the scanner role",
    scope: "Scope",
    cloud: "Cloud",
    connectionName: "Connection name",
    managementGroupId: "Management group id",
    subscriptionId: "Subscription id",
    create: "Continue",
    cancelSetupAction: "Cancel setup",
    resumeSetup: "Resume setup",
    setupCancelled: "Setup cancelled",
    readyToScan: "Ready to scan",

    // Scheduling. Off by default, and the copy says why rather than leaving a
    // dropdown to explain itself: a customer choosing an interval is choosing
    // a recurring cost on their own Azure bill.
    scheduleTitle: "Automatic scanning",
    scheduleLabel: "Re-read this environment",
    scheduleManual: "Only when I ask",
    scheduleEvery6Hours: "Every 6 hours",
    scheduleDaily: "Every day",
    scheduleEvery3Days: "Every 3 days",
    scheduleWeekly: "Every week",
    scheduleSaving: "Saving\u2026",
    scheduleSaved: "Saved",
    scheduleOn: "Scanning automatically",
    scheduleOff: "Manual scanning only",
    scheduleFirstRunNote:
      "The first automatic scan starts within minutes, then runs on this interval.",
    scheduleFloorNote: "At least this often \u2014 an interval, not a time of day.",

    // Change-triggered scanning. Two things have to survive the copy: that
    // turning it on wires nothing up on its own, and *why* -- CloudGuard holds
    // no write permission in the customer's tenant and will not ask for one.
    changeTitle: "React to changes",
    changeHelp: "Scans when something changes, not on a clock.",
    changeHelpExplain:
      "A schedule reads this environment on a clock. This reads it when something actually moves \u2014 a port opened, a role assigned, a storage account made public \u2014 so the finding arrives while whoever made the change is still at their desk.",
    changeTimingExplain:
      "A burst of changes becomes one scan, not one per event: Cleave waits for {quiet} minutes of quiet, and scans a connection at most once every {interval} minutes for change.",
    changeOn: "Listening for changes",
    changeOff: "Not listening",
    changeSaving: "Saving\u2026",
    changeNotWired:
      "The webhook is open. Nothing reaches it until you run the command below in each account \u2014 Cleave cannot create that wiring for you, because it holds no write permission in your cloud and does not ask for one.",
    changeCommandsLabel: "Run this once per account",
    // AWS needs three commands rather than one, and the reason is worth
    // stating: there is no single AWS call that points a rule at an HTTPS
    // endpoint, so the delivery goes through a topic the customer owns.
    changeCommandsLabelAws: "Run these once per account",
    changeNotWiredAws:
      "The webhook is open. Nothing reaches it until you run the commands below \u2014 EventBridge cannot deliver to an HTTPS endpoint on its own, so the change goes through an SNS topic in your account. Cleave creates none of it: it holds no write permission in your cloud and does not ask for one.",
    changeCopyCommand: "Copy command",
    changeNoEndpoint: "Cleave has no public address to receive deliveries",
    changeNoEndpointHelp:
      "This deployment has no public API base URL configured, so there is no endpoint for your cloud to deliver to. Change detection cannot be wired up until that is set.",
    changeLastEvent: "Last change heard",
    changeNeverHeard: "Nothing yet",
    changePending: "A change is settling; a scan starts once the environment is quiet",

    // The empty state, which is the first meaningful screen in the product.
    readWhatItDoes: "Read what Cleave will do",
    hideWhatItDoes: "Hide the detail",
    readOnlyPromise:
      "Read-only: it cannot change configuration or read data in storage, databases or vaults.",
    permissionsTitle: "The exact access Cleave asks for",
    graphPermissions: "Directory permissions",
    rbacRole: "Azure role",
    writesPerformed: "Writes performed",
    permissionsUnavailable:
      "This list comes from the API and could not be loaded. It is the same list Microsoft shows on the consent screen, which is the copy that actually governs.",

    // The connections list: one row per connection, opened for the detail.
    columnConnection: "Connection",
    columnStatus: "Status",
    // Column heading and section headings are rendered from the connection's
    // own vocabulary (lib/vocabulary.ts) where a provider is in hand. These
    // remain for the table header, which spans connections to both clouds and
    // so cannot be either one's word alone.
    columnSubscriptions: "Accounts",
    columnLastRead: "Last read",
    columnActions: "Actions",
    allInScope: "all in scope",
    someInScope: "in scope",
    expandRow: "Show this connection's detail",
    collapseRow: "Hide this connection's detail",
    scanNow: "Scan now",
    scanStarting: "Starting\u2026",
    scanQueued: "Scan queued",
    changeSchedule: "Change schedule",
    cadenceTitle: "How often this is read",
    cadenceLastRead: "Last read",
    cadenceNeverRead: "Not yet",
    cadenceClock: "On a clock",
    cadenceOnChange: "On change",
    accessTitle: "Access",
    scannerRole: "Scanner role",
    readerRole: "Reader role",
    verifiedOn: "verified",
    roleBehind: "behind",
    roleUpgradeTitle: "Some checks cannot run until the role is redeployed",
    roleUpgradeBody:
      "Cleave's scanner role gained permissions this connection was not " +
      "granted. The checks that need them report \u201cnot known\u201d " +
      "rather than passing \u2014 Cleave will not tell you something is " +
      "fine when it could not look.",
    roleUpgradeAffects: "Affected checks",
    consentIncomplete: "Granted, incomplete",
    permissionsMissingTitle: "Identity checks cannot run until consent is complete",
    permissionsMissingBody:
      "Admin consent completed, but it did not grant these directory " +
      "permissions. Subscription scanning is unaffected. Cleave's app " +
      "registration must declare them as application permissions \u2014 " +
      "delegated ones never reach a scanner \u2014 and a Global " +
      "Administrator must then consent again, because consent covers only what " +
      "the registration declared when it was granted.",
    roleUpgradeAction: "Redeploy the role",
    writePermission: "Write permission",
    noneByDesign: "None, by design",
    recheckAccess: "Re-check access",
    firstSeen: "first seen",
    newSinceLastRead: "new since last read",
    excludedByYou: "excluded by you",
    moreSubscriptions: "more",
    discoveryPromise: "Anything created beneath this connection appears here on the next read.",
    scopeFootnote:
      "Unticking one stops Cleave reading it. Its findings are kept, marked out of scope.",

    noSubscriptionsTitle: "Nothing found yet",
    noSubscriptionsBody:
      "The grant is working, but Cleave cannot see anything to scan. Access granted moments ago can take a few minutes to show up, and a grant deployed to the wrong scope will never show up at all.",
    lookAgain: "Look again",
    lookingAgain: "Looking…",
    runFirstScan: "Run a scan",
    noSubscriptionsYet: "Nothing discovered yet",
    noSubscriptionsYetHelp:
      "The connection is verified but nothing was found beneath it. If the grant was deployed at a narrower scope than this connection covers, nothing beneath it is visible.",
    cannotStartConsent: "Cleave cannot start the consent flow",
    cannotDeployYet: "Cleave cannot generate the deployment yet",
    whoYouNeed: "Who you will need",
    openConsent: "Open admin consent",
    copyConsentLink: "Copy link for your administrator",
    consentExpiry: "This link works once and expires in 30 minutes.",
    waitingForConsent: "Waiting for admin consent\u2026",
    consentGranted: "Admin consent granted",
    copied: "Copied",
    waitingForAccess: "Waiting for the read access grant\u2026",
    verified: "Connection verified",
    discovered: "found",
    inScopeCount: "in scope",
    inScope: "Scan this",
    saveScope: "Save selection",
    done: "Done",
    lastDiscovery: "Last checked",
    neverDiscovered: "Not yet discovered",
    consentSignal: "Admin consent",
    accessSignal: "Read access",
    readySignal: "Ready to scan",
    granted: "Granted",
    notGranted: "Not granted",
    notVerified: "Not verified",
    yes: "Yes",
    notYet: "Not yet",
    whatItReads: "The exact operations Cleave performs",
    principalId: "Service principal",
    scopePath: "Scope",
    cancel: "Cancel",
    cancelSetup: "Cancel setup",
    close: "Close",
    finishLater: "Finish later",
    discard: "Discard connection",
    discarding: "Discarding\u2026",
    discardTitle: "Discard this half-finished connection?",
    discardDetail: "Nothing has been scanned, so nothing is lost. Or leave it and resume later.",
    remove: "Remove connection",
    removing: "Removing\u2026",
    removeTitle: "Remove this connection?",
    removeDetail:
      "Its accounts, assets, scans and findings are deleted with it. This cannot be undone.",
    revokeTitle: "Revoke access in Azure",
    revokeIntro:
      "Removing the connection here deletes Cleave's copy of the data. It does not take away the access you granted \u2014 run these in Azure to do that.",
    checkRevoked: "Check whether access is gone",
    checking: "Checking\u2026",
    stillHasAccess: "Cleave can still read this environment",
    accessGone: "Confirmed: access revoked",
    removeAzureNote:
      "This does not revoke anything in Azure. To withdraw the access you granted, remove Cleave from Enterprise applications in Entra ID and delete its role assignment.",
    keep: "Keep it",
    notConfigured: "This Cleave deployment cannot connect Azure yet",
    notConfiguredDetail:
      "This is a setup step on Cleave's side, not yours \u2014 whoever operates this deployment needs to register its Entra application (docs/AZURE_INTEGRATION.md \u00a72.1).",
  },

  // The setup wizard. Its own block rather than more keys on `connection`,
  // because these strings are read in one sitting by somebody who has never
  // seen the product before, and they have to make sense in sequence.
  setup: {
    title: "Connect Azure",
    intro: "2 grants, about 3 minutes. No tenant id, subscription id or credential needed.",
    backToConnections: "Back to environments",
    railTitle: "What the 3 minutes look like",

    stepScope: "Choose the scope, and name it",
    stepScopeDetail: "A tenant, a management group or one subscription, under a name you choose.",
    stepConsent: "A Global Administrator grants admin consent",
    stepConsentDetail:
      "One Microsoft prompt per tenant. If that is not you, send the link Cleave gives you.",
    stepDeploy: "Deploy the reader role",
    stepDeployDetail: "One ARM template in Azure Portal. Needs Owner at the scope you chose.",
    stepAccounts: "Then Cleave finds the rest",
    stepAccountsDetail: "Every subscription beneath the scope, including ones created later.",

    // The wizard's frame: the header's facts, the rail's heading, the footer.
    // Short on purpose -- each one states a fact the intro used to spend a
    // sentence on, so the page can be scanned rather than read.
    railHeading: "Setup",
    // Under a finished row of the rail: what that step settled, read off the
    // connection.
    railDone: "Done",
    railConsented: (date: string) => `Granted ${date}`,
    railVerified: (date: string) => `Verified ${date}`,
    metaDuration: "About 3 minutes",
    metaReadOnly: "Read-only",
    metaNoCredentials: "No credential to hand over",
    footerPromise: "Read-only. Cleave never changes your resources.",

    // Step one, as cards rather than paragraphs.
    providerDetailAzure: "Entra ID consent and a read-only Azure role",
    providerDetailAws: "A read-only IAM role, deployed with CloudFormation",
    providerUnavailable: "Unavailable",
    operatorNotes: "Notes for whoever runs this deployment",
    nameHelp: "Shown on every finding, report and scan from this environment.",
    scopeTagWidest: "Full coverage",
    scopeTagNarrowest: "Quickest",
    permissionNeeded: "Permission needed",
    beforeYouStart: "Before you start",
    needFirstTitle: "A Global Administrator",
    needFirstDetail:
      "Approves admin consent once. A work or school account \u2014 a personal one cannot.",
    needSecondTitle: "Owner at the scope you choose",
    needSecondDetail:
      "Or User Access Administrator, to assign the read-only role. Often someone else.",
    noIdsNeeded:
      "No tenant id, subscription id or secret. Entra reports the tenant when consent is granted.",

    // The two steps that leave for the provider, and come back on their own.
    opensInNewTab: "Opens in a new tab",
    detectedAutomatically:
      "Detected automatically. You can close this page \u2014 setup carries on where it stopped.",
    publishingPrincipal: "Setting Cleave up in your directory\u2026",
    publishingPrincipalDetail: (left: string) =>
      "Entra can take a few minutes to publish Cleave in a directory that " +
      "has just consented. Cleave checks every few seconds and moves on by " +
      `itself; if it is still not there in ${left}, the reason will show here.`,
    deployHowTitle: "What happens next",
    deployHow1: "Open the Azure portal",
    deployHow1Detail: "Signed in as an Owner at the scope you chose.",
    deployHow2: "Review and create",
    deployHow2Detail: "The template is pre-filled. There is nothing to type.",
    deployHow3: "Cleave picks it up",
    deployHow3Detail: "Usually within a minute of the deployment finishing.",

    // The last step, once something can be scanned.
    doneHeadline: "{name} is connected",
    doneSummary:
      "{inScope} of {total} {accounts} in scope \u00b7 nothing is read until the first scan",
    runFirstScan: "Run the first scan",

    // AWS says the same four things in its own words, and one fewer of them.
    // Held as an override rather than as a second copy of the whole block:
    // most of setup is identical, and two full sets would drift.
    aws: {
      title: "Connect AWS",
      intro:
        "One stack and about 2 minutes. There is no consent screen and no credential to hand over \u2014 you deploy a read-only role, and Cleave proves it works by using it.",
      stepScope: "Choose the scope, and name it",
      stepScopeDetail:
        "A whole organization, one organizational unit, or a single account. Either way you name the account Cleave starts from.",
      stepDeploy: "Deploy the scanner stack",
      stepDeployDetail:
        "One CloudFormation stack, pre-filled. It creates a read-only role that only Cleave can assume, and only with the external id below.",
      stepAccounts: "Then Cleave finds the rest",
      stepAccountsDetail:
        "Every account in the organization is discovered and kept in step \u2014 including the ones opened after today.",
      metaDuration: "About 2 minutes",
      needFirstTitle: "Access to the account",
      needFirstDetail:
        "Permission to create a CloudFormation stack and an IAM role in the account you name.",
      needSecondTitle: "The account id",
      needSecondDetail:
        "Twelve digits, from the account menu in the top-right corner of the AWS console.",
      noIdsNeeded:
        "No access key and no secret. Cleave assumes the role you deploy, and only with the external id it generates.",
      deployHow1: "Open CloudFormation",
      deployHow1Detail: "Signed in to the account you named.",
      deployHow2: "Acknowledge and create",
      deployHow2Detail: "Tick the IAM acknowledgement, then create the stack.",
      deployHow3Detail: "Usually within a minute of the stack reaching CREATE_COMPLETE.",
      deployTitle: "Deploy the scanner stack",
      deployBody:
        "This creates one IAM role in your account. Every permission on it is a read of configuration \u2014 nothing it grants can read the contents of a bucket, a database or a secret.",
      launchStack: "Launch stack in AWS",
      externalIdTitle: "Your external id",
      externalIdBody:
        "The stack requires this value before the role can be assumed, and Cleave generated it for this connection alone. It is not a password: on its own it grants nothing, and it is useless to anyone without a role that demands it. Check it appears in the trust policy you are about to create.",
      roleArnTitle: "The role Cleave will assume",
      stackScopeOrganization:
        "Deployed in the management account you named. Use a StackSet to reach the member accounts, or run the same stack in each.",
      stackScopeAccount: "Deployed in the one account you named.",
      organizationId: "Management account id",
      organizationalUnitId: "Organizational unit id",
      accountId: "Account id",
      scopeOrganization: "Entire organization",
      scopeOrganizationDetail: "Discover and scan every account in the organization.",
      scopeOrganizationRequires:
        "Needs permission to create the stack in the management account, and a StackSet or one deployment per member account.",
      scopeOrganizationalUnit: "Organizational unit",
      scopeOrganizationalUnitDetail: "Limit to the accounts under one organizational unit.",
      scopeOrganizationalUnitRequires: "Needs the same stack in each account beneath the unit.",
      scopeAccount: "Single account",
      scopeAccountDetail: "Scan one account only.",
      scopeAccountRequires:
        "Needs permission to create a stack and an IAM role in that account \u2014 usually the easiest to complete.",
    },

    // Consent step.
    consentTitle: "Ask a Global Administrator to consent",
    consentBody: "One Microsoft prompt, granted once for the whole directory. It scans nothing.",
    consentBodyExplain:
      "Consent is what lets Cleave ask your directory who exists \u2014 its users, groups and applications. Nothing is read from a subscription until the scanner role is deployed and a scan runs.",
    notAdmin: "I am not a Global Administrator",
    handoffTitle: "Send it to someone who is",
    handoffBody: "The link works once and expires in 30 minutes. This page keeps waiting.",
    handoffMessage:
      "Please open this link and approve read-only access for Cleave, our cloud security tool. It needs a Global Administrator, takes one click, and grants no permission to change anything:",
    copyMessage: "Copy the message",
    consentFailed: "Admin consent did not complete",
    consentRetry: "Start consent again",

    // Deploy step.
    deployTitle: "Grant read access at the scope you chose",
    deployBody: "The template is pre-filled. Azure Portal opens on a review screen.",
    deployToAzure: "Deploy to Azure",
    stalledTitle: "This is taking longer than a deployment should",
    stalledBody: "The 3 things that usually explain it, in the order they are worth checking:",
    stalledPropagation:
      "A role assigned in the last few minutes has not propagated yet. Waiting a little longer is the fix.",
    stalledScopeTenant:
      "The deployment landed on a subscription rather than the tenant root. A connection covering the whole tenant only sees a role assigned at the root management group.",
    stalledScopeGroup:
      "The deployment landed on a subscription rather than on the management group this connection covers.",
    stalledScopeSubscription:
      "The deployment landed on a different subscription from the one this connection covers.",
    stalledOwner:
      "Whoever ran it holds Contributor rather than Owner or User Access Administrator. Contributor can deploy a template but cannot assign a role, and Azure reports that as a failed deployment rather than a missing permission.",
    checkAgain: "Check again",
    checking: "Checking\u2026",
    changeScope: "Choose a different scope",

    // The accounts step.
    discoverTitle: "Looking for what is beneath it",
    reviewTitle: "Choose what Cleave reads",
    reviewBody: "Everything beneath the scope is in scope. Untick any Cleave should not read.",
    reviewBodyExplain:
      "Unticking one stops Cleave reading it. Findings it already has are kept and marked out of scope, not deleted, and a subscription created later is picked up on its own.",
    nothingInScopeTitle: "Nothing is ticked, so nothing will be read",
    nothingInScopeBody: "Nothing is in scope. Tick at least one, or leave it and tick one later.",
    doneTitle: "Connected",
    backToList: "Back to connections",

    // Footer, on every step, and the way back in from the connections list.
    continueSetup: "Continue setup",
    finishLater: "Finish later",
    paused: "Setup is paused",
    pausedBody: "Nothing was scanned or granted. Pick it up when the right person is free.",
  },

  dashboard: {
    title: "Security posture",
    score: "Security score",
    outOf: "out of 100",
    trendTitle: "Score over time",
    trendTooShort:
      "One scan so far. A second one gives Cleave something to compare against, and this becomes a line.",
    scoreWorse: "since last scan",
    noPreviousScan: "No previous scan to compare against",
    sinceLastScan: "since last scan",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    topRisk: "Top risk",
    topRisks: "What matters most right now",
    remediation: "Verified fixes",
    resolvedRecently: "verified fixed in the last 30 days",
    coverage: "Assessment coverage",
    coverageHelp:
      "How much of your environment Cleave could conclusively assess. Tracked separately from your score so the score stays easy to explain.",
    assets: "Assets discovered",
    noScans: "No scan has run yet",
    noScansHelp: "Connect a cloud environment and run your first scan to see your posture.",
    runFirstScan: "Run your first scan",
    allClear: "No open findings. Nice.",
    couldNotLoad: "Couldn't load your dashboard",
    signInAgain: "Sign in again",
    openFindings: "Open findings",
    lastScan: "Last scan",

    // The overview's question marks (DECISIONS.md §166, §178): the page says
    // what each panel is in a line, and how it is measured here.
    today: "Today",
    openRisks: "Open risks",
    attackRoutes: "Attack routes",
    checksVerdicted: "Checks with a verdict",
    scoreExplainLabel: "How the score is worked out",
    scoreExplain:
      "Deducted against each finding's risk band \u2014 what it means on the asset it was found on \u2014 not the number of alerts raised. Checks with no verdict take nothing off and add nothing: they are counted under coverage instead.",
    priorityExplainLabel: "How risks are ranked",
    priorityExplain:
      "Ranked by what each would cost this business, not by how many alerts fired. Each row names the terms that raise its score: internet exposure, data sensitivity and asset criticality.",
    cutExplainLabel: "What the link to cut is",
    cutExplain:
      "The single change that closes the most routes from something exposed to something sensitive. The count is what cutting it alone closes; two cuts can close together what neither closes alone, so a plan is simulated whole.",
    coverageExplainLabel: "What coverage measures",
    coverageExplain:
      "The share of applicable checks that reached any verdict, pass or fail. It is not a security score. A check whose evidence could not be read reports no verdict, never a pass. Risks on assets Cleave could not classify are ranked as though they matter, but the score is charged only for what was established.",
    complianceExplainLabel: "What compliance coverage means",
    complianceExplain:
      "How many of each framework's controls reached a conclusion at the last scan, out of all of them. It says what Cleave can speak to, never whether you comply.",
  },
  findings: {
    pageExplainLabel: "How findings are ranked",
    pageExplain:
      "Ranked by what each means on the asset it was found on \u2014 how exposed it is, what data it holds and how critical it is \u2014 not by how loudly the rule fired. A finding closes only when a later scan observes the fix.",
    title: "Findings",
    empty: "No findings match these filters.",
    whyItMatters: "Why this matters",
    evidence: "Evidence",
    provenance: "How we know",
    restingOnReading: "Resting on one reading",
    provenanceIntro:
      "Where the evidence above came from \u2014 which listing, when the provider was read, and under which permission.",
    // `null` from the API: a fact about CloudGuard, not about this finding.
    provenanceUnrecorded:
      "This finding was raised before Cleave recorded where its evidence came from. The next scan that detects it will.",
    // `[]`: a fact about the rule, and a different sentence for that reason.
    provenanceNone: "This check reads no collected evidence.",
    provenanceRead: "Read",
    provenanceItems: "{count} items",
    provenanceUnder: "Read under",
    provenancePayload: "Capture",
    provenanceHeld: "Still stored",
    // The citation outlives the bytes on purpose, so this is a statement about
    // retention rather than an error.
    provenancePruned: "No longer stored",
    provenanceRule: "Evaluated by {rule} v{version}",
    controlsTitle: "What is standing in the way",
    controlsHelp:
      "Defences Cleave observed in the same reading. They make this harder to exploit without making it right, so this finding is ranked lower than it otherwise would be \u2014 and it is still open, because every one of them can be switched off, rescoped or have this account excluded in a change nobody reviews.",
    controlsStillNeeded: "An attacker still needs",
    howToFix: "How to fix it",
    riskScore: "Risk score",
    effort: "Estimated effort",
    minutes: "min",
    asset: "Asset",
    firstSeen: "First detected",
    lastSeen: "Last detected",
    resolvedBy: "Verified fixed by scan",
    actions: "Actions",
    assign: "Assign",
    decideOnRisk: "Decide on its risk",
    rescan: "Rescan to verify",
    rescanQueued: "Rescan queued. Cleave will close this finding automatically if the fix worked.",
    cancel: "Cancel",
    cannotResolveManually: "Findings are closed by a scan that confirms the fix, never by hand.",
    scoreBreakdown: "How this score was calculated",
    compliance: "Related controls",
  },
  assets: {
    pageExplainLabel: "How assets are listed",
    pageExplain:
      "Every resource a scan discovered, with what it is worth and how exposed it is. Ranked by open findings rather than by name, so what needs attention comes first.",
    title: "Assets",
    empty: "No assets discovered yet.",
    openFindings: "Open findings",
    // CloudGuard reporting its own limits. Phrased as what it does not
    // check rather than as a coverage percentage: a percentage invites the
    // reader to feel good about a high one, and the useful question is
    // which resources are unexamined, not what share of them are.
    unchecked: "{count} with no checks yet",
  },
  risks: {
    title: "Risks",
    empty: "No risks recorded yet.",
    // A scenario is not a louder finding. It is several of them seen as one
    // thing, and the label has to carry that or it reads as duplication.
    scenarioBadge: "Attack path",
    escalationBadge: "Privilege escalation",
    scenarioIntro: "Several findings, seen as one route",
    escalationIntro: "A route to an identity that can grant itself more",
    lastSeen: "This route was still there {when}.",
    // Not "never seen": the route exists because a scan found it. What is
    // missing is which reading, and saying so beats implying staleness we
    // cannot demonstrate.
    lastSeenUnknown:
      "The reading that found this route is no longer stored, so Cleave cannot say when it was last confirmed.",
    routeLabel: "The route",
    cutLabel: "Severing it",
    // The scoring, said in the terms the breakdown actually stores. A customer
    // asking "why is this above the finding inside it" gets an answer rather
    // than a number.
    worstMember: "Worst finding on the route",
    amplifier: "Added for the route itself",
    cappedNote: "Capped at 100.",
    memberCount: "findings on this route",
    // The detail page. What the list can rank but cannot show: which findings
    // a risk was actually built from.
    backToRisks: "Risks",
    builtFrom: "What this risk is built from",
    builtFromScenario:
      "The findings on this route. Fixing any one of them breaks the route \u2014 the cheapest is usually the identity or the role, never the containment.",
    builtFromFinding:
      "The observation this risk scores. A finding is what Cleave saw; the risk is what it means for this asset, with this data, at this level of exposure.",
    builtFromGroup:
      "Every asset failing this check. They are one risk because they are one mistake and one fix \u2014 scored as the worst of them, not as the sum, and each still tracked and verified on its own.",
    noMembers: "No findings are linked to this risk.",
    noMembersDetail:
      "The findings it was built from have been deleted, most likely with the scan that raised them. The score is kept as history rather than recomputed from nothing.",
    theArithmetic: "How this score was reached",
    notFound: "That risk no longer exists",
    notFoundDetail:
      "It may have been deleted with the scan that raised it. The risks list shows everything Cleave currently ranks.",
  },
  attackPaths: {
    routesLabel: "Routes to sensitive data",
    entryPointsLabel: "Exposed assets",
    sensitiveTargetsLabel: "Sensitive assets",
    title: "Attack paths",
    intro:
      "Routes from something exposed to something worth taking \u2014 and the one link that cuts each.",
    // The empty state has to distinguish three different nothings, because
    // they call for three different actions.
    emptyNoPaths: "Nothing exposed can reach anything sensitive",
    emptyNoPathsDetail:
      "No route joins what is exposed to what is sensitive. Below: where each way in stops.",
    exposedCount: "Exposed",
    sensitiveCount: "Sensitive",
    deadEndsTitle: "Where each way in stops",
    deadEndsMore: (n: number) => `and ${n} more`,
    deadEndReachesNothing: (type: string) =>
      type === "user" || type === "service_principal"
        ? "Holds no role over anything Cleave scanned."
        : "Runs as no identity, and no other machine on its network lets it in.",
    deadEndIdentityWithoutRole:
      "Runs as an identity that holds no role over anything Cleave scanned.",
    deadEndRolesWithoutControl:
      "Its identity's roles control nothing: read-only, unreadable, or under a condition.",
    deadEndNothingSensitive: (n: number) =>
      `Reaches ${n} ${n === 1 ? "asset" : "assets"}, none of them classified as sensitive.`,
    onlyAccountsSensitive:
      "Only accounts are classified as sensitive. Tag storage, databases and vaults too.",
    emptyNoEntry: "Nothing is reachable from the internet",
    emptyNoEntryDetail:
      "No asset here is exposed enough to be an entry point, so no route can start.",
    emptyNoTargets: "Nothing has been classified as sensitive",
    emptyNoTargetsDetail:
      "No asset is classified as sensitive. Tag data, or set criticality, to give routes an end.",
    emptyNoScan: "No scan has run yet",
    emptyNoScanDetail: "Built from what a scan found. Run one, and routes appear here.",
    hops: "hops",
    oneHop: "hop",
    from: "From",
    to: "To",
    route: "The route",
    cutHere: "Cut it here",
    chokeSitsOn:
      "It sits on {on} \u2014 the rest have another way round, so cutting this does not close them.",
    entryPoints: "exposed assets",
    sensitiveTargets: "sensitive assets",
    exposure: "Exposure",
    sensitivity: "Sensitivity",
    // The map. Columns are hops from the outside in, so reading left to right
    // is reading an attacker's progress.
    mapTitle: "Every route, drawn",
    // A link named a route the latest reading does not have: it closed, or the
    // estate changed under it. Said, rather than landing untraced in silence.
    traceMissing:
      "That route is not in the latest reading \u2014 it may have closed. Every route is below.",
    traceMissingClear: "Clear",
    mapHelpExplain:
      "Left to right is hops from the outside in. A line's thickness is how many routes close if it is cut — checked for every link. Press a line to add it to the simulation, or a box for the routes through it; press the empty canvas to put the box down. While a route is being read, pressing one of its own lines or boxes reads that hop instead. Pointing at a box fades what it does not touch. Arrow keys move between boxes.",
    mapHelpLabel: "How to read the drawing",
    legendEntry: "Reachable from the internet",
    legendSensitive: "Sensitive data",
    legendFindings: "Open findings",
    legendWeight: "Thicker: closes more routes if cut",
    legendCut: "In the simulated plan",
    legendClosed: "Out of reach with the plan made",
    mapDrawnOf: (drawn: number, total: number) =>
      `Drawing ${drawn} of ${total} routes — the rest are in the list.`,
    panelLabel: "The routes",
    listTitle: "Routes",
    patternsTitle: "The same route, repeated",
    patternsHelpExplain:
      "Grouped only where the routes are identical apart from one end, so each group is a claim you can check by opening it.",
    routesThrough: (n: number) => `On ${n} ${n === 1 ? "route" : "routes"}`,
    simulating: (n: number) =>
      `Simulating ${n} ${n === 1 ? "change" : "changes"} together — nothing in your cloud has changed.`,
    simulationShow: "Show the plan",
    tabRoutes: "Routes",
    tabSimulate: "Simulate",
    closesNothing: "Cutting this closes nothing: every route through it has another way round.",
    clearTrace: "Show every route",
    tracing: "Tracing one route",
    // The route navigator (DECISIONS.md §142): stops always shown, links walked.
    navigatorLabel: (entry: string, target: string) => `Attack path from ${entry} to ${target}`,
    previousRoute: "Previous route",
    nextRoute: "Next route",
    routeOf: (n: number, total: number) => `Route ${n} of ${total}`,
    onePattern: (description: string) => `One of a group: ${description}`,
    planCloses: "The simulated plan closes this route",
    planLeavesOpen: "Still open with the simulated plan made",
    hopsLabel: "Hops",
    hopOf: (n: number, total: number, text: string) => `Hop ${n} of ${total}: ${text}`,
    trackedAsRisk: "Tracked as a risk",
    notARisk: "Not a risk: nothing on this route fails a check",
    keysHops: "hops",
    keysRoutes: "routes",
    keysBack: "back to the list",
    openFindings: (n: number) => `${n} open ${n === 1 ? "finding" : "findings"}`,
    placeIn: "In",
    placeEnters: "Enters",
    earliestCut: "Earliest place to cut",
    closesMost: (n: number) => `Closes the most on this route: ${n} routes`,
    factsLabel: "What the link is",
    cannotRemove: "Where it lives. Containment cannot be removed, so this is not a place to cut.",
    notDrawn:
      "This link is past what the drawing holds, so what cutting it closes is not known here.",
    closesThis: (others: number) =>
      others === 0
        ? "Cutting it closes this route."
        : `Cutting it closes this route and ${others} ${others === 1 ? "other" : "others"}.`,
    wayRound: (severs: number) =>
      severs === 0
        ? "This route has a way round it: cutting this alone closes nothing."
        : `This route has a way round it. Cutting this alone closes ${severs} other ${severs === 1 ? "route" : "routes"}.`,
    sitsOn: (n: number) => `It sits on ${n}; the rest have another way round.`,
    addToPlan: "Add to the plan",
    takeOutOfPlan: "Take out of the plan",
    // The list's own controls.
    searchLabel: "Search routes",
    searchPlaceholder: "Search by asset",
    sortLabel: "Sort routes",
    sortHops: "Shortest first",
    sortSensitive: "Most sensitive target",
    sortExposed: "Most exposed entry",
    sortTracked: "Tracked risks first",
    trackedBadge: "Tracked",
    closedByPlan: "Closed by the plan",
    patternsHelpLabel: "What a group is",
    patternsCount: (n: number) => `${n} ${n === 1 ? "group" : "groups"}`,
    shownOf: (n: number, total: number) => `${n} of ${total} here`,
    trackedCount: (n: number) => `${n} tracked`,
    closedCount: (n: number) => `${n} closed by the plan`,
    noneNamed: (query: string) => `No route passes anything named “${query}”.`,
  },
  notifications: {
    aria: "Notifications",
    ariaUnread: "Notifications, {count} unread",
    title: "Notifications",
    // What one row's dismiss button is called for a screen reader. The button
    // itself is an icon, so this is the only place it is named.
    dismiss: "Dismiss",
    dismissOne: "Dismiss: {title}",
    clearAll: "Clear all",
    // Not "no notifications" alone: that is ambiguous between all quiet and
    // CloudGuard having stopped checking.
    empty:
      "Nothing new. Cleave tells you about reachable findings, verified fixes, and readings it could not take.",
  },
  scans: {
    title: "Scans",
    runScan: "Run scan",
    empty: "No scans yet.",
    resources: "Resources",
    rules: "Rules run",
    findings: "Findings",
    // A row opens the scan wizard on its scan: live while it runs, its result
    // once it has finished.
    watch: "Watch",
    open: "Open",
    history: "History",
    duration: "Duration",
    startedAt: "Started",
    evaluated: "Resources evaluated",
    scope: "Scope",
    identity: "Identity used",
    initiator: "Started by",
    scheduled: "Scheduled",
    // A manual scan whose user record is gone. Distinct from
    // "Scheduled": somebody did ask for this one, and we no longer
    // know who.
    manualUnknownUser: "Started by hand",
    deleteScan: "Delete",
    deleting: "Deleting\u2026",
    deleteTitle: "Delete this scan record?",
    // The choice itself, stated once above the two options: which of the two
    // deletions this is has to be decided before either button is read.
    deleteIntro: "Deleting a run and deleting what it found are different. Choose which you mean.",
    deleteRecordOnly: "Delete record only",
    deleteRecordOnlyDetail:
      "Removes the log. Its findings stay \u2014 they describe your environment, not this run.",
    deleteWithFindings: "Delete record and its unresolved findings",
    deleteWithFindingsDetail:
      "Also deletes the unresolved findings it last detected. Verified fixes are never deleted.",
    // Replay. Every scan stores the provider's own JSON before interpreting
    // it, so a rule written after that scan ran can still be applied to it --
    // and doing so costs nothing in the customer's cloud.
    replay: "Re-evaluate",
    replayQueueing: "Queueing\u2026",
    replayHelp:
      "Runs today's rules against what this scan already collected. No Azure call, no consent, no cost to your throttle budget \u2014 Cleave kept the provider's own JSON, so a check written since can still be applied to it.",
    replayBadge: "Re-evaluated a stored capture",
    replayOfLabel: "Re-evaluation of an earlier scan",
    // The distinction that keeps a replay honest. Only a replay of the newest
    // capture may touch findings; an older one reports and stops.
    replayAdvisoryTitle: "What the rules would have found",
    replayAdvisoryDetail:
      "Advisory: an older capture. No finding was created, resolved or reopened.",
    replayCurrentTitle: "Applied to your current picture",
    replayCurrentDetail:
      "Still the newest capture, so results count: findings change as a fresh scan would.",
    wouldHaveFound: "Findings (would have)",
    stuckTitle: "Nothing has picked this scan up",
    stuckDetail:
      "A scan is collected by Cleave's worker within seconds of being queued. Minutes of silence means no worker is running \u2014 check that the Celery worker service is deployed and can reach Redis.",
    nothingFound: "No resources were found here",
    nothingFoundHelp:
      "Every category came back empty: nothing to assess. Check Details if that is unexpected.",
    nothingFoundPartial:
      "Nothing assessed, and some categories failed to read \u2014 which is not the same as empty.",
    supportsOne: "1 finding rests on this",
    supportsMany: "{count} findings rest on this",
    supportsNone: "no findings rest on this",
    collectionTitle: "What was read",
    collectionSummary: "read completely",
    collectionPartial: "partial",
    collectionFailed: "failed",
    collectionSkipped: "skipped",
    collectionUnavailable: "not licensed",
    collectionAllComplete: "Every listing was read in full.",
    collectionAffects: "Affected checks",
    outcomeComplete: "Read in full",
    outcomePartial: "Incomplete",
    outcomeFailed: "Could not read",
    outcomeSkipped: "Not attempted",
    outcomeUnavailable: "Not licensed",
    partialHint: "An incomplete listing cannot support a pass: checks needing it report unknown.",
    // The same invariant for the readings that produced nothing at all. It
    // used to be stated only for PARTIAL, so a scan where storage failed
    // outright showed a badge, a count, and no word about what it cost --
    // leaving "could not read" to be read as "nothing to report".
    unreadHint:
      "A reading that produced nothing supports nothing: its checks report unknown, never passed.",
    // A licence gap is neither a failure nor a pass, and says which (section 196).
    unavailableHint: "Not in this tenant's licence: those checks report unknown, not passed.",
    partial: "Some data could not be collected — affected checks are marked unknown, not passed.",
  },
  rules: {
    pageExplainLabel: "How rules work",
    pageExplain:
      "Each rule reads configuration a scan collected and answers pass, fail, no verdict or not applicable. Rules are deterministic: the same environment always gives the same result, and a check that cannot be answered is never counted as a pass.",
    title: "Rule library",
    empty: "No rules loaded.",
    // A withdrawn rule is not a check CloudGuard runs, and listing it beside
    // the ones it does run made the catalogue overstate what is being checked.
    // The row exists because findings it raised still name it.
    withdrawn: "Withdrawn",
    withdrawnHelp:
      "This check has been taken out of the rule registry, so it no longer runs and compliance coverage no longer counts it. Findings it raised in the past are kept \u2014 they still describe what was true when it ran.",
    showWithdrawn: "Show withdrawn rules",
    hideWithdrawn: "Hide withdrawn rules",
    withdrawnCount: "withdrawn",
    // The rest of what the catalogue holds and never showed.
    why: "Why this matters",
    howToFix: "How to fix it",
    showDetail: "Why and how to fix",
    hideDetail: "Hide",
  },
  compliance: {
    title: "Compliance",
    intro:
      "Evidence toward each framework, with the controls nothing checks named rather than omitted.",
    notALegalClaim:
      "This is evidence, not a compliance verdict. A green control means specific misconfigurations were absent at the last scan; it is not a statement that a requirement is met in law or that an audit would pass.",
    coverage: "Assessable coverage",
    coverageHelp:
      "Share of the catalogued controls Cleave reached a conclusion on \u2014 pass or fail. Controls nothing checks, and controls it could not read, are excluded rather than counted as met.",
    controls: "controls",
    openFindings: "open findings",
    // Under a framework card's ring: its figure is controls with a verdict,
    // pass or fail, out of all of them (DECISIONS.md §185).
    withVerdict: "with a verdict",
    viewFramework: "View controls",
    scopeNote: "What this covers",
    ownWording:
      "Control titles are Cleave's own wording, not the published text. Follow the source link for authoritative definitions.",
    source: "Official source",
    noRules: "No rule checks this.",
    notAssessable: "Not observable by a scanner",
    notAssessableHelp:
      "This requirement is organizational, procedural or physical. No cloud posture scan can produce evidence for it.",
    evidenceFrom: "Evidence from",
    // The readings under a control, which is what turns a green row from a
    // claim into something a reader can check.
    readFrom: "Read from",
    readingNever: "not read in the last scan",
    readingScopes: "scope",
    readingScopesPlural: "scopes",
    readingPruned: "payload no longer stored",
    readingHelp:
      "The provider listings this control's verdict rests on, as the last scan took them. The oldest read and the worst outcome are shown: a control is only as current and as complete as the least of the things it rests on.",
    export: "Export",
    exportCsv: "Spreadsheet (CSV)",
    exportJson: "Machine-readable (JSON)",
    exporting: "Preparing\u2026",
    exportFailed: "Could not prepare the export",
    exportHelp:
      "Every control, its verdict, the rules behind it and the readings behind those \u2014 including the controls that passed.",
    assessedFrom: "Assessed from the scan completed",
    assessedPartial:
      "That scan could not read part of the estate, so this assessment has a gap in it.",
    empty: "No frameworks in the catalogue.",
    backToFrameworks: "All frameworks",
    statusHelp: {
      FAILING: "At least one mapped rule is currently failing.",
      INCONCLUSIVE: "Nothing failing, but a mapped rule could not be evaluated. Not a pass.",
      PASSING: "Every mapped rule was evaluated conclusively and none is failing.",
      NOT_ASSESSED: "Rules map here, but no scan has produced a result yet.",
      NOT_COVERED: "No rule maps here. Cleave has nothing to say about it.",
    },
  },
  changes: {
    title: "Changes",
    intro:
      "What moved in the environment, rather than what is true in it now. A quiet week here is a genuinely quiet week.",
    empty: "Nothing moved in this window",
    emptyDetail:
      "No asset appeared, disappeared, or changed exposure, sensitivity or criticality in the period you are looking at. Widen the window to look further back.",
    emptyFiltered: "No changes of this kind in this window",
    emptyFilteredDetail:
      "Something may still have moved \u2014 clear the filter, or widen the window, to see the rest of the feed.",
    // Each kind said as a sentence about the asset, not as an enum name. "The
    // exposure changed" is a fact about a column; "became reachable from more
    // of the internet" is a fact the reader can act on.
    kind: {
      APPEARED: "Appeared",
      DISAPPEARED: "Disappeared",
      EXPOSURE_CHANGED: "Internet exposure changed",
      SENSITIVITY_CHANGED: "Data sensitivity changed",
      CRITICALITY_CHANGED: "Criticality changed",
    },
    appeared: "First seen in this environment",
    // One row for a scan's arrivals when there are many (DECISIONS.md §188).
    appearedBatch: (n: number) => `${n} assets first seen`,
    appearedBatchDetail: "Everything one scan found for the first time, folded into one row.",
    showAssets: "Show them",
    hideAssets: "Hide them",
    disappeared: "A scan that covered its scope did not see it",
    // The distinction that decides whether a DISAPPEARED row is history or a
    // job. The asset row is never deleted, so both readings are possible.
    stillMissing: "still missing",
    returned: "seen again since",
    worse: "worse",
    better: "better",
    windowLabel: "Look back",
    kindLabel: "Kind of change",
    windows: {
      1: "Last 24 hours",
      7: "Last 7 days",
      30: "Last 30 days",
      90: "Last 90 days",
    },
    allKinds: "All kinds of change",
    count: "change",
    countPlural: "changes",
  },
  reports: {
    title: "Reports",
    intro:
      "The same evidence, fixed to a moment and made portable. Nothing is stored here \u2014 a library of past reports would outlive the evidence behind it.",
    executive: "Executive report",
    executiveDetail:
      "For a reader who does not touch Azure: the posture score and where it is going, the worst risks by what they would actually cost, and compliance coverage. Deliberately lists no findings \u2014 a summary that ends in a 400-row table is a technical report with a cover page.",
    technical: "Technical report",
    technicalDetail:
      "Everything the executive report says, from the same numbers, and then every open finding worst first \u2014 the asset it was found on, when it was first seen, and what to change.",
    download: "Download PDF",
    preparing: "Preparing\u2026",
    preview: "Preview",
    // The one failure worth its own copy: the server is missing native
    // libraries, which is an operator problem and not something a retry fixes.
    noPdfTitle: "This server cannot produce PDFs",
    failed: "Could not generate the report",
  },
  settings: {
    title: "Settings",
    intro:
      "Everything else in Cleave is something it observed. This is the other half of the evidence: what you told it.",

    // The organization profile. A correction, not a statement: saving a name
    // must not clear a country nobody touched.
    orgTitle: "Organization",
    orgHelp: "The name on reports and exported evidence.",
    orgName: "Name",
    orgIndustry: "Industry",
    orgCountry: "Country",
    orgCountryHelp: "Two-letter country code, e.g. AL.",
    orgSlug: "Identifier",
    orgSlugHelp:
      "Fixed when the organization was created and unchanged by a rename \u2014 it appears in stored references, so changing it would rename the thing rather than relabel it.",
    save: "Save changes",
    saving: "Saving\u2026",
    saved: "Saved",
    orgFailed: "Could not save the organization",
    // Only owners and admins may edit, and a reader who cannot should be told
    // why rather than meeting disabled fields with no explanation.
    orgReadOnly:
      "Your role can read this but not change it. An owner or an admin can edit the organization.",

    // The declarations. This is the part that changes what CloudGuard reports.
    contextTitle: "What your environments are for",
    contextHelp:
      "The highest-leverage thing you can tell Cleave. The risk engine multiplies every finding by it, and it decides what counts as a sensitive target when routes are traced. Anything you declare beats what Cleave infers from names and tags.",
    contextEmpty: "Nothing has been discovered yet",
    contextEmptyDetail:
      "Connect a cloud environment and Cleave will discover what is beneath it. There is nothing to describe until then.",
    environment: "Environment",
    criticality: "Criticality",
    dataSensitivity: "Data sensitivity",
    note: "Note",
    noteHelp: "Why this is what it is. Recorded with the declaration.",
    environmentPlaceholder: "production, staging, sandbox\u2026",
    // UNKNOWN is deliberately absent from these menus, and the copy says so:
    // it is CloudGuard's own word for "nothing said anything", so declaring it
    // would assert an absence that saying nothing already asserts.
    notDeclared: "Not declared",
    notDeclaredHelp:
      "Leaving a field unset is not the same as declaring it unknown \u2014 Cleave goes back to working it out for itself.",
    declaredBy: "Declared",
    declare: "Save declaration",
    clear: "Clear declaration",
    clearing: "Clearing\u2026",
    contextFailed: "Could not save the declaration",
    // The honest bit: a declaration is not retroactive.
    appliesNext:
      "Applied by the next evaluation of this environment \u2014 the next scan, or a replay of its latest capture. Existing scores are left alone: a risk score is what a scan concluded, and rewriting stored numbers from a form would leave findings carrying figures no observation ever produced.",

    dangerTitle: "Delete this organization",
    dangerHelp:
      "Removes the organization and everything under it: connections, discovered accounts, assets, scans, findings, risks and audit history. There is no soft delete and no undo.",
    dangerConfirmLabel: "Type the organization name to confirm",
    delete: "Delete organization",
    deleting: "Deleting\u2026",
    deleteFailed: "Could not delete the organization",
    dangerOwnerOnly: "Only an owner can delete an organization.",
  },
  // Members and invitations (DECISIONS.md §162).
  team: {
    title: "Members",
    help: "Who can see this organization, and what each person may do.",
    you: "you",
    noEmail: "Address shown after their next sign-in",
    joined: "Joined",
    role: "Role",
    remove: "Remove",
    lastOwner: "The last owner stays",
    removing: "Removing\u2026",
    removeConfirm: (who: string) => `Remove ${who} from this organization?`,
    removeDetail:
      "They lose access at once. Findings and tasks they worked on stay, and the removal is recorded.",
    cancel: "Cancel",
    changeFailed: "Could not change this member",
    readOnly:
      "Your role can see who is here but not change it. An owner or an admin manages members.",
    roles: {
      OWNER: "Owner",
      ADMIN: "Admin",
      SECURITY_ANALYST: "Security analyst",
      IT_ADMIN: "IT admin",
      VIEWER: "Viewer",
      ADVISOR: "Advisor",
    },
    inviteTitle: "Invite someone",
    inviteEmail: "Email address",
    inviteRole: "Role",
    invite: "Create invitation link",
    inviting: "Creating\u2026",
    inviteFailed: "Could not create the invitation",
    // Cleave sends no email, so the link is the invitation. Said plainly so an
    // admin knows it is theirs to pass on, and that it cannot be shown again.
    linkReady: (email: string) =>
      `Send this link to ${email}. It works only when they sign in with that address, expires in 7 days, and will not be shown again.`,
    copy: "Copy link",
    copied: "Copied",
    pendingTitle: "Waiting to join",
    pendingEmpty: "No invitations are waiting.",
    expires: "Expires",
    expired: "Expired",
    revoke: "Withdraw",
    revokeFailed: "Could not withdraw the invitation",
    owners:
      "Only an owner can make someone an owner. Invite them as another role, then change it once they have joined.",
  },

  // The audit trail (DECISIONS.md §163).
  audit: {
    title: "Activity",
    help: "Every change made in this organization, by whom and from where. Nobody can edit or delete an entry.",
    empty: "Nothing has been changed yet.",
    more: "Show more",
    failed: "Could not load the activity",
    // Nobody signed in made the change: an acceptance that ran out, say.
    system: "Cleave",
    formerMember: "A former member",
    from: (ip: string) => `from ${ip}`,
    actions: {
      "invitation.created": "invited someone",
      "invitation.revoked": "withdrew an invitation",
      "invitation.accepted": "joined by invitation",
      "member.role_changed": "changed a member's role",
      "member.removed": "removed a member",
      "organization.updated": "edited the organization",
      "connection.created": "added a connection",
      "connection.deleted": "deleted a connection",
      "connection.scope_changed": "changed which subscriptions are scanned",
      "connection.schedule_changed": "changed the scan schedule",
      "connection.change_events": "changed change detection",
      "connection.setup_cancelled": "cancelled a connection's setup",
      "connection.setup_resumed": "resumed a connection's setup",
      "scan.started": "started a scan",
      "scan.replayed": "replayed a scan",
      "scan.cancelled": "cancelled a scan",
      "scan.deleted": "deleted a scan",
      "webhook.created": "added an integration",
      "webhook.updated": "changed an integration",
      "webhook.deleted": "removed an integration",
      "webhook.tested": "tested an integration",
    } as Record<string, string>,
  },

  // Webhooks (DECISIONS.md §164).
  webhooks: {
    title: "Integrations",
    help: "Send notifications where your team already talks. Only owners and admins see this.",
    empty: "Nothing is connected yet. Notifications arrive only in the bell.",
    name: "Integration name",
    url: "Webhook URL",
    urlHelp: "HTTPS only. Addresses inside a private network are refused.",
    format: "Send as",
    formats: {
      GENERIC: "Webhook (signed JSON)",
      SLACK: "Slack",
      TEAMS: "Microsoft Teams",
    },
    kindsLabel: "Send",
    kinds: {
      REACHABLE_FINDING: "New findings on an attack route",
      VERIFIED_FIX: "Fixes Cleave has verified",
      COVERAGE_DROP: "Readings that stopped arriving",
    },
    add: "Add integration",
    adding: "Adding\u2026",
    addFailed: "Could not add the integration",
    secretReady:
      "Sign-check deliveries with this secret. It will not be shown again. Each request carries X-Cleave-Timestamp and X-Cleave-Signature: sha256 HMAC of \u201ctimestamp.body\u201d.",
    copySecret: "Copy secret",
    enabled: (name: string) => `Send to ${name}`,
    test: "Send test",
    testing: "Sending\u2026",
    testOk: "Delivered.",
    testFailed: (why: string) => `Not delivered: ${why}`,
    lastOk: (when: string) => `Last delivered ${when}`,
    lastFailed: (when: string, why: string) => `Failed ${when}: ${why}`,
    never: "Nothing sent yet",
    remove: "Remove",
    removeConfirm: (name: string) => `Remove ${name}? Nothing more will be sent to it.`,
    cancel: "Cancel",
    changeFailed: "Could not change the integration",
  },

  invite: {
    title: "Join an organization",
    loading: "Reading the invitation\u2026",
    offer: (org: string, role: string) => `You have been invited to ${org} as ${role}.`,
    forEmail: (email: string) => `This invitation is for ${email}.`,
    wrongAccount: (email: string) =>
      `You are signed in with a different address. Sign out and sign in as ${email} to accept it.`,
    signInFirst: "Sign in or create an account with the invited address to accept it.",
    signIn: "Sign in to accept",
    accept: "Join organization",
    accepting: "Joining\u2026",
    signOut: "Sign out",
    missing: "This link has no invitation in it. Ask for the link again.",
    invalid: "This invitation link is not valid. Ask for a new one.",
    status: {
      ACCEPTED: "This invitation has already been used.",
      REVOKED: "This invitation was withdrawn. Ask for a new one.",
      EXPIRED: "This invitation has expired. Ask for a new one.",
    },
    failed: "Could not join the organization",
    home: "Go to Cleave",
  },

  remediation: {
    title: "Remediation",
    empty: "No remediation tasks yet.",
    // Of two equally urgent fixes, the one on an attack path comes first --
    // which each row says, rather than the intro.
    description: "Ordered by impact against effort.",
    onRoutes: (n: number) => `on ${n} attack ${n === 1 ? "path" : "paths"}`,
    waitingOnScan: "Waiting on a scan",
    doneOn: (date: string) => `Done ${date}`,
    doneNote:
      "Marked done does not close a finding. Cleave reads the environment again on the next scan and closes it then, or leaves it open.",
  },
  access: {
    tab: "Access",
    holdersTitle: "Who can reach this",
    holdersDescription: (name: string) =>
      `Every role assigned on ${name} or on a container above it, whether or not anything exposed leads to the holder`,
    scopeHoldersDescription: (name: string) =>
      `Every role assigned on ${name} or above it. What each one controls is on the identity's own page.`,
    controlsGroup: "Can take what it holds",
    manageGroup: "Can change its configuration",
    readGroup: "Can read its configuration",
    unresolvedGroup: "Could not be read",
    eligibleGroup: "Eligible to activate",
    eligible: "eligible under PIM, not held until activated",
    holdersEmpty: "No role assignment the last scan read reaches this asset.",
    grantsTitle: "What this identity holds",
    grantsDescription: (name: string) =>
      `Every role ${name} holds, and the assets each one actually controls`,
    at: (scope: string) => `on ${scope}`,
    inherited: (origin: string) => `inherited from ${origin}`,
    conditional: "limited by a condition Cleave cannot evaluate",
    unresolved: "Cleave could not read what this role allows",
    runsOn: "used by",
    members: (n: number) => `${n} ${n === 1 ? "member" : "members"}`,
    membersUnread: "its members could not be read",
    via: "through",
    throughDirectory: "granted in the directory, not by an Azure role assignment",
    signsInAs: "by signing in as",
    controlsCount: (n: number) =>
      n === 0 ? "Controls nothing it lands on" : `Controls ${n} ${n === 1 ? "asset" : "assets"}`,
    andMore: (n: number) => `and ${n} more`,
    unplaced: (scope: string) => `on ${scope}, which this scan did not read`,
    kinds: {
      read: "reads configuration",
      manage: "changes configuration",
      read_data: "reads its data",
      execute: "runs code as it",
      edit_policy: "edits its access policy",
      grant_access: "grants itself any role",
      act_as: "signs in as it",
    },
    notInGraph:
      "This asset is not in the current graph — it may not have been in the most recent scan.",
    failed: "Could not read who holds access",
  },
  graph: {
    explore: "Explore in graph",
    opening: "Opening\u2026",
    gone: "This asset is not in the current graph",
    goneDetail: "A later scan no longer found it, so there is no graph to open around it.",
  },
  common: {
    loading: "Loading…",
    error: "Something went wrong",
    retry: "Try again",
    severity: "Severity",
    status: "Status",
    all: "All",
    unknown: "Unknown",
    never: "Never",
    back: "Back",
  },
} as const;

export type Strings = typeof en;
