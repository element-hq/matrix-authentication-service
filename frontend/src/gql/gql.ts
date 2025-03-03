/* eslint-disable */
import * as types from './graphql';



/**
 * Map of all GraphQL operations in the project.
 *
 * This map has several performance disadvantages:
 * 1. It is not tree-shakeable, so it will include all operations in the project.
 * 2. It is not minifiable, so the string of a GraphQL query will be multiple times inside the bundle.
 * 3. It does not support dead code elimination, so it will add unused operations.
 *
 * Therefore it is highly recommended to use the babel or swc plugin for production.
 * Learn more about it here: https://the-guild.dev/graphql/codegen/plugins/presets/preset-client#reducing-bundle-size
 */
type Documents = {
    "\n  fragment AccountDeleteButton_user on User {\n    username\n    hasPassword\n    matrix {\n      mxid\n      displayName\n    }\n  }\n": typeof types.AccountDeleteButton_UserFragmentDoc,
    "\n  fragment AccountDeleteButton_siteConfig on SiteConfig {\n    passwordLoginEnabled\n  }\n": typeof types.AccountDeleteButton_SiteConfigFragmentDoc,
    "\n  mutation DeactivateUser($hsErase: Boolean!, $password: String) {\n    deactivateUser(input: { hsErase: $hsErase, password: $password }) {\n      status\n    }\n  }\n": typeof types.DeactivateUserDocument,
    "\n  fragment PasswordChange_siteConfig on SiteConfig {\n    passwordChangeAllowed\n  }\n": typeof types.PasswordChange_SiteConfigFragmentDoc,
    "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    ...EndBrowserSessionButton_session\n    userAgent {\n      deviceType\n      name\n      os\n      model\n    }\n    lastActiveAt\n  }\n": typeof types.BrowserSession_SessionFragmentDoc,
    "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n": typeof types.OAuth2Client_DetailFragmentDoc,
    "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n    ...EndCompatSessionButton_session\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": typeof types.CompatSession_SessionFragmentDoc,
    "\n  fragment Footer_siteConfig on SiteConfig {\n    id\n    imprint\n    tosUri\n    policyUri\n  }\n": typeof types.Footer_SiteConfigFragmentDoc,
    "\n  query Footer {\n    siteConfig {\n      id\n      ...Footer_siteConfig\n    }\n  }\n": typeof types.FooterDocument,
    "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndOAuth2SessionButton_session\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n": typeof types.OAuth2Session_SessionFragmentDoc,
    "\n  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {\n    id\n    minimumPasswordComplexity\n  }\n": typeof types.PasswordCreationDoubleInput_SiteConfigFragmentDoc,
    "\n  fragment EndBrowserSessionButton_session on BrowserSession {\n    id\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n  }\n": typeof types.EndBrowserSessionButton_SessionFragmentDoc,
    "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n      }\n    }\n  }\n": typeof types.EndBrowserSessionDocument,
    "\n  fragment EndCompatSessionButton_session on CompatSession {\n    id\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": typeof types.EndCompatSessionButton_SessionFragmentDoc,
    "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n      }\n    }\n  }\n": typeof types.EndCompatSessionDocument,
    "\n  fragment EndOAuth2SessionButton_session on Oauth2Session {\n    id\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n": typeof types.EndOAuth2SessionButton_SessionFragmentDoc,
    "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n      }\n    }\n  }\n": typeof types.EndOAuth2SessionDocument,
    "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    ...EndBrowserSessionButton_session\n    userAgent {\n      name\n      model\n      os\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n": typeof types.BrowserSession_DetailFragmentDoc,
    "\n  mutation SetCompatSessionName($sessionId: ID!, $displayName: String!) {\n    setCompatSessionName(input: { compatSessionId: $sessionId, humanName: $displayName }) {\n      status\n    }\n  }\n": typeof types.SetCompatSessionNameDocument,
    "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndCompatSessionButton_session\n\n    userAgent {\n      name\n      os\n      model\n    }\n\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": typeof types.CompatSession_DetailFragmentDoc,
    "\n  mutation SetOAuth2SessionName($sessionId: ID!, $displayName: String!) {\n    setOauth2SessionName(input: { oauth2SessionId: $sessionId, humanName: $displayName }) {\n      status\n    }\n  }\n": typeof types.SetOAuth2SessionNameDocument,
    "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndOAuth2SessionButton_session\n\n    userAgent {\n      name\n      model\n      os\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n": typeof types.OAuth2Session_DetailFragmentDoc,
    "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n  }\n": typeof types.UserEmail_EmailFragmentDoc,
    "\n  mutation RemoveEmail($id: ID!, $password: String) {\n    removeEmail(input: { userEmailId: $id, password: $password }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n": typeof types.RemoveEmailDocument,
    "\n  fragment UserGreeting_user on User {\n    id\n    matrix {\n      mxid\n      displayName\n    }\n  }\n": typeof types.UserGreeting_UserFragmentDoc,
    "\n  fragment UserGreeting_siteConfig on SiteConfig {\n    displayNameChangeAllowed\n  }\n": typeof types.UserGreeting_SiteConfigFragmentDoc,
    "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n    }\n  }\n": typeof types.SetDisplayNameDocument,
    "\n  fragment AddEmailForm_user on User {\n    hasPassword\n  }\n": typeof types.AddEmailForm_UserFragmentDoc,
    "\n  fragment AddEmailForm_siteConfig on SiteConfig {\n    passwordLoginEnabled\n  }\n": typeof types.AddEmailForm_SiteConfigFragmentDoc,
    "\n  mutation AddEmail($email: String!, $password: String, $language: String!) {\n    startEmailAuthentication(\n      input: { email: $email, password: $password, language: $language }\n    ) {\n      status\n      violations\n      authentication {\n        id\n      }\n    }\n  }\n": typeof types.AddEmailDocument,
    "\n  query UserEmailList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    viewer {\n      __typename\n      ... on User {\n        emails(first: $first, after: $after, last: $last, before: $before) {\n          edges {\n            cursor\n            node {\n              ...UserEmail_email\n            }\n          }\n          totalCount\n          pageInfo {\n            hasNextPage\n            hasPreviousPage\n            startCursor\n            endCursor\n          }\n        }\n      }\n    }\n  }\n": typeof types.UserEmailListDocument,
    "\n  fragment UserEmailList_user on User {\n    hasPassword\n  }\n": typeof types.UserEmailList_UserFragmentDoc,
    "\n  fragment UserEmailList_siteConfig on SiteConfig {\n    emailChangeAllowed\n    passwordLoginEnabled\n  }\n": typeof types.UserEmailList_SiteConfigFragmentDoc,
    "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n": typeof types.BrowserSessionsOverview_UserFragmentDoc,
    "\n  query UserProfile {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n        user {\n          ...AddEmailForm_user\n          ...UserEmailList_user\n          ...AccountDeleteButton_user\n          hasPassword\n          emails(first: 0) {\n            totalCount\n          }\n        }\n      }\n    }\n\n    siteConfig {\n      emailChangeAllowed\n      passwordLoginEnabled\n      passkeysEnabled\n      accountDeactivationAllowed\n      ...AddEmailForm_siteConfig\n      ...UserEmailList_siteConfig\n      ...PasswordChange_siteConfig\n      ...AccountDeleteButton_siteConfig\n    }\n  }\n": typeof types.UserProfileDocument,
    "\n  query PlanManagementTab {\n    siteConfig {\n      planManagementIframeUri\n    }\n  }\n": typeof types.PlanManagementTabDocument,
    "\n  query BrowserSessionList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n    $lastActive: DateFilter\n  ) {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n\n          browserSessions(\n            first: $first\n            after: $after\n            last: $last\n            before: $before\n            lastActive: $lastActive\n            state: ACTIVE\n          ) {\n            totalCount\n\n            edges {\n              cursor\n              node {\n                id\n                ...BrowserSession_session\n              }\n            }\n\n            pageInfo {\n              hasNextPage\n              hasPreviousPage\n              startCursor\n              endCursor\n            }\n          }\n        }\n      }\n    }\n  }\n": typeof types.BrowserSessionListDocument,
    "\n  query SessionsOverview {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n": typeof types.SessionsOverviewDocument,
    "\n  query AppSessionsList(\n    $before: String\n    $after: String\n    $first: Int\n    $last: Int\n    $lastActive: DateFilter\n  ) {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        appSessions(\n          before: $before\n          after: $after\n          first: $first\n          last: $last\n          lastActive: $lastActive\n          state: ACTIVE\n        ) {\n          edges {\n            cursor\n            node {\n              __typename\n              ...CompatSession_session\n              ...OAuth2Session_session\n            }\n          }\n\n          totalCount\n          pageInfo {\n            startCursor\n            endCursor\n            hasNextPage\n            hasPreviousPage\n          }\n        }\n      }\n    }\n  }\n": typeof types.AppSessionsListDocument,
    "\n  query CurrentUserGreeting {\n    viewer {\n      __typename\n      ... on User {\n        ...UserGreeting_user\n      }\n    }\n\n    siteConfig {\n      ...UserGreeting_siteConfig\n      planManagementIframeUri\n    }\n  }\n": typeof types.CurrentUserGreetingDocument,
    "\n  query OAuth2Client($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n": typeof types.OAuth2ClientDocument,
    "\n  query CurrentViewer {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n": typeof types.CurrentViewerDocument,
    "\n  query DeviceRedirect($deviceId: String!, $userId: ID!) {\n    session(deviceId: $deviceId, userId: $userId) {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n": typeof types.DeviceRedirectDocument,
    "\n  query VerifyEmail($id: ID!) {\n    userEmailAuthentication(id: $id) {\n      id\n      email\n      completedAt\n    }\n  }\n": typeof types.VerifyEmailDocument,
    "\n  mutation DoVerifyEmail($id: ID!, $code: String!) {\n    completeEmailAuthentication(input: { id: $id, code: $code }) {\n      status\n    }\n  }\n": typeof types.DoVerifyEmailDocument,
    "\n  mutation ResendEmailAuthenticationCode($id: ID!, $language: String!) {\n    resendEmailAuthenticationCode(input: { id: $id, language: $language }) {\n      status\n    }\n  }\n": typeof types.ResendEmailAuthenticationCodeDocument,
    "\n  mutation ChangePassword(\n    $userId: ID!\n    $oldPassword: String!\n    $newPassword: String!\n  ) {\n    setPassword(\n      input: {\n        userId: $userId\n        currentPassword: $oldPassword\n        newPassword: $newPassword\n      }\n    ) {\n      status\n    }\n  }\n": typeof types.ChangePasswordDocument,
    "\n  query PasswordChange {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n\n    siteConfig {\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n": typeof types.PasswordChangeDocument,
    "\n  mutation RecoverPassword($ticket: String!, $newPassword: String!) {\n    setPasswordByRecovery(\n      input: { ticket: $ticket, newPassword: $newPassword }\n    ) {\n      status\n    }\n  }\n": typeof types.RecoverPasswordDocument,
    "\n  mutation ResendRecoveryEmail($ticket: String!) {\n    resendRecoveryEmail(input: { ticket: $ticket }) {\n      status\n      progressUrl\n    }\n  }\n": typeof types.ResendRecoveryEmailDocument,
    "\n  fragment RecoverPassword_userRecoveryTicket on UserRecoveryTicket {\n    username\n    email\n  }\n": typeof types.RecoverPassword_UserRecoveryTicketFragmentDoc,
    "\n  fragment RecoverPassword_siteConfig on SiteConfig {\n    ...PasswordCreationDoubleInput_siteConfig\n  }\n": typeof types.RecoverPassword_SiteConfigFragmentDoc,
    "\n  query PasswordRecovery($ticket: String!) {\n    siteConfig {\n      ...RecoverPassword_siteConfig\n    }\n\n    userRecoveryTicket(ticket: $ticket) {\n      status\n      ...RecoverPassword_userRecoveryTicket\n    }\n  }\n": typeof types.PasswordRecoveryDocument,
    "\n  mutation AllowCrossSigningReset($userId: ID!) {\n    allowUserCrossSigningReset(input: { userId: $userId }) {\n      user {\n        id\n      }\n    }\n  }\n": typeof types.AllowCrossSigningResetDocument,
    "\n  query SessionDetail($id: ID!) {\n    viewerSession {\n      ... on Node {\n        id\n      }\n    }\n\n    node(id: $id) {\n      __typename\n      id\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n      ...BrowserSession_detail\n    }\n  }\n": typeof types.SessionDetailDocument,
};
const documents: Documents = {
    "\n  fragment AccountDeleteButton_user on User {\n    username\n    hasPassword\n    matrix {\n      mxid\n      displayName\n    }\n  }\n": types.AccountDeleteButton_UserFragmentDoc,
    "\n  fragment AccountDeleteButton_siteConfig on SiteConfig {\n    passwordLoginEnabled\n  }\n": types.AccountDeleteButton_SiteConfigFragmentDoc,
    "\n  mutation DeactivateUser($hsErase: Boolean!, $password: String) {\n    deactivateUser(input: { hsErase: $hsErase, password: $password }) {\n      status\n    }\n  }\n": types.DeactivateUserDocument,
    "\n  fragment PasswordChange_siteConfig on SiteConfig {\n    passwordChangeAllowed\n  }\n": types.PasswordChange_SiteConfigFragmentDoc,
    "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    ...EndBrowserSessionButton_session\n    userAgent {\n      deviceType\n      name\n      os\n      model\n    }\n    lastActiveAt\n  }\n": types.BrowserSession_SessionFragmentDoc,
    "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n": types.OAuth2Client_DetailFragmentDoc,
    "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n    ...EndCompatSessionButton_session\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": types.CompatSession_SessionFragmentDoc,
    "\n  fragment Footer_siteConfig on SiteConfig {\n    id\n    imprint\n    tosUri\n    policyUri\n  }\n": types.Footer_SiteConfigFragmentDoc,
    "\n  query Footer {\n    siteConfig {\n      id\n      ...Footer_siteConfig\n    }\n  }\n": types.FooterDocument,
    "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndOAuth2SessionButton_session\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n": types.OAuth2Session_SessionFragmentDoc,
    "\n  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {\n    id\n    minimumPasswordComplexity\n  }\n": types.PasswordCreationDoubleInput_SiteConfigFragmentDoc,
    "\n  fragment EndBrowserSessionButton_session on BrowserSession {\n    id\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n  }\n": types.EndBrowserSessionButton_SessionFragmentDoc,
    "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n      }\n    }\n  }\n": types.EndBrowserSessionDocument,
    "\n  fragment EndCompatSessionButton_session on CompatSession {\n    id\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": types.EndCompatSessionButton_SessionFragmentDoc,
    "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n      }\n    }\n  }\n": types.EndCompatSessionDocument,
    "\n  fragment EndOAuth2SessionButton_session on Oauth2Session {\n    id\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n": types.EndOAuth2SessionButton_SessionFragmentDoc,
    "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n      }\n    }\n  }\n": types.EndOAuth2SessionDocument,
    "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    ...EndBrowserSessionButton_session\n    userAgent {\n      name\n      model\n      os\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n": types.BrowserSession_DetailFragmentDoc,
    "\n  mutation SetCompatSessionName($sessionId: ID!, $displayName: String!) {\n    setCompatSessionName(input: { compatSessionId: $sessionId, humanName: $displayName }) {\n      status\n    }\n  }\n": types.SetCompatSessionNameDocument,
    "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndCompatSessionButton_session\n\n    userAgent {\n      name\n      os\n      model\n    }\n\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": types.CompatSession_DetailFragmentDoc,
    "\n  mutation SetOAuth2SessionName($sessionId: ID!, $displayName: String!) {\n    setOauth2SessionName(input: { oauth2SessionId: $sessionId, humanName: $displayName }) {\n      status\n    }\n  }\n": types.SetOAuth2SessionNameDocument,
    "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndOAuth2SessionButton_session\n\n    userAgent {\n      name\n      model\n      os\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n": types.OAuth2Session_DetailFragmentDoc,
    "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n  }\n": types.UserEmail_EmailFragmentDoc,
    "\n  mutation RemoveEmail($id: ID!, $password: String) {\n    removeEmail(input: { userEmailId: $id, password: $password }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n": types.RemoveEmailDocument,
    "\n  fragment UserGreeting_user on User {\n    id\n    matrix {\n      mxid\n      displayName\n    }\n  }\n": types.UserGreeting_UserFragmentDoc,
    "\n  fragment UserGreeting_siteConfig on SiteConfig {\n    displayNameChangeAllowed\n  }\n": types.UserGreeting_SiteConfigFragmentDoc,
    "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n    }\n  }\n": types.SetDisplayNameDocument,
    "\n  fragment AddEmailForm_user on User {\n    hasPassword\n  }\n": types.AddEmailForm_UserFragmentDoc,
    "\n  fragment AddEmailForm_siteConfig on SiteConfig {\n    passwordLoginEnabled\n  }\n": types.AddEmailForm_SiteConfigFragmentDoc,
    "\n  mutation AddEmail($email: String!, $password: String, $language: String!) {\n    startEmailAuthentication(\n      input: { email: $email, password: $password, language: $language }\n    ) {\n      status\n      violations\n      authentication {\n        id\n      }\n    }\n  }\n": types.AddEmailDocument,
    "\n  query UserEmailList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    viewer {\n      __typename\n      ... on User {\n        emails(first: $first, after: $after, last: $last, before: $before) {\n          edges {\n            cursor\n            node {\n              ...UserEmail_email\n            }\n          }\n          totalCount\n          pageInfo {\n            hasNextPage\n            hasPreviousPage\n            startCursor\n            endCursor\n          }\n        }\n      }\n    }\n  }\n": types.UserEmailListDocument,
    "\n  fragment UserEmailList_user on User {\n    hasPassword\n  }\n": types.UserEmailList_UserFragmentDoc,
    "\n  fragment UserEmailList_siteConfig on SiteConfig {\n    emailChangeAllowed\n    passwordLoginEnabled\n  }\n": types.UserEmailList_SiteConfigFragmentDoc,
    "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n": types.BrowserSessionsOverview_UserFragmentDoc,
    "\n  query UserProfile {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n        user {\n          ...AddEmailForm_user\n          ...UserEmailList_user\n          ...AccountDeleteButton_user\n          hasPassword\n          emails(first: 0) {\n            totalCount\n          }\n        }\n      }\n    }\n\n    siteConfig {\n      emailChangeAllowed\n      passwordLoginEnabled\n      passkeysEnabled\n      accountDeactivationAllowed\n      ...AddEmailForm_siteConfig\n      ...UserEmailList_siteConfig\n      ...PasswordChange_siteConfig\n      ...AccountDeleteButton_siteConfig\n    }\n  }\n": types.UserProfileDocument,
    "\n  query PlanManagementTab {\n    siteConfig {\n      planManagementIframeUri\n    }\n  }\n": types.PlanManagementTabDocument,
    "\n  query BrowserSessionList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n    $lastActive: DateFilter\n  ) {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n\n          browserSessions(\n            first: $first\n            after: $after\n            last: $last\n            before: $before\n            lastActive: $lastActive\n            state: ACTIVE\n          ) {\n            totalCount\n\n            edges {\n              cursor\n              node {\n                id\n                ...BrowserSession_session\n              }\n            }\n\n            pageInfo {\n              hasNextPage\n              hasPreviousPage\n              startCursor\n              endCursor\n            }\n          }\n        }\n      }\n    }\n  }\n": types.BrowserSessionListDocument,
    "\n  query SessionsOverview {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n": types.SessionsOverviewDocument,
    "\n  query AppSessionsList(\n    $before: String\n    $after: String\n    $first: Int\n    $last: Int\n    $lastActive: DateFilter\n  ) {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        appSessions(\n          before: $before\n          after: $after\n          first: $first\n          last: $last\n          lastActive: $lastActive\n          state: ACTIVE\n        ) {\n          edges {\n            cursor\n            node {\n              __typename\n              ...CompatSession_session\n              ...OAuth2Session_session\n            }\n          }\n\n          totalCount\n          pageInfo {\n            startCursor\n            endCursor\n            hasNextPage\n            hasPreviousPage\n          }\n        }\n      }\n    }\n  }\n": types.AppSessionsListDocument,
    "\n  query CurrentUserGreeting {\n    viewer {\n      __typename\n      ... on User {\n        ...UserGreeting_user\n      }\n    }\n\n    siteConfig {\n      ...UserGreeting_siteConfig\n      planManagementIframeUri\n    }\n  }\n": types.CurrentUserGreetingDocument,
    "\n  query OAuth2Client($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n": types.OAuth2ClientDocument,
    "\n  query CurrentViewer {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n": types.CurrentViewerDocument,
    "\n  query DeviceRedirect($deviceId: String!, $userId: ID!) {\n    session(deviceId: $deviceId, userId: $userId) {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n": types.DeviceRedirectDocument,
    "\n  query VerifyEmail($id: ID!) {\n    userEmailAuthentication(id: $id) {\n      id\n      email\n      completedAt\n    }\n  }\n": types.VerifyEmailDocument,
    "\n  mutation DoVerifyEmail($id: ID!, $code: String!) {\n    completeEmailAuthentication(input: { id: $id, code: $code }) {\n      status\n    }\n  }\n": types.DoVerifyEmailDocument,
    "\n  mutation ResendEmailAuthenticationCode($id: ID!, $language: String!) {\n    resendEmailAuthenticationCode(input: { id: $id, language: $language }) {\n      status\n    }\n  }\n": types.ResendEmailAuthenticationCodeDocument,
    "\n  mutation ChangePassword(\n    $userId: ID!\n    $oldPassword: String!\n    $newPassword: String!\n  ) {\n    setPassword(\n      input: {\n        userId: $userId\n        currentPassword: $oldPassword\n        newPassword: $newPassword\n      }\n    ) {\n      status\n    }\n  }\n": types.ChangePasswordDocument,
    "\n  query PasswordChange {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n\n    siteConfig {\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n": types.PasswordChangeDocument,
    "\n  mutation RecoverPassword($ticket: String!, $newPassword: String!) {\n    setPasswordByRecovery(\n      input: { ticket: $ticket, newPassword: $newPassword }\n    ) {\n      status\n    }\n  }\n": types.RecoverPasswordDocument,
    "\n  mutation ResendRecoveryEmail($ticket: String!) {\n    resendRecoveryEmail(input: { ticket: $ticket }) {\n      status\n      progressUrl\n    }\n  }\n": types.ResendRecoveryEmailDocument,
    "\n  fragment RecoverPassword_userRecoveryTicket on UserRecoveryTicket {\n    username\n    email\n  }\n": types.RecoverPassword_UserRecoveryTicketFragmentDoc,
    "\n  fragment RecoverPassword_siteConfig on SiteConfig {\n    ...PasswordCreationDoubleInput_siteConfig\n  }\n": types.RecoverPassword_SiteConfigFragmentDoc,
    "\n  query PasswordRecovery($ticket: String!) {\n    siteConfig {\n      ...RecoverPassword_siteConfig\n    }\n\n    userRecoveryTicket(ticket: $ticket) {\n      status\n      ...RecoverPassword_userRecoveryTicket\n    }\n  }\n": types.PasswordRecoveryDocument,
    "\n  mutation AllowCrossSigningReset($userId: ID!) {\n    allowUserCrossSigningReset(input: { userId: $userId }) {\n      user {\n        id\n      }\n    }\n  }\n": types.AllowCrossSigningResetDocument,
    "\n  query SessionDetail($id: ID!) {\n    viewerSession {\n      ... on Node {\n        id\n      }\n    }\n\n    node(id: $id) {\n      __typename\n      id\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n      ...BrowserSession_detail\n    }\n  }\n": types.SessionDetailDocument,
};

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment AccountDeleteButton_user on User {\n    username\n    hasPassword\n    matrix {\n      mxid\n      displayName\n    }\n  }\n"): typeof import('./graphql').AccountDeleteButton_UserFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment AccountDeleteButton_siteConfig on SiteConfig {\n    passwordLoginEnabled\n  }\n"): typeof import('./graphql').AccountDeleteButton_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation DeactivateUser($hsErase: Boolean!, $password: String) {\n    deactivateUser(input: { hsErase: $hsErase, password: $password }) {\n      status\n    }\n  }\n"): typeof import('./graphql').DeactivateUserDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment PasswordChange_siteConfig on SiteConfig {\n    passwordChangeAllowed\n  }\n"): typeof import('./graphql').PasswordChange_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    ...EndBrowserSessionButton_session\n    userAgent {\n      deviceType\n      name\n      os\n      model\n    }\n    lastActiveAt\n  }\n"): typeof import('./graphql').BrowserSession_SessionFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n"): typeof import('./graphql').OAuth2Client_DetailFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n    ...EndCompatSessionButton_session\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"): typeof import('./graphql').CompatSession_SessionFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment Footer_siteConfig on SiteConfig {\n    id\n    imprint\n    tosUri\n    policyUri\n  }\n"): typeof import('./graphql').Footer_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query Footer {\n    siteConfig {\n      id\n      ...Footer_siteConfig\n    }\n  }\n"): typeof import('./graphql').FooterDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndOAuth2SessionButton_session\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n"): typeof import('./graphql').OAuth2Session_SessionFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {\n    id\n    minimumPasswordComplexity\n  }\n"): typeof import('./graphql').PasswordCreationDoubleInput_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment EndBrowserSessionButton_session on BrowserSession {\n    id\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n  }\n"): typeof import('./graphql').EndBrowserSessionButton_SessionFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').EndBrowserSessionDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment EndCompatSessionButton_session on CompatSession {\n    id\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"): typeof import('./graphql').EndCompatSessionButton_SessionFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').EndCompatSessionDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment EndOAuth2SessionButton_session on Oauth2Session {\n    id\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n"): typeof import('./graphql').EndOAuth2SessionButton_SessionFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').EndOAuth2SessionDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    ...EndBrowserSessionButton_session\n    userAgent {\n      name\n      model\n      os\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n"): typeof import('./graphql').BrowserSession_DetailFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation SetCompatSessionName($sessionId: ID!, $displayName: String!) {\n    setCompatSessionName(input: { compatSessionId: $sessionId, humanName: $displayName }) {\n      status\n    }\n  }\n"): typeof import('./graphql').SetCompatSessionNameDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndCompatSessionButton_session\n\n    userAgent {\n      name\n      os\n      model\n    }\n\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"): typeof import('./graphql').CompatSession_DetailFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation SetOAuth2SessionName($sessionId: ID!, $displayName: String!) {\n    setOauth2SessionName(input: { oauth2SessionId: $sessionId, humanName: $displayName }) {\n      status\n    }\n  }\n"): typeof import('./graphql').SetOAuth2SessionNameDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    humanName\n\n    ...EndOAuth2SessionButton_session\n\n    userAgent {\n      name\n      model\n      os\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n"): typeof import('./graphql').OAuth2Session_DetailFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n  }\n"): typeof import('./graphql').UserEmail_EmailFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation RemoveEmail($id: ID!, $password: String) {\n    removeEmail(input: { userEmailId: $id, password: $password }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').RemoveEmailDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserGreeting_user on User {\n    id\n    matrix {\n      mxid\n      displayName\n    }\n  }\n"): typeof import('./graphql').UserGreeting_UserFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserGreeting_siteConfig on SiteConfig {\n    displayNameChangeAllowed\n  }\n"): typeof import('./graphql').UserGreeting_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n    }\n  }\n"): typeof import('./graphql').SetDisplayNameDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment AddEmailForm_user on User {\n    hasPassword\n  }\n"): typeof import('./graphql').AddEmailForm_UserFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment AddEmailForm_siteConfig on SiteConfig {\n    passwordLoginEnabled\n  }\n"): typeof import('./graphql').AddEmailForm_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation AddEmail($email: String!, $password: String, $language: String!) {\n    startEmailAuthentication(\n      input: { email: $email, password: $password, language: $language }\n    ) {\n      status\n      violations\n      authentication {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').AddEmailDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query UserEmailList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    viewer {\n      __typename\n      ... on User {\n        emails(first: $first, after: $after, last: $last, before: $before) {\n          edges {\n            cursor\n            node {\n              ...UserEmail_email\n            }\n          }\n          totalCount\n          pageInfo {\n            hasNextPage\n            hasPreviousPage\n            startCursor\n            endCursor\n          }\n        }\n      }\n    }\n  }\n"): typeof import('./graphql').UserEmailListDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmailList_user on User {\n    hasPassword\n  }\n"): typeof import('./graphql').UserEmailList_UserFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmailList_siteConfig on SiteConfig {\n    emailChangeAllowed\n    passwordLoginEnabled\n  }\n"): typeof import('./graphql').UserEmailList_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n"): typeof import('./graphql').BrowserSessionsOverview_UserFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query UserProfile {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n        user {\n          ...AddEmailForm_user\n          ...UserEmailList_user\n          ...AccountDeleteButton_user\n          hasPassword\n          emails(first: 0) {\n            totalCount\n          }\n        }\n      }\n    }\n\n    siteConfig {\n      emailChangeAllowed\n      passwordLoginEnabled\n      passkeysEnabled\n      accountDeactivationAllowed\n      ...AddEmailForm_siteConfig\n      ...UserEmailList_siteConfig\n      ...PasswordChange_siteConfig\n      ...AccountDeleteButton_siteConfig\n    }\n  }\n"): typeof import('./graphql').UserProfileDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query PlanManagementTab {\n    siteConfig {\n      planManagementIframeUri\n    }\n  }\n"): typeof import('./graphql').PlanManagementTabDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query BrowserSessionList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n    $lastActive: DateFilter\n  ) {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n\n          browserSessions(\n            first: $first\n            after: $after\n            last: $last\n            before: $before\n            lastActive: $lastActive\n            state: ACTIVE\n          ) {\n            totalCount\n\n            edges {\n              cursor\n              node {\n                id\n                ...BrowserSession_session\n              }\n            }\n\n            pageInfo {\n              hasNextPage\n              hasPreviousPage\n              startCursor\n              endCursor\n            }\n          }\n        }\n      }\n    }\n  }\n"): typeof import('./graphql').BrowserSessionListDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query SessionsOverview {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n"): typeof import('./graphql').SessionsOverviewDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query AppSessionsList(\n    $before: String\n    $after: String\n    $first: Int\n    $last: Int\n    $lastActive: DateFilter\n  ) {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        appSessions(\n          before: $before\n          after: $after\n          first: $first\n          last: $last\n          lastActive: $lastActive\n          state: ACTIVE\n        ) {\n          edges {\n            cursor\n            node {\n              __typename\n              ...CompatSession_session\n              ...OAuth2Session_session\n            }\n          }\n\n          totalCount\n          pageInfo {\n            startCursor\n            endCursor\n            hasNextPage\n            hasPreviousPage\n          }\n        }\n      }\n    }\n  }\n"): typeof import('./graphql').AppSessionsListDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query CurrentUserGreeting {\n    viewer {\n      __typename\n      ... on User {\n        ...UserGreeting_user\n      }\n    }\n\n    siteConfig {\n      ...UserGreeting_siteConfig\n      planManagementIframeUri\n    }\n  }\n"): typeof import('./graphql').CurrentUserGreetingDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query OAuth2Client($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n"): typeof import('./graphql').OAuth2ClientDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query CurrentViewer {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').CurrentViewerDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query DeviceRedirect($deviceId: String!, $userId: ID!) {\n    session(deviceId: $deviceId, userId: $userId) {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').DeviceRedirectDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query VerifyEmail($id: ID!) {\n    userEmailAuthentication(id: $id) {\n      id\n      email\n      completedAt\n    }\n  }\n"): typeof import('./graphql').VerifyEmailDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation DoVerifyEmail($id: ID!, $code: String!) {\n    completeEmailAuthentication(input: { id: $id, code: $code }) {\n      status\n    }\n  }\n"): typeof import('./graphql').DoVerifyEmailDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation ResendEmailAuthenticationCode($id: ID!, $language: String!) {\n    resendEmailAuthenticationCode(input: { id: $id, language: $language }) {\n      status\n    }\n  }\n"): typeof import('./graphql').ResendEmailAuthenticationCodeDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation ChangePassword(\n    $userId: ID!\n    $oldPassword: String!\n    $newPassword: String!\n  ) {\n    setPassword(\n      input: {\n        userId: $userId\n        currentPassword: $oldPassword\n        newPassword: $newPassword\n      }\n    ) {\n      status\n    }\n  }\n"): typeof import('./graphql').ChangePasswordDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query PasswordChange {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n\n    siteConfig {\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n"): typeof import('./graphql').PasswordChangeDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation RecoverPassword($ticket: String!, $newPassword: String!) {\n    setPasswordByRecovery(\n      input: { ticket: $ticket, newPassword: $newPassword }\n    ) {\n      status\n    }\n  }\n"): typeof import('./graphql').RecoverPasswordDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation ResendRecoveryEmail($ticket: String!) {\n    resendRecoveryEmail(input: { ticket: $ticket }) {\n      status\n      progressUrl\n    }\n  }\n"): typeof import('./graphql').ResendRecoveryEmailDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment RecoverPassword_userRecoveryTicket on UserRecoveryTicket {\n    username\n    email\n  }\n"): typeof import('./graphql').RecoverPassword_UserRecoveryTicketFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment RecoverPassword_siteConfig on SiteConfig {\n    ...PasswordCreationDoubleInput_siteConfig\n  }\n"): typeof import('./graphql').RecoverPassword_SiteConfigFragmentDoc;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query PasswordRecovery($ticket: String!) {\n    siteConfig {\n      ...RecoverPassword_siteConfig\n    }\n\n    userRecoveryTicket(ticket: $ticket) {\n      status\n      ...RecoverPassword_userRecoveryTicket\n    }\n  }\n"): typeof import('./graphql').PasswordRecoveryDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation AllowCrossSigningReset($userId: ID!) {\n    allowUserCrossSigningReset(input: { userId: $userId }) {\n      user {\n        id\n      }\n    }\n  }\n"): typeof import('./graphql').AllowCrossSigningResetDocument;
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query SessionDetail($id: ID!) {\n    viewerSession {\n      ... on Node {\n        id\n      }\n    }\n\n    node(id: $id) {\n      __typename\n      id\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n      ...BrowserSession_detail\n    }\n  }\n"): typeof import('./graphql').SessionDetailDocument;


export function graphql(source: string) {
  return (documents as any)[source] ?? {};
}
