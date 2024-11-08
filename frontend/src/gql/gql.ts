/* eslint-disable */
import * as types from './graphql';
import type { TypedDocumentNode as DocumentNode } from '@graphql-typed-document-node/core';

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
const documents = {
    "\n  fragment PasswordChange_siteConfig on SiteConfig {\n    id\n    passwordChangeAllowed\n  }\n": types.PasswordChange_SiteConfigFragmentDoc,
    "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent {\n      raw\n      name\n      os\n      model\n      deviceType\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n": types.BrowserSession_SessionFragmentDoc,
    "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n        ...BrowserSession_session\n      }\n    }\n  }\n": types.EndBrowserSessionDocument,
    "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n": types.OAuth2Client_DetailFragmentDoc,
    "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": types.CompatSession_SessionFragmentDoc,
    "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n        finishedAt\n      }\n    }\n  }\n": types.EndCompatSessionDocument,
    "\n  fragment Footer_siteConfig on SiteConfig {\n    id\n    imprint\n    tosUri\n    policyUri\n  }\n": types.Footer_SiteConfigFragmentDoc,
    "\n  query FooterQuery {\n    siteConfig {\n      id\n      ...Footer_siteConfig\n    }\n  }\n": types.FooterQueryDocument,
    "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n": types.OAuth2Session_SessionFragmentDoc,
    "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n        ...OAuth2Session_session\n      }\n    }\n  }\n": types.EndOAuth2SessionDocument,
    "\n  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {\n    id\n    minimumPasswordComplexity\n  }\n": types.PasswordCreationDoubleInput_SiteConfigFragmentDoc,
    "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent {\n      name\n      model\n      os\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n": types.BrowserSession_DetailFragmentDoc,
    "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    userAgent {\n      name\n      os\n      model\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n": types.CompatSession_DetailFragmentDoc,
    "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n": types.OAuth2Session_DetailFragmentDoc,
    "\n  fragment UnverifiedEmailAlert_user on User {\n    id\n    unverifiedEmails: emails(first: 0, state: PENDING) {\n      totalCount\n    }\n  }\n": types.UnverifiedEmailAlert_UserFragmentDoc,
    "\n  fragment LinkUpstreamProvider_provider on UpstreamOAuth2Provider {\n    id\n    humanName\n    brandName\n  }\n": types.LinkUpstreamProvider_ProviderFragmentDoc,
    "\n  fragment UnlinkUpstreamProvider_provider on UpstreamOAuth2Provider {\n    id\n    createdAt\n    humanName\n    upstreamOauth2LinksForUser {\n      id\n      provider {\n        id\n      }\n    }\n  }\n": types.UnlinkUpstreamProvider_ProviderFragmentDoc,
    "\n  mutation RemoveUpstreamLink($id: ID!) {\n    removeUpstreamLink(input: { upstreamLinkId: $id }) {\n      status\n    }\n  }\n": types.RemoveUpstreamLinkDocument,
    "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    confirmedAt\n  }\n": types.UserEmail_EmailFragmentDoc,
    "\n  fragment UserEmail_siteConfig on SiteConfig {\n    id\n    emailChangeAllowed\n  }\n": types.UserEmail_SiteConfigFragmentDoc,
    "\n  mutation RemoveEmail($id: ID!) {\n    removeEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n": types.RemoveEmailDocument,
    "\n  mutation SetPrimaryEmail($id: ID!) {\n    setPrimaryEmail(input: { userEmailId: $id }) {\n      status\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n    }\n  }\n": types.SetPrimaryEmailDocument,
    "\n  fragment UserGreeting_user on User {\n    id\n    matrix {\n      mxid\n      displayName\n    }\n  }\n": types.UserGreeting_UserFragmentDoc,
    "\n  fragment UserGreeting_siteConfig on SiteConfig {\n    id\n    displayNameChangeAllowed\n  }\n": types.UserGreeting_SiteConfigFragmentDoc,
    "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n      user {\n        id\n        matrix {\n          displayName\n        }\n      }\n    }\n  }\n": types.SetDisplayNameDocument,
    "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      violations\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n": types.AddEmailDocument,
    "\n  query UpstreamProviderListQuery(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    upstreamOauth2Providers(\n      first: $first\n      after: $after\n      last: $last\n      before: $before\n    ) {\n      edges {\n        cursor\n        node {\n          id\n          upstreamOauth2LinksForUser {\n            id\n            provider {\n              id\n            }\n          }\n          ...LinkUpstreamProvider_provider\n          ...UnlinkUpstreamProvider_provider\n        }\n      }\n      totalCount\n      pageInfo {\n        hasNextPage\n        hasPreviousPage\n        startCursor\n        endCursor\n      }\n    }\n  }\n": types.UpstreamProviderListQueryDocument,
    "\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n": types.UserEmailListQueryDocument,
    "\n  fragment UserEmailList_user on User {\n    id\n    primaryEmail {\n      id\n    }\n  }\n": types.UserEmailList_UserFragmentDoc,
    "\n  fragment UserEmailList_siteConfig on SiteConfig {\n    id\n    ...UserEmail_siteConfig\n  }\n": types.UserEmailList_SiteConfigFragmentDoc,
    "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n": types.BrowserSessionsOverview_UserFragmentDoc,
    "\n  fragment UserEmail_verifyEmail on UserEmail {\n    id\n    email\n  }\n": types.UserEmail_VerifyEmailFragmentDoc,
    "\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n": types.VerifyEmailDocument,
    "\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n": types.ResendVerificationEmailDocument,
    "\n  query UserProfileQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n\n        primaryEmail {\n          id\n          ...UserEmail_email\n        }\n\n        ...UserEmailList_user\n      }\n    }\n\n    siteConfig {\n      id\n      emailChangeAllowed\n      passwordLoginEnabled\n      ...UserEmailList_siteConfig\n      ...UserEmail_siteConfig\n      ...PasswordChange_siteConfig\n    }\n  }\n": types.UserProfileQueryDocument,
    "\n  query SessionDetailQuery($id: ID!) {\n    viewerSession {\n      ... on Node {\n        id\n      }\n    }\n\n    node(id: $id) {\n      __typename\n      id\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n      ...BrowserSession_detail\n    }\n  }\n": types.SessionDetailQueryDocument,
    "\n  query BrowserSessionList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n    $lastActive: DateFilter\n  ) {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n\n          browserSessions(\n            first: $first\n            after: $after\n            last: $last\n            before: $before\n            lastActive: $lastActive\n            state: ACTIVE\n          ) {\n            totalCount\n\n            edges {\n              cursor\n              node {\n                id\n                ...BrowserSession_session\n              }\n            }\n\n            pageInfo {\n              hasNextPage\n              hasPreviousPage\n              startCursor\n              endCursor\n            }\n          }\n        }\n      }\n    }\n  }\n": types.BrowserSessionListDocument,
    "\n  query SessionsOverviewQuery {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n": types.SessionsOverviewQueryDocument,
    "\n  query AppSessionsListQuery(\n    $before: String\n    $after: String\n    $first: Int\n    $last: Int\n    $lastActive: DateFilter\n  ) {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        appSessions(\n          before: $before\n          after: $after\n          first: $first\n          last: $last\n          lastActive: $lastActive\n          state: ACTIVE\n        ) {\n          edges {\n            cursor\n            node {\n              __typename\n              ...CompatSession_session\n              ...OAuth2Session_session\n            }\n          }\n\n          totalCount\n          pageInfo {\n            startCursor\n            endCursor\n            hasNextPage\n            hasPreviousPage\n          }\n        }\n      }\n    }\n  }\n": types.AppSessionsListQueryDocument,
    "\n  query CurrentUserGreeting {\n    viewerSession {\n      __typename\n\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n          ...UnverifiedEmailAlert_user\n          ...UserGreeting_user\n        }\n      }\n    }\n\n    siteConfig {\n      id\n      ...UserGreeting_siteConfig\n    }\n  }\n": types.CurrentUserGreetingDocument,
    "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n": types.OAuth2ClientQueryDocument,
    "\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n": types.CurrentViewerQueryDocument,
    "\n  query DeviceRedirectQuery($deviceId: String!, $userId: ID!) {\n    session(deviceId: $deviceId, userId: $userId) {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n": types.DeviceRedirectQueryDocument,
    "\n  query VerifyEmailQuery($id: ID!) {\n    userEmail(id: $id) {\n      ...UserEmail_verifyEmail\n    }\n  }\n": types.VerifyEmailQueryDocument,
    "\n  mutation ChangePassword(\n    $userId: ID!\n    $oldPassword: String!\n    $newPassword: String!\n  ) {\n    setPassword(\n      input: {\n        userId: $userId\n        currentPassword: $oldPassword\n        newPassword: $newPassword\n      }\n    ) {\n      status\n    }\n  }\n": types.ChangePasswordDocument,
    "\n  query PasswordChangeQuery {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n\n    siteConfig {\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n": types.PasswordChangeQueryDocument,
    "\n  mutation RecoverPassword($ticket: String!, $newPassword: String!) {\n    setPasswordByRecovery(\n      input: { ticket: $ticket, newPassword: $newPassword }\n    ) {\n      status\n    }\n  }\n": types.RecoverPasswordDocument,
    "\n  query PasswordRecoveryQuery {\n    siteConfig {\n      id\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n": types.PasswordRecoveryQueryDocument,
    "\n  mutation AllowCrossSigningReset($userId: ID!) {\n    allowUserCrossSigningReset(input: { userId: $userId }) {\n      user {\n        id\n      }\n    }\n  }\n": types.AllowCrossSigningResetDocument,
};

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 *
 *
 * @example
 * ```ts
 * const query = graphql(`query GetUser($id: ID!) { user(id: $id) { name } }`);
 * ```
 *
 * The query argument is unknown!
 * Please regenerate the types.
 */
export function graphql(source: string): unknown;

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment PasswordChange_siteConfig on SiteConfig {\n    id\n    passwordChangeAllowed\n  }\n"): (typeof documents)["\n  fragment PasswordChange_siteConfig on SiteConfig {\n    id\n    passwordChangeAllowed\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent {\n      raw\n      name\n      os\n      model\n      deviceType\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n"): (typeof documents)["\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent {\n      raw\n      name\n      os\n      model\n      deviceType\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n        ...BrowserSession_session\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n        ...BrowserSession_session\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n"): (typeof documents)["\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"): (typeof documents)["\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    userAgent {\n      name\n      os\n      model\n      deviceType\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n        finishedAt\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n        finishedAt\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment Footer_siteConfig on SiteConfig {\n    id\n    imprint\n    tosUri\n    policyUri\n  }\n"): (typeof documents)["\n  fragment Footer_siteConfig on SiteConfig {\n    id\n    imprint\n    tosUri\n    policyUri\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query FooterQuery {\n    siteConfig {\n      id\n      ...Footer_siteConfig\n    }\n  }\n"): (typeof documents)["\n  query FooterQuery {\n    siteConfig {\n      id\n      ...Footer_siteConfig\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n"): (typeof documents)["\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n\n    userAgent {\n      name\n      model\n      os\n      deviceType\n    }\n\n    client {\n      id\n      clientId\n      clientName\n      applicationType\n      logoUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n        ...OAuth2Session_session\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n        ...OAuth2Session_session\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {\n    id\n    minimumPasswordComplexity\n  }\n"): (typeof documents)["\n  fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {\n    id\n    minimumPasswordComplexity\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent {\n      name\n      model\n      os\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n"): (typeof documents)["\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent {\n      name\n      model\n      os\n    }\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    userAgent {\n      name\n      os\n      model\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"): (typeof documents)["\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    userAgent {\n      name\n      os\n      model\n    }\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n"): (typeof documents)["\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UnverifiedEmailAlert_user on User {\n    id\n    unverifiedEmails: emails(first: 0, state: PENDING) {\n      totalCount\n    }\n  }\n"): (typeof documents)["\n  fragment UnverifiedEmailAlert_user on User {\n    id\n    unverifiedEmails: emails(first: 0, state: PENDING) {\n      totalCount\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment LinkUpstreamProvider_provider on UpstreamOAuth2Provider {\n    id\n    humanName\n    brandName\n  }\n"): (typeof documents)["\n  fragment LinkUpstreamProvider_provider on UpstreamOAuth2Provider {\n    id\n    humanName\n    brandName\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UnlinkUpstreamProvider_provider on UpstreamOAuth2Provider {\n    id\n    createdAt\n    humanName\n    upstreamOauth2LinksForUser {\n      id\n      provider {\n        id\n      }\n    }\n  }\n"): (typeof documents)["\n  fragment UnlinkUpstreamProvider_provider on UpstreamOAuth2Provider {\n    id\n    createdAt\n    humanName\n    upstreamOauth2LinksForUser {\n      id\n      provider {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation RemoveUpstreamLink($id: ID!) {\n    removeUpstreamLink(input: { upstreamLinkId: $id }) {\n      status\n    }\n  }\n"): (typeof documents)["\n  mutation RemoveUpstreamLink($id: ID!) {\n    removeUpstreamLink(input: { upstreamLinkId: $id }) {\n      status\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    confirmedAt\n  }\n"): (typeof documents)["\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    confirmedAt\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmail_siteConfig on SiteConfig {\n    id\n    emailChangeAllowed\n  }\n"): (typeof documents)["\n  fragment UserEmail_siteConfig on SiteConfig {\n    id\n    emailChangeAllowed\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation RemoveEmail($id: ID!) {\n    removeEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation RemoveEmail($id: ID!) {\n    removeEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation SetPrimaryEmail($id: ID!) {\n    setPrimaryEmail(input: { userEmailId: $id }) {\n      status\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation SetPrimaryEmail($id: ID!) {\n    setPrimaryEmail(input: { userEmailId: $id }) {\n      status\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserGreeting_user on User {\n    id\n    matrix {\n      mxid\n      displayName\n    }\n  }\n"): (typeof documents)["\n  fragment UserGreeting_user on User {\n    id\n    matrix {\n      mxid\n      displayName\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserGreeting_siteConfig on SiteConfig {\n    id\n    displayNameChangeAllowed\n  }\n"): (typeof documents)["\n  fragment UserGreeting_siteConfig on SiteConfig {\n    id\n    displayNameChangeAllowed\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n      user {\n        id\n        matrix {\n          displayName\n        }\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n      user {\n        id\n        matrix {\n          displayName\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      violations\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      violations\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query UpstreamProviderListQuery(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    upstreamOauth2Providers(\n      first: $first\n      after: $after\n      last: $last\n      before: $before\n    ) {\n      edges {\n        cursor\n        node {\n          id\n          upstreamOauth2LinksForUser {\n            id\n            provider {\n              id\n            }\n          }\n          ...LinkUpstreamProvider_provider\n          ...UnlinkUpstreamProvider_provider\n        }\n      }\n      totalCount\n      pageInfo {\n        hasNextPage\n        hasPreviousPage\n        startCursor\n        endCursor\n      }\n    }\n  }\n"): (typeof documents)["\n  query UpstreamProviderListQuery(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    upstreamOauth2Providers(\n      first: $first\n      after: $after\n      last: $last\n      before: $before\n    ) {\n      edges {\n        cursor\n        node {\n          id\n          upstreamOauth2LinksForUser {\n            id\n            provider {\n              id\n            }\n          }\n          ...LinkUpstreamProvider_provider\n          ...UnlinkUpstreamProvider_provider\n        }\n      }\n      totalCount\n      pageInfo {\n        hasNextPage\n        hasPreviousPage\n        startCursor\n        endCursor\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"): (typeof documents)["\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmailList_user on User {\n    id\n    primaryEmail {\n      id\n    }\n  }\n"): (typeof documents)["\n  fragment UserEmailList_user on User {\n    id\n    primaryEmail {\n      id\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmailList_siteConfig on SiteConfig {\n    id\n    ...UserEmail_siteConfig\n  }\n"): (typeof documents)["\n  fragment UserEmailList_siteConfig on SiteConfig {\n    id\n    ...UserEmail_siteConfig\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n"): (typeof documents)["\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  fragment UserEmail_verifyEmail on UserEmail {\n    id\n    email\n  }\n"): (typeof documents)["\n  fragment UserEmail_verifyEmail on UserEmail {\n    id\n    email\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query UserProfileQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n\n        primaryEmail {\n          id\n          ...UserEmail_email\n        }\n\n        ...UserEmailList_user\n      }\n    }\n\n    siteConfig {\n      id\n      emailChangeAllowed\n      passwordLoginEnabled\n      ...UserEmailList_siteConfig\n      ...UserEmail_siteConfig\n      ...PasswordChange_siteConfig\n    }\n  }\n"): (typeof documents)["\n  query UserProfileQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n\n        primaryEmail {\n          id\n          ...UserEmail_email\n        }\n\n        ...UserEmailList_user\n      }\n    }\n\n    siteConfig {\n      id\n      emailChangeAllowed\n      passwordLoginEnabled\n      ...UserEmailList_siteConfig\n      ...UserEmail_siteConfig\n      ...PasswordChange_siteConfig\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query SessionDetailQuery($id: ID!) {\n    viewerSession {\n      ... on Node {\n        id\n      }\n    }\n\n    node(id: $id) {\n      __typename\n      id\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n      ...BrowserSession_detail\n    }\n  }\n"): (typeof documents)["\n  query SessionDetailQuery($id: ID!) {\n    viewerSession {\n      ... on Node {\n        id\n      }\n    }\n\n    node(id: $id) {\n      __typename\n      id\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n      ...BrowserSession_detail\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query BrowserSessionList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n    $lastActive: DateFilter\n  ) {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n\n          browserSessions(\n            first: $first\n            after: $after\n            last: $last\n            before: $before\n            lastActive: $lastActive\n            state: ACTIVE\n          ) {\n            totalCount\n\n            edges {\n              cursor\n              node {\n                id\n                ...BrowserSession_session\n              }\n            }\n\n            pageInfo {\n              hasNextPage\n              hasPreviousPage\n              startCursor\n              endCursor\n            }\n          }\n        }\n      }\n    }\n  }\n"): (typeof documents)["\n  query BrowserSessionList(\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n    $lastActive: DateFilter\n  ) {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n\n          browserSessions(\n            first: $first\n            after: $after\n            last: $last\n            before: $before\n            lastActive: $lastActive\n            state: ACTIVE\n          ) {\n            totalCount\n\n            edges {\n              cursor\n              node {\n                id\n                ...BrowserSession_session\n              }\n            }\n\n            pageInfo {\n              hasNextPage\n              hasPreviousPage\n              startCursor\n              endCursor\n            }\n          }\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query SessionsOverviewQuery {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n"): (typeof documents)["\n  query SessionsOverviewQuery {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query AppSessionsListQuery(\n    $before: String\n    $after: String\n    $first: Int\n    $last: Int\n    $lastActive: DateFilter\n  ) {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        appSessions(\n          before: $before\n          after: $after\n          first: $first\n          last: $last\n          lastActive: $lastActive\n          state: ACTIVE\n        ) {\n          edges {\n            cursor\n            node {\n              __typename\n              ...CompatSession_session\n              ...OAuth2Session_session\n            }\n          }\n\n          totalCount\n          pageInfo {\n            startCursor\n            endCursor\n            hasNextPage\n            hasPreviousPage\n          }\n        }\n      }\n    }\n  }\n"): (typeof documents)["\n  query AppSessionsListQuery(\n    $before: String\n    $after: String\n    $first: Int\n    $last: Int\n    $lastActive: DateFilter\n  ) {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        appSessions(\n          before: $before\n          after: $after\n          first: $first\n          last: $last\n          lastActive: $lastActive\n          state: ACTIVE\n        ) {\n          edges {\n            cursor\n            node {\n              __typename\n              ...CompatSession_session\n              ...OAuth2Session_session\n            }\n          }\n\n          totalCount\n          pageInfo {\n            startCursor\n            endCursor\n            hasNextPage\n            hasPreviousPage\n          }\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query CurrentUserGreeting {\n    viewerSession {\n      __typename\n\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n          ...UnverifiedEmailAlert_user\n          ...UserGreeting_user\n        }\n      }\n    }\n\n    siteConfig {\n      id\n      ...UserGreeting_siteConfig\n    }\n  }\n"): (typeof documents)["\n  query CurrentUserGreeting {\n    viewerSession {\n      __typename\n\n      ... on BrowserSession {\n        id\n\n        user {\n          id\n          ...UnverifiedEmailAlert_user\n          ...UserGreeting_user\n        }\n      }\n    }\n\n    siteConfig {\n      id\n      ...UserGreeting_siteConfig\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n"): (typeof documents)["\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n"): (typeof documents)["\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query DeviceRedirectQuery($deviceId: String!, $userId: ID!) {\n    session(deviceId: $deviceId, userId: $userId) {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n"): (typeof documents)["\n  query DeviceRedirectQuery($deviceId: String!, $userId: ID!) {\n    session(deviceId: $deviceId, userId: $userId) {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query VerifyEmailQuery($id: ID!) {\n    userEmail(id: $id) {\n      ...UserEmail_verifyEmail\n    }\n  }\n"): (typeof documents)["\n  query VerifyEmailQuery($id: ID!) {\n    userEmail(id: $id) {\n      ...UserEmail_verifyEmail\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation ChangePassword(\n    $userId: ID!\n    $oldPassword: String!\n    $newPassword: String!\n  ) {\n    setPassword(\n      input: {\n        userId: $userId\n        currentPassword: $oldPassword\n        newPassword: $newPassword\n      }\n    ) {\n      status\n    }\n  }\n"): (typeof documents)["\n  mutation ChangePassword(\n    $userId: ID!\n    $oldPassword: String!\n    $newPassword: String!\n  ) {\n    setPassword(\n      input: {\n        userId: $userId\n        currentPassword: $oldPassword\n        newPassword: $newPassword\n      }\n    ) {\n      status\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query PasswordChangeQuery {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n\n    siteConfig {\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n"): (typeof documents)["\n  query PasswordChangeQuery {\n    viewer {\n      __typename\n      ... on Node {\n        id\n      }\n    }\n\n    siteConfig {\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation RecoverPassword($ticket: String!, $newPassword: String!) {\n    setPasswordByRecovery(\n      input: { ticket: $ticket, newPassword: $newPassword }\n    ) {\n      status\n    }\n  }\n"): (typeof documents)["\n  mutation RecoverPassword($ticket: String!, $newPassword: String!) {\n    setPasswordByRecovery(\n      input: { ticket: $ticket, newPassword: $newPassword }\n    ) {\n      status\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  query PasswordRecoveryQuery {\n    siteConfig {\n      id\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n"): (typeof documents)["\n  query PasswordRecoveryQuery {\n    siteConfig {\n      id\n      ...PasswordCreationDoubleInput_siteConfig\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(source: "\n  mutation AllowCrossSigningReset($userId: ID!) {\n    allowUserCrossSigningReset(input: { userId: $userId }) {\n      user {\n        id\n      }\n    }\n  }\n"): (typeof documents)["\n  mutation AllowCrossSigningReset($userId: ID!) {\n    allowUserCrossSigningReset(input: { userId: $userId }) {\n      user {\n        id\n      }\n    }\n  }\n"];

export function graphql(source: string) {
  return (documents as any)[source] ?? {};
}

export type DocumentType<TDocumentNode extends DocumentNode<any, any>> = TDocumentNode extends DocumentNode<  infer TType,  any>  ? TType  : never;