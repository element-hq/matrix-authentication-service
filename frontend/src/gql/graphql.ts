/* eslint-disable */
/** Internal type. DO NOT USE DIRECTLY. */
type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
/** Internal type. DO NOT USE DIRECTLY. */
export type Incremental<T> = T | { [P in keyof T]?: P extends ' $fragmentName' | '__typename' ? T[P] : never };
import type { DocumentTypeDecoration } from '@graphql-typed-document-node/core';
import { graphql, type GraphQLResponseResolver, type RequestHandlerOptions } from 'msw'
/** The status of the `completeEmailAuthentication` mutation */
export type CompleteEmailAuthenticationStatus =
  /** The authentication code has expired */
  | 'CODE_EXPIRED'
  /** The authentication was completed */
  | 'COMPLETED'
  /** The authentication code is invalid */
  | 'INVALID_CODE'
  /** The email address is already in use */
  | 'IN_USE'
  /** Too many attempts to complete an email authentication */
  | 'RATE_LIMITED';

/** A filter for dates, with a lower bound and an upper bound */
export type DateFilter = {
  /** The lower bound of the date range */
  after?: string | null | undefined;
  /** The upper bound of the date range */
  before?: string | null | undefined;
};

/** The status of the `deactivateUser` mutation. */
export type DeactivateUserStatus =
  /** The user was deactivated. */
  | 'DEACTIVATED'
  /** The password was wrong. */
  | 'INCORRECT_PASSWORD';

/** The type of a user agent */
export type DeviceType =
  /** A mobile phone. Can also sometimes be a tablet. */
  | 'MOBILE'
  /** A personal computer, laptop or desktop */
  | 'PC'
  /** A tablet */
  | 'TABLET'
  /** Unknown device type */
  | 'UNKNOWN';

/** The status of the `endBrowserSession` mutation. */
export type EndBrowserSessionStatus =
  /** The session was ended. */
  | 'ENDED'
  /** The session was not found. */
  | 'NOT_FOUND';

/** The status of the `endCompatSession` mutation. */
export type EndCompatSessionStatus =
  /** The session was ended. */
  | 'ENDED'
  /** The session was not found. */
  | 'NOT_FOUND';

/** The status of the `endOauth2Session` mutation. */
export type EndOAuth2SessionStatus =
  /** The session was ended. */
  | 'ENDED'
  /** The session was not found. */
  | 'NOT_FOUND';

/** The application type advertised by the client. */
export type Oauth2ApplicationType =
  /** Client is a native application. */
  | 'NATIVE'
  /** Client is a web application. */
  | 'WEB';

/** The status of the `removeEmail` mutation */
export type RemoveEmailStatus =
  /** The password provided is incorrect */
  | 'INCORRECT_PASSWORD'
  /** The email address was not found */
  | 'NOT_FOUND'
  /** The email address was removed */
  | 'REMOVED';

/** The status of the `resendEmailAuthenticationCode` mutation */
export type ResendEmailAuthenticationCodeStatus =
  /** The email authentication session is already completed */
  | 'COMPLETED'
  /** Too many attempts to resend an email authentication code */
  | 'RATE_LIMITED'
  /** The email was resent */
  | 'RESENT';

/** The status of the `resendRecoveryEmail` mutation. */
export type ResendRecoveryEmailStatus =
  /** The recovery ticket was not found. */
  | 'NO_SUCH_RECOVERY_TICKET'
  /** The rate limit was exceeded. */
  | 'RATE_LIMITED'
  /** The recovery email was sent. */
  | 'SENT';

/** The status of the `setCompatSessionName` mutation. */
export type SetCompatSessionNameStatus =
  /** The session was not found. */
  | 'NOT_FOUND'
  /** The session was updated. */
  | 'UPDATED';

/** The status of the `setDisplayName` mutation */
export type SetDisplayNameStatus =
  /** The display name is invalid */
  | 'INVALID'
  /** The display name was set */
  | 'SET';

/** The status of the `setOauth2SessionName` mutation. */
export type SetOAuth2SessionNameStatus =
  /** The session was not found. */
  | 'NOT_FOUND'
  /** The session was updated. */
  | 'UPDATED';

/** The status of the `setPassword` mutation. */
export type SetPasswordStatus =
  /** Your account is locked and you can't change its password. */
  | 'ACCOUNT_LOCKED'
  /** The password was updated. */
  | 'ALLOWED'
  /** The specified recovery ticket has expired. */
  | 'EXPIRED_RECOVERY_TICKET'
  /**
   * The new password is invalid. For example, it may not meet configured
   * security requirements.
   */
  | 'INVALID_NEW_PASSWORD'
  /**
   * You aren't allowed to set the password for that user.
   * This happens if you aren't setting your own password and you aren't a
   * server administrator.
   */
  | 'NOT_ALLOWED'
  /** The user was not found. */
  | 'NOT_FOUND'
  /** The user doesn't have a current password to attempt to match against. */
  | 'NO_CURRENT_PASSWORD'
  /** The specified recovery ticket does not exist. */
  | 'NO_SUCH_RECOVERY_TICKET'
  /**
   * Password support has been disabled.
   * This usually means that login is handled by an upstream identity
   * provider.
   */
  | 'PASSWORD_CHANGES_DISABLED'
  /**
   * The specified recovery ticket has already been used and cannot be used
   * again.
   */
  | 'RECOVERY_TICKET_ALREADY_USED'
  /** The supplied current password was wrong. */
  | 'WRONG_PASSWORD';

/** The status of the `startEmailAuthentication` mutation */
export type StartEmailAuthenticationStatus =
  /** The email address isn't allowed by the policy */
  | 'DENIED'
  /** The password provided is incorrect */
  | 'INCORRECT_PASSWORD'
  /** The email address is invalid */
  | 'INVALID_EMAIL_ADDRESS'
  /** The email address is already in use on this account */
  | 'IN_USE'
  /** Too many attempts to start an email authentication */
  | 'RATE_LIMITED'
  /** The email address was started */
  | 'STARTED';

/** The status of a recovery ticket */
export type UserRecoveryTicketStatus =
  /** The ticket has been consumed */
  | 'CONSUMED'
  /** The ticket has expired */
  | 'EXPIRED'
  /** The ticket is valid */
  | 'VALID';

export type AccountDeleteButton_UserFragment = { username: string, hasPassword: boolean, matrix: { mxid: string, displayName: string | null } } & { ' $fragmentName'?: 'AccountDeleteButton_UserFragment' };

export type AccountDeleteButton_SiteConfigFragment = { passwordLoginEnabled: boolean } & { ' $fragmentName'?: 'AccountDeleteButton_SiteConfigFragment' };

export type DeactivateUserMutationVariables = Exact<{
  hsErase: boolean;
  password?: string | null | undefined;
}>;


export type DeactivateUserMutation = { deactivateUser: { status: DeactivateUserStatus } };

export type PasswordChange_SiteConfigFragment = { passwordChangeAllowed: boolean } & { ' $fragmentName'?: 'PasswordChange_SiteConfigFragment' };

export type BrowserSession_SessionFragment = (
  { id: string, createdAt: string, finishedAt: string | null, lastActiveAt: string | null, userAgent: { deviceType: DeviceType, name: string | null, os: string | null, model: string | null } | null }
  & { ' $fragmentRefs'?: { 'EndBrowserSessionButton_SessionFragment': EndBrowserSessionButton_SessionFragment } }
) & { ' $fragmentName'?: 'BrowserSession_SessionFragment' };

export type OAuth2Client_DetailFragment = { id: string, clientId: string, clientName: string | null, clientUri: string | null, logoUri: string | null, tosUri: string | null, policyUri: string | null, redirectUris: Array<string> } & { ' $fragmentName'?: 'OAuth2Client_DetailFragment' };

export type CompatSession_SessionFragment = (
  { id: string, createdAt: string, deviceId: string | null, finishedAt: string | null, lastActiveIp: string | null, lastActiveAt: string | null, humanName: string | null, userAgent: { name: string | null, os: string | null, model: string | null, deviceType: DeviceType } | null, ssoLogin: { id: string, redirectUri: string } | null }
  & { ' $fragmentRefs'?: { 'EndCompatSessionButton_SessionFragment': EndCompatSessionButton_SessionFragment } }
) & { ' $fragmentName'?: 'CompatSession_SessionFragment' };

export type Footer_SiteConfigFragment = { id: string, imprint: string | null, tosUri: string | null, policyUri: string | null } & { ' $fragmentName'?: 'Footer_SiteConfigFragment' };

export type FooterQueryVariables = Exact<{ [key: string]: never; }>;


export type FooterQuery = { siteConfig: (
    { id: string }
    & { ' $fragmentRefs'?: { 'Footer_SiteConfigFragment': Footer_SiteConfigFragment } }
  ) };

export type OAuth2Session_SessionFragment = (
  { id: string, scope: string, createdAt: string, finishedAt: string | null, lastActiveIp: string | null, lastActiveAt: string | null, humanName: string | null, userAgent: { name: string | null, model: string | null, os: string | null, deviceType: DeviceType } | null, client: { id: string, clientId: string, clientName: string | null, applicationType: Oauth2ApplicationType | null, logoUri: string | null } }
  & { ' $fragmentRefs'?: { 'EndOAuth2SessionButton_SessionFragment': EndOAuth2SessionButton_SessionFragment } }
) & { ' $fragmentName'?: 'OAuth2Session_SessionFragment' };

export type PasswordCreationDoubleInput_SiteConfigFragment = { id: string, minimumPasswordComplexity: number } & { ' $fragmentName'?: 'PasswordCreationDoubleInput_SiteConfigFragment' };

export type EndBrowserSessionButton_SessionFragment = { id: string, userAgent: { name: string | null, os: string | null, model: string | null, deviceType: DeviceType } | null } & { ' $fragmentName'?: 'EndBrowserSessionButton_SessionFragment' };

export type EndBrowserSessionMutationVariables = Exact<{
  id: string | number;
}>;


export type EndBrowserSessionMutation = { endBrowserSession: { status: EndBrowserSessionStatus, browserSession: { id: string } | null } };

export type EndCompatSessionButton_SessionFragment = { id: string, userAgent: { name: string | null, os: string | null, model: string | null, deviceType: DeviceType } | null, ssoLogin: { id: string, redirectUri: string } | null } & { ' $fragmentName'?: 'EndCompatSessionButton_SessionFragment' };

export type EndCompatSessionMutationVariables = Exact<{
  id: string | number;
}>;


export type EndCompatSessionMutation = { endCompatSession: { status: EndCompatSessionStatus, compatSession: { id: string } | null } };

export type EndOAuth2SessionButton_SessionFragment = { id: string, userAgent: { name: string | null, model: string | null, os: string | null, deviceType: DeviceType } | null, client: { clientId: string, clientName: string | null, applicationType: Oauth2ApplicationType | null, logoUri: string | null } } & { ' $fragmentName'?: 'EndOAuth2SessionButton_SessionFragment' };

export type EndOAuth2SessionMutationVariables = Exact<{
  id: string | number;
}>;


export type EndOAuth2SessionMutation = { endOauth2Session: { status: EndOAuth2SessionStatus, oauth2Session: { id: string } | null } };

export type BrowserSession_DetailFragment = (
  { id: string, createdAt: string, finishedAt: string | null, lastActiveIp: string | null, lastActiveAt: string | null, userAgent: { name: string | null, model: string | null, os: string | null } | null, lastAuthentication: { id: string, createdAt: string } | null, user: { id: string, username: string } }
  & { ' $fragmentRefs'?: { 'EndBrowserSessionButton_SessionFragment': EndBrowserSessionButton_SessionFragment } }
) & { ' $fragmentName'?: 'BrowserSession_DetailFragment' };

export type SetCompatSessionNameMutationVariables = Exact<{
  sessionId: string | number;
  displayName: string;
}>;


export type SetCompatSessionNameMutation = { setCompatSessionName: { status: SetCompatSessionNameStatus } };

export type CompatSession_DetailFragment = (
  { id: string, createdAt: string, deviceId: string | null, finishedAt: string | null, lastActiveIp: string | null, lastActiveAt: string | null, humanName: string | null, userAgent: { name: string | null, os: string | null, model: string | null } | null, ssoLogin: { id: string, redirectUri: string } | null }
  & { ' $fragmentRefs'?: { 'EndCompatSessionButton_SessionFragment': EndCompatSessionButton_SessionFragment } }
) & { ' $fragmentName'?: 'CompatSession_DetailFragment' };

export type SetOAuth2SessionNameMutationVariables = Exact<{
  sessionId: string | number;
  displayName: string;
}>;


export type SetOAuth2SessionNameMutation = { setOauth2SessionName: { status: SetOAuth2SessionNameStatus } };

export type OAuth2Session_DetailFragment = (
  { id: string, scope: string, createdAt: string, finishedAt: string | null, lastActiveIp: string | null, lastActiveAt: string | null, humanName: string | null, userAgent: { name: string | null, model: string | null, os: string | null } | null, client: { id: string, clientId: string, clientName: string | null, clientUri: string | null, logoUri: string | null } }
  & { ' $fragmentRefs'?: { 'EndOAuth2SessionButton_SessionFragment': EndOAuth2SessionButton_SessionFragment } }
) & { ' $fragmentName'?: 'OAuth2Session_DetailFragment' };

export type UserEmail_EmailFragment = { id: string, email: string } & { ' $fragmentName'?: 'UserEmail_EmailFragment' };

export type RemoveEmailMutationVariables = Exact<{
  id: string | number;
  password?: string | null | undefined;
}>;


export type RemoveEmailMutation = { removeEmail: { status: RemoveEmailStatus, user: { id: string } | null } };

export type UserGreeting_UserFragment = { id: string, matrix: { mxid: string, displayName: string | null } } & { ' $fragmentName'?: 'UserGreeting_UserFragment' };

export type UserGreeting_SiteConfigFragment = { displayNameChangeAllowed: boolean } & { ' $fragmentName'?: 'UserGreeting_SiteConfigFragment' };

export type SetDisplayNameMutationVariables = Exact<{
  userId: string | number;
  displayName?: string | null | undefined;
}>;


export type SetDisplayNameMutation = { setDisplayName: { status: SetDisplayNameStatus } };

export type AddEmailForm_UserFragment = { hasPassword: boolean } & { ' $fragmentName'?: 'AddEmailForm_UserFragment' };

export type AddEmailForm_SiteConfigFragment = { passwordLoginEnabled: boolean } & { ' $fragmentName'?: 'AddEmailForm_SiteConfigFragment' };

export type AddEmailMutationVariables = Exact<{
  email: string;
  password?: string | null | undefined;
  language: string;
}>;


export type AddEmailMutation = { startEmailAuthentication: { status: StartEmailAuthenticationStatus, violations: Array<string> | null, authentication: { id: string } | null } };

export type UserEmailListQueryVariables = Exact<{
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
}>;


export type UserEmailListQuery = { viewer:
    | { __typename: 'Anonymous' }
    | { __typename: 'User', emails: { totalCount: number, edges: Array<{ cursor: string, node: { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } } }>, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null } } }
   };

export type UserEmailList_UserFragment = { hasPassword: boolean } & { ' $fragmentName'?: 'UserEmailList_UserFragment' };

export type UserEmailList_SiteConfigFragment = { emailChangeAllowed: boolean, passwordLoginEnabled: boolean } & { ' $fragmentName'?: 'UserEmailList_SiteConfigFragment' };

export type BrowserSessionsOverview_UserFragment = { browserSessions: { totalCount: number } } & { ' $fragmentName'?: 'BrowserSessionsOverview_UserFragment' };

export type UserProfileQueryVariables = Exact<{ [key: string]: never; }>;


export type UserProfileQuery = { viewerSession:
    | { __typename: 'Anonymous' }
    | { __typename: 'BrowserSession', id: string, user: (
        { hasPassword: boolean, emails: { totalCount: number } }
        & { ' $fragmentRefs'?: { 'AddEmailForm_UserFragment': AddEmailForm_UserFragment;'UserEmailList_UserFragment': UserEmailList_UserFragment;'AccountDeleteButton_UserFragment': AccountDeleteButton_UserFragment } }
      ) }
    | { __typename: 'Oauth2Session' }
  , siteConfig: (
    { emailChangeAllowed: boolean, passwordLoginEnabled: boolean, accountDeactivationAllowed: boolean }
    & { ' $fragmentRefs'?: { 'AddEmailForm_SiteConfigFragment': AddEmailForm_SiteConfigFragment;'UserEmailList_SiteConfigFragment': UserEmailList_SiteConfigFragment;'PasswordChange_SiteConfigFragment': PasswordChange_SiteConfigFragment;'AccountDeleteButton_SiteConfigFragment': AccountDeleteButton_SiteConfigFragment } }
  ) };

export type PlanManagementTabQueryVariables = Exact<{ [key: string]: never; }>;


export type PlanManagementTabQuery = { siteConfig: { planManagementIframeUri: string | null } };

export type BrowserSessionListQueryVariables = Exact<{
  first?: number | null | undefined;
  after?: string | null | undefined;
  last?: number | null | undefined;
  before?: string | null | undefined;
  lastActive?: DateFilter | null | undefined;
}>;


export type BrowserSessionListQuery = { viewerSession:
    | { __typename: 'Anonymous' }
    | { __typename: 'BrowserSession', id: string, user: { id: string, browserSessions: { totalCount: number, edges: Array<{ cursor: string, node: (
              { id: string }
              & { ' $fragmentRefs'?: { 'BrowserSession_SessionFragment': BrowserSession_SessionFragment } }
            ) }>, pageInfo: { hasNextPage: boolean, hasPreviousPage: boolean, startCursor: string | null, endCursor: string | null } } } }
    | { __typename: 'Oauth2Session' }
   };

export type SessionsOverviewQueryVariables = Exact<{ [key: string]: never; }>;


export type SessionsOverviewQuery = { viewer:
    | { __typename: 'Anonymous' }
    | (
      { __typename: 'User', id: string, unfilteredAppSessions: { totalCount: number } }
      & { ' $fragmentRefs'?: { 'BrowserSessionsOverview_UserFragment': BrowserSessionsOverview_UserFragment } }
    )
  , siteConfig: { sessionLimit: { softLimit: number } | null } };

export type AppSessionsListQueryVariables = Exact<{
  before?: string | null | undefined;
  after?: string | null | undefined;
  first?: number | null | undefined;
  last?: number | null | undefined;
  lastActive?: DateFilter | null | undefined;
}>;


export type AppSessionsListQuery = { viewer:
    | { __typename: 'Anonymous' }
    | { __typename: 'User', id: string, appSessions: { totalCount: number, edges: Array<{ cursor: string, node:
            | (
              { __typename: 'CompatSession' }
              & { ' $fragmentRefs'?: { 'CompatSession_SessionFragment': CompatSession_SessionFragment } }
            )
            | (
              { __typename: 'Oauth2Session' }
              & { ' $fragmentRefs'?: { 'OAuth2Session_SessionFragment': OAuth2Session_SessionFragment } }
            )
           }>, pageInfo: { startCursor: string | null, endCursor: string | null, hasNextPage: boolean, hasPreviousPage: boolean } } }
   };

export type CurrentUserGreetingQueryVariables = Exact<{ [key: string]: never; }>;


export type CurrentUserGreetingQuery = { viewer:
    | { __typename: 'Anonymous' }
    | (
      { __typename: 'User', unfilteredAppSessions: { totalCount: number } }
      & { ' $fragmentRefs'?: { 'UserGreeting_UserFragment': UserGreeting_UserFragment } }
    )
  , siteConfig: (
    { planManagementIframeUri: string | null, sessionLimit: { softLimit: number } | null }
    & { ' $fragmentRefs'?: { 'UserGreeting_SiteConfigFragment': UserGreeting_SiteConfigFragment } }
  ) };

export type OAuth2ClientQueryVariables = Exact<{
  id: string | number;
}>;


export type OAuth2ClientQuery = { oauth2Client: { ' $fragmentRefs'?: { 'OAuth2Client_DetailFragment': OAuth2Client_DetailFragment } } | null };

export type CurrentViewerQueryVariables = Exact<{ [key: string]: never; }>;


export type CurrentViewerQuery = { viewer:
    | { __typename: 'Anonymous', id: string }
    | { __typename: 'User', id: string }
   };

export type DeviceRedirectQueryVariables = Exact<{
  deviceId: string;
  userId: string | number;
}>;


export type DeviceRedirectQuery = { session:
    | { __typename: 'CompatSession', id: string }
    | { __typename: 'Oauth2Session', id: string }
   | null };

export type VerifyEmailQueryVariables = Exact<{
  id: string | number;
}>;


export type VerifyEmailQuery = { userEmailAuthentication: { id: string, email: string, completedAt: string | null } | null };

export type DoVerifyEmailMutationVariables = Exact<{
  id: string | number;
  code: string;
}>;


export type DoVerifyEmailMutation = { completeEmailAuthentication: { status: CompleteEmailAuthenticationStatus } };

export type ResendEmailAuthenticationCodeMutationVariables = Exact<{
  id: string | number;
  language: string;
}>;


export type ResendEmailAuthenticationCodeMutation = { resendEmailAuthenticationCode: { status: ResendEmailAuthenticationCodeStatus } };

export type ChangePasswordMutationVariables = Exact<{
  userId: string | number;
  oldPassword: string;
  newPassword: string;
}>;


export type ChangePasswordMutation = { setPassword: { status: SetPasswordStatus } };

export type PasswordChangeQueryVariables = Exact<{ [key: string]: never; }>;


export type PasswordChangeQuery = { viewer:
    | { __typename: 'Anonymous', id: string }
    | { __typename: 'User', id: string }
  , siteConfig: { ' $fragmentRefs'?: { 'PasswordCreationDoubleInput_SiteConfigFragment': PasswordCreationDoubleInput_SiteConfigFragment } } };

export type RecoverPasswordMutationVariables = Exact<{
  ticket: string;
  newPassword: string;
}>;


export type RecoverPasswordMutation = { setPasswordByRecovery: { status: SetPasswordStatus } };

export type ResendRecoveryEmailMutationVariables = Exact<{
  ticket: string;
}>;


export type ResendRecoveryEmailMutation = { resendRecoveryEmail: { status: ResendRecoveryEmailStatus, progressUrl: string | null } };

export type RecoverPassword_UserRecoveryTicketFragment = { username: string, email: string } & { ' $fragmentName'?: 'RecoverPassword_UserRecoveryTicketFragment' };

export type RecoverPassword_SiteConfigFragment = { ' $fragmentRefs'?: { 'PasswordCreationDoubleInput_SiteConfigFragment': PasswordCreationDoubleInput_SiteConfigFragment } } & { ' $fragmentName'?: 'RecoverPassword_SiteConfigFragment' };

export type PasswordRecoveryQueryVariables = Exact<{
  ticket: string;
}>;


export type PasswordRecoveryQuery = { siteConfig: { ' $fragmentRefs'?: { 'RecoverPassword_SiteConfigFragment': RecoverPassword_SiteConfigFragment } }, userRecoveryTicket: (
    { status: UserRecoveryTicketStatus }
    & { ' $fragmentRefs'?: { 'RecoverPassword_UserRecoveryTicketFragment': RecoverPassword_UserRecoveryTicketFragment } }
  ) | null };

export type AllowCrossSigningResetMutationVariables = Exact<{
  userId: string | number;
}>;


export type AllowCrossSigningResetMutation = { allowUserCrossSigningReset: { user: { id: string } | null } };

export type SessionDetailQueryVariables = Exact<{
  id: string | number;
}>;


export type SessionDetailQuery = { viewerSession:
    | { id: string }
    | { id: string }
    | { id: string }
  , node:
    | { __typename: 'Anonymous', id: string }
    | { __typename: 'Authentication', id: string }
    | (
      { __typename: 'BrowserSession', id: string }
      & { ' $fragmentRefs'?: { 'BrowserSession_DetailFragment': BrowserSession_DetailFragment } }
    )
    | (
      { __typename: 'CompatSession', id: string }
      & { ' $fragmentRefs'?: { 'CompatSession_DetailFragment': CompatSession_DetailFragment } }
    )
    | { __typename: 'CompatSsoLogin', id: string }
    | { __typename: 'Oauth2Client', id: string }
    | (
      { __typename: 'Oauth2Session', id: string }
      & { ' $fragmentRefs'?: { 'OAuth2Session_DetailFragment': OAuth2Session_DetailFragment } }
    )
    | { __typename: 'SiteConfig', id: string }
    | { __typename: 'UpstreamOAuth2Link', id: string }
    | { __typename: 'UpstreamOAuth2Provider', id: string }
    | { __typename: 'User', id: string }
    | { __typename: 'UserEmail', id: string }
    | { __typename: 'UserEmailAuthentication', id: string }
    | { __typename: 'UserRecoveryTicket', id: string }
   | null };

export class TypedDocumentString<TResult, TVariables>
  extends String
  implements DocumentTypeDecoration<TResult, TVariables>
{
  __apiType?: NonNullable<DocumentTypeDecoration<TResult, TVariables>['__apiType']>;
  private value: string;
  public __meta__?: Record<string, any> | undefined;

  constructor(value: string, __meta__?: Record<string, any> | undefined) {
    super(value);
    this.value = value;
    this.__meta__ = __meta__;
  }

  override toString(): string & DocumentTypeDecoration<TResult, TVariables> {
    return this.value;
  }
}
export const AccountDeleteButton_UserFragmentDoc = new TypedDocumentString(`
    fragment AccountDeleteButton_user on User {
  username
  hasPassword
  matrix {
    mxid
    displayName
  }
}
    `, {"fragmentName":"AccountDeleteButton_user"}) as unknown as TypedDocumentString<AccountDeleteButton_UserFragment, unknown>;
export const AccountDeleteButton_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment AccountDeleteButton_siteConfig on SiteConfig {
  passwordLoginEnabled
}
    `, {"fragmentName":"AccountDeleteButton_siteConfig"}) as unknown as TypedDocumentString<AccountDeleteButton_SiteConfigFragment, unknown>;
export const PasswordChange_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment PasswordChange_siteConfig on SiteConfig {
  passwordChangeAllowed
}
    `, {"fragmentName":"PasswordChange_siteConfig"}) as unknown as TypedDocumentString<PasswordChange_SiteConfigFragment, unknown>;
export const EndBrowserSessionButton_SessionFragmentDoc = new TypedDocumentString(`
    fragment EndBrowserSessionButton_session on BrowserSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
}
    `, {"fragmentName":"EndBrowserSessionButton_session"}) as unknown as TypedDocumentString<EndBrowserSessionButton_SessionFragment, unknown>;
export const BrowserSession_SessionFragmentDoc = new TypedDocumentString(`
    fragment BrowserSession_session on BrowserSession {
  id
  createdAt
  finishedAt
  ...EndBrowserSessionButton_session
  userAgent {
    deviceType
    name
    os
    model
  }
  lastActiveAt
}
    fragment EndBrowserSessionButton_session on BrowserSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
}`, {"fragmentName":"BrowserSession_session"}) as unknown as TypedDocumentString<BrowserSession_SessionFragment, unknown>;
export const OAuth2Client_DetailFragmentDoc = new TypedDocumentString(`
    fragment OAuth2Client_detail on Oauth2Client {
  id
  clientId
  clientName
  clientUri
  logoUri
  tosUri
  policyUri
  redirectUris
}
    `, {"fragmentName":"OAuth2Client_detail"}) as unknown as TypedDocumentString<OAuth2Client_DetailFragment, unknown>;
export const EndCompatSessionButton_SessionFragmentDoc = new TypedDocumentString(`
    fragment EndCompatSessionButton_session on CompatSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}
    `, {"fragmentName":"EndCompatSessionButton_session"}) as unknown as TypedDocumentString<EndCompatSessionButton_SessionFragment, unknown>;
export const CompatSession_SessionFragmentDoc = new TypedDocumentString(`
    fragment CompatSession_session on CompatSession {
  id
  createdAt
  deviceId
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndCompatSessionButton_session
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}
    fragment EndCompatSessionButton_session on CompatSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}`, {"fragmentName":"CompatSession_session"}) as unknown as TypedDocumentString<CompatSession_SessionFragment, unknown>;
export const Footer_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment Footer_siteConfig on SiteConfig {
  id
  imprint
  tosUri
  policyUri
}
    `, {"fragmentName":"Footer_siteConfig"}) as unknown as TypedDocumentString<Footer_SiteConfigFragment, unknown>;
export const EndOAuth2SessionButton_SessionFragmentDoc = new TypedDocumentString(`
    fragment EndOAuth2SessionButton_session on Oauth2Session {
  id
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    clientId
    clientName
    applicationType
    logoUri
  }
}
    `, {"fragmentName":"EndOAuth2SessionButton_session"}) as unknown as TypedDocumentString<EndOAuth2SessionButton_SessionFragment, unknown>;
export const OAuth2Session_SessionFragmentDoc = new TypedDocumentString(`
    fragment OAuth2Session_session on Oauth2Session {
  id
  scope
  createdAt
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndOAuth2SessionButton_session
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    id
    clientId
    clientName
    applicationType
    logoUri
  }
}
    fragment EndOAuth2SessionButton_session on Oauth2Session {
  id
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    clientId
    clientName
    applicationType
    logoUri
  }
}`, {"fragmentName":"OAuth2Session_session"}) as unknown as TypedDocumentString<OAuth2Session_SessionFragment, unknown>;
export const BrowserSession_DetailFragmentDoc = new TypedDocumentString(`
    fragment BrowserSession_detail on BrowserSession {
  id
  createdAt
  finishedAt
  ...EndBrowserSessionButton_session
  userAgent {
    name
    model
    os
  }
  lastActiveIp
  lastActiveAt
  lastAuthentication {
    id
    createdAt
  }
  user {
    id
    username
  }
}
    fragment EndBrowserSessionButton_session on BrowserSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
}`, {"fragmentName":"BrowserSession_detail"}) as unknown as TypedDocumentString<BrowserSession_DetailFragment, unknown>;
export const CompatSession_DetailFragmentDoc = new TypedDocumentString(`
    fragment CompatSession_detail on CompatSession {
  id
  createdAt
  deviceId
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndCompatSessionButton_session
  userAgent {
    name
    os
    model
  }
  ssoLogin {
    id
    redirectUri
  }
}
    fragment EndCompatSessionButton_session on CompatSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}`, {"fragmentName":"CompatSession_detail"}) as unknown as TypedDocumentString<CompatSession_DetailFragment, unknown>;
export const OAuth2Session_DetailFragmentDoc = new TypedDocumentString(`
    fragment OAuth2Session_detail on Oauth2Session {
  id
  scope
  createdAt
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndOAuth2SessionButton_session
  userAgent {
    name
    model
    os
  }
  client {
    id
    clientId
    clientName
    clientUri
    logoUri
  }
}
    fragment EndOAuth2SessionButton_session on Oauth2Session {
  id
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    clientId
    clientName
    applicationType
    logoUri
  }
}`, {"fragmentName":"OAuth2Session_detail"}) as unknown as TypedDocumentString<OAuth2Session_DetailFragment, unknown>;
export const UserEmail_EmailFragmentDoc = new TypedDocumentString(`
    fragment UserEmail_email on UserEmail {
  id
  email
}
    `, {"fragmentName":"UserEmail_email"}) as unknown as TypedDocumentString<UserEmail_EmailFragment, unknown>;
export const UserGreeting_UserFragmentDoc = new TypedDocumentString(`
    fragment UserGreeting_user on User {
  id
  matrix {
    mxid
    displayName
  }
}
    `, {"fragmentName":"UserGreeting_user"}) as unknown as TypedDocumentString<UserGreeting_UserFragment, unknown>;
export const UserGreeting_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment UserGreeting_siteConfig on SiteConfig {
  displayNameChangeAllowed
}
    `, {"fragmentName":"UserGreeting_siteConfig"}) as unknown as TypedDocumentString<UserGreeting_SiteConfigFragment, unknown>;
export const AddEmailForm_UserFragmentDoc = new TypedDocumentString(`
    fragment AddEmailForm_user on User {
  hasPassword
}
    `, {"fragmentName":"AddEmailForm_user"}) as unknown as TypedDocumentString<AddEmailForm_UserFragment, unknown>;
export const AddEmailForm_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment AddEmailForm_siteConfig on SiteConfig {
  passwordLoginEnabled
}
    `, {"fragmentName":"AddEmailForm_siteConfig"}) as unknown as TypedDocumentString<AddEmailForm_SiteConfigFragment, unknown>;
export const UserEmailList_UserFragmentDoc = new TypedDocumentString(`
    fragment UserEmailList_user on User {
  hasPassword
}
    `, {"fragmentName":"UserEmailList_user"}) as unknown as TypedDocumentString<UserEmailList_UserFragment, unknown>;
export const UserEmailList_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment UserEmailList_siteConfig on SiteConfig {
  emailChangeAllowed
  passwordLoginEnabled
}
    `, {"fragmentName":"UserEmailList_siteConfig"}) as unknown as TypedDocumentString<UserEmailList_SiteConfigFragment, unknown>;
export const BrowserSessionsOverview_UserFragmentDoc = new TypedDocumentString(`
    fragment BrowserSessionsOverview_user on User {
  browserSessions(first: 0, state: ACTIVE) {
    totalCount
  }
}
    `, {"fragmentName":"BrowserSessionsOverview_user"}) as unknown as TypedDocumentString<BrowserSessionsOverview_UserFragment, unknown>;
export const RecoverPassword_UserRecoveryTicketFragmentDoc = new TypedDocumentString(`
    fragment RecoverPassword_userRecoveryTicket on UserRecoveryTicket {
  username
  email
}
    `, {"fragmentName":"RecoverPassword_userRecoveryTicket"}) as unknown as TypedDocumentString<RecoverPassword_UserRecoveryTicketFragment, unknown>;
export const PasswordCreationDoubleInput_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
  id
  minimumPasswordComplexity
}
    `, {"fragmentName":"PasswordCreationDoubleInput_siteConfig"}) as unknown as TypedDocumentString<PasswordCreationDoubleInput_SiteConfigFragment, unknown>;
export const RecoverPassword_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment RecoverPassword_siteConfig on SiteConfig {
  ...PasswordCreationDoubleInput_siteConfig
}
    fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
  id
  minimumPasswordComplexity
}`, {"fragmentName":"RecoverPassword_siteConfig"}) as unknown as TypedDocumentString<RecoverPassword_SiteConfigFragment, unknown>;
export const DeactivateUserDocument = new TypedDocumentString(`
    mutation DeactivateUser($hsErase: Boolean!, $password: String) {
  deactivateUser(input: {hsErase: $hsErase, password: $password}) {
    status
  }
}
    `) as unknown as TypedDocumentString<DeactivateUserMutation, DeactivateUserMutationVariables>;
export const FooterDocument = new TypedDocumentString(`
    query Footer {
  siteConfig {
    id
    ...Footer_siteConfig
  }
}
    fragment Footer_siteConfig on SiteConfig {
  id
  imprint
  tosUri
  policyUri
}`) as unknown as TypedDocumentString<FooterQuery, FooterQueryVariables>;
export const EndBrowserSessionDocument = new TypedDocumentString(`
    mutation EndBrowserSession($id: ID!) {
  endBrowserSession(input: {browserSessionId: $id}) {
    status
    browserSession {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<EndBrowserSessionMutation, EndBrowserSessionMutationVariables>;
export const EndCompatSessionDocument = new TypedDocumentString(`
    mutation EndCompatSession($id: ID!) {
  endCompatSession(input: {compatSessionId: $id}) {
    status
    compatSession {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<EndCompatSessionMutation, EndCompatSessionMutationVariables>;
export const EndOAuth2SessionDocument = new TypedDocumentString(`
    mutation EndOAuth2Session($id: ID!) {
  endOauth2Session(input: {oauth2SessionId: $id}) {
    status
    oauth2Session {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<EndOAuth2SessionMutation, EndOAuth2SessionMutationVariables>;
export const SetCompatSessionNameDocument = new TypedDocumentString(`
    mutation SetCompatSessionName($sessionId: ID!, $displayName: String!) {
  setCompatSessionName(
    input: {compatSessionId: $sessionId, humanName: $displayName}
  ) {
    status
  }
}
    `) as unknown as TypedDocumentString<SetCompatSessionNameMutation, SetCompatSessionNameMutationVariables>;
export const SetOAuth2SessionNameDocument = new TypedDocumentString(`
    mutation SetOAuth2SessionName($sessionId: ID!, $displayName: String!) {
  setOauth2SessionName(
    input: {oauth2SessionId: $sessionId, humanName: $displayName}
  ) {
    status
  }
}
    `) as unknown as TypedDocumentString<SetOAuth2SessionNameMutation, SetOAuth2SessionNameMutationVariables>;
export const RemoveEmailDocument = new TypedDocumentString(`
    mutation RemoveEmail($id: ID!, $password: String) {
  removeEmail(input: {userEmailId: $id, password: $password}) {
    status
    user {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<RemoveEmailMutation, RemoveEmailMutationVariables>;
export const SetDisplayNameDocument = new TypedDocumentString(`
    mutation SetDisplayName($userId: ID!, $displayName: String) {
  setDisplayName(input: {userId: $userId, displayName: $displayName}) {
    status
  }
}
    `) as unknown as TypedDocumentString<SetDisplayNameMutation, SetDisplayNameMutationVariables>;
export const AddEmailDocument = new TypedDocumentString(`
    mutation AddEmail($email: String!, $password: String, $language: String!) {
  startEmailAuthentication(
    input: {email: $email, password: $password, language: $language}
  ) {
    status
    violations
    authentication {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<AddEmailMutation, AddEmailMutationVariables>;
export const UserEmailListDocument = new TypedDocumentString(`
    query UserEmailList($first: Int, $after: String, $last: Int, $before: String) {
  viewer {
    __typename
    ... on User {
      emails(first: $first, after: $after, last: $last, before: $before) {
        edges {
          cursor
          node {
            ...UserEmail_email
          }
        }
        totalCount
        pageInfo {
          hasNextPage
          hasPreviousPage
          startCursor
          endCursor
        }
      }
    }
  }
}
    fragment UserEmail_email on UserEmail {
  id
  email
}`) as unknown as TypedDocumentString<UserEmailListQuery, UserEmailListQueryVariables>;
export const UserProfileDocument = new TypedDocumentString(`
    query UserProfile {
  viewerSession {
    __typename
    ... on BrowserSession {
      id
      user {
        ...AddEmailForm_user
        ...UserEmailList_user
        ...AccountDeleteButton_user
        hasPassword
        emails(first: 0) {
          totalCount
        }
      }
    }
  }
  siteConfig {
    emailChangeAllowed
    passwordLoginEnabled
    accountDeactivationAllowed
    ...AddEmailForm_siteConfig
    ...UserEmailList_siteConfig
    ...PasswordChange_siteConfig
    ...AccountDeleteButton_siteConfig
  }
}
    fragment AccountDeleteButton_user on User {
  username
  hasPassword
  matrix {
    mxid
    displayName
  }
}
fragment AccountDeleteButton_siteConfig on SiteConfig {
  passwordLoginEnabled
}
fragment PasswordChange_siteConfig on SiteConfig {
  passwordChangeAllowed
}
fragment AddEmailForm_user on User {
  hasPassword
}
fragment AddEmailForm_siteConfig on SiteConfig {
  passwordLoginEnabled
}
fragment UserEmailList_user on User {
  hasPassword
}
fragment UserEmailList_siteConfig on SiteConfig {
  emailChangeAllowed
  passwordLoginEnabled
}`) as unknown as TypedDocumentString<UserProfileQuery, UserProfileQueryVariables>;
export const PlanManagementTabDocument = new TypedDocumentString(`
    query PlanManagementTab {
  siteConfig {
    planManagementIframeUri
  }
}
    `) as unknown as TypedDocumentString<PlanManagementTabQuery, PlanManagementTabQueryVariables>;
export const BrowserSessionListDocument = new TypedDocumentString(`
    query BrowserSessionList($first: Int, $after: String, $last: Int, $before: String, $lastActive: DateFilter) {
  viewerSession {
    __typename
    ... on BrowserSession {
      id
      user {
        id
        browserSessions(
          first: $first
          after: $after
          last: $last
          before: $before
          lastActive: $lastActive
          state: ACTIVE
        ) {
          totalCount
          edges {
            cursor
            node {
              id
              ...BrowserSession_session
            }
          }
          pageInfo {
            hasNextPage
            hasPreviousPage
            startCursor
            endCursor
          }
        }
      }
    }
  }
}
    fragment BrowserSession_session on BrowserSession {
  id
  createdAt
  finishedAt
  ...EndBrowserSessionButton_session
  userAgent {
    deviceType
    name
    os
    model
  }
  lastActiveAt
}
fragment EndBrowserSessionButton_session on BrowserSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
}`) as unknown as TypedDocumentString<BrowserSessionListQuery, BrowserSessionListQueryVariables>;
export const SessionsOverviewDocument = new TypedDocumentString(`
    query SessionsOverview {
  viewer {
    __typename
    ... on User {
      id
      ...BrowserSessionsOverview_user
      unfilteredAppSessions: appSessions(first: 1, state: ACTIVE) {
        totalCount
      }
    }
  }
  siteConfig {
    sessionLimit {
      softLimit
    }
  }
}
    fragment BrowserSessionsOverview_user on User {
  browserSessions(first: 0, state: ACTIVE) {
    totalCount
  }
}`) as unknown as TypedDocumentString<SessionsOverviewQuery, SessionsOverviewQueryVariables>;
export const AppSessionsListDocument = new TypedDocumentString(`
    query AppSessionsList($before: String, $after: String, $first: Int, $last: Int, $lastActive: DateFilter) {
  viewer {
    __typename
    ... on User {
      id
      appSessions(
        before: $before
        after: $after
        first: $first
        last: $last
        lastActive: $lastActive
        state: ACTIVE
      ) {
        edges {
          cursor
          node {
            __typename
            ...CompatSession_session
            ...OAuth2Session_session
          }
        }
        totalCount
        pageInfo {
          startCursor
          endCursor
          hasNextPage
          hasPreviousPage
        }
      }
    }
  }
}
    fragment CompatSession_session on CompatSession {
  id
  createdAt
  deviceId
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndCompatSessionButton_session
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}
fragment OAuth2Session_session on Oauth2Session {
  id
  scope
  createdAt
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndOAuth2SessionButton_session
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    id
    clientId
    clientName
    applicationType
    logoUri
  }
}
fragment EndCompatSessionButton_session on CompatSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}
fragment EndOAuth2SessionButton_session on Oauth2Session {
  id
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    clientId
    clientName
    applicationType
    logoUri
  }
}`) as unknown as TypedDocumentString<AppSessionsListQuery, AppSessionsListQueryVariables>;
export const CurrentUserGreetingDocument = new TypedDocumentString(`
    query CurrentUserGreeting {
  viewer {
    __typename
    ... on User {
      ...UserGreeting_user
      unfilteredAppSessions: appSessions(first: 1, state: ACTIVE) {
        totalCount
      }
    }
  }
  siteConfig {
    ...UserGreeting_siteConfig
    planManagementIframeUri
    sessionLimit {
      softLimit
    }
  }
}
    fragment UserGreeting_user on User {
  id
  matrix {
    mxid
    displayName
  }
}
fragment UserGreeting_siteConfig on SiteConfig {
  displayNameChangeAllowed
}`) as unknown as TypedDocumentString<CurrentUserGreetingQuery, CurrentUserGreetingQueryVariables>;
export const OAuth2ClientDocument = new TypedDocumentString(`
    query OAuth2Client($id: ID!) {
  oauth2Client(id: $id) {
    ...OAuth2Client_detail
  }
}
    fragment OAuth2Client_detail on Oauth2Client {
  id
  clientId
  clientName
  clientUri
  logoUri
  tosUri
  policyUri
  redirectUris
}`) as unknown as TypedDocumentString<OAuth2ClientQuery, OAuth2ClientQueryVariables>;
export const CurrentViewerDocument = new TypedDocumentString(`
    query CurrentViewer {
  viewer {
    __typename
    ... on Node {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<CurrentViewerQuery, CurrentViewerQueryVariables>;
export const DeviceRedirectDocument = new TypedDocumentString(`
    query DeviceRedirect($deviceId: String!, $userId: ID!) {
  session(deviceId: $deviceId, userId: $userId) {
    __typename
    ... on Node {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<DeviceRedirectQuery, DeviceRedirectQueryVariables>;
export const VerifyEmailDocument = new TypedDocumentString(`
    query VerifyEmail($id: ID!) {
  userEmailAuthentication(id: $id) {
    id
    email
    completedAt
  }
}
    `) as unknown as TypedDocumentString<VerifyEmailQuery, VerifyEmailQueryVariables>;
export const DoVerifyEmailDocument = new TypedDocumentString(`
    mutation DoVerifyEmail($id: ID!, $code: String!) {
  completeEmailAuthentication(input: {id: $id, code: $code}) {
    status
  }
}
    `) as unknown as TypedDocumentString<DoVerifyEmailMutation, DoVerifyEmailMutationVariables>;
export const ResendEmailAuthenticationCodeDocument = new TypedDocumentString(`
    mutation ResendEmailAuthenticationCode($id: ID!, $language: String!) {
  resendEmailAuthenticationCode(input: {id: $id, language: $language}) {
    status
  }
}
    `) as unknown as TypedDocumentString<ResendEmailAuthenticationCodeMutation, ResendEmailAuthenticationCodeMutationVariables>;
export const ChangePasswordDocument = new TypedDocumentString(`
    mutation ChangePassword($userId: ID!, $oldPassword: String!, $newPassword: String!) {
  setPassword(
    input: {userId: $userId, currentPassword: $oldPassword, newPassword: $newPassword}
  ) {
    status
  }
}
    `) as unknown as TypedDocumentString<ChangePasswordMutation, ChangePasswordMutationVariables>;
export const PasswordChangeDocument = new TypedDocumentString(`
    query PasswordChange {
  viewer {
    __typename
    ... on Node {
      id
    }
  }
  siteConfig {
    ...PasswordCreationDoubleInput_siteConfig
  }
}
    fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
  id
  minimumPasswordComplexity
}`) as unknown as TypedDocumentString<PasswordChangeQuery, PasswordChangeQueryVariables>;
export const RecoverPasswordDocument = new TypedDocumentString(`
    mutation RecoverPassword($ticket: String!, $newPassword: String!) {
  setPasswordByRecovery(input: {ticket: $ticket, newPassword: $newPassword}) {
    status
  }
}
    `) as unknown as TypedDocumentString<RecoverPasswordMutation, RecoverPasswordMutationVariables>;
export const ResendRecoveryEmailDocument = new TypedDocumentString(`
    mutation ResendRecoveryEmail($ticket: String!) {
  resendRecoveryEmail(input: {ticket: $ticket}) {
    status
    progressUrl
  }
}
    `) as unknown as TypedDocumentString<ResendRecoveryEmailMutation, ResendRecoveryEmailMutationVariables>;
export const PasswordRecoveryDocument = new TypedDocumentString(`
    query PasswordRecovery($ticket: String!) {
  siteConfig {
    ...RecoverPassword_siteConfig
  }
  userRecoveryTicket(ticket: $ticket) {
    status
    ...RecoverPassword_userRecoveryTicket
  }
}
    fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
  id
  minimumPasswordComplexity
}
fragment RecoverPassword_userRecoveryTicket on UserRecoveryTicket {
  username
  email
}
fragment RecoverPassword_siteConfig on SiteConfig {
  ...PasswordCreationDoubleInput_siteConfig
}`) as unknown as TypedDocumentString<PasswordRecoveryQuery, PasswordRecoveryQueryVariables>;
export const AllowCrossSigningResetDocument = new TypedDocumentString(`
    mutation AllowCrossSigningReset($userId: ID!) {
  allowUserCrossSigningReset(input: {userId: $userId}) {
    user {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<AllowCrossSigningResetMutation, AllowCrossSigningResetMutationVariables>;
export const SessionDetailDocument = new TypedDocumentString(`
    query SessionDetail($id: ID!) {
  viewerSession {
    ... on Node {
      id
    }
  }
  node(id: $id) {
    __typename
    id
    ...CompatSession_detail
    ...OAuth2Session_detail
    ...BrowserSession_detail
  }
}
    fragment EndBrowserSessionButton_session on BrowserSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
}
fragment EndCompatSessionButton_session on CompatSession {
  id
  userAgent {
    name
    os
    model
    deviceType
  }
  ssoLogin {
    id
    redirectUri
  }
}
fragment EndOAuth2SessionButton_session on Oauth2Session {
  id
  userAgent {
    name
    model
    os
    deviceType
  }
  client {
    clientId
    clientName
    applicationType
    logoUri
  }
}
fragment BrowserSession_detail on BrowserSession {
  id
  createdAt
  finishedAt
  ...EndBrowserSessionButton_session
  userAgent {
    name
    model
    os
  }
  lastActiveIp
  lastActiveAt
  lastAuthentication {
    id
    createdAt
  }
  user {
    id
    username
  }
}
fragment CompatSession_detail on CompatSession {
  id
  createdAt
  deviceId
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndCompatSessionButton_session
  userAgent {
    name
    os
    model
  }
  ssoLogin {
    id
    redirectUri
  }
}
fragment OAuth2Session_detail on Oauth2Session {
  id
  scope
  createdAt
  finishedAt
  lastActiveIp
  lastActiveAt
  humanName
  ...EndOAuth2SessionButton_session
  userAgent {
    name
    model
    os
  }
  client {
    id
    clientId
    clientName
    clientUri
    logoUri
  }
}`) as unknown as TypedDocumentString<SessionDetailQuery, SessionDetailQueryVariables>;

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockDeactivateUserMutation(
 *   ({ query, variables }) => {
 *     const { hsErase, password } = variables;
 *     return HttpResponse.json({
 *       data: { deactivateUser }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockDeactivateUserMutation = (resolver: GraphQLResponseResolver<DeactivateUserMutation, DeactivateUserMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<DeactivateUserMutation, DeactivateUserMutationVariables>(
    'DeactivateUser',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockFooterQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { siteConfig }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockFooterQuery = (resolver: GraphQLResponseResolver<FooterQuery, FooterQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<FooterQuery, FooterQueryVariables>(
    'Footer',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockEndBrowserSessionMutation(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { endBrowserSession }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockEndBrowserSessionMutation = (resolver: GraphQLResponseResolver<EndBrowserSessionMutation, EndBrowserSessionMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<EndBrowserSessionMutation, EndBrowserSessionMutationVariables>(
    'EndBrowserSession',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockEndCompatSessionMutation(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { endCompatSession }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockEndCompatSessionMutation = (resolver: GraphQLResponseResolver<EndCompatSessionMutation, EndCompatSessionMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<EndCompatSessionMutation, EndCompatSessionMutationVariables>(
    'EndCompatSession',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockEndOAuth2SessionMutation(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { endOauth2Session }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockEndOAuth2SessionMutation = (resolver: GraphQLResponseResolver<EndOAuth2SessionMutation, EndOAuth2SessionMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<EndOAuth2SessionMutation, EndOAuth2SessionMutationVariables>(
    'EndOAuth2Session',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockSetCompatSessionNameMutation(
 *   ({ query, variables }) => {
 *     const { sessionId, displayName } = variables;
 *     return HttpResponse.json({
 *       data: { setCompatSessionName }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockSetCompatSessionNameMutation = (resolver: GraphQLResponseResolver<SetCompatSessionNameMutation, SetCompatSessionNameMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<SetCompatSessionNameMutation, SetCompatSessionNameMutationVariables>(
    'SetCompatSessionName',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockSetOAuth2SessionNameMutation(
 *   ({ query, variables }) => {
 *     const { sessionId, displayName } = variables;
 *     return HttpResponse.json({
 *       data: { setOauth2SessionName }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockSetOAuth2SessionNameMutation = (resolver: GraphQLResponseResolver<SetOAuth2SessionNameMutation, SetOAuth2SessionNameMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<SetOAuth2SessionNameMutation, SetOAuth2SessionNameMutationVariables>(
    'SetOAuth2SessionName',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockRemoveEmailMutation(
 *   ({ query, variables }) => {
 *     const { id, password } = variables;
 *     return HttpResponse.json({
 *       data: { removeEmail }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockRemoveEmailMutation = (resolver: GraphQLResponseResolver<RemoveEmailMutation, RemoveEmailMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<RemoveEmailMutation, RemoveEmailMutationVariables>(
    'RemoveEmail',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockSetDisplayNameMutation(
 *   ({ query, variables }) => {
 *     const { userId, displayName } = variables;
 *     return HttpResponse.json({
 *       data: { setDisplayName }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockSetDisplayNameMutation = (resolver: GraphQLResponseResolver<SetDisplayNameMutation, SetDisplayNameMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<SetDisplayNameMutation, SetDisplayNameMutationVariables>(
    'SetDisplayName',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockAddEmailMutation(
 *   ({ query, variables }) => {
 *     const { email, password, language } = variables;
 *     return HttpResponse.json({
 *       data: { startEmailAuthentication }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockAddEmailMutation = (resolver: GraphQLResponseResolver<AddEmailMutation, AddEmailMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<AddEmailMutation, AddEmailMutationVariables>(
    'AddEmail',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockUserEmailListQuery(
 *   ({ query, variables }) => {
 *     const { first, after, last, before } = variables;
 *     return HttpResponse.json({
 *       data: { viewer }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockUserEmailListQuery = (resolver: GraphQLResponseResolver<UserEmailListQuery, UserEmailListQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<UserEmailListQuery, UserEmailListQueryVariables>(
    'UserEmailList',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockUserProfileQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { viewerSession, siteConfig }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockUserProfileQuery = (resolver: GraphQLResponseResolver<UserProfileQuery, UserProfileQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<UserProfileQuery, UserProfileQueryVariables>(
    'UserProfile',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockPlanManagementTabQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { siteConfig }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockPlanManagementTabQuery = (resolver: GraphQLResponseResolver<PlanManagementTabQuery, PlanManagementTabQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<PlanManagementTabQuery, PlanManagementTabQueryVariables>(
    'PlanManagementTab',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockBrowserSessionListQuery(
 *   ({ query, variables }) => {
 *     const { first, after, last, before, lastActive } = variables;
 *     return HttpResponse.json({
 *       data: { viewerSession }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockBrowserSessionListQuery = (resolver: GraphQLResponseResolver<BrowserSessionListQuery, BrowserSessionListQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<BrowserSessionListQuery, BrowserSessionListQueryVariables>(
    'BrowserSessionList',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockSessionsOverviewQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { viewer, siteConfig }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockSessionsOverviewQuery = (resolver: GraphQLResponseResolver<SessionsOverviewQuery, SessionsOverviewQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<SessionsOverviewQuery, SessionsOverviewQueryVariables>(
    'SessionsOverview',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockAppSessionsListQuery(
 *   ({ query, variables }) => {
 *     const { before, after, first, last, lastActive } = variables;
 *     return HttpResponse.json({
 *       data: { viewer }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockAppSessionsListQuery = (resolver: GraphQLResponseResolver<AppSessionsListQuery, AppSessionsListQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<AppSessionsListQuery, AppSessionsListQueryVariables>(
    'AppSessionsList',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockCurrentUserGreetingQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { viewer, siteConfig }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockCurrentUserGreetingQuery = (resolver: GraphQLResponseResolver<CurrentUserGreetingQuery, CurrentUserGreetingQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<CurrentUserGreetingQuery, CurrentUserGreetingQueryVariables>(
    'CurrentUserGreeting',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockOAuth2ClientQuery(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { oauth2Client }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockOAuth2ClientQuery = (resolver: GraphQLResponseResolver<OAuth2ClientQuery, OAuth2ClientQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<OAuth2ClientQuery, OAuth2ClientQueryVariables>(
    'OAuth2Client',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockCurrentViewerQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { viewer }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockCurrentViewerQuery = (resolver: GraphQLResponseResolver<CurrentViewerQuery, CurrentViewerQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<CurrentViewerQuery, CurrentViewerQueryVariables>(
    'CurrentViewer',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockDeviceRedirectQuery(
 *   ({ query, variables }) => {
 *     const { deviceId, userId } = variables;
 *     return HttpResponse.json({
 *       data: { session }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockDeviceRedirectQuery = (resolver: GraphQLResponseResolver<DeviceRedirectQuery, DeviceRedirectQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<DeviceRedirectQuery, DeviceRedirectQueryVariables>(
    'DeviceRedirect',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockVerifyEmailQuery(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { userEmailAuthentication }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockVerifyEmailQuery = (resolver: GraphQLResponseResolver<VerifyEmailQuery, VerifyEmailQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<VerifyEmailQuery, VerifyEmailQueryVariables>(
    'VerifyEmail',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockDoVerifyEmailMutation(
 *   ({ query, variables }) => {
 *     const { id, code } = variables;
 *     return HttpResponse.json({
 *       data: { completeEmailAuthentication }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockDoVerifyEmailMutation = (resolver: GraphQLResponseResolver<DoVerifyEmailMutation, DoVerifyEmailMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<DoVerifyEmailMutation, DoVerifyEmailMutationVariables>(
    'DoVerifyEmail',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockResendEmailAuthenticationCodeMutation(
 *   ({ query, variables }) => {
 *     const { id, language } = variables;
 *     return HttpResponse.json({
 *       data: { resendEmailAuthenticationCode }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockResendEmailAuthenticationCodeMutation = (resolver: GraphQLResponseResolver<ResendEmailAuthenticationCodeMutation, ResendEmailAuthenticationCodeMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<ResendEmailAuthenticationCodeMutation, ResendEmailAuthenticationCodeMutationVariables>(
    'ResendEmailAuthenticationCode',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockChangePasswordMutation(
 *   ({ query, variables }) => {
 *     const { userId, oldPassword, newPassword } = variables;
 *     return HttpResponse.json({
 *       data: { setPassword }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockChangePasswordMutation = (resolver: GraphQLResponseResolver<ChangePasswordMutation, ChangePasswordMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<ChangePasswordMutation, ChangePasswordMutationVariables>(
    'ChangePassword',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockPasswordChangeQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { viewer, siteConfig }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockPasswordChangeQuery = (resolver: GraphQLResponseResolver<PasswordChangeQuery, PasswordChangeQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<PasswordChangeQuery, PasswordChangeQueryVariables>(
    'PasswordChange',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockRecoverPasswordMutation(
 *   ({ query, variables }) => {
 *     const { ticket, newPassword } = variables;
 *     return HttpResponse.json({
 *       data: { setPasswordByRecovery }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockRecoverPasswordMutation = (resolver: GraphQLResponseResolver<RecoverPasswordMutation, RecoverPasswordMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<RecoverPasswordMutation, RecoverPasswordMutationVariables>(
    'RecoverPassword',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockResendRecoveryEmailMutation(
 *   ({ query, variables }) => {
 *     const { ticket } = variables;
 *     return HttpResponse.json({
 *       data: { resendRecoveryEmail }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockResendRecoveryEmailMutation = (resolver: GraphQLResponseResolver<ResendRecoveryEmailMutation, ResendRecoveryEmailMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<ResendRecoveryEmailMutation, ResendRecoveryEmailMutationVariables>(
    'ResendRecoveryEmail',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockPasswordRecoveryQuery(
 *   ({ query, variables }) => {
 *     const { ticket } = variables;
 *     return HttpResponse.json({
 *       data: { siteConfig, userRecoveryTicket }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockPasswordRecoveryQuery = (resolver: GraphQLResponseResolver<PasswordRecoveryQuery, PasswordRecoveryQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<PasswordRecoveryQuery, PasswordRecoveryQueryVariables>(
    'PasswordRecovery',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockAllowCrossSigningResetMutation(
 *   ({ query, variables }) => {
 *     const { userId } = variables;
 *     return HttpResponse.json({
 *       data: { allowUserCrossSigningReset }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockAllowCrossSigningResetMutation = (resolver: GraphQLResponseResolver<AllowCrossSigningResetMutation, AllowCrossSigningResetMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<AllowCrossSigningResetMutation, AllowCrossSigningResetMutationVariables>(
    'AllowCrossSigningReset',
    resolver,
    options
  )

/**
 * @param resolver A function that accepts [resolver arguments](https://mswjs.io/docs/api/graphql#resolver-argument) and must always return the instruction on what to do with the intercepted request. ([see more](https://mswjs.io/docs/concepts/response-resolver#resolver-instructions))
 * @param options Options object to customize the behavior of the mock. ([see more](https://mswjs.io/docs/api/graphql#handler-options))
 * @see https://mswjs.io/docs/basics/response-resolver
 * @example
 * mockSessionDetailQuery(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { viewerSession, node }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockSessionDetailQuery = (resolver: GraphQLResponseResolver<SessionDetailQuery, SessionDetailQueryVariables>, options?: RequestHandlerOptions) =>
  graphql.query<SessionDetailQuery, SessionDetailQueryVariables>(
    'SessionDetail',
    resolver,
    options
  )
