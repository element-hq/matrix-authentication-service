/* eslint-disable */
import type { DocumentTypeDecoration } from '@graphql-typed-document-node/core';
import { graphql, type GraphQLResponseResolver, type RequestHandlerOptions } from 'msw'
export type Maybe<T> = T | null;
export type InputMaybe<T> = Maybe<T>;
export type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
export type MakeOptional<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]?: Maybe<T[SubKey]> };
export type MakeMaybe<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]: Maybe<T[SubKey]> };
export type MakeEmpty<T extends { [key: string]: unknown }, K extends keyof T> = { [_ in K]?: never };
export type Incremental<T> = T | { [P in keyof T]?: P extends ' $fragmentName' | '__typename' ? T[P] : never };
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: { input: string; output: string; }
  String: { input: string; output: string; }
  Boolean: { input: boolean; output: boolean; }
  Int: { input: number; output: number; }
  Float: { input: number; output: number; }
  /**
   * Implement the DateTime<Utc> scalar
   *
   * The input/output is a string in RFC3339 format.
   */
  DateTime: { input: string; output: string; }
  /** URL is a String implementing the [URL Standard](http://url.spec.whatwg.org/) */
  Url: { input: string; output: string; }
};

/** The input for the `addEmail` mutation */
export type AddEmailInput = {
  /** The email address to add */
  email: Scalars['String']['input'];
  /** Skip the email address policy check. Only allowed for admins. */
  skipPolicyCheck?: InputMaybe<Scalars['Boolean']['input']>;
  /** Skip the email address verification. Only allowed for admins. */
  skipVerification?: InputMaybe<Scalars['Boolean']['input']>;
  /** The ID of the user to add the email address to */
  userId: Scalars['ID']['input'];
};

/** The payload of the `addEmail` mutation */
export type AddEmailPayload = {
  __typename?: 'AddEmailPayload';
  /** The email address that was added */
  email?: Maybe<UserEmail>;
  /** Status of the operation */
  status: AddEmailStatus;
  /** The user to whom the email address was added */
  user?: Maybe<User>;
  /** The list of policy violations if the email address was denied */
  violations?: Maybe<Array<Scalars['String']['output']>>;
};

/** The status of the `addEmail` mutation */
export type AddEmailStatus =
  /** The email address was added */
  | 'ADDED'
  /** The email address is not allowed by the policy */
  | 'DENIED'
  /** The email address already exists */
  | 'EXISTS'
  /** The email address is invalid */
  | 'INVALID';

/** The input for the `addUser` mutation. */
export type AddUserInput = {
  /**
   * Skip checking with the homeserver whether the username is valid.
   *
   * Use this with caution! The main reason to use this, is when a user used
   * by an application service needs to exist in MAS to craft special
   * tokens (like with admin access) for them
   */
  skipHomeserverCheck?: InputMaybe<Scalars['Boolean']['input']>;
  /** The username of the user to add. */
  username: Scalars['String']['input'];
};

/** The payload for the `addUser` mutation. */
export type AddUserPayload = {
  __typename?: 'AddUserPayload';
  /** Status of the operation */
  status: AddUserStatus;
  /** The user that was added. */
  user?: Maybe<User>;
};

/** The status of the `addUser` mutation. */
export type AddUserStatus =
  /** The user was added. */
  | 'ADDED'
  /** The user already exists. */
  | 'EXISTS'
  /** The username is invalid. */
  | 'INVALID'
  /** The username is reserved. */
  | 'RESERVED';

/** The input for the `allowUserCrossSigningReset` mutation. */
export type AllowUserCrossSigningResetInput = {
  /** The ID of the user to update. */
  userId: Scalars['ID']['input'];
};

/** The payload for the `allowUserCrossSigningReset` mutation. */
export type AllowUserCrossSigningResetPayload = {
  __typename?: 'AllowUserCrossSigningResetPayload';
  /** The user that was updated. */
  user?: Maybe<User>;
};

export type Anonymous = Node & {
  __typename?: 'Anonymous';
  id: Scalars['ID']['output'];
};

/** A session in an application, either a compatibility or an OAuth 2.0 one */
export type AppSession = CompatSession | Oauth2Session;

export type AppSessionConnection = {
  __typename?: 'AppSessionConnection';
  /** A list of edges. */
  edges: Array<AppSessionEdge>;
  /** A list of nodes. */
  nodes: Array<AppSession>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type AppSessionEdge = {
  __typename?: 'AppSessionEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: AppSession;
};

/**
 * An authentication records when a user enter their credential in a browser
 * session.
 */
export type Authentication = CreationEvent & Node & {
  __typename?: 'Authentication';
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** ID of the object. */
  id: Scalars['ID']['output'];
};

/** A browser session represents a logged in user in a browser. */
export type BrowserSession = CreationEvent & Node & {
  __typename?: 'BrowserSession';
  /**
   * Get the list of both compat and OAuth 2.0 sessions started by this
   * browser session, chronologically sorted
   */
  appSessions: AppSessionConnection;
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** When the session was finished. */
  finishedAt?: Maybe<Scalars['DateTime']['output']>;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** The last time the session was active. */
  lastActiveAt?: Maybe<Scalars['DateTime']['output']>;
  /** The last IP address used by the session. */
  lastActiveIp?: Maybe<Scalars['String']['output']>;
  /** The most recent authentication of this session. */
  lastAuthentication?: Maybe<Authentication>;
  /** The state of the session. */
  state: SessionState;
  /** The user logged in this session. */
  user: User;
  /** The user-agent with which the session was created. */
  userAgent?: Maybe<UserAgent>;
};


/** A browser session represents a logged in user in a browser. */
export type BrowserSessionAppSessionsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  device?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  state?: InputMaybe<SessionState>;
};

export type BrowserSessionConnection = {
  __typename?: 'BrowserSessionConnection';
  /** A list of edges. */
  edges: Array<BrowserSessionEdge>;
  /** A list of nodes. */
  nodes: Array<BrowserSession>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type BrowserSessionEdge = {
  __typename?: 'BrowserSessionEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: BrowserSession;
};

export type CaptchaConfig = {
  __typename?: 'CaptchaConfig';
  id: Scalars['ID']['output'];
  /** Which Captcha service is being used */
  service: CaptchaService;
  /** The site key used by the instance */
  siteKey: Scalars['String']['output'];
};

/** Which Captcha service is being used */
export type CaptchaService =
  | 'CLOUDFLARE_TURNSTILE'
  | 'H_CAPTCHA'
  | 'RECAPTCHA_V2';

/**
 * A compat session represents a client session which used the legacy Matrix
 * login API.
 */
export type CompatSession = CreationEvent & Node & {
  __typename?: 'CompatSession';
  /** The browser session which started this session, if any. */
  browserSession?: Maybe<BrowserSession>;
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** The Matrix Device ID of this session. */
  deviceId: Scalars['String']['output'];
  /** When the session ended. */
  finishedAt?: Maybe<Scalars['DateTime']['output']>;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** The last time the session was active. */
  lastActiveAt?: Maybe<Scalars['DateTime']['output']>;
  /** The last IP address used by the session. */
  lastActiveIp?: Maybe<Scalars['String']['output']>;
  /** The associated SSO login, if any. */
  ssoLogin?: Maybe<CompatSsoLogin>;
  /** The state of the session. */
  state: SessionState;
  /** The user authorized for this session. */
  user: User;
  /** The user-agent with which the session was created. */
  userAgent?: Maybe<UserAgent>;
};

export type CompatSessionConnection = {
  __typename?: 'CompatSessionConnection';
  /** A list of edges. */
  edges: Array<CompatSessionEdge>;
  /** A list of nodes. */
  nodes: Array<CompatSession>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type CompatSessionEdge = {
  __typename?: 'CompatSessionEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: CompatSession;
};

/** The type of a compatibility session. */
export type CompatSessionType =
  /** The session was created by a SSO login. */
  | 'SSO_LOGIN'
  /** The session was created by an unknown method. */
  | 'UNKNOWN';

/**
 * A compat SSO login represents a login done through the legacy Matrix login
 * API, via the `m.login.sso` login method.
 */
export type CompatSsoLogin = Node & {
  __typename?: 'CompatSsoLogin';
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** When the client exchanged the login token sent during the redirection. */
  exchangedAt?: Maybe<Scalars['DateTime']['output']>;
  /**
   * When the login was fulfilled, and the user was redirected back to the
   * client.
   */
  fulfilledAt?: Maybe<Scalars['DateTime']['output']>;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** The redirect URI used during the login. */
  redirectUri: Scalars['Url']['output'];
  /** The compat session which was started by this login. */
  session?: Maybe<CompatSession>;
};

export type CompatSsoLoginConnection = {
  __typename?: 'CompatSsoLoginConnection';
  /** A list of edges. */
  edges: Array<CompatSsoLoginEdge>;
  /** A list of nodes. */
  nodes: Array<CompatSsoLogin>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type CompatSsoLoginEdge = {
  __typename?: 'CompatSsoLoginEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: CompatSsoLogin;
};

/** The input of the `createOauth2Session` mutation. */
export type CreateOAuth2SessionInput = {
  /** Whether the session should issue a never-expiring access token */
  permanent?: InputMaybe<Scalars['Boolean']['input']>;
  /** The scope of the session */
  scope: Scalars['String']['input'];
  /** The ID of the user for which to create the session */
  userId: Scalars['ID']['input'];
};

/** The payload of the `createOauth2Session` mutation. */
export type CreateOAuth2SessionPayload = {
  __typename?: 'CreateOAuth2SessionPayload';
  /** Access token for this session */
  accessToken: Scalars['String']['output'];
  /** The OAuth 2.0 session which was just created */
  oauth2Session: Oauth2Session;
  /** Refresh token for this session, if it is not a permanent session */
  refreshToken?: Maybe<Scalars['String']['output']>;
};

/** An object with a creation date. */
export type CreationEvent = {
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
};

/** A filter for dates, with a lower bound and an upper bound */
export type DateFilter = {
  /** The lower bound of the date range */
  after?: InputMaybe<Scalars['DateTime']['input']>;
  /** The upper bound of the date range */
  before?: InputMaybe<Scalars['DateTime']['input']>;
};

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

/** The input of the `endBrowserSession` mutation. */
export type EndBrowserSessionInput = {
  /** The ID of the session to end. */
  browserSessionId: Scalars['ID']['input'];
};

export type EndBrowserSessionPayload = {
  __typename?: 'EndBrowserSessionPayload';
  /** Returns the ended session. */
  browserSession?: Maybe<BrowserSession>;
  /** The status of the mutation. */
  status: EndBrowserSessionStatus;
};

/** The status of the `endBrowserSession` mutation. */
export type EndBrowserSessionStatus =
  /** The session was ended. */
  | 'ENDED'
  /** The session was not found. */
  | 'NOT_FOUND';

/** The input of the `endCompatSession` mutation. */
export type EndCompatSessionInput = {
  /** The ID of the session to end. */
  compatSessionId: Scalars['ID']['input'];
};

export type EndCompatSessionPayload = {
  __typename?: 'EndCompatSessionPayload';
  /** Returns the ended session. */
  compatSession?: Maybe<CompatSession>;
  /** The status of the mutation. */
  status: EndCompatSessionStatus;
};

/** The status of the `endCompatSession` mutation. */
export type EndCompatSessionStatus =
  /** The session was ended. */
  | 'ENDED'
  /** The session was not found. */
  | 'NOT_FOUND';

/** The input of the `endOauth2Session` mutation. */
export type EndOAuth2SessionInput = {
  /** The ID of the session to end. */
  oauth2SessionId: Scalars['ID']['input'];
};

export type EndOAuth2SessionPayload = {
  __typename?: 'EndOAuth2SessionPayload';
  /** Returns the ended session. */
  oauth2Session?: Maybe<Oauth2Session>;
  /** The status of the mutation. */
  status: EndOAuth2SessionStatus;
};

/** The status of the `endOauth2Session` mutation. */
export type EndOAuth2SessionStatus =
  /** The session was ended. */
  | 'ENDED'
  /** The session was not found. */
  | 'NOT_FOUND';

/** The input for the `lockUser` mutation. */
export type LockUserInput = {
  /** Permanently lock the user. */
  deactivate?: InputMaybe<Scalars['Boolean']['input']>;
  /** The ID of the user to lock. */
  userId: Scalars['ID']['input'];
};

/** The payload for the `lockUser` mutation. */
export type LockUserPayload = {
  __typename?: 'LockUserPayload';
  /** Status of the operation */
  status: LockUserStatus;
  /** The user that was locked. */
  user?: Maybe<User>;
};

/** The status of the `lockUser` mutation. */
export type LockUserStatus =
  /** The user was locked. */
  | 'LOCKED'
  /** The user was not found. */
  | 'NOT_FOUND';

export type MatrixUser = {
  __typename?: 'MatrixUser';
  /** The avatar URL of the user, if any. */
  avatarUrl?: Maybe<Scalars['String']['output']>;
  /** Whether the user is deactivated on the homeserver. */
  deactivated: Scalars['Boolean']['output'];
  /** The display name of the user, if any. */
  displayName?: Maybe<Scalars['String']['output']>;
  /** The Matrix ID of the user. */
  mxid: Scalars['String']['output'];
};

/** The mutations root of the GraphQL interface. */
export type Mutation = {
  __typename?: 'Mutation';
  /** Add an email address to the specified user */
  addEmail: AddEmailPayload;
  /** Add a user. This is only available to administrators. */
  addUser: AddUserPayload;
  /** Temporarily allow user to reset their cross-signing keys. */
  allowUserCrossSigningReset: AllowUserCrossSigningResetPayload;
  /**
   * Create a new arbitrary OAuth 2.0 Session.
   *
   * Only available for administrators.
   */
  createOauth2Session: CreateOAuth2SessionPayload;
  endBrowserSession: EndBrowserSessionPayload;
  endCompatSession: EndCompatSessionPayload;
  endOauth2Session: EndOAuth2SessionPayload;
  /** Lock a user. This is only available to administrators. */
  lockUser: LockUserPayload;
  /** Remove an email address */
  removeEmail: RemoveEmailPayload;
  /** Send a verification code for an email address */
  sendVerificationEmail: SendVerificationEmailPayload;
  /**
   * Set whether a user can request admin. This is only available to
   * administrators.
   */
  setCanRequestAdmin: SetCanRequestAdminPayload;
  /** Set the display name of a user */
  setDisplayName: SetDisplayNamePayload;
  /**
   * Set the password for a user.
   *
   * This can be used by server administrators to set any user's password,
   * or, provided the capability hasn't been disabled on this server,
   * by a user to change their own password as long as they know their
   * current password.
   */
  setPassword: SetPasswordPayload;
  /** Set the password for yourself, using a recovery ticket sent by e-mail. */
  setPasswordByRecovery: SetPasswordPayload;
  /** Set an email address as primary */
  setPrimaryEmail: SetPrimaryEmailPayload;
  /** Unlock a user. This is only available to administrators. */
  unlockUser: UnlockUserPayload;
  /** Submit a verification code for an email address */
  verifyEmail: VerifyEmailPayload;
};


/** The mutations root of the GraphQL interface. */
export type MutationAddEmailArgs = {
  input: AddEmailInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationAddUserArgs = {
  input: AddUserInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationAllowUserCrossSigningResetArgs = {
  input: AllowUserCrossSigningResetInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationCreateOauth2SessionArgs = {
  input: CreateOAuth2SessionInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationEndBrowserSessionArgs = {
  input: EndBrowserSessionInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationEndCompatSessionArgs = {
  input: EndCompatSessionInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationEndOauth2SessionArgs = {
  input: EndOAuth2SessionInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationLockUserArgs = {
  input: LockUserInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationRemoveEmailArgs = {
  input: RemoveEmailInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSendVerificationEmailArgs = {
  input: SendVerificationEmailInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSetCanRequestAdminArgs = {
  input: SetCanRequestAdminInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSetDisplayNameArgs = {
  input: SetDisplayNameInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSetPasswordArgs = {
  input: SetPasswordInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSetPasswordByRecoveryArgs = {
  input: SetPasswordByRecoveryInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSetPrimaryEmailArgs = {
  input: SetPrimaryEmailInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationUnlockUserArgs = {
  input: UnlockUserInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationVerifyEmailArgs = {
  input: VerifyEmailInput;
};

/** An object with an ID. */
export type Node = {
  /** ID of the object. */
  id: Scalars['ID']['output'];
};

/** The application type advertised by the client. */
export type Oauth2ApplicationType =
  /** Client is a native application. */
  | 'NATIVE'
  /** Client is a web application. */
  | 'WEB';

/** An OAuth 2.0 client */
export type Oauth2Client = Node & {
  __typename?: 'Oauth2Client';
  /** The application type advertised by the client. */
  applicationType?: Maybe<Oauth2ApplicationType>;
  /** OAuth 2.0 client ID */
  clientId: Scalars['String']['output'];
  /** Client name advertised by the client. */
  clientName?: Maybe<Scalars['String']['output']>;
  /** Client URI advertised by the client. */
  clientUri?: Maybe<Scalars['Url']['output']>;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** Logo URI advertised by the client. */
  logoUri?: Maybe<Scalars['Url']['output']>;
  /** Privacy policy URI advertised by the client. */
  policyUri?: Maybe<Scalars['Url']['output']>;
  /** List of redirect URIs used for authorization grants by the client. */
  redirectUris: Array<Scalars['Url']['output']>;
  /** Terms of services URI advertised by the client. */
  tosUri?: Maybe<Scalars['Url']['output']>;
};

/**
 * An OAuth 2.0 session represents a client session which used the OAuth APIs
 * to login.
 */
export type Oauth2Session = CreationEvent & Node & {
  __typename?: 'Oauth2Session';
  /** The browser session which started this OAuth 2.0 session. */
  browserSession?: Maybe<BrowserSession>;
  /** OAuth 2.0 client used by this session. */
  client: Oauth2Client;
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** When the session ended. */
  finishedAt?: Maybe<Scalars['DateTime']['output']>;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** The last time the session was active. */
  lastActiveAt?: Maybe<Scalars['DateTime']['output']>;
  /** The last IP address used by the session. */
  lastActiveIp?: Maybe<Scalars['String']['output']>;
  /** Scope granted for this session. */
  scope: Scalars['String']['output'];
  /** The state of the session. */
  state: SessionState;
  /** User authorized for this session. */
  user?: Maybe<User>;
  /** The user-agent with which the session was created. */
  userAgent?: Maybe<UserAgent>;
};

export type Oauth2SessionConnection = {
  __typename?: 'Oauth2SessionConnection';
  /** A list of edges. */
  edges: Array<Oauth2SessionEdge>;
  /** A list of nodes. */
  nodes: Array<Oauth2Session>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type Oauth2SessionEdge = {
  __typename?: 'Oauth2SessionEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: Oauth2Session;
};

/** Information about pagination in a connection */
export type PageInfo = {
  __typename?: 'PageInfo';
  /** When paginating forwards, the cursor to continue. */
  endCursor?: Maybe<Scalars['String']['output']>;
  /** When paginating forwards, are there more items? */
  hasNextPage: Scalars['Boolean']['output'];
  /** When paginating backwards, are there more items? */
  hasPreviousPage: Scalars['Boolean']['output'];
  /** When paginating backwards, the cursor to continue. */
  startCursor?: Maybe<Scalars['String']['output']>;
};

/** The query root of the GraphQL interface. */
export type Query = {
  __typename?: 'Query';
  /** Fetch a browser session by its ID. */
  browserSession?: Maybe<BrowserSession>;
  /** Fetch a compatible session by its ID. */
  compatSession?: Maybe<CompatSession>;
  /**
   * Get the current logged in browser session
   * @deprecated Use `viewerSession` instead.
   */
  currentBrowserSession?: Maybe<BrowserSession>;
  /**
   * Get the current logged in user
   * @deprecated Use `viewer` instead.
   */
  currentUser?: Maybe<User>;
  /** Fetches an object given its ID. */
  node?: Maybe<Node>;
  /** Fetch an OAuth 2.0 client by its ID. */
  oauth2Client?: Maybe<Oauth2Client>;
  /** Fetch an OAuth 2.0 session by its ID. */
  oauth2Session?: Maybe<Oauth2Session>;
  /** Lookup a compat or OAuth 2.0 session */
  session?: Maybe<Session>;
  /** Get the current site configuration */
  siteConfig: SiteConfig;
  /** Fetch an upstream OAuth 2.0 link by its ID. */
  upstreamOauth2Link?: Maybe<UpstreamOAuth2Link>;
  /** Fetch an upstream OAuth 2.0 provider by its ID. */
  upstreamOauth2Provider?: Maybe<UpstreamOAuth2Provider>;
  /** Get a list of upstream OAuth 2.0 providers. */
  upstreamOauth2Providers: UpstreamOAuth2ProviderConnection;
  /** Fetch a user by its ID. */
  user?: Maybe<User>;
  /** Fetch a user by its username. */
  userByUsername?: Maybe<User>;
  /** Fetch a user email by its ID. */
  userEmail?: Maybe<UserEmail>;
  /**
   * Get a list of users.
   *
   * This is only available to administrators.
   */
  users: UserConnection;
  /** Get the viewer */
  viewer: Viewer;
  /** Get the viewer's session */
  viewerSession: ViewerSession;
};


/** The query root of the GraphQL interface. */
export type QueryBrowserSessionArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryCompatSessionArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryNodeArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryOauth2ClientArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryOauth2SessionArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QuerySessionArgs = {
  deviceId: Scalars['String']['input'];
  userId: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryUpstreamOauth2LinkArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryUpstreamOauth2ProviderArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryUpstreamOauth2ProvidersArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
};


/** The query root of the GraphQL interface. */
export type QueryUserArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryUserByUsernameArgs = {
  username: Scalars['String']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryUserEmailArgs = {
  id: Scalars['ID']['input'];
};


/** The query root of the GraphQL interface. */
export type QueryUsersArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  canRequestAdmin?: InputMaybe<Scalars['Boolean']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  state?: InputMaybe<UserState>;
};

/** The input for the `removeEmail` mutation */
export type RemoveEmailInput = {
  /** The ID of the email address to remove */
  userEmailId: Scalars['ID']['input'];
};

/** The payload of the `removeEmail` mutation */
export type RemoveEmailPayload = {
  __typename?: 'RemoveEmailPayload';
  /** The email address that was removed */
  email?: Maybe<UserEmail>;
  /** Status of the operation */
  status: RemoveEmailStatus;
  /** The user to whom the email address belonged */
  user?: Maybe<User>;
};

/** The status of the `removeEmail` mutation */
export type RemoveEmailStatus =
  /** The email address was not found */
  | 'NOT_FOUND'
  /** Can't remove the primary email address */
  | 'PRIMARY'
  /** The email address was removed */
  | 'REMOVED';

/** The input for the `sendVerificationEmail` mutation */
export type SendVerificationEmailInput = {
  /** The ID of the email address to verify */
  userEmailId: Scalars['ID']['input'];
};

/** The payload of the `sendVerificationEmail` mutation */
export type SendVerificationEmailPayload = {
  __typename?: 'SendVerificationEmailPayload';
  /** The email address to which the verification email was sent */
  email: UserEmail;
  /** Status of the operation */
  status: SendVerificationEmailStatus;
  /** The user to whom the email address belongs */
  user: User;
};

/** The status of the `sendVerificationEmail` mutation */
export type SendVerificationEmailStatus =
  /** The email address is already verified */
  | 'ALREADY_VERIFIED'
  /** The verification email was sent */
  | 'SENT';

/** A client session, either compat or OAuth 2.0 */
export type Session = CompatSession | Oauth2Session;

/** The state of a session */
export type SessionState =
  /** The session is active. */
  | 'ACTIVE'
  /** The session is no longer active. */
  | 'FINISHED';

/** The input for the `setCanRequestAdmin` mutation. */
export type SetCanRequestAdminInput = {
  /** Whether the user can request admin. */
  canRequestAdmin: Scalars['Boolean']['input'];
  /** The ID of the user to update. */
  userId: Scalars['ID']['input'];
};

/** The payload for the `setCanRequestAdmin` mutation. */
export type SetCanRequestAdminPayload = {
  __typename?: 'SetCanRequestAdminPayload';
  /** The user that was updated. */
  user?: Maybe<User>;
};

/** The input for the `addEmail` mutation */
export type SetDisplayNameInput = {
  /** The display name to set. If `None`, the display name will be removed. */
  displayName?: InputMaybe<Scalars['String']['input']>;
  /** The ID of the user to add the email address to */
  userId: Scalars['ID']['input'];
};

/** The payload of the `setDisplayName` mutation */
export type SetDisplayNamePayload = {
  __typename?: 'SetDisplayNamePayload';
  /** Status of the operation */
  status: SetDisplayNameStatus;
  /** The user that was updated */
  user?: Maybe<User>;
};

/** The status of the `setDisplayName` mutation */
export type SetDisplayNameStatus =
  /** The display name is invalid */
  | 'INVALID'
  /** The display name was set */
  | 'SET';

/** The input for the `setPasswordByRecovery` mutation. */
export type SetPasswordByRecoveryInput = {
  /** The new password for the user. */
  newPassword: Scalars['String']['input'];
  /**
   * The recovery ticket to use.
   * This identifies the user as well as proving authorisation to perform the
   * recovery operation.
   */
  ticket: Scalars['String']['input'];
};

/** The input for the `setPassword` mutation. */
export type SetPasswordInput = {
  /**
   * The current password of the user.
   * Required if you are not a server administrator.
   */
  currentPassword?: InputMaybe<Scalars['String']['input']>;
  /** The new password for the user. */
  newPassword: Scalars['String']['input'];
  /**
   * The ID of the user to set the password for.
   * If you are not a server administrator then this must be your own user
   * ID.
   */
  userId: Scalars['ID']['input'];
};

/** The return type for the `setPassword` mutation. */
export type SetPasswordPayload = {
  __typename?: 'SetPasswordPayload';
  /** Status of the operation */
  status: SetPasswordStatus;
};

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

/** The input for the `setPrimaryEmail` mutation */
export type SetPrimaryEmailInput = {
  /** The ID of the email address to set as primary */
  userEmailId: Scalars['ID']['input'];
};

/** The payload of the `setPrimaryEmail` mutation */
export type SetPrimaryEmailPayload = {
  __typename?: 'SetPrimaryEmailPayload';
  status: SetPrimaryEmailStatus;
  /** The user to whom the email address belongs */
  user?: Maybe<User>;
};

/** The status of the `setPrimaryEmail` mutation */
export type SetPrimaryEmailStatus =
  /** The email address was not found */
  | 'NOT_FOUND'
  /** The email address was set as primary */
  | 'SET'
  /** Can't make an unverified email address primary */
  | 'UNVERIFIED';

export type SiteConfig = Node & {
  __typename?: 'SiteConfig';
  /** The configuration of CAPTCHA provider. */
  captchaConfig?: Maybe<CaptchaConfig>;
  /** Whether users can change their display name. */
  displayNameChangeAllowed: Scalars['Boolean']['output'];
  /** Whether users can change their email. */
  emailChangeAllowed: Scalars['Boolean']['output'];
  /** The ID of the site configuration. */
  id: Scalars['ID']['output'];
  /** Imprint to show in the footer. */
  imprint?: Maybe<Scalars['String']['output']>;
  /**
   * Minimum password complexity, from 0 to 4, in terms of a zxcvbn score.
   * The exact scorer (including dictionaries and other data tables)
   * in use is <https://crates.io/crates/zxcvbn>.
   */
  minimumPasswordComplexity: Scalars['Int']['output'];
  /** Whether passwords are enabled and users can change their own passwords. */
  passwordChangeAllowed: Scalars['Boolean']['output'];
  /** Whether passwords are enabled for login. */
  passwordLoginEnabled: Scalars['Boolean']['output'];
  /** Whether passwords are enabled and users can register using a password. */
  passwordRegistrationEnabled: Scalars['Boolean']['output'];
  /** The URL to the privacy policy. */
  policyUri?: Maybe<Scalars['Url']['output']>;
  /** The server name of the homeserver. */
  serverName: Scalars['String']['output'];
  /** The URL to the terms of service. */
  tosUri?: Maybe<Scalars['Url']['output']>;
};

/** The input for the `unlockUser` mutation. */
export type UnlockUserInput = {
  /** The ID of the user to unlock */
  userId: Scalars['ID']['input'];
};

/** The payload for the `unlockUser` mutation. */
export type UnlockUserPayload = {
  __typename?: 'UnlockUserPayload';
  /** Status of the operation */
  status: UnlockUserStatus;
  /** The user that was unlocked. */
  user?: Maybe<User>;
};

/** The status of the `unlockUser` mutation. */
export type UnlockUserStatus =
  /** The user was not found. */
  | 'NOT_FOUND'
  /** The user was unlocked. */
  | 'UNLOCKED';

export type UpstreamOAuth2Link = CreationEvent & Node & {
  __typename?: 'UpstreamOAuth2Link';
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** The provider for which this link is. */
  provider: UpstreamOAuth2Provider;
  /** Subject used for linking */
  subject: Scalars['String']['output'];
  /** The user to which this link is associated. */
  user?: Maybe<User>;
};

export type UpstreamOAuth2LinkConnection = {
  __typename?: 'UpstreamOAuth2LinkConnection';
  /** A list of edges. */
  edges: Array<UpstreamOAuth2LinkEdge>;
  /** A list of nodes. */
  nodes: Array<UpstreamOAuth2Link>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type UpstreamOAuth2LinkEdge = {
  __typename?: 'UpstreamOAuth2LinkEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: UpstreamOAuth2Link;
};

export type UpstreamOAuth2Provider = CreationEvent & Node & {
  __typename?: 'UpstreamOAuth2Provider';
  /** Client ID used for this provider. */
  clientId: Scalars['String']['output'];
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** OpenID Connect issuer URL. */
  issuer: Scalars['String']['output'];
};

export type UpstreamOAuth2ProviderConnection = {
  __typename?: 'UpstreamOAuth2ProviderConnection';
  /** A list of edges. */
  edges: Array<UpstreamOAuth2ProviderEdge>;
  /** A list of nodes. */
  nodes: Array<UpstreamOAuth2Provider>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type UpstreamOAuth2ProviderEdge = {
  __typename?: 'UpstreamOAuth2ProviderEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: UpstreamOAuth2Provider;
};

/** A user is an individual's account. */
export type User = Node & {
  __typename?: 'User';
  /**
   * Get the list of both compat and OAuth 2.0 sessions, chronologically
   * sorted
   */
  appSessions: AppSessionConnection;
  /** Get the list of active browser sessions, chronologically sorted */
  browserSessions: BrowserSessionConnection;
  /** Whether the user can request admin privileges. */
  canRequestAdmin: Scalars['Boolean']['output'];
  /** Get the list of compatibility sessions, chronologically sorted */
  compatSessions: CompatSessionConnection;
  /** Get the list of compatibility SSO logins, chronologically sorted */
  compatSsoLogins: CompatSsoLoginConnection;
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** Get the list of emails, chronologically sorted */
  emails: UserEmailConnection;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** When the user was locked out. */
  lockedAt?: Maybe<Scalars['DateTime']['output']>;
  /** Access to the user's Matrix account information. */
  matrix: MatrixUser;
  /** Get the list of OAuth 2.0 sessions, chronologically sorted */
  oauth2Sessions: Oauth2SessionConnection;
  /** Primary email address of the user. */
  primaryEmail?: Maybe<UserEmail>;
  /** Get the list of upstream OAuth 2.0 links */
  upstreamOauth2Links: UpstreamOAuth2LinkConnection;
  /** Username chosen by the user. */
  username: Scalars['String']['output'];
};


/** A user is an individual's account. */
export type UserAppSessionsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  browserSession?: InputMaybe<Scalars['ID']['input']>;
  device?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  lastActive?: InputMaybe<DateFilter>;
  state?: InputMaybe<SessionState>;
};


/** A user is an individual's account. */
export type UserBrowserSessionsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  lastActive?: InputMaybe<DateFilter>;
  state?: InputMaybe<SessionState>;
};


/** A user is an individual's account. */
export type UserCompatSessionsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  lastActive?: InputMaybe<DateFilter>;
  state?: InputMaybe<SessionState>;
  type?: InputMaybe<CompatSessionType>;
};


/** A user is an individual's account. */
export type UserCompatSsoLoginsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
};


/** A user is an individual's account. */
export type UserEmailsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  state?: InputMaybe<UserEmailState>;
};


/** A user is an individual's account. */
export type UserOauth2SessionsArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  client?: InputMaybe<Scalars['ID']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  lastActive?: InputMaybe<DateFilter>;
  state?: InputMaybe<SessionState>;
};


/** A user is an individual's account. */
export type UserUpstreamOauth2LinksArgs = {
  after?: InputMaybe<Scalars['String']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
};

/** A parsed user agent string */
export type UserAgent = {
  __typename?: 'UserAgent';
  /** The device type */
  deviceType: DeviceType;
  /** The device model */
  model?: Maybe<Scalars['String']['output']>;
  /** The name of the browser */
  name?: Maybe<Scalars['String']['output']>;
  /** The operating system name */
  os?: Maybe<Scalars['String']['output']>;
  /** The operating system version */
  osVersion?: Maybe<Scalars['String']['output']>;
  /** The user agent string */
  raw: Scalars['String']['output'];
  /** The version of the browser */
  version?: Maybe<Scalars['String']['output']>;
};

export type UserConnection = {
  __typename?: 'UserConnection';
  /** A list of edges. */
  edges: Array<UserEdge>;
  /** A list of nodes. */
  nodes: Array<User>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type UserEdge = {
  __typename?: 'UserEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: User;
};

/** A user email address */
export type UserEmail = CreationEvent & Node & {
  __typename?: 'UserEmail';
  /**
   * When the email address was confirmed. Is `null` if the email was never
   * verified by the user.
   */
  confirmedAt?: Maybe<Scalars['DateTime']['output']>;
  /** When the object was created. */
  createdAt: Scalars['DateTime']['output'];
  /** Email address */
  email: Scalars['String']['output'];
  /** ID of the object. */
  id: Scalars['ID']['output'];
};

export type UserEmailConnection = {
  __typename?: 'UserEmailConnection';
  /** A list of edges. */
  edges: Array<UserEmailEdge>;
  /** A list of nodes. */
  nodes: Array<UserEmail>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int']['output'];
};

/** An edge in a connection. */
export type UserEmailEdge = {
  __typename?: 'UserEmailEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String']['output'];
  /** The item at the end of the edge */
  node: UserEmail;
};

/** The state of a compatibility session. */
export type UserEmailState =
  /** The email address has been confirmed. */
  | 'CONFIRMED'
  /** The email address is pending confirmation. */
  | 'PENDING';

/** The state of a user. */
export type UserState =
  /** The user is active. */
  | 'ACTIVE'
  /** The user is locked. */
  | 'LOCKED';

/** The input for the `verifyEmail` mutation */
export type VerifyEmailInput = {
  /** The verification code */
  code: Scalars['String']['input'];
  /** The ID of the email address to verify */
  userEmailId: Scalars['ID']['input'];
};

/** The payload of the `verifyEmail` mutation */
export type VerifyEmailPayload = {
  __typename?: 'VerifyEmailPayload';
  /** The email address that was verified */
  email?: Maybe<UserEmail>;
  /** Status of the operation */
  status: VerifyEmailStatus;
  /** The user to whom the email address belongs */
  user?: Maybe<User>;
};

/** The status of the `verifyEmail` mutation */
export type VerifyEmailStatus =
  /** The email address was already verified before */
  | 'ALREADY_VERIFIED'
  /** The verification code is invalid */
  | 'INVALID_CODE'
  /** The email address was just verified */
  | 'VERIFIED';

/** Represents the current viewer */
export type Viewer = Anonymous | User;

/** Represents the current viewer's session */
export type ViewerSession = Anonymous | BrowserSession | Oauth2Session;

export type PasswordChange_SiteConfigFragment = { __typename?: 'SiteConfig', passwordChangeAllowed: boolean } & { ' $fragmentName'?: 'PasswordChange_SiteConfigFragment' };

export type BrowserSession_SessionFragment = { __typename?: 'BrowserSession', id: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', raw: string, name?: string | null, os?: string | null, model?: string | null, deviceType: DeviceType } | null, lastAuthentication?: { __typename?: 'Authentication', id: string, createdAt: string } | null } & { ' $fragmentName'?: 'BrowserSession_SessionFragment' };

export type EndBrowserSessionMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type EndBrowserSessionMutation = { __typename?: 'Mutation', endBrowserSession: { __typename?: 'EndBrowserSessionPayload', status: EndBrowserSessionStatus, browserSession?: (
      { __typename?: 'BrowserSession', id: string }
      & { ' $fragmentRefs'?: { 'BrowserSession_SessionFragment': BrowserSession_SessionFragment } }
    ) | null } };

export type OAuth2Client_DetailFragment = { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, clientUri?: string | null, logoUri?: string | null, tosUri?: string | null, policyUri?: string | null, redirectUris: Array<string> } & { ' $fragmentName'?: 'OAuth2Client_DetailFragment' };

export type CompatSession_SessionFragment = { __typename?: 'CompatSession', id: string, createdAt: string, deviceId: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, os?: string | null, model?: string | null, deviceType: DeviceType } | null, ssoLogin?: { __typename?: 'CompatSsoLogin', id: string, redirectUri: string } | null } & { ' $fragmentName'?: 'CompatSession_SessionFragment' };

export type EndCompatSessionMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type EndCompatSessionMutation = { __typename?: 'Mutation', endCompatSession: { __typename?: 'EndCompatSessionPayload', status: EndCompatSessionStatus, compatSession?: { __typename?: 'CompatSession', id: string } | null } };

export type Footer_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, imprint?: string | null, tosUri?: string | null, policyUri?: string | null } & { ' $fragmentName'?: 'Footer_SiteConfigFragment' };

export type FooterQueryVariables = Exact<{ [key: string]: never; }>;


export type FooterQuery = { __typename?: 'Query', siteConfig: (
    { __typename?: 'SiteConfig', id: string }
    & { ' $fragmentRefs'?: { 'Footer_SiteConfigFragment': Footer_SiteConfigFragment } }
  ) };

export type OAuth2Session_SessionFragment = { __typename?: 'Oauth2Session', id: string, scope: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, model?: string | null, os?: string | null, deviceType: DeviceType } | null, client: { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, applicationType?: Oauth2ApplicationType | null, logoUri?: string | null } } & { ' $fragmentName'?: 'OAuth2Session_SessionFragment' };

export type EndOAuth2SessionMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type EndOAuth2SessionMutation = { __typename?: 'Mutation', endOauth2Session: { __typename?: 'EndOAuth2SessionPayload', status: EndOAuth2SessionStatus, oauth2Session?: { __typename?: 'Oauth2Session', id: string } | null } };

export type PasswordCreationDoubleInput_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, minimumPasswordComplexity: number } & { ' $fragmentName'?: 'PasswordCreationDoubleInput_SiteConfigFragment' };

export type BrowserSession_DetailFragment = { __typename?: 'BrowserSession', id: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, model?: string | null, os?: string | null } | null, lastAuthentication?: { __typename?: 'Authentication', id: string, createdAt: string } | null, user: { __typename?: 'User', id: string, username: string } } & { ' $fragmentName'?: 'BrowserSession_DetailFragment' };

export type CompatSession_DetailFragment = { __typename?: 'CompatSession', id: string, createdAt: string, deviceId: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, os?: string | null, model?: string | null } | null, ssoLogin?: { __typename?: 'CompatSsoLogin', id: string, redirectUri: string } | null } & { ' $fragmentName'?: 'CompatSession_DetailFragment' };

export type OAuth2Session_DetailFragment = { __typename?: 'Oauth2Session', id: string, scope: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, client: { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, clientUri?: string | null, logoUri?: string | null } } & { ' $fragmentName'?: 'OAuth2Session_DetailFragment' };

export type UnverifiedEmailAlert_UserFragment = { __typename?: 'User', unverifiedEmails: { __typename?: 'UserEmailConnection', totalCount: number } } & { ' $fragmentName'?: 'UnverifiedEmailAlert_UserFragment' };

export type UserEmail_EmailFragment = { __typename?: 'UserEmail', id: string, email: string, confirmedAt?: string | null } & { ' $fragmentName'?: 'UserEmail_EmailFragment' };

export type UserEmail_SiteConfigFragment = { __typename?: 'SiteConfig', emailChangeAllowed: boolean } & { ' $fragmentName'?: 'UserEmail_SiteConfigFragment' };

export type RemoveEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type RemoveEmailMutation = { __typename?: 'Mutation', removeEmail: { __typename?: 'RemoveEmailPayload', status: RemoveEmailStatus, user?: { __typename?: 'User', id: string } | null } };

export type SetPrimaryEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type SetPrimaryEmailMutation = { __typename?: 'Mutation', setPrimaryEmail: { __typename?: 'SetPrimaryEmailPayload', status: SetPrimaryEmailStatus, user?: { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null } | null } };

export type UserGreeting_UserFragment = { __typename?: 'User', id: string, matrix: { __typename?: 'MatrixUser', mxid: string, displayName?: string | null } } & { ' $fragmentName'?: 'UserGreeting_UserFragment' };

export type UserGreeting_SiteConfigFragment = { __typename?: 'SiteConfig', displayNameChangeAllowed: boolean } & { ' $fragmentName'?: 'UserGreeting_SiteConfigFragment' };

export type SetDisplayNameMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
  displayName?: InputMaybe<Scalars['String']['input']>;
}>;


export type SetDisplayNameMutation = { __typename?: 'Mutation', setDisplayName: { __typename?: 'SetDisplayNamePayload', status: SetDisplayNameStatus } };

export type AddEmailMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
  email: Scalars['String']['input'];
}>;


export type AddEmailMutation = { __typename?: 'Mutation', addEmail: { __typename?: 'AddEmailPayload', status: AddEmailStatus, violations?: Array<string> | null, email?: (
      { __typename?: 'UserEmail', id: string }
      & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
    ) | null } };

export type UserEmailListQueryVariables = Exact<{
  userId: Scalars['ID']['input'];
  first?: InputMaybe<Scalars['Int']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
}>;


export type UserEmailListQuery = { __typename?: 'Query', user?: { __typename?: 'User', id: string, emails: { __typename?: 'UserEmailConnection', totalCount: number, edges: Array<{ __typename?: 'UserEmailEdge', cursor: string, node: (
          { __typename?: 'UserEmail', id: string }
          & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
        ) }>, pageInfo: { __typename?: 'PageInfo', hasNextPage: boolean, hasPreviousPage: boolean, startCursor?: string | null, endCursor?: string | null } } } | null };

export type UserEmailList_UserFragment = { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null } & { ' $fragmentName'?: 'UserEmailList_UserFragment' };

export type UserEmailList_SiteConfigFragment = (
  { __typename?: 'SiteConfig' }
  & { ' $fragmentRefs'?: { 'UserEmail_SiteConfigFragment': UserEmail_SiteConfigFragment } }
) & { ' $fragmentName'?: 'UserEmailList_SiteConfigFragment' };

export type BrowserSessionsOverview_UserFragment = { __typename?: 'User', id: string, browserSessions: { __typename?: 'BrowserSessionConnection', totalCount: number } } & { ' $fragmentName'?: 'BrowserSessionsOverview_UserFragment' };

export type UserEmail_VerifyEmailFragment = { __typename?: 'UserEmail', id: string, email: string } & { ' $fragmentName'?: 'UserEmail_VerifyEmailFragment' };

export type DoVerifyEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
  code: Scalars['String']['input'];
}>;


export type DoVerifyEmailMutation = { __typename?: 'Mutation', verifyEmail: { __typename?: 'VerifyEmailPayload', status: VerifyEmailStatus, user?: { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null } | null, email?: (
      { __typename?: 'UserEmail', id: string }
      & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
    ) | null } };

export type ResendVerificationEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type ResendVerificationEmailMutation = { __typename?: 'Mutation', sendVerificationEmail: { __typename?: 'SendVerificationEmailPayload', status: SendVerificationEmailStatus, user: { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null }, email: (
      { __typename?: 'UserEmail', id: string }
      & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
    ) } };

export type UserProfileQueryVariables = Exact<{ [key: string]: never; }>;


export type UserProfileQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous' } | (
    { __typename: 'User', id: string, primaryEmail?: (
      { __typename?: 'UserEmail', id: string }
      & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
    ) | null }
    & { ' $fragmentRefs'?: { 'UserEmailList_UserFragment': UserEmailList_UserFragment } }
  ), siteConfig: (
    { __typename?: 'SiteConfig', emailChangeAllowed: boolean, passwordLoginEnabled: boolean }
    & { ' $fragmentRefs'?: { 'UserEmailList_SiteConfigFragment': UserEmailList_SiteConfigFragment;'UserEmail_SiteConfigFragment': UserEmail_SiteConfigFragment;'PasswordChange_SiteConfigFragment': PasswordChange_SiteConfigFragment } }
  ) };

export type SessionDetailQueryVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type SessionDetailQuery = { __typename?: 'Query', viewerSession: { __typename?: 'Anonymous', id: string } | { __typename?: 'BrowserSession', id: string } | { __typename?: 'Oauth2Session', id: string }, node?: { __typename: 'Anonymous', id: string } | { __typename: 'Authentication', id: string } | (
    { __typename: 'BrowserSession', id: string }
    & { ' $fragmentRefs'?: { 'BrowserSession_DetailFragment': BrowserSession_DetailFragment } }
  ) | (
    { __typename: 'CompatSession', id: string }
    & { ' $fragmentRefs'?: { 'CompatSession_DetailFragment': CompatSession_DetailFragment } }
  ) | { __typename: 'CompatSsoLogin', id: string } | { __typename: 'Oauth2Client', id: string } | (
    { __typename: 'Oauth2Session', id: string }
    & { ' $fragmentRefs'?: { 'OAuth2Session_DetailFragment': OAuth2Session_DetailFragment } }
  ) | { __typename: 'SiteConfig', id: string } | { __typename: 'UpstreamOAuth2Link', id: string } | { __typename: 'UpstreamOAuth2Provider', id: string } | { __typename: 'User', id: string } | { __typename: 'UserEmail', id: string } | null };

export type BrowserSessionListQueryVariables = Exact<{
  first?: InputMaybe<Scalars['Int']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
  lastActive?: InputMaybe<DateFilter>;
}>;


export type BrowserSessionListQuery = { __typename?: 'Query', viewerSession: { __typename: 'Anonymous' } | { __typename: 'BrowserSession', id: string, user: { __typename?: 'User', id: string, browserSessions: { __typename?: 'BrowserSessionConnection', totalCount: number, edges: Array<{ __typename?: 'BrowserSessionEdge', cursor: string, node: (
            { __typename?: 'BrowserSession', id: string }
            & { ' $fragmentRefs'?: { 'BrowserSession_SessionFragment': BrowserSession_SessionFragment } }
          ) }>, pageInfo: { __typename?: 'PageInfo', hasNextPage: boolean, hasPreviousPage: boolean, startCursor?: string | null, endCursor?: string | null } } } } | { __typename: 'Oauth2Session' } };

export type SessionsOverviewQueryVariables = Exact<{ [key: string]: never; }>;


export type SessionsOverviewQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous' } | (
    { __typename: 'User', id: string }
    & { ' $fragmentRefs'?: { 'BrowserSessionsOverview_UserFragment': BrowserSessionsOverview_UserFragment } }
  ) };

export type AppSessionsListQueryVariables = Exact<{
  before?: InputMaybe<Scalars['String']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  lastActive?: InputMaybe<DateFilter>;
}>;


export type AppSessionsListQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous' } | { __typename: 'User', id: string, appSessions: { __typename?: 'AppSessionConnection', totalCount: number, edges: Array<{ __typename?: 'AppSessionEdge', cursor: string, node: (
          { __typename: 'CompatSession' }
          & { ' $fragmentRefs'?: { 'CompatSession_SessionFragment': CompatSession_SessionFragment } }
        ) | (
          { __typename: 'Oauth2Session' }
          & { ' $fragmentRefs'?: { 'OAuth2Session_SessionFragment': OAuth2Session_SessionFragment } }
        ) }>, pageInfo: { __typename?: 'PageInfo', startCursor?: string | null, endCursor?: string | null, hasNextPage: boolean, hasPreviousPage: boolean } } } };

export type CurrentUserGreetingQueryVariables = Exact<{ [key: string]: never; }>;


export type CurrentUserGreetingQuery = { __typename?: 'Query', viewerSession: { __typename: 'Anonymous' } | { __typename: 'BrowserSession', id: string, user: (
      { __typename?: 'User' }
      & { ' $fragmentRefs'?: { 'UnverifiedEmailAlert_UserFragment': UnverifiedEmailAlert_UserFragment;'UserGreeting_UserFragment': UserGreeting_UserFragment } }
    ) } | { __typename: 'Oauth2Session' }, siteConfig: (
    { __typename?: 'SiteConfig' }
    & { ' $fragmentRefs'?: { 'UserGreeting_SiteConfigFragment': UserGreeting_SiteConfigFragment } }
  ) };

export type OAuth2ClientQueryVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type OAuth2ClientQuery = { __typename?: 'Query', oauth2Client?: (
    { __typename?: 'Oauth2Client' }
    & { ' $fragmentRefs'?: { 'OAuth2Client_DetailFragment': OAuth2Client_DetailFragment } }
  ) | null };

export type CurrentViewerQueryVariables = Exact<{ [key: string]: never; }>;


export type CurrentViewerQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous', id: string } | { __typename: 'User', id: string } };

export type DeviceRedirectQueryVariables = Exact<{
  deviceId: Scalars['String']['input'];
  userId: Scalars['ID']['input'];
}>;


export type DeviceRedirectQuery = { __typename?: 'Query', session?: { __typename: 'CompatSession', id: string } | { __typename: 'Oauth2Session', id: string } | null };

export type VerifyEmailQueryVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type VerifyEmailQuery = { __typename?: 'Query', userEmail?: (
    { __typename?: 'UserEmail' }
    & { ' $fragmentRefs'?: { 'UserEmail_VerifyEmailFragment': UserEmail_VerifyEmailFragment } }
  ) | null };

export type ChangePasswordMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
  oldPassword: Scalars['String']['input'];
  newPassword: Scalars['String']['input'];
}>;


export type ChangePasswordMutation = { __typename?: 'Mutation', setPassword: { __typename?: 'SetPasswordPayload', status: SetPasswordStatus } };

export type PasswordChangeQueryVariables = Exact<{ [key: string]: never; }>;


export type PasswordChangeQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous', id: string } | { __typename: 'User', id: string }, siteConfig: (
    { __typename?: 'SiteConfig' }
    & { ' $fragmentRefs'?: { 'PasswordCreationDoubleInput_SiteConfigFragment': PasswordCreationDoubleInput_SiteConfigFragment } }
  ) };

export type RecoverPasswordMutationVariables = Exact<{
  ticket: Scalars['String']['input'];
  newPassword: Scalars['String']['input'];
}>;


export type RecoverPasswordMutation = { __typename?: 'Mutation', setPasswordByRecovery: { __typename?: 'SetPasswordPayload', status: SetPasswordStatus } };

export type PasswordRecoveryQueryVariables = Exact<{ [key: string]: never; }>;


export type PasswordRecoveryQuery = { __typename?: 'Query', siteConfig: (
    { __typename?: 'SiteConfig' }
    & { ' $fragmentRefs'?: { 'PasswordCreationDoubleInput_SiteConfigFragment': PasswordCreationDoubleInput_SiteConfigFragment } }
  ) };

export type AllowCrossSigningResetMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
}>;


export type AllowCrossSigningResetMutation = { __typename?: 'Mutation', allowUserCrossSigningReset: { __typename?: 'AllowUserCrossSigningResetPayload', user?: { __typename?: 'User', id: string } | null } };

export class TypedDocumentString<TResult, TVariables>
  extends String
  implements DocumentTypeDecoration<TResult, TVariables>
{
  __apiType?: DocumentTypeDecoration<TResult, TVariables>['__apiType'];

  constructor(private value: string, public __meta__?: Record<string, any> | undefined) {
    super(value);
  }

  toString(): string & DocumentTypeDecoration<TResult, TVariables> {
    return this.value;
  }
}
export const PasswordChange_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment PasswordChange_siteConfig on SiteConfig {
  passwordChangeAllowed
}
    `, {"fragmentName":"PasswordChange_siteConfig"}) as unknown as TypedDocumentString<PasswordChange_SiteConfigFragment, unknown>;
export const BrowserSession_SessionFragmentDoc = new TypedDocumentString(`
    fragment BrowserSession_session on BrowserSession {
  id
  createdAt
  finishedAt
  userAgent {
    raw
    name
    os
    model
    deviceType
  }
  lastActiveIp
  lastActiveAt
  lastAuthentication {
    id
    createdAt
  }
}
    `, {"fragmentName":"BrowserSession_session"}) as unknown as TypedDocumentString<BrowserSession_SessionFragment, unknown>;
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
export const CompatSession_SessionFragmentDoc = new TypedDocumentString(`
    fragment CompatSession_session on CompatSession {
  id
  createdAt
  deviceId
  finishedAt
  lastActiveIp
  lastActiveAt
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
    `, {"fragmentName":"CompatSession_session"}) as unknown as TypedDocumentString<CompatSession_SessionFragment, unknown>;
export const Footer_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment Footer_siteConfig on SiteConfig {
  id
  imprint
  tosUri
  policyUri
}
    `, {"fragmentName":"Footer_siteConfig"}) as unknown as TypedDocumentString<Footer_SiteConfigFragment, unknown>;
export const OAuth2Session_SessionFragmentDoc = new TypedDocumentString(`
    fragment OAuth2Session_session on Oauth2Session {
  id
  scope
  createdAt
  finishedAt
  lastActiveIp
  lastActiveAt
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
    `, {"fragmentName":"OAuth2Session_session"}) as unknown as TypedDocumentString<OAuth2Session_SessionFragment, unknown>;
export const PasswordCreationDoubleInput_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
  id
  minimumPasswordComplexity
}
    `, {"fragmentName":"PasswordCreationDoubleInput_siteConfig"}) as unknown as TypedDocumentString<PasswordCreationDoubleInput_SiteConfigFragment, unknown>;
export const BrowserSession_DetailFragmentDoc = new TypedDocumentString(`
    fragment BrowserSession_detail on BrowserSession {
  id
  createdAt
  finishedAt
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
    `, {"fragmentName":"BrowserSession_detail"}) as unknown as TypedDocumentString<BrowserSession_DetailFragment, unknown>;
export const CompatSession_DetailFragmentDoc = new TypedDocumentString(`
    fragment CompatSession_detail on CompatSession {
  id
  createdAt
  deviceId
  finishedAt
  lastActiveIp
  lastActiveAt
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
    `, {"fragmentName":"CompatSession_detail"}) as unknown as TypedDocumentString<CompatSession_DetailFragment, unknown>;
export const OAuth2Session_DetailFragmentDoc = new TypedDocumentString(`
    fragment OAuth2Session_detail on Oauth2Session {
  id
  scope
  createdAt
  finishedAt
  lastActiveIp
  lastActiveAt
  client {
    id
    clientId
    clientName
    clientUri
    logoUri
  }
}
    `, {"fragmentName":"OAuth2Session_detail"}) as unknown as TypedDocumentString<OAuth2Session_DetailFragment, unknown>;
export const UnverifiedEmailAlert_UserFragmentDoc = new TypedDocumentString(`
    fragment UnverifiedEmailAlert_user on User {
  unverifiedEmails: emails(first: 0, state: PENDING) {
    totalCount
  }
}
    `, {"fragmentName":"UnverifiedEmailAlert_user"}) as unknown as TypedDocumentString<UnverifiedEmailAlert_UserFragment, unknown>;
export const UserEmail_EmailFragmentDoc = new TypedDocumentString(`
    fragment UserEmail_email on UserEmail {
  id
  email
  confirmedAt
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
export const UserEmailList_UserFragmentDoc = new TypedDocumentString(`
    fragment UserEmailList_user on User {
  id
  primaryEmail {
    id
  }
}
    `, {"fragmentName":"UserEmailList_user"}) as unknown as TypedDocumentString<UserEmailList_UserFragment, unknown>;
export const UserEmail_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment UserEmail_siteConfig on SiteConfig {
  emailChangeAllowed
}
    `, {"fragmentName":"UserEmail_siteConfig"}) as unknown as TypedDocumentString<UserEmail_SiteConfigFragment, unknown>;
export const UserEmailList_SiteConfigFragmentDoc = new TypedDocumentString(`
    fragment UserEmailList_siteConfig on SiteConfig {
  ...UserEmail_siteConfig
}
    fragment UserEmail_siteConfig on SiteConfig {
  emailChangeAllowed
}`, {"fragmentName":"UserEmailList_siteConfig"}) as unknown as TypedDocumentString<UserEmailList_SiteConfigFragment, unknown>;
export const BrowserSessionsOverview_UserFragmentDoc = new TypedDocumentString(`
    fragment BrowserSessionsOverview_user on User {
  id
  browserSessions(first: 0, state: ACTIVE) {
    totalCount
  }
}
    `, {"fragmentName":"BrowserSessionsOverview_user"}) as unknown as TypedDocumentString<BrowserSessionsOverview_UserFragment, unknown>;
export const UserEmail_VerifyEmailFragmentDoc = new TypedDocumentString(`
    fragment UserEmail_verifyEmail on UserEmail {
  id
  email
}
    `, {"fragmentName":"UserEmail_verifyEmail"}) as unknown as TypedDocumentString<UserEmail_VerifyEmailFragment, unknown>;
export const EndBrowserSessionDocument = new TypedDocumentString(`
    mutation EndBrowserSession($id: ID!) {
  endBrowserSession(input: {browserSessionId: $id}) {
    status
    browserSession {
      id
      ...BrowserSession_session
    }
  }
}
    fragment BrowserSession_session on BrowserSession {
  id
  createdAt
  finishedAt
  userAgent {
    raw
    name
    os
    model
    deviceType
  }
  lastActiveIp
  lastActiveAt
  lastAuthentication {
    id
    createdAt
  }
}`) as unknown as TypedDocumentString<EndBrowserSessionMutation, EndBrowserSessionMutationVariables>;
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
export const RemoveEmailDocument = new TypedDocumentString(`
    mutation RemoveEmail($id: ID!) {
  removeEmail(input: {userEmailId: $id}) {
    status
    user {
      id
    }
  }
}
    `) as unknown as TypedDocumentString<RemoveEmailMutation, RemoveEmailMutationVariables>;
export const SetPrimaryEmailDocument = new TypedDocumentString(`
    mutation SetPrimaryEmail($id: ID!) {
  setPrimaryEmail(input: {userEmailId: $id}) {
    status
    user {
      id
      primaryEmail {
        id
      }
    }
  }
}
    `) as unknown as TypedDocumentString<SetPrimaryEmailMutation, SetPrimaryEmailMutationVariables>;
export const SetDisplayNameDocument = new TypedDocumentString(`
    mutation SetDisplayName($userId: ID!, $displayName: String) {
  setDisplayName(input: {userId: $userId, displayName: $displayName}) {
    status
  }
}
    `) as unknown as TypedDocumentString<SetDisplayNameMutation, SetDisplayNameMutationVariables>;
export const AddEmailDocument = new TypedDocumentString(`
    mutation AddEmail($userId: ID!, $email: String!) {
  addEmail(input: {userId: $userId, email: $email}) {
    status
    violations
    email {
      id
      ...UserEmail_email
    }
  }
}
    fragment UserEmail_email on UserEmail {
  id
  email
  confirmedAt
}`) as unknown as TypedDocumentString<AddEmailMutation, AddEmailMutationVariables>;
export const UserEmailListDocument = new TypedDocumentString(`
    query UserEmailList($userId: ID!, $first: Int, $after: String, $last: Int, $before: String) {
  user(id: $userId) {
    id
    emails(first: $first, after: $after, last: $last, before: $before) {
      edges {
        cursor
        node {
          id
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
    fragment UserEmail_email on UserEmail {
  id
  email
  confirmedAt
}`) as unknown as TypedDocumentString<UserEmailListQuery, UserEmailListQueryVariables>;
export const DoVerifyEmailDocument = new TypedDocumentString(`
    mutation DoVerifyEmail($id: ID!, $code: String!) {
  verifyEmail(input: {userEmailId: $id, code: $code}) {
    status
    user {
      id
      primaryEmail {
        id
      }
    }
    email {
      id
      ...UserEmail_email
    }
  }
}
    fragment UserEmail_email on UserEmail {
  id
  email
  confirmedAt
}`) as unknown as TypedDocumentString<DoVerifyEmailMutation, DoVerifyEmailMutationVariables>;
export const ResendVerificationEmailDocument = new TypedDocumentString(`
    mutation ResendVerificationEmail($id: ID!) {
  sendVerificationEmail(input: {userEmailId: $id}) {
    status
    user {
      id
      primaryEmail {
        id
      }
    }
    email {
      id
      ...UserEmail_email
    }
  }
}
    fragment UserEmail_email on UserEmail {
  id
  email
  confirmedAt
}`) as unknown as TypedDocumentString<ResendVerificationEmailMutation, ResendVerificationEmailMutationVariables>;
export const UserProfileDocument = new TypedDocumentString(`
    query UserProfile {
  viewer {
    __typename
    ... on User {
      id
      primaryEmail {
        id
        ...UserEmail_email
      }
      ...UserEmailList_user
    }
  }
  siteConfig {
    emailChangeAllowed
    passwordLoginEnabled
    ...UserEmailList_siteConfig
    ...UserEmail_siteConfig
    ...PasswordChange_siteConfig
  }
}
    fragment PasswordChange_siteConfig on SiteConfig {
  passwordChangeAllowed
}
fragment UserEmail_email on UserEmail {
  id
  email
  confirmedAt
}
fragment UserEmail_siteConfig on SiteConfig {
  emailChangeAllowed
}
fragment UserEmailList_user on User {
  id
  primaryEmail {
    id
  }
}
fragment UserEmailList_siteConfig on SiteConfig {
  ...UserEmail_siteConfig
}`) as unknown as TypedDocumentString<UserProfileQuery, UserProfileQueryVariables>;
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
    fragment BrowserSession_detail on BrowserSession {
  id
  createdAt
  finishedAt
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
  client {
    id
    clientId
    clientName
    clientUri
    logoUri
  }
}`) as unknown as TypedDocumentString<SessionDetailQuery, SessionDetailQueryVariables>;
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
  userAgent {
    raw
    name
    os
    model
    deviceType
  }
  lastActiveIp
  lastActiveAt
  lastAuthentication {
    id
    createdAt
  }
}`) as unknown as TypedDocumentString<BrowserSessionListQuery, BrowserSessionListQueryVariables>;
export const SessionsOverviewDocument = new TypedDocumentString(`
    query SessionsOverview {
  viewer {
    __typename
    ... on User {
      id
      ...BrowserSessionsOverview_user
    }
  }
}
    fragment BrowserSessionsOverview_user on User {
  id
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
}`) as unknown as TypedDocumentString<AppSessionsListQuery, AppSessionsListQueryVariables>;
export const CurrentUserGreetingDocument = new TypedDocumentString(`
    query CurrentUserGreeting {
  viewerSession {
    __typename
    ... on BrowserSession {
      id
      user {
        ...UnverifiedEmailAlert_user
        ...UserGreeting_user
      }
    }
  }
  siteConfig {
    ...UserGreeting_siteConfig
  }
}
    fragment UnverifiedEmailAlert_user on User {
  unverifiedEmails: emails(first: 0, state: PENDING) {
    totalCount
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
  userEmail(id: $id) {
    ...UserEmail_verifyEmail
  }
}
    fragment UserEmail_verifyEmail on UserEmail {
  id
  email
}`) as unknown as TypedDocumentString<VerifyEmailQuery, VerifyEmailQueryVariables>;
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
export const PasswordRecoveryDocument = new TypedDocumentString(`
    query PasswordRecovery {
  siteConfig {
    ...PasswordCreationDoubleInput_siteConfig
  }
}
    fragment PasswordCreationDoubleInput_siteConfig on SiteConfig {
  id
  minimumPasswordComplexity
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
 * mockRemoveEmailMutation(
 *   ({ query, variables }) => {
 *     const { id } = variables;
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
 * mockSetPrimaryEmailMutation(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { setPrimaryEmail }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockSetPrimaryEmailMutation = (resolver: GraphQLResponseResolver<SetPrimaryEmailMutation, SetPrimaryEmailMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<SetPrimaryEmailMutation, SetPrimaryEmailMutationVariables>(
    'SetPrimaryEmail',
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
 *     const { userId, email } = variables;
 *     return HttpResponse.json({
 *       data: { addEmail }
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
 *     const { userId, first, after, last, before } = variables;
 *     return HttpResponse.json({
 *       data: { user }
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
 * mockDoVerifyEmailMutation(
 *   ({ query, variables }) => {
 *     const { id, code } = variables;
 *     return HttpResponse.json({
 *       data: { verifyEmail }
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
 * mockResendVerificationEmailMutation(
 *   ({ query, variables }) => {
 *     const { id } = variables;
 *     return HttpResponse.json({
 *       data: { sendVerificationEmail }
 *     })
 *   },
 *   requestOptions
 * )
 */
export const mockResendVerificationEmailMutation = (resolver: GraphQLResponseResolver<ResendVerificationEmailMutation, ResendVerificationEmailMutationVariables>, options?: RequestHandlerOptions) =>
  graphql.mutation<ResendVerificationEmailMutation, ResendVerificationEmailMutationVariables>(
    'ResendVerificationEmail',
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
 *       data: { viewer, siteConfig }
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
 *       data: { viewer }
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
 *       data: { viewerSession, siteConfig }
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
 *       data: { userEmail }
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
 * mockPasswordRecoveryQuery(
 *   ({ query, variables }) => {
 *     return HttpResponse.json({
 *       data: { siteConfig }
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
