/* eslint-disable */
import type { TypedDocumentNode as DocumentNode } from '@graphql-typed-document-node/core';
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
  /** The human-readable name of the provider. */
  humanName?: Maybe<Scalars['String']['output']>;
  /** ID of the object. */
  id: Scalars['ID']['output'];
  /** OpenID Connect issuer URL. */
  issuer: Scalars['String']['output'];
  /** UpstreamOAuth2Links associated with this provider for the current user. */
  upstreamOauth2LinksForUser: Array<UpstreamOAuth2Link>;
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

export type PasswordChange_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, passwordChangeAllowed: boolean } & { ' $fragmentName'?: 'PasswordChange_SiteConfigFragment' };

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


export type EndCompatSessionMutation = { __typename?: 'Mutation', endCompatSession: { __typename?: 'EndCompatSessionPayload', status: EndCompatSessionStatus, compatSession?: { __typename?: 'CompatSession', id: string, finishedAt?: string | null } | null } };

export type Footer_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, imprint?: string | null, tosUri?: string | null, policyUri?: string | null } & { ' $fragmentName'?: 'Footer_SiteConfigFragment' };

export type FooterQueryQueryVariables = Exact<{ [key: string]: never; }>;


export type FooterQueryQuery = { __typename?: 'Query', siteConfig: (
    { __typename?: 'SiteConfig', id: string }
    & { ' $fragmentRefs'?: { 'Footer_SiteConfigFragment': Footer_SiteConfigFragment } }
  ) };

export type OAuth2Session_SessionFragment = { __typename?: 'Oauth2Session', id: string, scope: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, model?: string | null, os?: string | null, deviceType: DeviceType } | null, client: { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, applicationType?: Oauth2ApplicationType | null, logoUri?: string | null } } & { ' $fragmentName'?: 'OAuth2Session_SessionFragment' };

export type EndOAuth2SessionMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type EndOAuth2SessionMutation = { __typename?: 'Mutation', endOauth2Session: { __typename?: 'EndOAuth2SessionPayload', status: EndOAuth2SessionStatus, oauth2Session?: (
      { __typename?: 'Oauth2Session', id: string }
      & { ' $fragmentRefs'?: { 'OAuth2Session_SessionFragment': OAuth2Session_SessionFragment } }
    ) | null } };

export type PasswordCreationDoubleInput_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, minimumPasswordComplexity: number } & { ' $fragmentName'?: 'PasswordCreationDoubleInput_SiteConfigFragment' };

export type BrowserSession_DetailFragment = { __typename?: 'BrowserSession', id: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, model?: string | null, os?: string | null } | null, lastAuthentication?: { __typename?: 'Authentication', id: string, createdAt: string } | null, user: { __typename?: 'User', id: string, username: string } } & { ' $fragmentName'?: 'BrowserSession_DetailFragment' };

export type CompatSession_DetailFragment = { __typename?: 'CompatSession', id: string, createdAt: string, deviceId: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, userAgent?: { __typename?: 'UserAgent', name?: string | null, os?: string | null, model?: string | null } | null, ssoLogin?: { __typename?: 'CompatSsoLogin', id: string, redirectUri: string } | null } & { ' $fragmentName'?: 'CompatSession_DetailFragment' };

export type OAuth2Session_DetailFragment = { __typename?: 'Oauth2Session', id: string, scope: string, createdAt: string, finishedAt?: string | null, lastActiveIp?: string | null, lastActiveAt?: string | null, client: { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, clientUri?: string | null, logoUri?: string | null } } & { ' $fragmentName'?: 'OAuth2Session_DetailFragment' };

export type UnverifiedEmailAlert_UserFragment = { __typename?: 'User', id: string, unverifiedEmails: { __typename?: 'UserEmailConnection', totalCount: number } } & { ' $fragmentName'?: 'UnverifiedEmailAlert_UserFragment' };

export type UpstreamProvider_ProviderFragment = { __typename?: 'UpstreamOAuth2Provider', id: string, createdAt: string, humanName?: string | null, upstreamOauth2LinksForUser: Array<{ __typename?: 'UpstreamOAuth2Link', id: string, provider: { __typename?: 'UpstreamOAuth2Provider', id: string } }> } & { ' $fragmentName'?: 'UpstreamProvider_ProviderFragment' };

export type UserEmail_EmailFragment = { __typename?: 'UserEmail', id: string, email: string, confirmedAt?: string | null } & { ' $fragmentName'?: 'UserEmail_EmailFragment' };

export type UserEmail_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, emailChangeAllowed: boolean } & { ' $fragmentName'?: 'UserEmail_SiteConfigFragment' };

export type RemoveEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type RemoveEmailMutation = { __typename?: 'Mutation', removeEmail: { __typename?: 'RemoveEmailPayload', status: RemoveEmailStatus, user?: { __typename?: 'User', id: string } | null } };

export type SetPrimaryEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type SetPrimaryEmailMutation = { __typename?: 'Mutation', setPrimaryEmail: { __typename?: 'SetPrimaryEmailPayload', status: SetPrimaryEmailStatus, user?: { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null } | null } };

export type UserGreeting_UserFragment = { __typename?: 'User', id: string, matrix: { __typename?: 'MatrixUser', mxid: string, displayName?: string | null } } & { ' $fragmentName'?: 'UserGreeting_UserFragment' };

export type UserGreeting_SiteConfigFragment = { __typename?: 'SiteConfig', id: string, displayNameChangeAllowed: boolean } & { ' $fragmentName'?: 'UserGreeting_SiteConfigFragment' };

export type SetDisplayNameMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
  displayName?: InputMaybe<Scalars['String']['input']>;
}>;


export type SetDisplayNameMutation = { __typename?: 'Mutation', setDisplayName: { __typename?: 'SetDisplayNamePayload', status: SetDisplayNameStatus, user?: { __typename?: 'User', id: string, matrix: { __typename?: 'MatrixUser', displayName?: string | null } } | null } };

export type AddEmailMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
  email: Scalars['String']['input'];
}>;


export type AddEmailMutation = { __typename?: 'Mutation', addEmail: { __typename?: 'AddEmailPayload', status: AddEmailStatus, violations?: Array<string> | null, email?: (
      { __typename?: 'UserEmail', id: string }
      & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
    ) | null } };

export type UpstreamProviderListQueryQueryVariables = Exact<{
  first?: InputMaybe<Scalars['Int']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
}>;


export type UpstreamProviderListQueryQuery = { __typename?: 'Query', upstreamOauth2Providers: { __typename?: 'UpstreamOAuth2ProviderConnection', totalCount: number, edges: Array<{ __typename?: 'UpstreamOAuth2ProviderEdge', cursor: string, node: (
        { __typename?: 'UpstreamOAuth2Provider', id: string, upstreamOauth2LinksForUser: Array<{ __typename?: 'UpstreamOAuth2Link', id: string, provider: { __typename?: 'UpstreamOAuth2Provider', id: string } }> }
        & { ' $fragmentRefs'?: { 'UpstreamProvider_ProviderFragment': UpstreamProvider_ProviderFragment } }
      ) }>, pageInfo: { __typename?: 'PageInfo', hasNextPage: boolean, hasPreviousPage: boolean, startCursor?: string | null, endCursor?: string | null } } };

export type UserEmailListQueryQueryVariables = Exact<{
  userId: Scalars['ID']['input'];
  first?: InputMaybe<Scalars['Int']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  before?: InputMaybe<Scalars['String']['input']>;
}>;


export type UserEmailListQueryQuery = { __typename?: 'Query', user?: { __typename?: 'User', id: string, emails: { __typename?: 'UserEmailConnection', totalCount: number, edges: Array<{ __typename?: 'UserEmailEdge', cursor: string, node: (
          { __typename?: 'UserEmail', id: string }
          & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
        ) }>, pageInfo: { __typename?: 'PageInfo', hasNextPage: boolean, hasPreviousPage: boolean, startCursor?: string | null, endCursor?: string | null } } } | null };

export type UserEmailList_UserFragment = { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null } & { ' $fragmentName'?: 'UserEmailList_UserFragment' };

export type UserEmailList_SiteConfigFragment = (
  { __typename?: 'SiteConfig', id: string }
  & { ' $fragmentRefs'?: { 'UserEmail_SiteConfigFragment': UserEmail_SiteConfigFragment } }
) & { ' $fragmentName'?: 'UserEmailList_SiteConfigFragment' };

export type BrowserSessionsOverview_UserFragment = { __typename?: 'User', id: string, browserSessions: { __typename?: 'BrowserSessionConnection', totalCount: number } } & { ' $fragmentName'?: 'BrowserSessionsOverview_UserFragment' };

export type UserEmail_VerifyEmailFragment = { __typename?: 'UserEmail', id: string, email: string } & { ' $fragmentName'?: 'UserEmail_VerifyEmailFragment' };

export type VerifyEmailMutationVariables = Exact<{
  id: Scalars['ID']['input'];
  code: Scalars['String']['input'];
}>;


export type VerifyEmailMutation = { __typename?: 'Mutation', verifyEmail: { __typename?: 'VerifyEmailPayload', status: VerifyEmailStatus, user?: { __typename?: 'User', id: string, primaryEmail?: { __typename?: 'UserEmail', id: string } | null } | null, email?: (
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

export type UserProfileQueryQueryVariables = Exact<{ [key: string]: never; }>;


export type UserProfileQueryQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous' } | (
    { __typename: 'User', id: string, primaryEmail?: (
      { __typename?: 'UserEmail', id: string }
      & { ' $fragmentRefs'?: { 'UserEmail_EmailFragment': UserEmail_EmailFragment } }
    ) | null }
    & { ' $fragmentRefs'?: { 'UserEmailList_UserFragment': UserEmailList_UserFragment } }
  ), siteConfig: (
    { __typename?: 'SiteConfig', id: string, emailChangeAllowed: boolean, passwordLoginEnabled: boolean }
    & { ' $fragmentRefs'?: { 'UserEmailList_SiteConfigFragment': UserEmailList_SiteConfigFragment;'UserEmail_SiteConfigFragment': UserEmail_SiteConfigFragment;'PasswordChange_SiteConfigFragment': PasswordChange_SiteConfigFragment } }
  ) };

export type SessionDetailQueryQueryVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type SessionDetailQueryQuery = { __typename?: 'Query', viewerSession: { __typename?: 'Anonymous', id: string } | { __typename?: 'BrowserSession', id: string } | { __typename?: 'Oauth2Session', id: string }, node?: { __typename: 'Anonymous', id: string } | { __typename: 'Authentication', id: string } | (
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

export type SessionsOverviewQueryQueryVariables = Exact<{ [key: string]: never; }>;


export type SessionsOverviewQueryQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous' } | (
    { __typename: 'User', id: string }
    & { ' $fragmentRefs'?: { 'BrowserSessionsOverview_UserFragment': BrowserSessionsOverview_UserFragment } }
  ) };

export type AppSessionsListQueryQueryVariables = Exact<{
  before?: InputMaybe<Scalars['String']['input']>;
  after?: InputMaybe<Scalars['String']['input']>;
  first?: InputMaybe<Scalars['Int']['input']>;
  last?: InputMaybe<Scalars['Int']['input']>;
  lastActive?: InputMaybe<DateFilter>;
}>;


export type AppSessionsListQueryQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous' } | { __typename: 'User', id: string, appSessions: { __typename?: 'AppSessionConnection', totalCount: number, edges: Array<{ __typename?: 'AppSessionEdge', cursor: string, node: (
          { __typename: 'CompatSession' }
          & { ' $fragmentRefs'?: { 'CompatSession_SessionFragment': CompatSession_SessionFragment } }
        ) | (
          { __typename: 'Oauth2Session' }
          & { ' $fragmentRefs'?: { 'OAuth2Session_SessionFragment': OAuth2Session_SessionFragment } }
        ) }>, pageInfo: { __typename?: 'PageInfo', startCursor?: string | null, endCursor?: string | null, hasNextPage: boolean, hasPreviousPage: boolean } } } };

export type CurrentUserGreetingQueryVariables = Exact<{ [key: string]: never; }>;


export type CurrentUserGreetingQuery = { __typename?: 'Query', viewerSession: { __typename: 'Anonymous' } | { __typename: 'BrowserSession', id: string, user: (
      { __typename?: 'User', id: string }
      & { ' $fragmentRefs'?: { 'UnverifiedEmailAlert_UserFragment': UnverifiedEmailAlert_UserFragment;'UserGreeting_UserFragment': UserGreeting_UserFragment } }
    ) } | { __typename: 'Oauth2Session' }, siteConfig: (
    { __typename?: 'SiteConfig', id: string }
    & { ' $fragmentRefs'?: { 'UserGreeting_SiteConfigFragment': UserGreeting_SiteConfigFragment } }
  ) };

export type OAuth2ClientQueryQueryVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type OAuth2ClientQueryQuery = { __typename?: 'Query', oauth2Client?: (
    { __typename?: 'Oauth2Client' }
    & { ' $fragmentRefs'?: { 'OAuth2Client_DetailFragment': OAuth2Client_DetailFragment } }
  ) | null };

export type CurrentViewerQueryQueryVariables = Exact<{ [key: string]: never; }>;


export type CurrentViewerQueryQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous', id: string } | { __typename: 'User', id: string } };

export type DeviceRedirectQueryQueryVariables = Exact<{
  deviceId: Scalars['String']['input'];
  userId: Scalars['ID']['input'];
}>;


export type DeviceRedirectQueryQuery = { __typename?: 'Query', session?: { __typename: 'CompatSession', id: string } | { __typename: 'Oauth2Session', id: string } | null };

export type VerifyEmailQueryQueryVariables = Exact<{
  id: Scalars['ID']['input'];
}>;


export type VerifyEmailQueryQuery = { __typename?: 'Query', userEmail?: (
    { __typename?: 'UserEmail' }
    & { ' $fragmentRefs'?: { 'UserEmail_VerifyEmailFragment': UserEmail_VerifyEmailFragment } }
  ) | null };

export type ChangePasswordMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
  oldPassword: Scalars['String']['input'];
  newPassword: Scalars['String']['input'];
}>;


export type ChangePasswordMutation = { __typename?: 'Mutation', setPassword: { __typename?: 'SetPasswordPayload', status: SetPasswordStatus } };

export type PasswordChangeQueryQueryVariables = Exact<{ [key: string]: never; }>;


export type PasswordChangeQueryQuery = { __typename?: 'Query', viewer: { __typename: 'Anonymous', id: string } | { __typename: 'User', id: string }, siteConfig: (
    { __typename?: 'SiteConfig' }
    & { ' $fragmentRefs'?: { 'PasswordCreationDoubleInput_SiteConfigFragment': PasswordCreationDoubleInput_SiteConfigFragment } }
  ) };

export type RecoverPasswordMutationVariables = Exact<{
  ticket: Scalars['String']['input'];
  newPassword: Scalars['String']['input'];
}>;


export type RecoverPasswordMutation = { __typename?: 'Mutation', setPasswordByRecovery: { __typename?: 'SetPasswordPayload', status: SetPasswordStatus } };

export type PasswordRecoveryQueryQueryVariables = Exact<{ [key: string]: never; }>;


export type PasswordRecoveryQueryQuery = { __typename?: 'Query', siteConfig: (
    { __typename?: 'SiteConfig', id: string }
    & { ' $fragmentRefs'?: { 'PasswordCreationDoubleInput_SiteConfigFragment': PasswordCreationDoubleInput_SiteConfigFragment } }
  ) };

export type AllowCrossSigningResetMutationVariables = Exact<{
  userId: Scalars['ID']['input'];
}>;


export type AllowCrossSigningResetMutation = { __typename?: 'Mutation', allowUserCrossSigningReset: { __typename?: 'AllowUserCrossSigningResetPayload', user?: { __typename?: 'User', id: string } | null } };

export const PasswordChange_SiteConfigFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"PasswordChange_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"passwordChangeAllowed"}}]}}]} as unknown as DocumentNode<PasswordChange_SiteConfigFragment, unknown>;
export const BrowserSession_SessionFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"raw"}},{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}}]}}]} as unknown as DocumentNode<BrowserSession_SessionFragment, unknown>;
export const OAuth2Client_DetailFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Client_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Client"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}},{"kind":"Field","name":{"kind":"Name","value":"tosUri"}},{"kind":"Field","name":{"kind":"Name","value":"policyUri"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUris"}}]}}]} as unknown as DocumentNode<OAuth2Client_DetailFragment, unknown>;
export const CompatSession_SessionFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"ssoLogin"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}}]}}]}}]} as unknown as DocumentNode<CompatSession_SessionFragment, unknown>;
export const Footer_SiteConfigFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"Footer_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"imprint"}},{"kind":"Field","name":{"kind":"Name","value":"tosUri"}},{"kind":"Field","name":{"kind":"Name","value":"policyUri"}}]}}]} as unknown as DocumentNode<Footer_SiteConfigFragment, unknown>;
export const OAuth2Session_SessionFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"applicationType"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}}]}}]}}]} as unknown as DocumentNode<OAuth2Session_SessionFragment, unknown>;
export const PasswordCreationDoubleInput_SiteConfigFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"PasswordCreationDoubleInput_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"minimumPasswordComplexity"}}]}}]} as unknown as DocumentNode<PasswordCreationDoubleInput_SiteConfigFragment, unknown>;
export const BrowserSession_DetailFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"os"}}]}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"username"}}]}}]}}]} as unknown as DocumentNode<BrowserSession_DetailFragment, unknown>;
export const CompatSession_DetailFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSession_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}}]}},{"kind":"Field","name":{"kind":"Name","value":"ssoLogin"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}}]}}]}}]} as unknown as DocumentNode<CompatSession_DetailFragment, unknown>;
export const OAuth2Session_DetailFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}}]}}]}}]} as unknown as DocumentNode<OAuth2Session_DetailFragment, unknown>;
export const UnverifiedEmailAlert_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UnverifiedEmailAlert_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","alias":{"kind":"Name","value":"unverifiedEmails"},"name":{"kind":"Name","value":"emails"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"IntValue","value":"0"}},{"kind":"Argument","name":{"kind":"Name","value":"state"},"value":{"kind":"EnumValue","value":"PENDING"}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"totalCount"}}]}}]}}]} as unknown as DocumentNode<UnverifiedEmailAlert_UserFragment, unknown>;
export const UpstreamProvider_ProviderFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UpstreamProvider_provider"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UpstreamOAuth2Provider"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"humanName"}},{"kind":"Field","name":{"kind":"Name","value":"upstreamOauth2LinksForUser"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"provider"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]} as unknown as DocumentNode<UpstreamProvider_ProviderFragment, unknown>;
export const UserEmail_EmailFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_email"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}},{"kind":"Field","name":{"kind":"Name","value":"confirmedAt"}}]}}]} as unknown as DocumentNode<UserEmail_EmailFragment, unknown>;
export const UserGreeting_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserGreeting_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"matrix"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"mxid"}},{"kind":"Field","name":{"kind":"Name","value":"displayName"}}]}}]}}]} as unknown as DocumentNode<UserGreeting_UserFragment, unknown>;
export const UserGreeting_SiteConfigFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserGreeting_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"displayNameChangeAllowed"}}]}}]} as unknown as DocumentNode<UserGreeting_SiteConfigFragment, unknown>;
export const UserEmailList_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmailList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"primaryEmail"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]} as unknown as DocumentNode<UserEmailList_UserFragment, unknown>;
export const UserEmail_SiteConfigFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"emailChangeAllowed"}}]}}]} as unknown as DocumentNode<UserEmail_SiteConfigFragment, unknown>;
export const UserEmailList_SiteConfigFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmailList_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_siteConfig"}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"emailChangeAllowed"}}]}}]} as unknown as DocumentNode<UserEmailList_SiteConfigFragment, unknown>;
export const BrowserSessionsOverview_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSessionsOverview_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"browserSessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"IntValue","value":"0"}},{"kind":"Argument","name":{"kind":"Name","value":"state"},"value":{"kind":"EnumValue","value":"ACTIVE"}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"totalCount"}}]}}]}}]} as unknown as DocumentNode<BrowserSessionsOverview_UserFragment, unknown>;
export const UserEmail_VerifyEmailFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_verifyEmail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}}]}}]} as unknown as DocumentNode<UserEmail_VerifyEmailFragment, unknown>;
export const EndBrowserSessionDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"EndBrowserSession"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"endBrowserSession"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"browserSessionId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"browserSession"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSession_session"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"raw"}},{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}}]}}]} as unknown as DocumentNode<EndBrowserSessionMutation, EndBrowserSessionMutationVariables>;
export const EndCompatSessionDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"EndCompatSession"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"endCompatSession"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"compatSessionId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"compatSession"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}}]}}]}}]}}]} as unknown as DocumentNode<EndCompatSessionMutation, EndCompatSessionMutationVariables>;
export const FooterQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"FooterQuery"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"siteConfig"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"Footer_siteConfig"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"Footer_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"imprint"}},{"kind":"Field","name":{"kind":"Name","value":"tosUri"}},{"kind":"Field","name":{"kind":"Name","value":"policyUri"}}]}}]} as unknown as DocumentNode<FooterQueryQuery, FooterQueryQueryVariables>;
export const EndOAuth2SessionDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"EndOAuth2Session"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"endOauth2Session"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"oauth2SessionId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"oauth2Session"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2Session_session"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"applicationType"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}}]}}]}}]} as unknown as DocumentNode<EndOAuth2SessionMutation, EndOAuth2SessionMutationVariables>;
export const RemoveEmailDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"RemoveEmail"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"removeEmail"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userEmailId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]} as unknown as DocumentNode<RemoveEmailMutation, RemoveEmailMutationVariables>;
export const SetPrimaryEmailDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"SetPrimaryEmail"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"setPrimaryEmail"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userEmailId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"primaryEmail"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]}}]} as unknown as DocumentNode<SetPrimaryEmailMutation, SetPrimaryEmailMutationVariables>;
export const SetDisplayNameDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"SetDisplayName"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"userId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"displayName"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"setDisplayName"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"userId"}}},{"kind":"ObjectField","name":{"kind":"Name","value":"displayName"},"value":{"kind":"Variable","name":{"kind":"Name","value":"displayName"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"matrix"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"displayName"}}]}}]}}]}}]}}]} as unknown as DocumentNode<SetDisplayNameMutation, SetDisplayNameMutationVariables>;
export const AddEmailDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"AddEmail"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"userId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"email"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"addEmail"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"userId"}}},{"kind":"ObjectField","name":{"kind":"Name","value":"email"},"value":{"kind":"Variable","name":{"kind":"Name","value":"email"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"violations"}},{"kind":"Field","name":{"kind":"Name","value":"email"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_email"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_email"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}},{"kind":"Field","name":{"kind":"Name","value":"confirmedAt"}}]}}]} as unknown as DocumentNode<AddEmailMutation, AddEmailMutationVariables>;
export const UpstreamProviderListQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"UpstreamProviderListQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"first"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"after"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"last"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"before"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"upstreamOauth2Providers"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"first"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"after"}}},{"kind":"Argument","name":{"kind":"Name","value":"last"},"value":{"kind":"Variable","name":{"kind":"Name","value":"last"}}},{"kind":"Argument","name":{"kind":"Name","value":"before"},"value":{"kind":"Variable","name":{"kind":"Name","value":"before"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"upstreamOauth2LinksForUser"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"provider"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UpstreamProvider_provider"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"totalCount"}},{"kind":"Field","name":{"kind":"Name","value":"pageInfo"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"hasNextPage"}},{"kind":"Field","name":{"kind":"Name","value":"hasPreviousPage"}},{"kind":"Field","name":{"kind":"Name","value":"startCursor"}},{"kind":"Field","name":{"kind":"Name","value":"endCursor"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UpstreamProvider_provider"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UpstreamOAuth2Provider"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"humanName"}},{"kind":"Field","name":{"kind":"Name","value":"upstreamOauth2LinksForUser"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"provider"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]} as unknown as DocumentNode<UpstreamProviderListQueryQuery, UpstreamProviderListQueryQueryVariables>;
export const UserEmailListQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"UserEmailListQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"userId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"first"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"after"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"last"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"before"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"user"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"id"},"value":{"kind":"Variable","name":{"kind":"Name","value":"userId"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"emails"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"first"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"after"}}},{"kind":"Argument","name":{"kind":"Name","value":"last"},"value":{"kind":"Variable","name":{"kind":"Name","value":"last"}}},{"kind":"Argument","name":{"kind":"Name","value":"before"},"value":{"kind":"Variable","name":{"kind":"Name","value":"before"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_email"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"totalCount"}},{"kind":"Field","name":{"kind":"Name","value":"pageInfo"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"hasNextPage"}},{"kind":"Field","name":{"kind":"Name","value":"hasPreviousPage"}},{"kind":"Field","name":{"kind":"Name","value":"startCursor"}},{"kind":"Field","name":{"kind":"Name","value":"endCursor"}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_email"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}},{"kind":"Field","name":{"kind":"Name","value":"confirmedAt"}}]}}]} as unknown as DocumentNode<UserEmailListQueryQuery, UserEmailListQueryQueryVariables>;
export const VerifyEmailDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"VerifyEmail"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"code"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"verifyEmail"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userEmailId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}},{"kind":"ObjectField","name":{"kind":"Name","value":"code"},"value":{"kind":"Variable","name":{"kind":"Name","value":"code"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"primaryEmail"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"email"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_email"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_email"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}},{"kind":"Field","name":{"kind":"Name","value":"confirmedAt"}}]}}]} as unknown as DocumentNode<VerifyEmailMutation, VerifyEmailMutationVariables>;
export const ResendVerificationEmailDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"ResendVerificationEmail"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"sendVerificationEmail"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userEmailId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"primaryEmail"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"email"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_email"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_email"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}},{"kind":"Field","name":{"kind":"Name","value":"confirmedAt"}}]}}]} as unknown as DocumentNode<ResendVerificationEmailMutation, ResendVerificationEmailMutationVariables>;
export const UserProfileQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"UserProfileQuery"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewer"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"primaryEmail"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_email"}}]}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmailList_user"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"siteConfig"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"emailChangeAllowed"}},{"kind":"Field","name":{"kind":"Name","value":"passwordLoginEnabled"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmailList_siteConfig"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_siteConfig"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"PasswordChange_siteConfig"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"emailChangeAllowed"}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_email"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}},{"kind":"Field","name":{"kind":"Name","value":"confirmedAt"}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmailList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"primaryEmail"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmailList_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_siteConfig"}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"PasswordChange_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"passwordChangeAllowed"}}]}}]} as unknown as DocumentNode<UserProfileQueryQuery, UserProfileQueryQueryVariables>;
export const SessionDetailQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"SessionDetailQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewerSession"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Node"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"node"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"id"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"CompatSession_detail"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2Session_detail"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSession_detail"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSession_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}}]}},{"kind":"Field","name":{"kind":"Name","value":"ssoLogin"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"os"}}]}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"username"}}]}}]}}]} as unknown as DocumentNode<SessionDetailQueryQuery, SessionDetailQueryQueryVariables>;
export const BrowserSessionListDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"BrowserSessionList"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"first"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"after"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"last"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"before"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"lastActive"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"DateFilter"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewerSession"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"browserSessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"first"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"after"}}},{"kind":"Argument","name":{"kind":"Name","value":"last"},"value":{"kind":"Variable","name":{"kind":"Name","value":"last"}}},{"kind":"Argument","name":{"kind":"Name","value":"before"},"value":{"kind":"Variable","name":{"kind":"Name","value":"before"}}},{"kind":"Argument","name":{"kind":"Name","value":"lastActive"},"value":{"kind":"Variable","name":{"kind":"Name","value":"lastActive"}}},{"kind":"Argument","name":{"kind":"Name","value":"state"},"value":{"kind":"EnumValue","value":"ACTIVE"}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"totalCount"}},{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSession_session"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"pageInfo"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"hasNextPage"}},{"kind":"Field","name":{"kind":"Name","value":"hasPreviousPage"}},{"kind":"Field","name":{"kind":"Name","value":"startCursor"}},{"kind":"Field","name":{"kind":"Name","value":"endCursor"}}]}}]}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"raw"}},{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}}]}}]} as unknown as DocumentNode<BrowserSessionListQuery, BrowserSessionListQueryVariables>;
export const SessionsOverviewQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"SessionsOverviewQuery"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewer"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSessionsOverview_user"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSessionsOverview_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"browserSessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"IntValue","value":"0"}},{"kind":"Argument","name":{"kind":"Name","value":"state"},"value":{"kind":"EnumValue","value":"ACTIVE"}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"totalCount"}}]}}]}}]} as unknown as DocumentNode<SessionsOverviewQueryQuery, SessionsOverviewQueryQueryVariables>;
export const AppSessionsListQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"AppSessionsListQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"before"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"after"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"first"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"last"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"lastActive"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"DateFilter"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewer"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"appSessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"before"},"value":{"kind":"Variable","name":{"kind":"Name","value":"before"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"after"}}},{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"first"}}},{"kind":"Argument","name":{"kind":"Name","value":"last"},"value":{"kind":"Variable","name":{"kind":"Name","value":"last"}}},{"kind":"Argument","name":{"kind":"Name","value":"lastActive"},"value":{"kind":"Variable","name":{"kind":"Name","value":"lastActive"}}},{"kind":"Argument","name":{"kind":"Name","value":"state"},"value":{"kind":"EnumValue","value":"ACTIVE"}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"CompatSession_session"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2Session_session"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"totalCount"}},{"kind":"Field","name":{"kind":"Name","value":"pageInfo"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"startCursor"}},{"kind":"Field","name":{"kind":"Name","value":"endCursor"}},{"kind":"Field","name":{"kind":"Name","value":"hasNextPage"}},{"kind":"Field","name":{"kind":"Name","value":"hasPreviousPage"}}]}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"ssoLogin"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveIp"}},{"kind":"Field","name":{"kind":"Name","value":"lastActiveAt"}},{"kind":"Field","name":{"kind":"Name","value":"userAgent"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"name"}},{"kind":"Field","name":{"kind":"Name","value":"model"}},{"kind":"Field","name":{"kind":"Name","value":"os"}},{"kind":"Field","name":{"kind":"Name","value":"deviceType"}}]}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"applicationType"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}}]}}]}}]} as unknown as DocumentNode<AppSessionsListQueryQuery, AppSessionsListQueryQueryVariables>;
export const CurrentUserGreetingDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"CurrentUserGreeting"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewerSession"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UnverifiedEmailAlert_user"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserGreeting_user"}}]}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"siteConfig"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserGreeting_siteConfig"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UnverifiedEmailAlert_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","alias":{"kind":"Name","value":"unverifiedEmails"},"name":{"kind":"Name","value":"emails"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"IntValue","value":"0"}},{"kind":"Argument","name":{"kind":"Name","value":"state"},"value":{"kind":"EnumValue","value":"PENDING"}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"totalCount"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserGreeting_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"matrix"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"mxid"}},{"kind":"Field","name":{"kind":"Name","value":"displayName"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserGreeting_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"displayNameChangeAllowed"}}]}}]} as unknown as DocumentNode<CurrentUserGreetingQuery, CurrentUserGreetingQueryVariables>;
export const OAuth2ClientQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"OAuth2ClientQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"oauth2Client"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"id"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2Client_detail"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Client_detail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Client"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}},{"kind":"Field","name":{"kind":"Name","value":"logoUri"}},{"kind":"Field","name":{"kind":"Name","value":"tosUri"}},{"kind":"Field","name":{"kind":"Name","value":"policyUri"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUris"}}]}}]} as unknown as DocumentNode<OAuth2ClientQueryQuery, OAuth2ClientQueryQueryVariables>;
export const CurrentViewerQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"CurrentViewerQuery"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewer"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Node"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]} as unknown as DocumentNode<CurrentViewerQueryQuery, CurrentViewerQueryQueryVariables>;
export const DeviceRedirectQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"DeviceRedirectQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"deviceId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"userId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"session"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"deviceId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"deviceId"}}},{"kind":"Argument","name":{"kind":"Name","value":"userId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"userId"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Node"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]} as unknown as DocumentNode<DeviceRedirectQueryQuery, DeviceRedirectQueryQueryVariables>;
export const VerifyEmailQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"VerifyEmailQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"userEmail"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"id"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"FragmentSpread","name":{"kind":"Name","value":"UserEmail_verifyEmail"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserEmail_verifyEmail"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"UserEmail"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"email"}}]}}]} as unknown as DocumentNode<VerifyEmailQueryQuery, VerifyEmailQueryQueryVariables>;
export const ChangePasswordDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"ChangePassword"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"userId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"oldPassword"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"newPassword"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"setPassword"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"userId"}}},{"kind":"ObjectField","name":{"kind":"Name","value":"currentPassword"},"value":{"kind":"Variable","name":{"kind":"Name","value":"oldPassword"}}},{"kind":"ObjectField","name":{"kind":"Name","value":"newPassword"},"value":{"kind":"Variable","name":{"kind":"Name","value":"newPassword"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}}]}}]}}]} as unknown as DocumentNode<ChangePasswordMutation, ChangePasswordMutationVariables>;
export const PasswordChangeQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"PasswordChangeQuery"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"viewer"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"__typename"}},{"kind":"InlineFragment","typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Node"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}},{"kind":"Field","name":{"kind":"Name","value":"siteConfig"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"FragmentSpread","name":{"kind":"Name","value":"PasswordCreationDoubleInput_siteConfig"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"PasswordCreationDoubleInput_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"minimumPasswordComplexity"}}]}}]} as unknown as DocumentNode<PasswordChangeQueryQuery, PasswordChangeQueryQueryVariables>;
export const RecoverPasswordDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"RecoverPassword"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"ticket"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"newPassword"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"setPasswordByRecovery"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"ticket"},"value":{"kind":"Variable","name":{"kind":"Name","value":"ticket"}}},{"kind":"ObjectField","name":{"kind":"Name","value":"newPassword"},"value":{"kind":"Variable","name":{"kind":"Name","value":"newPassword"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"status"}}]}}]}}]} as unknown as DocumentNode<RecoverPasswordMutation, RecoverPasswordMutationVariables>;
export const PasswordRecoveryQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"PasswordRecoveryQuery"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"siteConfig"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"PasswordCreationDoubleInput_siteConfig"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"PasswordCreationDoubleInput_siteConfig"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"SiteConfig"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"minimumPasswordComplexity"}}]}}]} as unknown as DocumentNode<PasswordRecoveryQueryQuery, PasswordRecoveryQueryQueryVariables>;
export const AllowCrossSigningResetDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"mutation","name":{"kind":"Name","value":"AllowCrossSigningReset"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"userId"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"allowUserCrossSigningReset"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"input"},"value":{"kind":"ObjectValue","fields":[{"kind":"ObjectField","name":{"kind":"Name","value":"userId"},"value":{"kind":"Variable","name":{"kind":"Name","value":"userId"}}}]}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}}]}}]}}]}}]} as unknown as DocumentNode<AllowCrossSigningResetMutation, AllowCrossSigningResetMutationVariables>;