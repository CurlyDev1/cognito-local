import {
  InvalidParameterError,
  NotAuthorizedError,
  NotImplementedError,
} from "../errors";
import { Services } from "../services";
import { Context } from "../services/context";
import { Target } from "../targets/Target";

type HandleTokenServices = Pick<Services, "cognito" | "tokenGenerator">;

type GetTokenRequest = URLSearchParams;

interface GetTokenResponse {
  access_token: string;
  refresh_token?: string;
}

export type GetTokenTarget = Target<GetTokenRequest, GetTokenResponse>;

async function getWithRefreshToken(
  ctx: Context,
  services: HandleTokenServices,
  params: GetTokenRequest
) {
  const clientId = params.get("client_id");
  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    clientId as string
  );
  const userPoolClient = await services.cognito.getAppClient(
    ctx,
    clientId as string
  );
  const user = await userPool.getUserByRefreshToken(
    ctx,
    params.get("refresh_token") as string
  );
  if (!user || !userPoolClient) {
    throw new NotAuthorizedError();
  }

  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    undefined,
    "RefreshTokens"
  );

  return {
    access_token: tokens.AccessToken,
    refresh_token: tokens.RefreshToken,
  };
}

async function getWithClientCredentials(
  ctx: Context,
  services: HandleTokenServices,
  params: GetTokenRequest
) {
  const clientId = params.get("client_id");
  const clientSecret = params.get("client_secret");
  const userPoolClient = await services.cognito.getAppClient(
    ctx,
    clientId as string
  );
  if (!userPoolClient) {
    throw new NotAuthorizedError();
  }
  if (
    userPoolClient.ClientSecret &&
    userPoolClient.ClientSecret != clientSecret
  ) {
    throw new NotAuthorizedError();
  }

  const tokens = await services.tokenGenerator.generateWithClientCreds(
    ctx,
    userPoolClient
  );
  if (!tokens) {
    throw new NotAuthorizedError();
  }

  return {
    access_token: tokens.AccessToken,
  };
}

export const GetToken =
  (services: HandleTokenServices): GetTokenTarget =>
  async (ctx, req) => {
    const params = new URLSearchParams(req);
    switch (params.get("grant_type")) {
      case "authorization_code": {
        throw new NotImplementedError();
      }
      case "client_credentials": {
        return getWithClientCredentials(ctx, services, params);
      }
      case "refresh_token": {
        return getWithRefreshToken(ctx, services, params);
      }
      default: {
        console.log("Invalid grant type passed:", params.get("grant_type"));
        throw new InvalidParameterError();
      }
    }
  };
