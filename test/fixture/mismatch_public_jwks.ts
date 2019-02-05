import { SignedPublicJWKS } from '../../src/index';

export const mismatchPublicJWKS: SignedPublicJWKS = {
  keys: [
    {
      kty: 'RSA',
      kid: 'KIBANA_7.0',
      use: 'enc',
      alg: 'RSA-OAEP',
      e: 'AQAB',
      n:
        'vyIzsTq1h4QqjvdKyYj-TSllzFsziRiCCCaekfw27ZCpgHqwtZjq9XjHGnyqvFu7FOxYpqQhrqIsGjmHmaB12GKBoE9fLiGz4OCko-m95vOUbaZ8aBx0JZZ0Fd2IaU3hGG9dc--n1YQ8cONkzogNXt7GCIWJhN9V0LBHpex3c3k',
      cnf:
        'eyJ6aXAiOiJERUYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAiLCJraWQiOiJFTlNmMndSRVhVVkM3OEgySk1fcDkxRWNZVWJCWTJ3QjZGVW92Q0pDVlJJIn0.Sy3j2gbqmVjLXnv8_4CSiKSZqwHnGMdkviZBRUesh058A1MgVZRoZyDaR7QSTRSGYilaYonLnudJQZ6X2DE8zNcdpH_eWTSU5olrr2izMKqr92EV4rNSOBNliYQAGAWB3UonoYJyiUVx0AFnHzxj0rbl86iz2ZTDlVAcGRuVVbs.FYkMyrY51VARUqC1CC26Qg.KknWxyyYGxw_dyw51u9rg6knpH5cKGVnAwdyMmoSzE3fO2XxFs-ku2JuQgzCxKJV.pdm5Z9GqyPBwPHcjZuKWTw',
    },
  ],
};
