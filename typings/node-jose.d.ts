declare module 'node-jose' {
  interface untyped { [x: string]: any }
  export interface JWK extends untyped {}
  export interface JWE extends untyped {}
  export interface JWKS extends untyped {}
  export interface Util extends untyped {}

  export const JWK : JWK
  export const JWE : JWE
  export const util : Util
}