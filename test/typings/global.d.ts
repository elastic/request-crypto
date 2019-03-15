declare module "*.json";
declare var expect: any;

declare namespace NodeJS {
  interface Global {
    expect: any
  }
}
