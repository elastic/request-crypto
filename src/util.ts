export function checkNodeCompatiblity(targetMajorMinor: number): void {
  if (+process.version.match(/v(\d{1,2}.\d{1,2}).\d{1,2}/)![1] < targetMajorMinor) {
    throw Error(`Node.js version must be v${targetMajorMinor} or newer to run this command.`);
  }
}
