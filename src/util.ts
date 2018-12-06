export
function checkCompatiblity(): void {
  if(+process.version.match(/v(\d{1,2}.\d{1,2}).\d{1,2}/)![1] < 10.12) {
    throw Error('Node.js version must be above v10.12 to run this command.');
  }
}