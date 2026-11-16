import fs from 'node:fs';
import path from 'node:path';

// Read at runtime so `--version` and the MCP server always report the
// published package version. dist/ sits next to package.json.
export const VERSION: string = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')
).version;
