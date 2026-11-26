![Siftkeep](assets/siftkeep-logo.png)

Siftkeep checks what goes into your public web build and guards sensitive operations on your server. Use it to catch source maps before deployment or require fresh user approval before a private data export.

## Check a web build

From the Siftkeep checkout, install dependencies with Node.js 24 or later:

```sh
npm ci
npm run siftkeep -- audit ../my-app/dist
```

Replace `../my-app/dist` with your app’s finished build directory. The audit prints findings as JSON and exits with code 1 when it finds an issue, so you can use it in CI.

To prepare a deployment copy:

```sh
npm run siftkeep -- harden ../my-app/dist
```

Siftkeep writes a new directory beside the original, omits external source maps, and prints the output path. Embedded map markers, development source files, and private inputs such as `.env` block staging. JavaScript delivered to a browser remains readable.

## Guard a private operation

Build the middleware with `npm run build`. In an Express app, mount the shield after authentication and input validation:

```ts
import { createCoreShield } from './dist/index.js';

app.post('/api/export', createCoreShield({
  resolvePrincipal: resolveVerifiedPrincipal,
  authorize: canExportRequestedData,
  consumeUserVerification: consumeExportApproval,
}), exportPrivateData);
```

Your app supplies the three callbacks. Resolve the session from trusted server state, check permission for the requested export, and consume a one-time approval bound to that session and action. The export handler runs only after all three checks pass.

## Examples

- **Monitor repeated reads.** Run `npm run demo`, then `npm run simulate` in a second terminal. The demo logs a suspected extraction event. [Demo server](examples/server.ts)
- **Find possible copies.** Add a project fingerprint to your HTML and search indexed GitHub code for matches to review. [Example GitHub workflow](examples/github-clone-watch.yml)

## Upgrading from Ultron

Use `npm run siftkeep`, import `Siftkeep`, and use the `SIFTKEEP_` prefix for settings. The previous CLI, class export, environment variables and webhook headers remain supported. Keep your existing project ID and secret to continue finding previously deployed fingerprints.
