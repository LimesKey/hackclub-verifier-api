# onboard-verifier

This program runs as a Cloudflare Wrangler worker at https://ysws.limeskey.com. The inital domain redirects to a special Slack Auth link which has my custom bot's Client ID and scopes. Then, after completing a successful Slack Auth, it redirects to https://verify.limeskey.com which takes all this information and does some movie magic to derive the user's Slack ID, Username, and eligiblity status according to the YSWS Unifed Verification Airtable database. Finally, I add I append this data as a URL parameter for the fillout form.

# Dependencies
### PNPM
    `pnpm install`

# Build

### Wrangler Dev
    `pnpm wrangler deploy`


