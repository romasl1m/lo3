# Deployment
# Olek is a vibecoder, me not so
Vercel serves this app through a Node.js reverse-proxy function. The C++ Crow server and its SQLite database must run separately as a persistent Docker web service; Vercel functions cannot keep this server or a local SQLite database alive. The included `render.yaml` deploys that backend to Render with a persistent disk.

## Deploy the backend

1. Push this repository to GitHub and create a Render Blueprint from it. Render uses `render.yaml` to build and run the C++ service with a persistent disk mounted at `/var/data`.
2. After the service is live, initialize its accounts once from the Render Shell:

   ```sh
   SEED_PASSWORD='choose-a-strong-password' bash ./createusers.sh
   ```

   This creates the generated user codes from `createusers.sh`; `3A17` and `3A35` are administrators. All generated accounts initially share the supplied password. Users can change it after signing in.
3. Keep the Render disk attached. The database is `/var/data/events.db`; removing the disk removes user, event, and registration data.

## Deploy the Vercel front door

1. Import the same GitHub repository into Vercel. The included `vercel.json` routes the app's pages and static assets through its proxy functions.
2. In the Vercel project settings, add `APP_ORIGIN` with the public origin of the Render service, for example `https://event-registration.onrender.com`. Do not include a path. Redeploy after setting it.
3. Use the Vercel deployment URL as the app URL. The Render service remains the backend and can also be reached directly through its Render URL.

For local Docker use, the C++ app defaults to port `8080` and `events.db`. Set `PORT` or `DATABASE_PATH` to override those defaults.
