import {OAuth2Client} from '@google/oauth2';

const client = new OAuth2Client({
  clientId: "870291072299-m50nfpmvp1ich1gmkmt09ggull0gh5ud.apps.googleusercontent.com",
  redirectUri: "http://localhost:3000/oauth2callback"
});

const authorizeUrl = client.generateAuthUrl({
  access_type: 'offline',
  scope: 'https://www.googleapis.com/auth/plus.me'
});

console.log(authorizeUrl);
