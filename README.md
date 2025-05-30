# Hathr Backend

Hathr is a spotify application that curates monthly playlists based on your listening history.

## Getting Started

Copy the `.env.template` to your own file with and fill in the values.

```sh
cp .env.template .env
```

Next, run the application:

```sh
make run
```

Next, generate a private and public key for JWT authentication

```sh
openssl genrsa -out hathr_key.pem 2048
openssl rsa -in hathr_key.pem -outform PEM -pubout -out hathr_key.pem.pub
```

Then convert the public key to a JWK through this [JWK Generator](https://russelldavies.github.io/jwk-creator/). The public key use is "Signing", Algorithm is "RS256", and the initial key ID is 1.

Create a `jwks.json` file in the root directory and paste the JWK into it. The file should look like this:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "<your_n_value>",
      "e": "<your_e_value>",
      "alg": "RS256",
      "kid": "1",
      "use": "sig"
    }
  ]
}
```

Next, insert the private key into the database. Enter the Postgres database:

```sh
psql postgresql://<username>:<password>@localhost:5432/hathr
```

Then run the following SQL command:

```sql
INSERT INTO private_keys (value) VALUES ('<your_private_key>');
```
