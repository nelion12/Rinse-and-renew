# Rinse & Renew

A service-booking and item-tracking prototype for laundry, carpet, shoe, and garment care.

## Run locally

Requires Node.js 22.13 or later (uses the built-in `node:sqlite` module). No npm packages are required.

```sh
node server.mjs
```

Open <http://127.0.0.1:3000>. SQLite data is stored in `data/rinse-renew.sqlite` and is ignored by Git.

## Customer flow

- Register or sign in with an email and password.
- Request a pickup for one of the listed services.
- Describe items one per line. To add a condition note, separate it from the item description with an em dash, en dash, or vertical bar. Example: `White sneakers — light scuffing on the toes`.
- View pickup requests, status, and item condition notes under **My account**.

## Staff access

Create an account through the site first, stop the server, then run:

```sh
node server.mjs promote-staff staff@example.com
```

The staff order update endpoint is `PATCH /api/staff/orders/:orderId`. It accepts an optional `status` and/or an `item_conditions` array containing `{ "id": "item-id", "intake_condition": "Condition observed at check-in" }` objects. Restart the server after promotion.

## API routes

- `GET /api/health`
- `POST /api/auth/register` — `{ "name", "email", "password" }`
- `POST /api/auth/login` — `{ "email", "password" }`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `POST /api/orders` — `{ "service", "pickup_date", "pickup_area", "items" }`
- `GET /api/orders`
- `PATCH /api/staff/orders/:orderId`

This starter accepts booking requests but does not charge customers. Payment processing, deployment, backups, and SMS/email notifications still need to be configured before launch.

