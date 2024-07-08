# MegaAuth

Welcome to **MegaAuth**. The authentication and authorization service that validates and verifies the access of the users to the **Mega** ecosystem of applications and services.

Just the auth microservice inside the **Mega** architecture.

## See more

- [MegaProxy](https://github.com/MegaGera/MegaProxy): Proxy of the MegaGera ecosystem
- [MegaGoal](https://github.com/MegaGera/MegaGoal): Application for storing football matches viewed
- MegaDocu: Own documentation application built with [Docusaurus](https://docusaurus.io/)
- [MegaHome](https://github.com/MegaGera/MegaHome): Main home portal application for redirect between services and applications

## Production

Already running in production in [https://megaauth.megagera.com](https://megaauth.megagera.com).

To try it or know more about it just message me and I will give you access!

## Project info

[Node.js](https://nodejs.org/en) authentication and authorization service using [Express.js](https://expressjs.com/) for create an API.

Storing user information in a local database using [db-local](https://www.npmjs.com/package/db-local). Passwords stored using [bcrypt](https://www.npmjs.com/package/bcrypt).

User information stored in a protected Cookie using [jwt](https://jwt.io/).

Handle permissions for the users for the different services of the **Mega** ecosystem.

Frontend views developed with [ejs](https://ejs.co/) javascript templates.

All the microservices are running with docker.

Based on the tutorial of [@midudev](https://github.com/midudev): [Autenticación de Usuario, Sesión, Cookies y JWT con Node.js](https://www.youtube.com/watch?v=UqnnhAZxRac).