# Deployment (SR-19, SR-20)

This folder will hold the Workstream E deployment:

- Docker Compose deployment with isolated compartments and networks
- Least-privilege database roles
- Setup scripts for secrets, test certificates, backups and restore

Generated secrets go in `deploy/secrets/`, which is git-ignored.
Never commit real secrets, passwords or keys.
