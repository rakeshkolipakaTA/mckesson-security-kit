# Node scanner: npm (for `npm audit`) + ESLint with security plugins.
# The ESLint config is mounted at run time (configs/eslint/eslint.config.mjs or a project override) so plugin
# resolution works from /opt/eslint/node_modules.
FROM node:22-alpine
WORKDIR /opt/eslint
COPY package.json ./
RUN npm install --ignore-scripts --no-audit --no-fund && npm cache clean --force
ENV HOME=/tmp NPM_CONFIG_UPDATE_NOTIFIER=false PATH=/opt/eslint/node_modules/.bin:$PATH
WORKDIR /src
