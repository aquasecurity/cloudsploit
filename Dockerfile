FROM node:lts-alpine3.22

# Define a build argment that can be supplied when building the container
# You can then do the following:
#
# docker build --build-arg PACKAGENAME=@myscope/cloudsploit
#
# This allows a fork to build their own container from this common Dockerfile.
# You could also use this to specify a particular version number.
ARG PACKAGENAME=cloudsploit

# Create a non-root user and group
RUN addgroup -S cloudsploit && adduser -S cloudsploit -G cloudsploit

COPY . /var/scan/cloudsploit/

# Set the working directory to /var/scan
WORKDIR /var/scan

# Install cloudsploit/scan into the container using npm from NPM
RUN npm init --yes \
&& npm install ${PACKAGENAME} \
&& npm link /var/scan/cloudsploit \
&& chown -R cloudsploit:cloudsploit /var/scan

# Setup the container's path so that you can run cloudsploit directly
# in case someone wants to customize it when running the container.
ENV PATH "$PATH:/var/scan/node_modules/.bin"

# Switch to non-root user
USER cloudsploit

# By default, run the scan. CMD allows consumers of the container to supply
# command line arguments to the run command to control how this executes.
# Thus, you can use the parameters that you would normally give to index.js
# when running in a container.
ENTRYPOINT ["cloudsploit-scan"]
CMD []
