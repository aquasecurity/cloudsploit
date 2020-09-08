# GitHub CloudSploit Scans

## Background

CloudSploit provides GitHub account security auditing capabilities. CloudSploit uses the GitHub APIs to obtain metadata about the GitHub account (number of repositories, configuration, security settings, etc.) which is then used to evaluate alignment with security best practices.

## Getting Started

To use the GitHub scans, you need a GitHub personal access token for an organization owner with read-only access. You can read more about the permission model below. Follow these steps:

1. Log into your GitHub organization account as an owner
2. Create a new machine (generic) user for the CloudSploit service (depending on your organization's configuration, you may need to impersonate this user to get access to its settings page). **NOTE**: You can optionally use an existing organization owner for this token, but we strongly recommend creating a new user.
3. Ensure the user is added as an owner of the Git organization.
4. Log into GitHub as this user.
5. Navigate to "Settings" > "Developer Settings" > "Personal Access Tokens"
6. Click "Generate new token" and give it a description.
7. Check the following permissions:

- [ ] repo
	- [x] repo:status
	- [x] repo_deployment
	- [ ] public_repo
	- [ ] repo:invite
- [ ] admin:org
	- [ ] write:org
	- [x] read:org
- [ ] admin:public_key
	- [ ] write:public_key
	- [x] read:public_key
- [ ] admin:repo_hook
	- [ ] write:repo_hook
	- [x] read:repo_hook
- [ ] admin:org_hook
- [ ] gist
- [ ] notifications
- [ ] user
	- [x] read:user
	- [x] user:email
	- [ ] user:follow
- [ ] delete_repo
- [ ] write:discussion
	- [ ] read:discussion
- [ ] admin:business
	- [ ] manage_billing:business
	- [x] read:business
- [ ] admin:gpg_key
	- [ ] write:gpg_key
	- [x] read:gpg_key

8. Save the permissions to obtain a token. Copy this token for use with CloudSploit.

```
GITHUB_ORG=<org name> GITHUB_TOKEN=<paste token> node index.js
```

## Permission Model

GitHub has a number of ways to provide access to its APIs, each with different levels of access. These include: third-party OAuth applications, GitHub applications, and personal access tokens.

CloudSploit requires personal access tokens because many of the APIs it invokes are not exposed to OAuth and GitHub applications. These applications were designed to provide functionality around creating repositories, issues, checks, pull requests, etc., and were not designed for use as auditing tools.

CloudSploit recommends creating a machine user (also called a generic user in some organizations) for the auditing service. This user must be added as an organization owner (required to have visibility into all repositories and settings). However, a read-only access key can be created for it to limit the scope in which it operates.


## Developing New Plugins

CloudSploit GitHub scans contain two main pieces: 1) a collector that queries the GitHub APIs for information and 2) an executor which uses that information in "plugins" to evaluate security best practice adherence. To add new plugins follow the below steps.

All code changes can be found in `collectors/github/collector.js` or as a plugin inside `plugins/github`.

### Using Octokit

CloudSploit uses [Octokit](https://octokit.github.io/rest.js), which is a Node.js module for making GitHub API calls.

### Determine the API Calls Needed for Your Plugin

The source data required for the plugin will be different depending on the information being evaluated. For example, if you would like to make a plugin that checks that an organization does not have too many admins, you will need the following APIs: `orgs:listMembers` and `orgs:getMembership`. The former API call returns a list of all members of the organization, while the latter call returns the membership type for each user.

### Evaluate API Call Order

CloudSploit supports both `calls` and `postcalls` in the collector. `calls` defined API calls that can be made at any time; in other words, the order does not matter. `postcalls` are API calls that must be made after a previous call is made because it relies on some information within that dependent call.

In our org admins example, the `orgs:listMembers` API call returns a list of all members of an organization:

```
"listMembers": {
  "data": [
    {
      "login": "userone",
      "id": 123456,
      ...
    },
    {
      "login": "usertwo",
      "id": 123576,
      ...
    }
  ]
}
```

From this list, we must now iterate over each member and call the `orgs:getMembership` API call, passing `username` as an argument. To do this, we define the postcall as such:

```
var postcalls = [
	{
		orgs: {
			getMembership: {
				type: 'token',
				inject_org: true,
				reliesOnService: 'orgs',
				reliesOnCall: 'listMembers',
				filterKey: 'username',
				filterValue: 'login'
			}
		}
	}
];
```

This definition tells the collector to wait on the `orgs:listMembers` API call before making this call (`reliesOnService` and `reliesOnCall`). Then, it instructs the collector to iterate through each of the members returned from the first call, using the `login` property (`filterValue`) as a source argument to the `username` (`filterKey`) passed into the subsequent `orgs:getMembership` API call.

This returns the following data:

```
"getMembership": {
  "userone": {
    "data": {
      "url": "https://api.github.com/orgs/myorg/memberships/userone",
      "state": "active",
      "role": "admin",
      ...
    }
  },
  "usertwo": {
    "data": {
      "url": "https://api.github.com/orgs/myorg/memberships/usertwo",
      "state": "active",
      "role": "admin",
      ...
    }
  }
}
```

### Create a Plugin

Once the API data is in order, create a new plugin by creating a file inside of `plugins/github/{service}`. The file must look like:

```
var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
	title: 'Org Excessive Admins',
	org: true,
	category: 'Orgs',
	description: 'Checks that the org does not have too many admins.',
	more_info: 'Having too many admins places the organization at risk.',
	link: 'https://developer.github.com/v3/orgs/#get-an-organization',
	recommended_action: 'Remove unused or unneeded admins.',
	apis: ['orgs:listMembers', 'orgs:getMembership'],

	run: function(cache, settings, callback) {
		// Plugin functionality

		callback(null, results, source);
	}
};

```

Note the following important pieces:

1. The plugin title, category, description, link, and recommended action.
2. The plugin `apis` which list the API calls necessary to obtain the data needed for this plugin to work. In this case, we pass in both `orgs:listMembers` and `orgs:getMembership`.
3. The `run` function which defines the logic of the plugin, returning a callback with results and the original source.

For more examples of the logic contained within the plugin, view the working examples in `plugins/github`.

### Export the Plugin

For the plugin to run, you must export it in the `exports.js` file (add it in the `github` section).
