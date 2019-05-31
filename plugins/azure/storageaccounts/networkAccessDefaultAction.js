const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
  title: 'Network Access Default Action',
  category: 'Storage Accounts',
  description: 'Ensure that Storage Account access is restricted to trusted networks.',
  more_info: 'Storage Accounts should be configured to accept traffic only from trusted networks. By default, all networks are selected but can be changed when creating a new storage account or in firewall settings.',
  recommended_action: 'Go to your Storage Account, select "Firewalls and virtual networks", ensure that allow access from all networks is not selected.',
  link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security',
  apis: ['storageAccounts:list'],

  run: function (cache, settings, callback) {
    const results = [];
    const source = {};
    const locations = helpers.locations(settings.govcloud);

    async.each(locations.storageAccounts, function (location, rcb) {
      const storageAccount = helpers.addSource(cache, source,
        ['storageAccounts', 'list', location]
      );

      if(!storageAccount) return rcb();

      if (storageAccount.err || !storageAccount.data) {
        helpers.addResult(results, 3,
          'Unable to query Storage Accounts: ' + helpers.addError(storageAccount),
          location
        );
        return rcb();
      }

      if (!storageAccount.data.length) {
        helpers.addResult(results, 0, 'No storage accounts found', location);
        return rcb();
      }

      for (acct in storageAccount.data) {
        const account = storageAccount.data[acct];

        if (account.networkRuleSet &&
            account.networkRuleSet.defaultAction &&
            account.networkRuleSet.defaultAction.toLowerCase() === 'deny') {
          helpers.addResult(results, 0, 'Storage Account default network access rule set to deny', location, account.id);
        } else {
          helpers.addResult(results, 2, 'Storage Account default network access rule set to allow from all networks', location, account.id);
        }
      }

      rcb();
    }, function () {
      // Global checking goes here
      callback(null, results, source);
    });
  }
};
