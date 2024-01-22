const expect = require('chai').expect;
const advancedThreatProtectionNotificationEnabled = require('./enableATPNotification');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const securityContactsEnabled = {
    "data": [
        {
            "alertNotifications": {
                "state": "On"
            }
        }
    ]
};

const securityContactsDisabled = {
    "data": [
        {
            "alertNotifications": {
                "state": "Off"
            }
        }
    ]
};

const advancedThreatProtectionSettingsEnabled = {
    "data": [
        {
            "state": "Enabled"
        }
    ]
};

const advancedThreatProtectionSettingsDisabled = {
    "data": [
        {
            "state": "Disabled"
        }
    ]
};

const createCache = (servers, securityContacts, advancedThreatProtectionSettings) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;

    return {
        servers: {
            listSql: {
                'eastus': {
                    err: null,
                    data: servers
                }
            }
        },
        securityContactv2: {
            listAll: {
                'global': {
                    err: null,
                    data: securityContacts
                }
            }
        },
        advancedThreatProtectionSettings: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: null,
                        data: advancedThreatProtectionSettings
                    }
                }
            }
        }
    };
};

describe('advancedThreatProtectionNotificationEnabled', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([]);
            advancedThreatProtectionNotificationEnabled.run(cache, {}, callback);
        });

        it('should give passing result if Advanced Threat Protection is disabled for SQL server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Advanced Threat Protection for the SQL server is disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(servers, securityContactsEnabled.data, advancedThreatProtectionSettingsDisabled.data);
            advancedThreatProtectionNotificationEnabled.run(cache, {}, callback);
        });

        it('should give passing result if Advanced Threat Protection Notification is enabled and ATP is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Advanced Threat Protection Notification for the SQL server is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(servers, securityContactsEnabled.data, advancedThreatProtectionSettingsEnabled.data);
            advancedThreatProtectionNotificationEnabled.run(cache, {}, callback);
        });

        it('should give failing result if Advanced Threat Protection Notification is disabled and ATP is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Advanced Threat Protection Notification for the SQL server is disbaled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(servers, securityContactsDisabled.data, advancedThreatProtectionSettingsEnabled.data);
            advancedThreatProtectionNotificationEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(null, null, null);
            advancedThreatProtectionNotificationEnabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Advanced Threat Protection settings', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Advanced Threat Protection settings');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(servers, securityContactsEnabled.data, null);
            advancedThreatProtectionNotificationEnabled.run(cache, {}, callback);
        });
    });
});
