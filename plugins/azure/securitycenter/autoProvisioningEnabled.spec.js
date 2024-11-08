var expect = require('chai').expect;
var autoProvisioningEnabled = require('./autoProvisioningEnabled');

const autoProvisioningSettings = [
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/autoProvisioningSettings/default',
        'name': 'default',
        'autoProvision': 'On'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/autoProvisioningSettings/default',
        'name': 'default',
        'autoProvision': 'Off'
    }
];

const createCache = (autoProvisioningSettings) => {
    return {
        autoProvisioningSettings: {
            list: {
                global:{
                    data: autoProvisioningSettings
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        autoProvisioningSettings: {
            list: {
                global: {}
            }
        }
    };
};

describe('autoProvisioningEnabled', function() {
    describe('run', function() {
        it('should give failing result if no auto provisioning settings', function(done) {
            const cache = createCache([]);
            autoProvisioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing auto provisioning settings found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query auto provisioning settings', function(done) {
            const cache = createErrorCache();
            autoProvisioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query auto provisioning settings');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if auto provisioning is enabled', function(done) {
            const cache = createCache([autoProvisioningSettings[0]]);
            autoProvisioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Monitoring Agent Auto Provisioning is enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if auto provisioning is disabled', function(done) {
            const cache = createCache([autoProvisioningSettings[1]]);
            autoProvisioningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Monitoring Agent Auto Provisioning is disabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});