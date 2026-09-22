var expect = require('chai').expect;
var attackPathNotificationsEnabled = require('./attackPathNotificationsEnabled');

const securityContacts = [
    {
        'name': 'default',
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/default',
        'type': 'Microsoft.Security/securityContacts',
        'notificationsSources': [
            {
                'minimalRiskLevel': 'High',
                'sourceType': 'AttackPath'
            },
            {
                'minimalSeverity': 'High',
                'sourceType': 'Alert'
            }
        ]
    },
    {
        'name': 'default',
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/default',
        'type': 'Microsoft.Security/securityContacts',
        'notificationsSources': [
            {
                'minimalSeverity': 'High',
                'sourceType': 'Alert'
            }
        ]
    },
    {
        'name': 'default',
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/default',
        'type': 'Microsoft.Security/securityContacts'
    }
];

const createCache = (securityContacts) => {
    return {
        securityContactv3: {
            listAll: {
                'global': {
                    data: securityContacts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        securityContactv3: {
            listAll: {
                'global': {}
            }
        }
    };
};

describe('attackPathNotificationsEnabled', function () {
    describe('run', function () {
        it('should give failing result if no security contacts found', function (done) {
            const cache = createCache([]);
            attackPathNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for security contacts', function (done) {
            const cache = createErrorCache();
            attackPathNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if attack path notifications are enabled', function (done) {
            const cache = createCache([securityContacts[0]]);
            attackPathNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Attack path email notifications are enabled with minimum risk level High');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if attack path notification source is not present', function (done) {
            const cache = createCache([securityContacts[1]]);
            attackPathNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Attack path email notifications are not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if no notification sources are configured', function (done) {
            const cache = createCache([securityContacts[2]]);
            attackPathNotificationsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Attack path email notifications are not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
