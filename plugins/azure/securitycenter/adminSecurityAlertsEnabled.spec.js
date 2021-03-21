var expect = require('chai').expect;
var adminSecurityAlertsEnabled = require('./adminSecurityAlertsEnabled');

const securityContacts = [
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'alertsToAdmins': 'On'
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'alertsToAdmins': 'Off'
    }
];

const createCache = (securityContacts) => {
    return {
        securityContacts: {
            list: {
                global:{
                    data: securityContacts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        securityContacts: {
            list: {
                global: {}
            }
        }
    };
};

describe('adminSecurityAlertsEnabled', function() {
    describe('run', function() {
        it('should give failing result if no security contacts', function(done) {
            const cache = createCache([]);
            adminSecurityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for security contacts', function(done) {
            const cache = createErrorCache();
            adminSecurityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if security alerts are being sent to admins', function(done) {
            const cache = createCache([securityContacts[0]]);
            adminSecurityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security alerts for the subscription are configured to be sent to admins');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if security alerts are not being sent to admins', function(done) {
            const cache = createCache([securityContacts[1]]);
            adminSecurityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security alerts for the subscription are not configured to be sent to admins');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});