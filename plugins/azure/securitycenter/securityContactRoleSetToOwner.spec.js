var expect = require('chai').expect;
var securityContactRoleSetToOwner = require('./securityContactRoleSetToOwner');

const securityContacts = [
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'alertsToAdmins': 'On',
        'email': 'xyz@gmail.com',

        "notificationsByRole": {
          "state": "On",
          "roles": [
            "Owner",
          ]
        },
    },
    {
        'id': '/subscriptions/123/providers/Microsoft.Security/securityContacts/contact1',
        'name': 'contact1',
        'alertsToAdmins': 'Off',
        'email': '',

        "notificationsByRole": {
          "state": "On",
          "roles": [
            "Admin"
          ]
        }
    }
];

const createCache = (securityContacts) => {
    return {
        securityContactv2: {
            listAll: {
                global:{
                    data: securityContacts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        securityContactv2: {
            listAll: {
                global: {}
            }
        }
    };
};

describe('securityContactRoleSetToOwner', function() {
    describe('run', function() {
        it('should give failing result if no security contacts', function(done) {
            const cache = createCache([]);
            securityContactRoleSetToOwner.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for security contacts', function(done) {
            const cache = createErrorCache();
            securityContactRoleSetToOwner.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if Security Contact email is configured for subscription owners', function(done) {
            const cache = createCache([securityContacts[0]]);
            securityContactRoleSetToOwner.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security Contact email is configured for subscription owners');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if Security Contact email is not configured for subscription owners', function(done) {
            const cache = createCache([securityContacts[1]]);
            securityContactRoleSetToOwner.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security Contact email is not configured for subscription owners');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});