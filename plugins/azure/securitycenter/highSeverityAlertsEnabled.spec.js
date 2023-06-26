var expect = require('chai').expect;
var highSeverityAlertsEnabled = require('./highSeverityAlertsEnabled');

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
        alertNotifications : { state: "On", minimalSeverity: 'High' },
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
        },
        alertNotifications : { state: "On", minimalSeverity: 'Low' },
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
        },
        alertNotifications : { state: "Off", minimalSeverity: 'Low' },
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

describe('highSeverityAlertsEnabled', function() {
    describe('run', function() {
        it('should give failing result if no security contacts', function(done) {
            const cache = createCache([]);
            highSeverityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give unknown result if unable to query for security contacts', function(done) {
            const cache = createErrorCache();
            highSeverityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for security contacts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if Security Contact email alert severity is greater or equal then desired', function(done) {
            const cache = createCache([securityContacts[0]]);
            highSeverityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Security contacts email alert notifications enabled with minimum severity level');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if Security Contact email alert severity is less then desired', function(done) {
            const cache = createCache([securityContacts[1]]);
            highSeverityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security contacts email alert notifications enabled with minimum severity');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if Security Contact email alert notification not enabled', function(done) {
            const cache = createCache([securityContacts[2]]);
            highSeverityAlertsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Security contacts email alert notification are not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});