var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./highSeverityAlertsEnabled');

const createCache = (err, data) => {
    return {
        securityContacts: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('highSeverityAlertsEnabled', function() {
    describe('run', function() {
        it('should give failing result if no security contacts', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing security contacts');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if disable App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('High severity alerts for the subscription are not configured');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Security/securityContacts/default1",
                        "name": "default1",
                        "type": "Microsoft.Security/securityContacts",
                        "email": "rod_giovanni@yahoo.com",
                        "phone": "3053232490",
                        "alertNotifications": "Off",
                        "alertsToAdmins": "Off",
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if enabled App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('High severity alerts for the subscription are configured');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/providers/Microsoft.Security/securityContacts/default1",
                        "name": "default1",
                        "type": "Microsoft.Security/securityContacts",
                        "email": "rod_giovanni@yahoo.com",
                        "phone": "3053232490",
                        "alertNotifications": "On",
                        "alertsToAdmins": "Off",
                        "location": "global"
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})